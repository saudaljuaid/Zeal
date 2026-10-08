// The isolated broker owns this finite table. Only the injected production
// lifecycle/transport seam creates, rebinds, sends, stops or reaps kernel objects.
const abi = @import("abi.zig");
pub const wire = @import("contract_wire.zig");
pub const capacity = 2;
pub const Backing = abi.CreateResult;
pub const State = wire.State;
pub const Reason = wire.Reason;
pub const Fence = struct { generation: u64, faults: u32, restarts: u32 };
pub const Settlement = struct { cleaned: bool, stable: bool };
pub const Error = error{ denied, invalid, stale, no_space, exhausted, resource, transport, cleanup, not_terminal, not_ready };
pub const Domain = struct {
    owned_slots: u32, owned_pages: u32, available_slots: u32, available_pages: u32,
    slot_limit: u32 = 2, page_limit: u32 = 4,
    pub fn valid(self: Domain) bool {
        return self.slot_limit == 2 and self.page_limit == 4 and self.owned_slots <= 2 and self.owned_pages <= 4 and
            self.available_slots == 2 - self.owned_slots and self.available_pages == 4 - self.owned_pages;
    }
};
pub const Record = struct {
    token: u64 = 0, offer_id: u64 = 0, input: u64 = 0, profile: u8 = wire.profile, state: State = .free,
    worker: Backing = .{ .instance = 0, .control = 0, .endpoint = 0, .channel = 0, .creation = 0, .slot = 0, .identity = 0 },
    attempt: u8 = 0, rpc: u64 = 0, execution: u64 = 0, retries: u8 = 0, reason: Reason = .ok,
    cleanup_attempts: u8 = 0,
    backing_slots: u8 = 0, backing_pages: u8 = 0, verified: bool = false, result: u64 = 0,
    pub fn terminal(self: *const Record) bool { return self.state == .completed or self.state == .cancelled or self.state == .failed; }
};
pub const Broker = struct {
    issuer: u64, requester: u64,
    records: [capacity]Record = [_]Record{.{}} ** capacity,
    next_serial: u64 = 1, offer_highwater: u64 = 0, rpc_sequence: wire.Sequence = .{},
    pub fn init(issuer: u64, requester: u64) Broker { return .{ .issuer = issuer, .requester = requester }; }
    fn owner(self: *const Broker, sender: u64) Error!void {
        if (self.issuer == 0 or self.requester == 0 or sender != self.requester) return Error.denied;
    }
    pub fn status(self: *const Broker, sender: u64, token_value: u64) Error!*const Record {
        try self.owner(sender);
        const slot = wire.tokenSlot(token_value) orelse return Error.invalid;
        if (wire.tokenIssuer(token_value) != self.issuer) return Error.stale;
        const record = &self.records[slot];
        if (record.state == .free or record.token != token_value) return Error.stale;
        return record;
    }
    fn mutable(self: *Broker, sender: u64, token_value: u64) Error!*Record {
        _ = try self.status(sender, token_value);
        return &self.records[wire.tokenSlot(token_value).?];
    }
    pub fn findOffer(self: *const Broker, sender: u64, id: u64) Error!*const Record {
        try self.owner(sender);
        if (id == 0) return Error.invalid;
        for (&self.records) |*record| if (record.state != .free and record.offer_id == id) return record;
        return Error.stale;
    }
    pub fn snapshot(self: *const Broker, record: *const Record) wire.Snapshot {
        return .{ .token = record.token, .state = record.state, .profile_id = record.profile, .retries = record.retries,
            .attempt = record.attempt, .reason = record.reason, .slots = record.backing_slots, .pages = record.backing_pages,
            .verified = record.verified, .input = record.input, .requester = self.requester, .issuer = self.issuer,
            .instance = record.worker.instance, .endpoint = if (record.attempt == 0) record.worker.endpoint else record.execution,
            .rpc = record.rpc, .result = record.result };
    }
    fn charges(self: *const Broker) struct { slots: u32, pages: u32 } {
        var slots: u32 = 0;
        var pages: u32 = 0;
        for (self.records) |record| { slots += record.backing_slots; pages += record.backing_pages; }
        return .{ .slots = slots, .pages = pages };
    }
    pub fn conserved(self: *const Broker, domain: Domain) bool {
        const held = self.charges();
        return domain.valid() and held.slots == domain.owned_slots and held.pages == domain.owned_pages;
    }
    fn validBacking(worker: Backing) bool {
        return worker.instance != 0 and worker.control != 0 and worker.endpoint != 0 and worker.channel != 0 and
            worker.creation == 0 and worker.slot >= 4 and worker.slot < 8;
    }
    pub fn offer(self: *Broker, sender: u64, id: u64, input: u64, profile: u8, seam: anytype) Error!*Record {
        try self.owner(sender);
        if (id == 0 or profile != wire.profile) return Error.invalid;
        if (self.issuer & 255 < 1 or self.issuer & 255 > 8) return Error.invalid;
        for (&self.records) |*record| {
            if (record.state != .free and record.offer_id == id) {
                if (record.input != input or record.profile != profile) return Error.invalid;
                return record;
            }
        }
        if (id <= self.offer_highwater) return Error.stale;
        var free: ?usize = null;
        for (self.records, 0..) |record, index| if (record.state == .free) { free = index; break; };
        const slot = free orelse return Error.no_space;
        if (self.next_serial == 0 or self.next_serial > wire.serial_limit or self.issuer >> 8 == 0 or self.issuer >> 8 > wire.generation_limit) return Error.exhausted;
        const before = seam.domain() orelse return Error.resource;
        if (!self.conserved(before)) return Error.resource;
        if (before.available_slots < 1 or before.available_pages < 2) return Error.no_space;
        // Only after all pure prevalidation succeeds is the offer transaction consumed.
        const serial = self.next_serial;
        self.next_serial = if (serial == wire.serial_limit) 0 else serial + 1;
        self.offer_highwater = id;
        const worker = seam.create() orelse return Error.resource;
        const record = &self.records[slot];
        record.* = .{ .token = wire.token(serial, slot, self.issuer).?, .offer_id = id, .input = input, .profile = profile,
            .state = .offered, .worker = worker, .backing_slots = 1, .backing_pages = 2 };
        var unique = true;
        for (self.records, 0..) |other, index| {
            if (index != slot and other.backing_slots != 0 and (other.worker.instance == worker.instance or
                other.worker.control == worker.control or other.worker.endpoint == worker.endpoint or other.worker.slot == worker.slot)) unique = false;
        }
        if (!unique) {
            // A duplicate numeric control is not authority to destroy another
            // obligation. Production checked creation guarantees this cannot occur.
            record.* = .{};
            return Error.resource;
        }
        const after = seam.domain();
        if (!validBacking(worker) or after == null or !self.conserved(after.?)) {
            try self.finish(record, .failed, .resource, seam);
            return Error.resource;
        }
        return record;
    }
    fn sendAttempt(self: *Broker, record: *Record, seam: anytype) Error!void {
        const rpc = self.rpc_sequence.take() orelse {
            try self.finish(record, .failed, .counter_exhausted, seam);
            return Error.exhausted;
        };
        record.rpc = rpc;
        record.attempt = record.retries + 1;
        record.execution = record.worker.endpoint;
        record.state = .running;
        const message = wire.encode(wire.request_operation, .{ .id = rpc, .command = .work, .detail = record.attempt,
            .token = record.token, .data = record.input });
        if (!seam.send(record.worker, message)) {
            try self.finish(record, .failed, .transport, seam);
            return Error.transport;
        }
    }
    pub fn accept(self: *Broker, sender: u64, token_value: u64, input: u64, profile: u8, seam: anytype) Error!*Record {
        const record = try self.mutable(sender, token_value);
        if (profile != record.profile or input != record.input) return Error.invalid;
        if (record.state == .running or record.state == .recovering or record.state == .completed) return record;
        if (record.state != .offered) return Error.not_ready;
        try self.sendAttempt(record, seam);
        return record;
    }
    // Read actual remaining charges after a partial stop/reap failure. Other records
    // are untouched, so this never fabricates a resource refund from service state.
    fn refreshCharges(self: *Broker, record: *Record, seam: anytype) void {
        const domain = seam.domain() orelse return;
        if (!domain.valid()) return;
        var other_slots: u32 = 0;
        var other_pages: u32 = 0;
        for (&self.records) |*other| if (other != record) { other_slots += other.backing_slots; other_pages += other.backing_pages; };
        if (domain.owned_slots < other_slots or domain.owned_pages < other_pages) return;
        const slots = domain.owned_slots - other_slots;
        const pages = domain.owned_pages - other_pages;
        if (slots <= 1 and pages <= 2) { record.backing_slots = @intCast(slots); record.backing_pages = @intCast(pages); }
    }
    fn finish(self: *Broker, record: *Record, state: State, reason: Reason, seam: anytype) Error!void {
        _ = try self.finishCandidate(record, state, reason, null, seam);
    }
    fn finishCandidate(self: *Broker, record: *Record, state: State, reason: Reason, fence: ?Fence, seam: anytype) Error!bool {
        record.verified = false;
        record.result = 0;
        if (record.cleanup_attempts >= 2) return Error.cleanup;
        record.cleanup_attempts += 1;
        const settlement: Settlement = if (fence) |admitted| seam.settleCandidate(record.worker, admitted) else
            .{ .cleaned = seam.settle(record.worker), .stable = true };
        if (!settlement.cleaned) {
            record.state = .failed;
            record.reason = .lifecycle;
            self.refreshCharges(record, seam);
            return Error.cleanup;
        }
        self.refreshCharges(record, seam);
        const domain = seam.domain() orelse {
            record.state = .failed; record.reason = .lifecycle; return Error.cleanup;
        };
        if (!self.conserved(domain) or record.backing_slots != 0 or record.backing_pages != 0) {
            record.state = .failed; record.reason = .lifecycle; return Error.cleanup;
        }
        if (!settlement.stable) {
            record.state = .failed;
            record.reason = .lifecycle;
            return false;
        }
        record.state = state;
        record.reason = reason;
        return true;
    }
    pub fn cancel(self: *Broker, sender: u64, token_value: u64, seam: anytype) Error!*Record {
        const record = try self.mutable(sender, token_value);
        if (record.state == .failed and (record.backing_slots != 0 or record.backing_pages != 0)) {
            try self.finish(record, .failed, record.reason, seam);
            return record;
        }
        if (record.terminal()) return record;
        try self.finish(record, .cancelled, .cancelled, seam);
        return record;
    }
    pub fn expire(self: *Broker, token_value: u64, seam: anytype) Error!*Record {
        const record = try self.mutable(self.requester, token_value);
        if (record.terminal()) return record;
        if (record.state != .running and record.state != .recovering) return Error.not_ready;
        try self.finish(record, .failed, .transport, seam);
        return record;
    }
    // An unavailable provider is a lifecycle failure, never requester consent
    // to cancel. Settled decisions remain immutable and late results stay fenced.
    pub fn workerUnavailable(self: *Broker, token_value: u64, seam: anytype) Error!*Record {
        const record = try self.mutable(self.requester, token_value);
        if (record.terminal()) return record;
        try self.finish(record, .failed, .lifecycle, seam);
        return record;
    }
    pub fn reap(self: *Broker, sender: u64, token_value: u64) Error!void {
        const record = try self.mutable(sender, token_value);
        if (!record.terminal() or record.backing_slots != 0 or record.backing_pages != 0) return Error.not_terminal;
        record.* = .{};
    }
    pub fn deliver(self: *Broker, message: *const abi.Message, seam: anytype) Error!*Record {
        const packet = wire.decodeWork(message, message.sender, wire.reply_operation) orelse return Error.invalid;
        const record = try self.mutable(self.requester, packet.token);
        if (record.state != .running or record.execution != message.sender or record.worker.endpoint != message.sender or record.rpc != packet.id or record.attempt != packet.detail) return Error.stale;
        if (packet.data != wire.calculate(record.input)) {
            try self.finish(record, .failed, .invalid_result, seam);
            return Error.invalid;
        }
        const fence = seam.admit(record.worker) orelse {
            try self.finish(record, .failed, .lifecycle, seam);
            return Error.stale;
        };
        if (fence.generation != record.execution >> 8 or fence.faults == @import("std").math.maxInt(u32)) {
            try self.finish(record, .failed, .lifecycle, seam);
            return Error.stale;
        }
        const result = packet.data;
        seam.validated(record.token, record.worker, record.rpc, record.attempt, record.input, result);
        if (!try self.finishCandidate(record, .completed, .ok, fence, seam)) return Error.stale;
        record.result = result;
        record.verified = true;
        return record;
    }
    pub fn workerFault(self: *Broker, endpoint: u64, seam: anytype) Error!*Record {
        for (&self.records) |*record| {
            if (record.state == .running and record.worker.endpoint == endpoint) {
                if (record.retries == 1) try self.finish(record, .failed, .second_fault, seam) else record.state = .recovering;
                return record;
            }
        }
        return Error.stale;
    }
    pub fn retry(self: *Broker, token_value: u64, seam: anytype) Error!*Record {
        const record = try self.mutable(self.requester, token_value);
        if (record.state != .recovering) return Error.not_ready;
        if (record.retries >= 1) { try self.finish(record, .failed, .second_fault, seam); return record; }
        const replacement = seam.rebind(record.worker) orelse {
            try self.finish(record, .failed, .rebind, seam); return Error.resource;
        };
        if (!validBacking(replacement) or replacement.instance != record.worker.instance or replacement.control != record.worker.control or
            replacement.slot != record.worker.slot or replacement.identity != record.worker.identity or replacement.endpoint >> 8 <= record.worker.endpoint >> 8 or
            replacement.channel == record.worker.channel) {
            try self.finish(record, .failed, .rebind, seam); return Error.resource;
        }
        record.worker = replacement;
        record.retries = 1;
        try self.sendAttempt(record, seam);
        return record;
    }
};
