// The native work broker runs in this private ring-3 cell. Its seam is the
// existing checked kernel ABI; the finite service table never mints authority.
const abi = @import("abi.zig");
const syscall = @import("syscall.zig");
const core = @import("contract_core.zig");
const wire = core.wire;
const dispatcher = @import("contract_dispatch.zig");
const hosting = @import("hosting_runtime.zig");
const app = @import("hosting_app.zig");
const transport = @import("contract_transport.zig");
comptime {
    _ = @import("memory.zig");
}

pub const broker_template: u32 = 3;
pub const worker_template: u32 = 4;
pub const scenario: u64 = 24;
// These are declared native demonstration inputs. They retain the same result
// rule; only the bounded scheduling/fault exercise depends on the input.
pub const interleave_input: u64 = 0x7a65616c00000011;
pub const cancellation_input: u64 = 0x7a65616c00000022;
pub const sibling_input: u64 = 0x7a65616c00000033;
pub const recovery_input: u64 = 0x7a65616c00000044;
const require = hosting.require;

pub fn report(code: u64, value: u64, extra: u64) void {
    // Trace quota is independent of work/RPC volume and cannot silently erase
    // the evidence needed to check a service transition.
    require(syscall.raw(@intFromEnum(abi.Call.report), code, value, extra) == 0);
}

fn boot(role: abi.Role) abi.BootInfo {
    var info: abi.BootInfo = undefined;
    require(syscall.boot(&info) == 0 and info.abi == abi.version and info.role == @intFromEnum(role) and
        info.endpoint != 0 and info.generation != 0 and info.instance != 0 and info.parent_endpoint != 0 and
        info.scenario == scenario and info.reserved == 0);
    return info;
}
fn bind(info: *abi.BootInfo, creation: bool) void {
    var bootstrap: app.Bootstrap = .{ .endpoint = info.endpoint, .parent = info.parent_endpoint, .instance = info.instance, .needs_creation = creation };
    while (true) switch (bootstrap.inspect(info.*)) {
        .ready => break,
        .failed => {
            require(false);
            unreachable;
        },
        .waiting => {
            require(syscall.sleep(1) == 0);
            info.* = boot(@enumFromInt(info.role));
        },
    };
    var cap: abi.CapabilityInfo = undefined;
    require(syscall.query(info.parent_channel, &cap) == 0 and cap.holder == info.endpoint and cap.target == info.parent_endpoint and
        cap.rights == abi.right(.hosting_reply) and cap.reserved == 0 and cap.parent == 0);
}
fn initialize(info: abi.BootInfo) u64 {
    const stack: *volatile u64 = @ptrFromInt(abi.stack_base + 64);
    const memory: *volatile [2]u64 = @ptrFromInt(abi.memory_base);
    require(stack.* == 0 and memory[0] == 0 and memory[1] == 0);
    report(40, info.endpoint, info.instance);
    report(41, stack.*, memory[0]);
    const sentinel = app.memory_salt ^ info.endpoint;
    stack.* = app.guard_salt ^ info.endpoint;
    memory[0] = sentinel;
    memory[1] = ~sentinel;
    report(42, memory[0], memory[1]);
    return sentinel;
}
fn observe(info: abi.BootInfo, sentinel: u64, evidence: bool) void {
    const stack: *volatile u64 = @ptrFromInt(abi.stack_base + 64);
    const memory: *volatile [2]u64 = @ptrFromInt(abi.memory_base);
    require(stack.* == app.guard_salt ^ info.endpoint and memory[0] == sentinel and memory[1] == ~sentinel);
    if (evidence) report(42, memory[0], memory[1]);
}
fn deniedStorage(info: abi.BootInfo) void {
    const fs = syscall.lookup(.filesystem);
    const block = syscall.lookup(.block);
    var file_message = @import("storage_wire.zig").openRequest(1, "/forbidden");
    var block_message = @import("storage_wire.zig").request(.block_read, 1, 0, 0, 8, &.{});
    const first = syscall.send(fs, &file_message, info.parent_channel);
    const second = syscall.send(block, &block_message, info.parent_channel);
    require(first == @intFromEnum(abi.Error.denied) and second == @intFromEnum(abi.Error.denied) and
        syscall.find(fs, abi.right(.file_open)) == @intFromEnum(abi.Error.denied) and
        syscall.find(block, abi.right(.block_read)) == @intFromEnum(abi.Error.denied));
    report(49, @bitCast(first), @bitCast(second));
}

pub fn worker() noreturn {
    var info = boot(.worker);
    require(info.template_id == worker_template and info.depth == 2 and info.creation == 0);
    const sentinel = initialize(info);
    bind(&info, false);
    deniedStorage(info);
    var ready = wire.encode(wire.reply_operation, .{ .id = 1, .command = .bootstrap, .kind = .response, .data = info.instance });
    require(hosting.sendBounded(info.parent_endpoint, &ready, info.parent_channel) == 0);
    var state: wire.Worker = .{ .parent = info.parent_endpoint };
    while (true) {
        var message: abi.Message = undefined;
        if (syscall.receiveWait(&message, 10) != 0) continue;
        const packet = state.accept(&message) orelse continue;
        observe(info, sentinel, true);
        // A worker may know its contract reference but owns only reply rights.
        // It cannot turn that service reference into requester authorization.
        var forbidden_accept = wire.encode(wire.request_operation, .{ .id = packet.id, .command = .accept, .detail = wire.profile, .token = packet.token, .data = packet.data });
        const denied_accept = syscall.send(info.parent_endpoint, &forbidden_accept, info.parent_channel);
        require(denied_accept == @intFromEnum(abi.Error.denied));
        report(57, info.parent_channel, @bitCast(denied_accept));
        if (packet.data == recovery_input and packet.detail == 1) asm volatile ("ud2");
        const delay: u64 = if (packet.data == interleave_input) 16 else if (packet.data == sibling_input) 32 else 0;
        if (delay != 0) {
            report(46, delay, info.endpoint);
            require(syscall.sleep(delay) == 0);
            observe(info, sentinel, true);
            report(47, sentinel, delay);
        }
        const answer = wire.calculate(packet.data);
        report(43, packet.id, answer);
        var response = wire.encode(wire.reply_operation, .{ .id = packet.id, .command = .work, .kind = .response, .detail = packet.detail, .token = packet.token, .data = answer });
        require(hosting.sendBounded(info.parent_endpoint, &response, info.parent_channel) == 0);
    }
}

const Service = struct {
    info: abi.BootInfo,
    table: core.Broker,
    management: wire.Sequence = .{},
    inbox: transport.Inbox = .{},
    deferred: transport.Replies = .{},
    announced: [2]bool = .{ false, false },
    waiting: [2]u16 = .{ 0, 0 },
    waiting_rpc: [2]u64 = .{ 0, 0 },
    sentinel: u64,

    fn tokenFor(self: *const Service, control: u64) u64 {
        for (self.table.records) |record| if (record.state != .free and record.worker.control == control) return record.token;
        return 0;
    }
    pub fn domain(self: *Service) ?core.Domain {
        var status: abi.DomainStatus = undefined;
        if (syscall.domainStatus(self.info.creation, &status) != 0 or status.holder != self.info.endpoint or
            status.instance != self.info.instance or status.reserved_slots != 0 or status.reserved_pages != 0 or
            status.slot_limit != 2 or status.page_limit != 4 or status.revoked != 0 or
            status.template_mask != 8 or status.recipe != 1) return null;
        return .{ .owned_slots = status.owned_slots, .owned_pages = status.owned_pages, .available_slots = status.available_slots, .available_pages = status.available_pages };
    }
    pub fn create(self: *Service) ?core.Backing {
        const id = self.management.take() orelse return null;
        const request: abi.CreateRequest = .{ .authority = self.info.creation, .request = id, .template_id = worker_template };
        var child: abi.CreateResult = undefined;
        if (syscall.create(&request, &child) != 0) return null;
        var status: abi.CellStatus = undefined;
        var cap: abi.CapabilityInfo = undefined;
        if (syscall.status(child.control, &status) != 0 or status.instance != child.instance or status.endpoint != child.endpoint or
            status.own_pages != 2 or status.parent_endpoint != self.info.endpoint or status.parent_instance != self.info.instance or
            status.template_id != worker_template or status.depth != 2 or status.phase != 1 or child.creation != 0 or
            syscall.query(child.channel, &cap) != 0 or cap.holder != self.info.endpoint or cap.target != child.endpoint or
            cap.rights != abi.right(.hosting_request) or cap.parent != 0)
        {
            require(self.settle(child));
            return null;
        }
        // A created worker is backing only after its private cold boot and exact
        // current-generation channel validation have been acknowledged.
        for (0..16) |_| {
            var message: abi.Message = undefined;
            const received = syscall.receiveWait(&message, 1);
            if (received == 0) {
                if (wire.decodeBootstrap(&message, child.endpoint, child.instance)) {
                    require(syscall.sleep(1) == 0);
                    return child;
                }
                if ((message.sender == self.info.parent_endpoint or wire.decodeWork(&message, message.sender, wire.reply_operation) != null) and
                    !self.inbox.push(message)) break;
            } else if (received != @intFromEnum(abi.Error.timeout)) break;
        }
        require(self.settle(child));
        return null;
    }
    pub fn settle(self: *Service, child: core.Backing) bool {
        return self.retire(child, null).cleaned;
    }
    pub fn admit(self: *Service, child: core.Backing) ?core.Fence {
        var status: abi.CellStatus = undefined;
        if (syscall.status(child.control, &status) != 0) return null;
        return dispatcher.admissionFence(child, status, self.info.endpoint);
    }
    pub fn settleCandidate(self: *Service, child: core.Backing, fence: core.Fence) core.Settlement {
        return self.retire(child, fence);
    }
    fn retire(self: *Service, child: core.Backing, fence: ?core.Fence) core.Settlement {
        _ = self;
        const failed: core.Settlement = .{ .cleaned = false, .stable = false };
        if (syscall.stop(child.control) != 0) return failed;
        var status: abi.CellStatus = undefined;
        if (syscall.status(child.control, &status) != 0 or !dispatcher.backingReleased(child, status)) return failed;
        // Stop removed scheduling eligibility. Comparing the terminal counters
        // catches retirement after admission, before any receipt can publish.
        const stable = if (fence) |sample| dispatcher.fenceStable(child, status, sample) else true;
        if (syscall.reap(child.control) != 0) return failed;
        if (syscall.status(child.control, &status) != @intFromEnum(abi.Error.stale)) return failed;
        report(55, child.control, child.instance);
        return .{ .cleaned = true, .stable = stable };
    }
    pub fn send(self: *Service, child: core.Backing, message: abi.Message) bool {
        const packet = wire.decodeWork(&message, self.info.endpoint, wire.request_operation) orelse blk: {
            var copied = message;
            copied.sender = self.info.endpoint;
            break :blk wire.decodeWork(&copied, self.info.endpoint, wire.request_operation) orelse return false;
        };
        if (packet.detail == 1) report(75, packet.token, packet.data);
        report(76, packet.token, packet.id);
        report(77, packet.token, packet.detail);
        return hosting.sendBounded(child.endpoint, &message, child.channel) == 0;
    }
    pub fn validated(self: *Service, token: u64, child: core.Backing, rpc: u64, attempt: u8, input: u64, result: u64) void {
        _ = self;
        _ = child;
        _ = rpc;
        _ = attempt;
        require(result == wire.calculate(input));
        report(78, token, result);
    }
    pub fn rebind(self: *Service, old: core.Backing) ?core.Backing {
        var status: abi.CellStatus = undefined;
        if (syscall.status(old.control, &status) != 0 or status.phase != 1 or status.endpoint == old.endpoint or
            status.instance != old.instance or status.control != old.control or status.own_pages != 2) return null;
        var stale = wire.encode(wire.request_operation, .{ .id = 0xffffffffffffffff, .command = .work, .detail = 1, .token = self.tokenFor(old.control), .data = 1 });
        const old_endpoint = syscall.send(old.endpoint, &stale, old.channel);
        const old_channel = syscall.send(status.endpoint, &stale, old.channel);
        require(old_endpoint == @intFromEnum(abi.Error.stale) and old_channel == @intFromEnum(abi.Error.stale));
        report(51, old.endpoint, @bitCast(old_endpoint));
        report(51, old.channel, @bitCast(old_channel));
        const request: abi.RebindRequest = .{ .authority = self.info.creation, .control = old.control, .request = self.management.take() orelse return null };
        var child: abi.CreateResult = undefined;
        if (syscall.rebind(&request, &child) != 0) return null;
        var cap: abi.CapabilityInfo = undefined;
        if (syscall.query(child.channel, &cap) != 0 or cap.holder != self.info.endpoint or cap.target != child.endpoint or
            cap.rights != abi.right(.hosting_request) or cap.parent != 0 or child.channel == old.channel) return null;
        report(83, self.tokenFor(old.control), child.endpoint);
        return child;
    }
    fn ledger(self: *Service) void {
        const domain_status = self.domain() orelse {
            require(false);
            unreachable;
        };
        require(self.table.conserved(domain_status));
        hosting.checkLedger(self.info.creation, domain_status.owned_slots, domain_status.owned_pages, 0, 0, domain_status.available_slots, domain_status.available_pages);
    }
    fn offerEvidence(self: *Service, record: *const core.Record) void {
        report(70, record.token, record.offer_id);
        report(71, record.token, record.input);
        report(72, record.token, record.worker.instance);
        report(73, record.token, record.worker.control);
        report(74, record.token, record.worker.endpoint);
        self.ledger();
    }
    fn terminalEvidence(self: *Service) void {
        for (&self.table.records, 0..) |*record, index| {
            if (!record.terminal() or self.announced[index]) continue;
            self.ledger();
            report(79, record.token, self.table.snapshot(record).flags());
            self.announced[index] = true;
        }
    }
    fn response(self: *Service, packet: wire.Packet, snapshot: wire.Snapshot) void {
        var messages = snapshot.messages(packet.id, packet.command);
        for (&messages) |*message| {
            // Failed output publication leaves the owner-scoped record intact;
            // STATUS/OFFER resynchronization never creates another worker.
            if (hosting.sendBounded(self.info.parent_endpoint, message, self.info.parent_channel) != 0) return;
        }
    }
    fn failureReply(self: *Service, packet: wire.Packet, failure: core.Error) void {
        const code = dispatcher.failureCode(failure);
        var message = wire.encode(wire.reply_operation, .{ .id = packet.id, .command = packet.command, .kind = .failure, .token = packet.token, .data = code });
        _ = hosting.sendBounded(self.info.parent_endpoint, &message, self.info.parent_channel);
    }
    fn handleRequest(self: *Service, message: *const abi.Message) void {
        const result = dispatcher.dispatch(&self.table, message, self);
        self.terminalEvidence();
        switch (result) {
            .ignored => {},
            .failure => |failure| self.failureReply(failure.request, failure.reason),
            .snapshot => |reply| {
                if (reply.new_offer) self.offerEvidence(self.table.status(self.info.parent_endpoint, reply.value.token) catch {
                    require(false);
                    unreachable;
                });
                self.response(reply.request, reply.value);
            },
            .reaped => |packet| {
                const slot = wire.tokenSlot(packet.token).?;
                self.announced[slot] = false;
                // Private delivery storage has its own release point. A reaped
                // predecessor cannot occupy the successor's delivery slot.
                if (self.deferred.release(packet.token)) |old_message| {
                    const old = wire.decodeWork(&old_message, old_message.sender, wire.reply_operation).?;
                    _ = self.table.deliver(&old_message, self) catch {
                        report(81, old.token, old.id);
                    };
                }
                report(80, packet.token, wire.tokenSerial(packet.token));
                var reply = wire.encode(wire.reply_operation, .{ .id = packet.id, .command = .reap, .kind = .response, .token = packet.token });
                _ = hosting.sendBounded(self.info.parent_endpoint, &reply, self.info.parent_channel);
            },
        }
    }
    fn deferReply(self: *Service, message: abi.Message) void {
        const packet = wire.decodeWork(&message, message.sender, wire.reply_operation) orelse return;
        switch (self.deferred.hold(&self.table, message)) {
            .accepted => report(86, packet.token, packet.id),
            .rejected, .full => report(81, packet.token, packet.id),
        }
    }
    fn observeLifecycle(self: *Service, count_window: bool) void {
        // A checked status sample is the service's observation boundary. It is
        // reconciled before owner snapshots and staged-result consumption; it
        // does not create an atomic kernel/service transaction across syscalls.
        for (&self.table.records, 0..) |*record, index| {
            if (record.state != .offered and record.state != .running and record.state != .recovering) continue;
            if (count_window and record.state != .offered) {
                if (self.waiting_rpc[index] != record.rpc) {
                    self.waiting_rpc[index] = record.rpc;
                    self.waiting[index] = 0;
                }
                self.waiting[index] += 1;
                if (self.waiting[index] == 160) {
                    _ = self.table.expire(record.token, self) catch {
                        require(record.terminal());
                        continue;
                    };
                    continue;
                }
            }
            var status: abi.CellStatus = undefined;
            require(syscall.status(record.worker.control, &status) == 0);
            const previous = record.state;
            const endpoint = record.worker.endpoint;
            _ = (if (count_window) dispatcher.reconcile(&self.table, record.token, status, self) else dispatcher.observe(&self.table, record.token, status, self)) catch {
                require(record.terminal());
                continue;
            };
            if (previous == .running and record.state == .recovering) report(82, record.token, endpoint);
        }
        self.terminalEvidence();
    }
    fn advance(self: *Service) void {
        // Reconcile retirement first: an old dequeued result cannot settle a
        // faulted attempt merely because its bounded private window matured.
        self.observeLifecycle(true);
        for (self.deferred.advance()) |pending| {
            const message = pending orelse continue;
            const packet = wire.decodeWork(&message, message.sender, wire.reply_operation).?;
            _ = self.table.deliver(&message, self) catch {
                report(81, packet.token, packet.id);
                continue;
            };
            self.terminalEvidence();
        }
        self.terminalEvidence();
    }
};

pub fn broker() noreturn {
    var info = boot(.supervisor);
    require(info.template_id == broker_template and info.depth == 1);
    const sentinel = initialize(info);
    bind(&info, true);
    deniedStorage(info);
    var service: Service = .{ .info = info, .table = core.Broker.init(info.endpoint, info.parent_endpoint), .sentinel = sentinel };
    service.ledger();
    while (true) {
        var message: abi.Message = undefined;
        const received = if (service.inbox.pop()) |queued| blk: {
            message = queued;
            break :blk @as(i64, 0);
        } else syscall.receiveWait(&message, 1);
        if (received == 0) {
            observe(info, sentinel, false);
            if (message.sender == info.parent_endpoint) {
                service.observeLifecycle(false);
                service.handleRequest(&message);
            } else service.deferReply(message);
        } else require(received == @intFromEnum(abi.Error.timeout));
        service.advance();
    }
}
