// Owner-requested result staging shares the broker's existing two delivery
// slots. A pin is scoped to one accepted execution, never authority to settle.
const abi = @import("abi.zig");
const core = @import("contract_core.zig");
const wire = core.wire;
const analysis = @import("analysis_wire.zig");
pub const Deferred = union(enum) { ignored: void, held: analysis.Result, rejected: wire.Packet };
pub const Ready = struct { request: wire.Packet, snapshot: wire.Snapshot };
const Gate = struct {
    request: wire.Packet,
    owner: u64,
    issuer: u64,
    endpoint: u64,
    rpc: u64,
    attempt: u8,
    notified: bool = false,
    fn matches(self: Gate, table: *const core.Broker) bool {
        const record = table.status(self.owner, self.request.token) catch return false;
        return table.requester == self.owner and table.issuer == self.issuer and record.profile == analysis.profile and
            record.state == .running and record.input == self.request.data and record.worker.endpoint == self.endpoint and
            record.rpc == self.rpc and record.attempt == self.attempt;
    }
    fn candidate(self: Gate, result: analysis.Result) bool {
        return result.token == self.request.token and result.endpoint == self.endpoint and result.id == self.rpc and result.attempt == self.attempt;
    }
};
pub const Staging = struct {
    results: analysis.Results = .{},
    gates: [core.capacity]?Gate = .{ null, null },

    pub fn request(self: *Staging, table: *core.Broker, message: *const abi.Message, seam: anytype) core.Error!?wire.Snapshot {
        // Recheck the production wire/sender even when called through dispatch.
        const packet = wire.decodeRequest(message, table.requester) orelse return error.denied;
        if (packet.command != .stage) return error.invalid;
        const record = try table.status(message.sender, packet.token);
        if (record.profile != analysis.profile) return error.invalid;
        const slot = wire.tokenSlot(packet.token).?;
        if (packet.detail == 0) {
            const gate = self.gates[slot] orelse return error.not_ready;
            if (!gate.matches(table) or packet.data != gate.rpc) return error.stale;
            const complete = self.results.peek(packet.token) orelse return error.not_ready;
            if (!gate.notified or !gate.candidate(complete)) return error.not_ready;
            self.gates[slot] = null;
            return table.snapshot(record);
        }
        if (packet.data != record.input) return error.invalid;
        if (self.gates[slot]) |*gate| {
            if (!gate.matches(table)) return error.stale;
            if (gate.request.id != packet.id) return error.invalid;
            // Same request can recover a partial/lost ready reply without a
            // second dispatch or a different execution scope.
            gate.notified = false;
            return null;
        }
        if (record.state != .offered) return error.not_ready;
        const accepted = try table.accept(message.sender, packet.token, packet.data, analysis.profile, seam);
        // accept may enqueue worker IPC, but this broker cannot privately
        // dequeue it until request returns. Install before that boundary.
        self.gates[slot] = .{ .request = packet, .owner = table.requester, .issuer = table.issuer,
            .endpoint = accepted.worker.endpoint, .rpc = accepted.rpc, .attempt = accepted.attempt };
        return null;
    }
    pub fn push(self: *Staging, table: *const core.Broker, message: *const abi.Message) Deferred {
        const packet = wire.decode(message, message.sender, wire.reply_operation) orelse return .{ .ignored = {} };
        if (packet.command != .work and packet.command != .analysis_tuple) return .{ .ignored = {} };
        const record = table.status(table.requester, packet.token) catch return .{ .rejected = packet };
        if (record.profile != analysis.profile or record.state != .running or record.worker.endpoint != message.sender or
            record.rpc != packet.id or record.attempt != packet.detail) return .{ .rejected = packet };
        const candidate = self.results.push(message) orelse return .{ .ignored = {} };
        return if (self.results.hold(candidate)) .{ .held = candidate } else .{ .rejected = packet };
    }
    // Called only after checked lifecycle reconciliation. The complete held
    // tuple and current scope are both necessary for a readiness snapshot.
    pub fn ready(self: *Staging, table: *const core.Broker) [core.capacity]?Ready {
        var replies: [core.capacity]?Ready = .{ null, null };
        for (&self.gates, 0..) |*pending, slot| {
            const gate = if (pending.*) |*gate| gate else continue;
            if (gate.notified or !gate.matches(table)) continue;
            const candidate = self.results.peek(gate.request.token) orelse continue;
            if (!gate.candidate(candidate)) continue;
            const record = table.status(gate.owner, gate.request.token) catch continue;
            replies[slot] = .{ .request = gate.request, .snapshot = table.snapshot(record) };
            gate.notified = true;
        }
        return replies;
    }
    pub fn advance(self: *Staging, table: *const core.Broker) [core.capacity]?analysis.Result {
        var retired: [core.capacity]?analysis.Result = .{ null, null };
        var pinned: [core.capacity]bool = .{ false, false };
        for (&self.gates, 0..) |*pending, slot| {
            const gate = pending.* orelse continue;
            if (gate.matches(table)) {
                pinned[slot] = true;
            } else {
                // Terminal/expired/retired gates cannot survive or inherit a
                // successor. A full candidate still takes normal admission;
                // partial tuple storage is discarded without claiming a result.
                retired[slot] = self.results.take(gate.request.token);
                pending.* = null;
            }
        }
        var ready_results = self.results.advanceExcept(pinned);
        for (retired, 0..) |candidate, slot| if (candidate != null) { ready_results[slot] = candidate; };
        return ready_results;
    }
    pub fn take(self: *Staging, token: u64) ?analysis.Result {
        const candidate = self.results.peek(token);
        self.release(token);
        return candidate;
    }
    pub fn contains(self: *const Staging, token: u64) bool { return self.results.contains(token); }
    pub fn release(self: *Staging, token: u64) void {
        self.results.release(token);
        const slot = wire.tokenSlot(token) orelse return;
        if (self.gates[slot]) |gate| if (gate.request.token == token) { self.gates[slot] = null; };
    }
};
pub const gate_metadata_bytes = @sizeOf(Staging) - @sizeOf(analysis.Results);
