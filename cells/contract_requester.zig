// Root identity400 exercises the same bounded protocol available to its
// authenticated requester generation. Every successful result is recomputed.
const abi = @import("abi.zig");
const syscall = @import("syscall.zig");
const wire = @import("contract_wire.zig");
const runtime = @import("contract_runtime.zig");
const hosting = @import("hosting_runtime.zig");
const require = hosting.require;

const Reply = union(enum) { snapshot: wire.Snapshot, failure: u64, reaped: void };
const Requester = struct {
    info: abi.BootInfo,
    broker: abi.CreateResult,
    sequence: wire.Sequence = .{},
    accepted: [2]?wire.Snapshot = .{ null, null },
    fn id(self: *Requester) u64 {
        return self.sequence.take() orelse {
            require(false);
            unreachable;
        };
    }
    fn call(self: *Requester, packet: wire.Packet) Reply {
        var message = wire.encode(wire.request_operation, packet);
        require(hosting.sendBounded(self.broker.endpoint, &message, self.broker.channel) == 0);
        var collector: wire.Collector = .{ .issuer = self.broker.endpoint, .requester = self.info.endpoint, .id = packet.id, .command = packet.command, .token = packet.token };
        for (0..16) |_| {
            var response: abi.Message = undefined;
            const received = syscall.receiveWait(&response, 10);
            if (received == @intFromEnum(abi.Error.timeout)) continue;
            require(received == 0);
            const parsed = wire.decode(&response, self.broker.endpoint, wire.reply_operation) orelse continue;
            if (parsed.id != packet.id or parsed.command != packet.command) continue;
            if (parsed.kind == .failure) {
                require(parsed.detail == 0 and parsed.token == packet.token and parsed.data >= 1 and parsed.data <= 10);
                return .{ .failure = parsed.data };
            }
            if (packet.command == .reap and parsed.kind == .response) {
                require(parsed.token == packet.token and parsed.detail == 0 and parsed.data == 0);
                return .{ .reaped = {} };
            }
            require(collector.push(&response));
            if (collector.count == wire.snapshot_parts) return .{ .snapshot = collector.take() orelse {
                require(false);
                unreachable;
            } };
        }
        require(false);
        unreachable;
    }
    fn snapshot(self: *Requester, packet: wire.Packet) wire.Snapshot {
        return switch (self.call(packet)) {
            .snapshot => |value| value,
            else => {
                require(false);
                unreachable;
            },
        };
    }
    fn discardReply(self: *Requester, packet: wire.Packet) void {
        var message = wire.encode(wire.request_operation, packet);
        require(hosting.sendBounded(self.broker.endpoint, &message, self.broker.channel) == 0);
        var part: u8 = 0;
        for (0..16) |_| {
            var response: abi.Message = undefined;
            const received = syscall.receiveWait(&response, 10);
            if (received == @intFromEnum(abi.Error.timeout)) continue;
            require(received == 0);
            const parsed = wire.decode(&response, self.broker.endpoint, wire.reply_operation) orelse continue;
            if (parsed.id != packet.id or parsed.command != packet.command) continue;
            require(parsed.kind == .snapshot and parsed.detail == part);
            // The requester intentionally does not collect any token, flags or
            // result fields from this reply. Only authoritative resynchronization
            // may subsequently give it an offer or completed result.
            part += 1;
            if (part == wire.snapshot_parts) {
                runtime.report(87, packet.id, @intFromEnum(packet.command));
                return;
            }
        }
        require(false);
    }
    fn offer(self: *Requester, input: u64) wire.Snapshot {
        const snapshot_value = self.snapshot(.{ .id = self.id(), .command = .offer, .detail = wire.profile, .data = input });
        require(snapshot_value.state == .offered and snapshot_value.input == input and snapshot_value.slots == 1 and snapshot_value.pages == 2);
        return snapshot_value;
    }
    fn status(self: *Requester, token: u64) wire.Snapshot {
        return self.snapshot(.{ .id = self.id(), .command = .status, .token = token });
    }
    fn accept(self: *Requester, offered: wire.Snapshot) wire.Snapshot {
        const snapshot_value = self.snapshot(.{ .id = self.id(), .command = .accept, .detail = wire.profile, .token = offered.token, .data = offered.input });
        require(snapshot_value.state == .running and snapshot_value.attempt == 1 and snapshot_value.retries == 0 and
            snapshot_value.endpoint == offered.endpoint and snapshot_value.instance == offered.instance);
        self.accepted[wire.tokenSlot(snapshot_value.token).?] = snapshot_value;
        return snapshot_value;
    }
    fn receipt(self: *Requester, offered: wire.Snapshot, attempt: u8) wire.Snapshot {
        const snapshot_value = self.snapshot(.{ .id = self.id(), .command = .receipt, .token = offered.token });
        const accepted = self.accepted[wire.tokenSlot(offered.token).?] orelse {
            require(false);
            unreachable;
        };
        require(accepted.token == offered.token and accepted.input == offered.input and accepted.instance == offered.instance);
        require(snapshot_value.state == .completed and snapshot_value.verified and snapshot_value.input == offered.input and
            snapshot_value.instance == offered.instance and snapshot_value.attempt == attempt and snapshot_value.retries == attempt - 1 and
            snapshot_value.result == wire.calculate(offered.input) and snapshot_value.slots == 0 and snapshot_value.pages == 0);
        if (attempt == 1) require(snapshot_value.rpc == accepted.rpc and snapshot_value.endpoint == accepted.endpoint) else {
            require(snapshot_value.rpc > accepted.rpc and snapshot_value.endpoint >> 8 > accepted.endpoint >> 8);
            const authoritative = self.status(offered.token);
            require(authoritative.state == .completed and authoritative.endpoint == snapshot_value.endpoint and
                authoritative.rpc == snapshot_value.rpc and authoritative.attempt == snapshot_value.attempt and
                authoritative.result == snapshot_value.result);
        }
        runtime.report(84, snapshot_value.token, snapshot_value.result);
        return snapshot_value;
    }
    fn cancel(self: *Requester, token: u64) wire.Snapshot {
        const snapshot_value = self.snapshot(.{ .id = self.id(), .command = .cancel, .token = token });
        require(snapshot_value.state == .cancelled and !snapshot_value.verified and snapshot_value.result == 0 and
            snapshot_value.slots == 0 and snapshot_value.pages == 0 and snapshot_value.reason == .cancelled);
        return snapshot_value;
    }
    fn reap(self: *Requester, token: u64) void {
        switch (self.call(.{ .id = self.id(), .command = .reap, .token = token })) {
            .reaped => {},
            else => {
                require(false);
                unreachable;
            },
        }
        self.accepted[wire.tokenSlot(token).?] = null;
    }
    fn rejected(self: *Requester, packet: wire.Packet, expected: u64, check: u64) void {
        const failure = switch (self.call(packet)) {
            .failure => |value| value,
            else => {
                require(false);
                unreachable;
            },
        };
        require(failure == expected);
        runtime.report(52, check, failure);
    }
    fn rootLedger(self: *Requester) void {
        hosting.checkLedger(self.info.creation, 1, 4, 2, 4, 1, 40);
    }
};

pub fn run(info: abi.BootInfo) noreturn {
    require(info.abi == abi.version and info.role == @intFromEnum(abi.Role.probe) and info.identity == 400 and
        info.scenario == runtime.scenario and info.endpoint != 0 and info.creation != 0 and info.parent_endpoint == 0 and
        info.instance == 0 and info.depth == 0);
    hosting.checkLedger(info.creation, 0, 0, 0, 0, 4, 48);
    var management: wire.Sequence = .{};
    const broker = hosting.create(info.creation, &management, runtime.broker_template, 2, 4);
    var cap: abi.CapabilityInfo = undefined;
    require(syscall.query(broker.channel, &cap) == 0 and cap.holder == info.endpoint and cap.target == broker.endpoint and
        cap.rights == abi.right(.hosting_request) and cap.parent == 0);
    var requester: Requester = .{ .info = info, .broker = broker };
    requester.rootLedger();
    // The independent storage owner establishes and verifies all three files
    // before any contract worker is requested; none was prebooted.
    require(syscall.sleep(30) == 0);

    const first_offer_id = requester.id();
    const first_packet: wire.Packet = .{ .id = first_offer_id, .command = .offer, .detail = wire.profile, .data = runtime.interleave_input };
    // Deliberately discard the OFFER reply before obtaining its reference. A
    // STATUS-by-offer-transaction request first recovers the backed record.
    requester.discardReply(first_packet);
    const first = requester.snapshot(.{ .id = requester.id(), .command = .status, .data = first_offer_id });
    require(first.state == .offered);
    const replay = requester.snapshot(first_packet);
    require(replay.token == first.token and replay.instance == first.instance and replay.endpoint == first.endpoint);
    const second = requester.offer(0x123456789abcdef0);
    require(first.token != second.token and first.instance != second.instance and first.endpoint != second.endpoint);
    requester.rootLedger();
    requester.rejected(.{ .id = requester.id(), .command = .offer, .detail = wire.profile, .data = 9 }, 4, 101);
    requester.rejected(.{ .id = requester.id(), .command = .accept, .detail = wire.profile, .token = broker.control, .data = first.input }, 2, 102);
    requester.rejected(.{ .id = requester.id(), .command = .accept, .detail = 2, .token = first.token, .data = first.input }, 2, 103);
    requester.rejected(.{ .id = requester.id(), .command = .accept, .detail = wire.profile, .token = first.token, .data = first.input ^ 1 }, 2, 104);
    const first_running = requester.accept(first);
    const duplicate = requester.snapshot(.{ .id = requester.id(), .command = .accept, .detail = wire.profile, .token = first.token, .data = first.input });
    require(duplicate.rpc == first_running.rpc and duplicate.attempt == first_running.attempt);
    _ = requester.accept(second);
    // WorkerA sleeps for16ticks; B's genuine result arrives and settles first.
    require(syscall.sleep(30) == 0);
    _ = requester.receipt(second, 1);
    requester.discardReply(.{ .id = requester.id(), .command = .receipt, .token = first.token });
    // A genuinely discarded completion reply is recovered from retained
    // authoritative terminal metadata without accepted-work retransmission.
    const queried = requester.status(first.token);
    require(queried.result == wire.calculate(first.input) and queried.rpc == first_running.rpc and queried.state == .completed);
    _ = requester.receipt(first, 1);
    requester.rejected(.{ .id = requester.id(), .command = .offer, .detail = wire.profile, .data = 10 }, 4, 105);
    requester.reap(second.token);
    requester.reap(first.token);
    requester.rejected(.{ .id = requester.id(), .command = .status, .token = first.token }, 3, 106);

    const offered_cancel = requester.offer(0x3141592653589793);
    _ = requester.cancel(offered_cancel.token);
    const cancelled_query = requester.status(offered_cancel.token);
    require(cancelled_query.state == .cancelled and cancelled_query.attempt == 0 and cancelled_query.rpc == 0);
    requester.rejected(.{ .id = requester.id(), .command = .accept, .detail = wire.profile, .token = offered_cancel.token, .data = offered_cancel.input }, 10, 107);
    requester.reap(offered_cancel.token);
    const active_cancel = requester.offer(runtime.cancellation_input);
    require(active_cancel.token != offered_cancel.token and wire.tokenSerial(active_cancel.token) > wire.tokenSerial(offered_cancel.token));
    requester.rejected(.{ .id = requester.id(), .command = .status, .token = offered_cancel.token }, 3, 108);
    const preserved = requester.offer(runtime.sibling_input);
    _ = requester.accept(preserved);
    _ = requester.accept(active_cancel);
    // The broker's bounded private delivery stage lets current owner control
    // take precedence. A real dequeued result is then rejected after CANCEL.
    require(syscall.sleep(3) == 0);
    _ = requester.cancel(active_cancel.token);
    const sibling_status = requester.status(preserved.token);
    require(sibling_status.state == .running and sibling_status.endpoint == preserved.endpoint and
        sibling_status.instance == preserved.instance and sibling_status.attempt == 1);
    require(syscall.sleep(45) == 0);
    require(requester.status(active_cancel.token).state == .cancelled);
    _ = requester.receipt(preserved, 1);
    requester.reap(active_cancel.token);
    requester.reap(preserved.token);

    const recovering = requester.offer(runtime.recovery_input);
    const unrelated = requester.offer(runtime.sibling_input);
    _ = requester.accept(unrelated);
    _ = requester.accept(recovering);
    require(syscall.sleep(2) == 0);
    const unrelated_during = requester.status(unrelated.token);
    require(unrelated_during.state == .running and unrelated_during.endpoint == unrelated.endpoint and
        unrelated_during.instance == unrelated.instance and unrelated_during.attempt == 1);
    require(syscall.sleep(20) == 0);
    const recovered = requester.receipt(recovering, 2);
    require(recovered.endpoint != recovering.endpoint and recovered.endpoint >> 8 > recovering.endpoint >> 8);
    const unrelated_after = requester.status(unrelated.token);
    require(unrelated_after.endpoint == unrelated.endpoint and unrelated_after.instance == unrelated.instance and unrelated_after.attempt == 1);
    require(syscall.sleep(25) == 0);
    _ = requester.receipt(unrelated, 1);
    requester.reap(recovering.token);
    requester.reap(unrelated.token);
    requester.rootLedger();
    // Terminal service metadata is gone and all workers have already returned
    // their backing. Finally retire the broker and return its own reservation.
    require(syscall.stop(broker.control) == 0);
    var stopped: abi.CellStatus = undefined;
    require(syscall.status(broker.control, &stopped) == 0 and stopped.phase == 4 and stopped.own_pages == 0 and
        stopped.reserved_slots == 0 and stopped.reserved_pages == 0);
    require(syscall.reap(broker.control) == 0);
    runtime.report(55, broker.control, broker.instance);
    hosting.checkLedger(info.creation, 0, 0, 0, 0, 4, 48);
    require(syscall.sleep(30) == 0);
    runtime.report(85, runtime.scenario, 0);
    while (true) require(syscall.sleep(1) == 0);
}
