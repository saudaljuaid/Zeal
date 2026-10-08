// Root400 owns its own live handles and immutable inputs. References sent to
// hosted cells convey service identity; checked kernel routes and explicit FS
// bindings remain separately necessary. Every verified tuple comes from bytes.
const abi = @import("abi.zig");
const syscall = @import("syscall.zig");
const wire = @import("contract_wire.zig");
const analysis = @import("analysis_wire.zig");
const snapshot = @import("snapshot.zig");
const snapshots = @import("snapshot_client.zig");
const swire = @import("snapshot_wire.zig");
const files = @import("storage_wire.zig");
const storage_runtime = @import("storage_runtime.zig");
const runtime = @import("contract_runtime.zig");
const hosting = @import("hosting_runtime.zig");
const require = hosting.require;
const source = @import("analysis_storage.zig");

const Input = struct { transaction: u64, reference: snapshot.Ref, length: u8, tuple: analysis.Tuple };
const Held = struct { offered: wire.Snapshot, input: Input };
const Reply = union(enum) { value: wire.Snapshot, failure: u64, reaped: void };
const Requester = struct {
    info: abi.BootInfo,
    broker: abi.CreateResult,
    filesystem: u64,
    sequence: wire.Sequence = .{},
    file_sequence: files.Sequence = .{ .next = 0x100000 },
    snapshots: snapshots.Client = .{},
    inbox: @import("hosting_transport.zig").Inbox = .{},
    held: [2]?Held = .{ null, null },
    fn nextId(self: *Requester) u64 {
        return self.sequence.take() orelse {
            require(false);
            unreachable;
        };
    }
    fn receive(self: *Requester, message: *abi.Message, ticks: u64) i64 {
        if (self.inbox.pop()) |queued| {
            message.* = queued;
            return 0;
        }
        return syscall.receiveWait(message, ticks);
    }
    fn notice(self: *Requester, message: *const abi.Message) bool {
        const packet = wire.decode(message, self.broker.endpoint, wire.reply_operation) orelse return false;
        if (packet.command != .rebind_input) return false;
        require(packet.kind == .response and packet.detail == 0 and packet.data != 0);
        const held = self.held[wire.tokenSlot(packet.token).?] orelse {
            require(false);
            unreachable;
        };
        require(held.offered.token == packet.token and packet.data >> 8 > held.offered.endpoint >> 8);
        self.control(held.input.reference.token, held.offered.endpoint, .revoke);
        self.control(held.input.reference.token, packet.data, .bind);
        runtime.report(97, held.input.reference.token, packet.data);
        var ack = wire.encode(wire.request_operation, .{ .id = packet.id, .command = .authorize_input, .token = packet.token, .data = packet.data });
        require(hosting.sendBounded(self.broker.endpoint, &ack, self.broker.channel) == 0);
        return true;
    }
    fn call(self: *Requester, packet: wire.Packet, discard: bool) Reply {
        var message = wire.encode(wire.request_operation, packet);
        require(hosting.sendBounded(self.broker.endpoint, &message, self.broker.channel) == 0);
        var collector: analysis.Collector = .{ .base = .{ .issuer = self.broker.endpoint, .requester = self.info.endpoint, .id = packet.id, .command = packet.command, .token = if (packet.command == .offer) 0 else packet.token } };
        for (0..32) |_| {
            var response: abi.Message = undefined;
            const received = self.receive(&response, 10);
            if (received == @intFromEnum(abi.Error.timeout)) continue;
            require(received == 0);
            if (self.notice(&response)) continue;
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
            if (collector.count == 2) {
                if (discard) {
                    runtime.report(87, packet.id, @intFromEnum(packet.command));
                    return .{ .value = .{} };
                }
                return .{ .value = collector.take() orelse {
                    require(false);
                    unreachable;
                } };
            }
        }
        require(false);
        unreachable;
    }
    fn snapshotValue(self: *Requester, packet: wire.Packet) wire.Snapshot {
        return switch (self.call(packet, false)) {
            .value => |value| value,
            else => {
                require(false);
                unreachable;
            },
        };
    }
    fn control(self: *Requester, token: u64, peer: u64, action: swire.Action) void {
        const transaction = self.snapshots.sequence.take() orelse {
            require(false);
            unreachable;
        };
        const result = self.snapshots.controlTransactionWith(self.filesystem, transaction, token, peer, action, &self.inbox) orelse {
            require(false);
            unreachable;
        };
        require(result.status == .ok);
    }
    fn file(self: *Requester, operation: abi.Operation, handle: u64, offset: u32, count: u32, data: []const u8, name: []const u8) files.Header {
        const id = self.file_sequence.take().?;
        var request = if (operation == .file_open) files.openRequest(id, name) else files.request(operation, id, handle, offset, count, data);
        require(storage_runtime.sendBounded(self.filesystem, &request, operation) == 0);
        for (0..16) |_| {
            var reply: abi.Message = undefined;
            const received = self.receive(&reply, 10);
            if (received == @intFromEnum(abi.Error.timeout)) continue;
            require(received == 0);
            if (self.notice(&reply)) continue;
            if (files.decodeReply(&reply, .file_result, self.filesystem, id)) |result| {
                require(result.offset == offset and (operation == .file_open or result.handle == handle));
                return result;
            }
        }
        require(false);
        unreachable;
    }
    fn open(self: *Requester, name: []const u8) u64 {
        const opened = self.file(.file_open, 0, 0, 0, &.{}, name);
        require(opened.value == 0 and opened.handle != 0);
        return opened.handle;
    }
    fn capture(self: *Requester, handle: u64, expected: []const u8, recover: bool) Input {
        const transaction = self.snapshots.sequence.take().?;
        const reply = self.snapshots.controlTransactionWith(self.filesystem, transaction, handle, 0, .create, &self.inbox) orelse {
            require(false);
            unreachable;
        };
        require(reply.status == .ok and reply.state == .live and reply.length == expected.len and reply.block == syscall.lookup(.block));
        const prepared = if (recover) blk: {
            // Ignore the returned identity and resolve the owner-scoped creation
            // transaction. This status must recover the same single record.
            const query = self.snapshots.sequence.take().?;
            const recovered = self.snapshots.controlTransactionWith(self.filesystem, query, transaction, 0, .status, &self.inbox) orelse {
                require(false);
                unreachable;
            };
            require(recovered.status == .ok and recovered.length == expected.len and recovered.state == .live);
            runtime.report(102, transaction, recovered.reference.token);
            break :blk recovered;
        } else reply;
        var bytes: [128]u8 = undefined;
        require(self.snapshots.collectWith(prepared.reference, prepared.length, &bytes, &self.inbox));
        for (expected, 0..) |byte, offset| require(bytes[offset] == byte);
        return .{ .transaction = transaction, .reference = prepared.reference, .length = prepared.length, .tuple = analysis.calculate(bytes[0..prepared.length]).? };
    }
    fn bindChecker(self: *Requester, input: Input) void {
        self.control(input.reference.token, self.broker.endpoint, .bind_check);
        runtime.report(97, input.reference.token, self.broker.endpoint);
    }
    fn offer(self: *Requester, input: Input, lose: bool) wire.Snapshot {
        self.bindChecker(input);
        const id = self.nextId();
        const packet: wire.Packet = .{ .id = id, .command = .offer, .detail = analysis.profile, .token = input.reference.issuer, .data = input.reference.token };
        const offered = if (lose) blk: {
            _ = self.call(packet, true);
            break :blk self.snapshotValue(.{ .id = self.nextId(), .command = .status, .data = id });
        } else self.snapshotValue(packet);
        require(offered.state == .offered and offered.profile_id == analysis.profile and offered.input == input.reference.token and
            offered.input_issuer == input.reference.issuer and offered.input_length == input.length and offered.slots == 1 and offered.pages == 2);
        self.held[wire.tokenSlot(offered.token).?] = .{ .offered = offered, .input = input };
        self.control(input.reference.token, offered.endpoint, .bind);
        runtime.report(97, input.reference.token, offered.endpoint);
        return offered;
    }
    fn accept(self: *Requester, offered: wire.Snapshot) wire.Snapshot {
        const running = self.snapshotValue(.{ .id = self.nextId(), .command = .accept, .detail = analysis.profile, .token = offered.token, .data = offered.input });
        require(running.state == .running and running.rpc != 0 and running.attempt == 1 and running.input == offered.input and
            running.input_issuer == offered.input_issuer and running.input_length == offered.input_length and running.endpoint == offered.endpoint);
        return running;
    }
    fn status(self: *Requester, token: u64) wire.Snapshot {
        return self.snapshotValue(.{ .id = self.nextId(), .command = .status, .token = token });
    }
    fn verifyReceipt(self: *Requester, offered: wire.Snapshot, attempt: u8, lose: bool) void {
        var done = false;
        for (0..80) |_| {
            const state = self.status(offered.token);
            if (state.state == .completed) {
                done = true;
                break;
            }
            require(state.state == .running or state.state == .recovering);
            require(syscall.sleep(3) == 0);
        }
        require(done);
        if (lose) _ = self.call(.{ .id = self.nextId(), .command = .receipt, .token = offered.token }, true);
        const receipt = self.snapshotValue(.{ .id = self.nextId(), .command = .receipt, .token = offered.token });
        const held = self.held[wire.tokenSlot(offered.token).?].?;
        require(receipt.state == .completed and receipt.verified and receipt.attempt == attempt and receipt.retries == attempt - 1 and
            receipt.input == held.input.reference.token and receipt.input_issuer == held.input.reference.issuer and receipt.input_length == held.input.tuple.length and
            receipt.newlines == held.input.tuple.newlines and receipt.result == held.input.tuple.digest and receipt.instance == offered.instance and receipt.slots == 0 and receipt.pages == 0);
        if (attempt == 1) require(receipt.endpoint == offered.endpoint) else require(receipt.endpoint >> 8 > offered.endpoint >> 8);
        runtime.report(84, receipt.token, receipt.result);
        runtime.report(94, receipt.token, @as(u64, receipt.input_length) | (@as(u64, receipt.newlines) << 16));
        const transaction = self.snapshots.sequence.take().?;
        const input_status = self.snapshots.controlTransactionWith(self.filesystem, transaction, held.input.transaction, 0, .status, &self.inbox) orelse {
            require(false);
            unreachable;
        };
        require(input_status.status == .ok and input_status.state == .settled);
    }
    fn cancel(self: *Requester, offered: wire.Snapshot) void {
        const cancelled = self.snapshotValue(.{ .id = self.nextId(), .command = .cancel, .token = offered.token });
        require(cancelled.state == .cancelled and !cancelled.verified and cancelled.slots == 0 and cancelled.pages == 0 and cancelled.result == 0);
        require(self.status(offered.token).state == .cancelled);
    }
    fn retire(self: *Requester, offered: wire.Snapshot) void {
        const held = self.held[wire.tokenSlot(offered.token).?].?;
        self.control(held.input.reference.token, 0, .close);
        self.control(held.input.reference.token, 0, .reap);
        runtime.report(98, held.input.reference.token, offered.token);
        switch (self.call(.{ .id = self.nextId(), .command = .reap, .token = offered.token }, false)) {
            .reaped => {},
            else => require(false),
        }
        self.held[wire.tokenSlot(offered.token).?] = null;
        const stale = self.snapshots.readWith(held.input.reference, 0, 8, &self.inbox) orelse {
            require(false);
            unreachable;
        };
        require(stale.status == .stale);
        runtime.report(99, held.input.reference.token, @bitCast(@as(i64, -3)));
    }
    fn reject(self: *Requester, packet: wire.Packet, expected: u64) void {
        switch (self.call(packet, false)) {
            .failure => |code| require(code == expected),
            else => require(false),
        }
        runtime.report(52, packet.id, expected);
    }
    fn mutate(self: *Requester, handle: u64) void {
        const client = syscall.lookup(.client);
        const id = self.nextId();
        var pause = wire.encode(wire.request_operation, .{ .id = id, .command = .input, .detail = 1, .data = 1 });
        require(syscall.sendGranted(client, &pause, .hosting_request) == 0);
        var paused = false;
        for (0..16) |_| {
            var message: abi.Message = undefined;
            if (self.receive(&message, 10) != 0) continue;
            if (self.notice(&message)) continue;
            if (wire.decode(&message, client, wire.reply_operation)) |ack| {
                require(ack.id == id and ack.command == .input and ack.detail == 1 and ack.kind == .response and ack.data == 1 and ack.token == 0);
                paused = true;
                break;
            }
        }
        require(paused);
        require(self.file(.file_write, handle, 0, 8, source.changed[0..8], &.{}).value == 8);
        const read = self.file(.file_chunk_read, handle, 0, 8, &.{}, &.{});
        require(read.value == 8);
        for (source.changed[0..8], 0..) |byte, index| require(read.data[index] == byte);
        var actual: u64 = 0;
        for (read.data, 0..) |byte, index| actual |= @as(u64, byte) << @intCast(index * 8);
        syscall.reportValues(32, read.id, actual);
        runtime.report(96, handle, id);
        pause = wire.encode(wire.request_operation, .{ .id = id, .command = .input, .detail = 2, .data = 2 });
        require(syscall.sendGranted(client, &pause, .hosting_request) == 0);
        var resumed = false;
        for (0..16) |_| {
            var message: abi.Message = undefined;
            if (self.receive(&message, 10) != 0) continue;
            if (self.notice(&message)) continue;
            if (wire.decode(&message, client, wire.reply_operation)) |ack| {
                require(ack.id == id and ack.command == .input and ack.detail == 2 and ack.kind == .response and ack.data == 2 and ack.token == 0);
                resumed = true;
                break;
            }
        }
        require(resumed);
    }
};
pub fn run(info: abi.BootInfo) noreturn {
    require(info.scenario == 25 and info.identity == 400 and info.creation != 0 and info.parent_endpoint == 0);
    hosting.checkLedger(info.creation, 0, 0, 0, 0, 4, 48);
    // All roots run and byte-verify their workload before hosting is requested.
    require(syscall.sleep(30) == 0);
    var requester: Requester = .{ .info = info, .filesystem = syscall.lookup(.filesystem), .broker = undefined };
    const alpha = requester.open("/alpha");
    const beta = requester.open("/beta");
    const first_input = requester.capture(alpha, source.alpha, true);
    var management: wire.Sequence = .{};
    requester.broker = hosting.create(info.creation, &management, 5, 2, 4);
    const first = requester.offer(first_input, true);
    requester.reject(.{ .id = requester.nextId(), .command = .accept, .detail = 2, .token = first.token, .data = first.input ^ 1 }, 2);
    requester.reject(.{ .id = requester.nextId(), .command = .accept, .detail = 3, .token = first.token, .data = first.input }, 2);
    requester.reject(.{ .id = requester.nextId(), .command = .offer, .detail = 2, .token = first.input_issuer + 256, .data = first.input }, 3);
    const running = requester.accept(first);
    const duplicate = requester.snapshotValue(.{ .id = requester.nextId(), .command = .accept, .detail = 2, .token = first.token, .data = first.input });
    require(duplicate.rpc == running.rpc and duplicate.attempt == running.attempt);
    requester.mutate(alpha);
    requester.verifyReceipt(first, 1, true);
    requester.retire(first);
    const retired_create = requester.snapshots.controlTransactionWith(requester.filesystem, first_input.transaction, alpha, 0, .create, &requester.inbox) orelse {
        require(false);
        unreachable;
    };
    require(retired_create.status == .stale);
    runtime.report(104, first_input.transaction, first_input.reference.token);
    requester.reject(.{ .id = requester.nextId(), .command = .status, .token = first.token }, 3);

    const offered_cancel = requester.offer(requester.capture(beta, @import("hosting_storage.zig").beta, false), false);
    requester.cancel(offered_cancel);
    requester.reject(.{ .id = requester.nextId(), .command = .accept, .detail = 2, .token = offered_cancel.token, .data = offered_cancel.input }, 10);
    requester.retire(offered_cancel);

    const active = requester.offer(requester.capture(alpha, source.changed, false), false);
    const sibling = requester.offer(requester.capture(beta, @import("hosting_storage.zig").beta, false), false);
    _ = requester.accept(sibling);
    _ = requester.accept(active);
    require(syscall.sleep(6) == 0);
    requester.control(active.input, active.endpoint, .revoke);
    requester.cancel(active);
    const live = requester.status(sibling.token);
    require(live.state == .running and live.endpoint == sibling.endpoint);
    requester.verifyReceipt(sibling, 1, false);
    require(requester.status(active.token).state == .cancelled);
    requester.retire(active);
    requester.retire(sibling);

    const retry = requester.offer(requester.capture(alpha, source.changed, false), false);
    const preserved = requester.offer(requester.capture(beta, @import("hosting_storage.zig").beta, false), false);
    _ = requester.accept(preserved);
    _ = requester.accept(retry);
    require(syscall.sleep(2) == 0);
    require(requester.status(preserved.token).state == .running);
    requester.verifyReceipt(retry, 2, false);
    requester.verifyReceipt(preserved, 1, false);
    requester.retire(retry);
    requester.retire(preserved);
    const inventory_transaction = requester.snapshots.sequence.take().?;
    const inventory = requester.snapshots.controlTransactionWith(requester.filesystem, inventory_transaction, 1, 0, .inventory, &requester.inbox) orelse {
        require(false);
        unreachable;
    };
    require(inventory.status == .ok and inventory.state == .empty and inventory.reference.token == 0 and inventory.length == 0 and inventory.block == syscall.lookup(.block));
    require(requester.file(.file_close, alpha, 0, 0, &.{}, &.{}).value == 0);
    require(requester.file(.file_close, beta, 0, 0, &.{}, &.{}).value == 0);
    require(syscall.stop(requester.broker.control) == 0);
    require(syscall.reap(requester.broker.control) == 0);
    hosting.checkLedger(info.creation, 0, 0, 0, 0, 4, 48);
    runtime.report(85, 25, 0);
    while (true) require(syscall.sleep(8) == 0);
}
