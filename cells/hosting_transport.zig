const abi = @import("abi.zig");
const wire = @import("hosting_wire.zig");
pub const pending_limit = 4;
pub const inbox_limit = 8;
pub const send_limit = 4;
pub const receive_limit = 16;
pub const receive_ticks = 10;

pub const Inbox = struct {
    messages: [inbox_limit]abi.Message = undefined,
    head: usize = 0,
    count: usize = 0,
    pub fn push(self: *Inbox, message: abi.Message) bool {
        if (self.count == inbox_limit) return false;
        self.messages[(self.head + self.count) % inbox_limit] = message;
        self.count += 1;
        return true;
    }
    pub fn pop(self: *Inbox) ?abi.Message {
        if (self.count == 0) return null;
        const result = self.messages[self.head];
        self.head = (self.head + 1) % inbox_limit;
        self.count -= 1;
        return result;
    }
};

pub const Phase = enum { free, enqueue, waiting, complete, failed };
pub const Pending = struct {
    phase: Phase = .free,
    endpoint: u64 = 0,
    packet: wire.Packet = .{ .id = 0, .command = .challenge, .argument = 0, .value = 0 },
    sends: u8 = 0,
    receives: u8 = 0,
    failure: i64 = 0,

    pub fn message(self: *const Pending) abi.Message {
        return wire.encode(wire.request_operation, self.packet);
    }
    pub fn sent(self: *Pending, result: i64) void {
        if (self.phase != .enqueue) return;
        self.sends += 1;
        if (result == 0) self.phase = .waiting else if (result != @intFromEnum(abi.Error.again) or self.sends == send_limit) {
            self.phase = .failed;
            self.failure = if (result == @intFromEnum(abi.Error.again)) @intFromEnum(abi.Error.timeout) else result;
        }
    }
};

pub const DispatchResult = enum { matched, deferred, rejected, full };
pub const Dispatcher = struct {
    sequence: wire.Sequence = .{},
    pending: [pending_limit]Pending = [_]Pending{.{}} ** pending_limit,
    inbox: Inbox = .{},

    pub fn begin(self: *Dispatcher, endpoint: u64, command: wire.Command, argument: u64, value: u64) ?usize {
        if (endpoint == 0) return null;
        for (&self.pending, 0..) |*pending, index| {
            if (pending.phase != .free) continue;
            const id = self.sequence.take() orelse return null;
            const packet: wire.Packet = .{ .id = id, .command = command, .argument = argument, .value = value };
            var validation = wire.encode(wire.request_operation, packet);
            validation.sender = endpoint;
            if (wire.decodeRequest(&validation, endpoint) == null) return null;
            pending.* = .{ .phase = .enqueue, .endpoint = endpoint, .packet = packet };
            return index;
        }
        return null;
    }

    // Only authenticated parent requests enter the deferred FIFO. Replies are routed in place.
    pub fn dispatch(self: *Dispatcher, message: abi.Message, parent: u64) DispatchResult {
        if (message.operation == wire.reply_operation) {
            for (&self.pending) |*pending| {
                if (pending.phase != .waiting) continue;
                const reply = wire.decodeReply(&message, pending.endpoint, pending.packet.id, pending.packet.command, pending.packet.argument) orelse continue;
                const expected = wire.expected(pending.packet.command, pending.packet.argument) orelse return .rejected;
                if (reply.value != expected) {
                    pending.phase = .failed;
                    pending.failure = @intFromEnum(abi.Error.invalid);
                    return .rejected;
                }
                pending.packet = reply;
                pending.phase = .complete;
                return .matched;
            }
            return .rejected;
        }
        if (wire.decodeRequest(&message, parent) == null) return .rejected;
        return if (self.inbox.push(message)) .deferred else .full;
    }

    pub fn receiveStep(self: *Dispatcher, result: i64) void {
        for (&self.pending) |*pending| {
            if (pending.phase != .waiting) continue;
            pending.receives += 1;
            if ((result != 0 and result != @intFromEnum(abi.Error.timeout)) or pending.receives == receive_limit) {
                pending.phase = .failed;
                pending.failure = if (result != 0) result else @intFromEnum(abi.Error.timeout);
            }
        }
    }

    pub fn retire(self: *Dispatcher, endpoint: u64) void {
        for (&self.pending) |*pending| {
            if (pending.endpoint == endpoint and pending.phase != .free) {
                pending.phase = .failed;
                pending.failure = @intFromEnum(abi.Error.stale);
            }
        }
    }

    pub fn take(self: *Dispatcher, index: usize) ?wire.Packet {
        if (index >= pending_limit or self.pending[index].phase != .complete) return null;
        const result = self.pending[index].packet;
        self.pending[index] = .{};
        return result;
    }
    pub fn release(self: *Dispatcher, index: usize) void {
        if (index < pending_limit) self.pending[index] = .{};
    }
};

const testing = @import("std").testing;
fn answer(pending: Pending) abi.Message {
    var packet = pending.packet;
    packet.value = wire.expected(packet.command, packet.argument).?;
    var message = wire.encode(wire.reply_operation, packet);
    message.sender = pending.endpoint;
    return message;
}

test "dispatcher preserves interleaved replies from distinct endpoints" {
    var dispatcher: Dispatcher = .{};
    const first = dispatcher.begin(0x105, .challenge, 17, 0).?;
    const second = dispatcher.begin(0x106, .challenge, 31, 0).?;
    dispatcher.pending[first].sent(0);
    dispatcher.pending[second].sent(0);
    try testing.expectEqual(DispatchResult.matched, dispatcher.dispatch(answer(dispatcher.pending[second]), 0));
    try testing.expect(dispatcher.take(first) == null);
    try testing.expectEqual(Phase.complete, dispatcher.pending[second].phase);
    try testing.expectEqual(DispatchResult.matched, dispatcher.dispatch(answer(dispatcher.pending[first]), 0));
    try testing.expectEqual(@as(u64, 17), dispatcher.take(first).?.argument);
    try testing.expectEqual(@as(u64, 31), dispatcher.take(second).?.argument);
}

test "two outstanding challenges to sleeping sibling retain FIFO identities" {
    var dispatcher: Dispatcher = .{};
    const first = dispatcher.begin(0x107, .challenge, 0x1133557799bbddff, 0).?;
    const second = dispatcher.begin(0x107, .challenge, 0x22446688aaccee00, 0).?;
    dispatcher.pending[first].sent(0);
    dispatcher.pending[second].sent(0);
    try testing.expect(dispatcher.pending[first].packet.id != dispatcher.pending[second].packet.id);
    try testing.expectEqual(DispatchResult.matched, dispatcher.dispatch(answer(dispatcher.pending[first]), 0));
    try testing.expectEqual(DispatchResult.matched, dispatcher.dispatch(answer(dispatcher.pending[second]), 0));
    try testing.expect(dispatcher.take(first).?.id < dispatcher.take(second).?.id);
}

test "pending dispatcher pressure is explicit and cannot overwrite work" {
    var dispatcher: Dispatcher = .{};
    for (0..pending_limit) |index| try testing.expectEqual(index, dispatcher.begin(0x105 + index, .challenge, index, 0).?);
    const next = dispatcher.sequence.next;
    try testing.expect(dispatcher.begin(0x108, .challenge, 99, 0) == null);
    try testing.expectEqual(next, dispatcher.sequence.next);
    dispatcher.release(2);
    try testing.expectEqual(@as(usize, 2), dispatcher.begin(0x205, .challenge, 99, 0).?);
}

test "deferred parent inbox authenticates requests preserves FIFO and fails on full" {
    var dispatcher: Dispatcher = .{};
    for (0..inbox_limit) |index| {
        var message = wire.encode(wire.request_operation, .{ .id = index + 1, .command = .challenge, .argument = index, .value = 0 });
        message.sender = 0x104;
        try testing.expectEqual(DispatchResult.rejected, dispatcher.dispatch(message, 0x204));
        try testing.expectEqual(DispatchResult.deferred, dispatcher.dispatch(message, 0x104));
    }
    var ninth = wire.encode(wire.request_operation, .{ .id = 9, .command = .challenge, .argument = 9, .value = 0 });
    ninth.sender = 0x104;
    try testing.expectEqual(DispatchResult.full, dispatcher.dispatch(ninth, 0x104));
    for (0..inbox_limit) |index| {
        const message = dispatcher.inbox.pop().?;
        try testing.expectEqual(@as(u64, index + 1), wire.decodeRequest(&message, 0x104).?.id);
    }
    try testing.expect(dispatcher.inbox.pop() == null);
}

test "late unsolicited wrong generation and malformed replies cannot complete a request" {
    var dispatcher: Dispatcher = .{};
    const index = dispatcher.begin(0x105, .challenge, 19, 0).?;
    dispatcher.pending[index].sent(0);
    var late = answer(dispatcher.pending[index]);
    late.sender = 0x205;
    try testing.expectEqual(DispatchResult.rejected, dispatcher.dispatch(late, 0));
    late = answer(dispatcher.pending[index]);
    late.length = 31;
    try testing.expectEqual(DispatchResult.rejected, dispatcher.dispatch(late, 0));
    for (0..receive_limit) |_| dispatcher.receiveStep(@intFromEnum(abi.Error.timeout));
    try testing.expectEqual(Phase.failed, dispatcher.pending[index].phase);
    late = answer(dispatcher.pending[index]);
    try testing.expectEqual(DispatchResult.rejected, dispatcher.dispatch(late, 0));
    dispatcher.release(index);
    const fresh = dispatcher.begin(0x105, .challenge, 19, 0).?;
    dispatcher.pending[fresh].sent(0);
    try testing.expectEqual(DispatchResult.rejected, dispatcher.dispatch(late, 0));
    try testing.expectEqual(Phase.waiting, dispatcher.pending[fresh].phase);
}

test "enqueue backpressure finite receive and endpoint retirement clear pending states" {
    var dispatcher: Dispatcher = .{};
    const index = dispatcher.begin(0x105, .challenge, 19, 0).?;
    for (0..send_limit) |_| dispatcher.pending[index].sent(@intFromEnum(abi.Error.again));
    try testing.expectEqual(Phase.failed, dispatcher.pending[index].phase);
    dispatcher.release(index);
    const fresh = dispatcher.begin(0x205, .challenge, 19, 0).?;
    dispatcher.pending[fresh].sent(0);
    dispatcher.pending[fresh].sent(0);
    try testing.expectEqual(@as(u8, 1), dispatcher.pending[fresh].sends);
    for (0..receive_limit) |_| dispatcher.receiveStep(0);
    try testing.expectEqual(Phase.failed, dispatcher.pending[fresh].phase);
    dispatcher.release(fresh);
    const rebound = dispatcher.begin(0x305, .challenge, 19, 0).?;
    dispatcher.retire(0x305);
    try testing.expectEqual(Phase.failed, dispatcher.pending[rebound].phase);
    try testing.expectEqual(@as(i64, @intFromEnum(abi.Error.stale)), dispatcher.pending[rebound].failure);
}

test "forged computed result fails matching request explicitly" {
    var dispatcher: Dispatcher = .{};
    const index = dispatcher.begin(0x105, .challenge, 19, 0).?;
    dispatcher.pending[index].sent(0);
    var packet = dispatcher.pending[index].packet;
    packet.value = wire.calculate(19) ^ 1;
    var message = wire.encode(wire.reply_operation, packet);
    message.sender = 0x105;
    try testing.expectEqual(DispatchResult.rejected, dispatcher.dispatch(message, 0));
    try testing.expectEqual(Phase.failed, dispatcher.pending[index].phase);
}

test "dispatcher last request identity completes once and remains exhausted after release" {
    var dispatcher: Dispatcher = .{ .sequence = .{ .next = 0xffffffffffffffff } };
    const index = dispatcher.begin(0x105, .challenge, 19, 0).?;
    try testing.expectEqual(@as(u64, 0xffffffffffffffff), dispatcher.pending[index].packet.id);
    dispatcher.pending[index].sent(0);
    const message = answer(dispatcher.pending[index]);
    try testing.expectEqual(DispatchResult.matched, dispatcher.dispatch(message, 0));
    try testing.expect(dispatcher.take(index) != null);
    try testing.expect(dispatcher.begin(0x105, .challenge, 20, 0) == null);
    try testing.expect(dispatcher.begin(0x205, .challenge, 20, 0) == null);
    try testing.expectEqual(DispatchResult.rejected, dispatcher.dispatch(message, 0));
}

test "invalid dispatcher request retires its identity without occupying a pending record" {
    var dispatcher: Dispatcher = .{};
    try testing.expect(dispatcher.begin(0x105, .sleep, 1001, 0) == null);
    try testing.expectEqual(@as(u64, 2), dispatcher.sequence.next);
    for (dispatcher.pending) |pending| try testing.expectEqual(Phase.free, pending.phase);
    const index = dispatcher.begin(0x105, .challenge, 20, 0).?;
    try testing.expectEqual(@as(u64, 2), dispatcher.pending[index].packet.id);
}

test "every one-bit mutation of a hosting reply is rejected without affecting another pending child" {
    for (0..@sizeOf(abi.Message) * 8) |bit| {
        var dispatcher: Dispatcher = .{};
        const first = dispatcher.begin(0x105, .challenge, 0x82e493b7056c1fad, 0).?;
        const second = dispatcher.begin(0x106, .challenge, 0x7410ab9c3e6582df, 0).?;
        dispatcher.pending[first].sent(0);
        dispatcher.pending[second].sent(0);
        var mutated = answer(dispatcher.pending[first]);
        const bytes = @as(*[@sizeOf(abi.Message)]u8, @ptrCast(&mutated));
        bytes[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
        try testing.expectEqual(DispatchResult.rejected, dispatcher.dispatch(mutated, 0));
        try testing.expectEqual(Phase.waiting, dispatcher.pending[second].phase);
        try testing.expectEqual(DispatchResult.matched, dispatcher.dispatch(answer(dispatcher.pending[second]), 0));
        try testing.expectEqual(wire.calculate(0x7410ab9c3e6582df), dispatcher.take(second).?.value);
        if (dispatcher.pending[first].phase == .waiting) {
            try testing.expectEqual(DispatchResult.matched, dispatcher.dispatch(answer(dispatcher.pending[first]), 0));
            try testing.expect(dispatcher.take(first) != null);
        } else try testing.expectEqual(Phase.failed, dispatcher.pending[first].phase);
    }
}

test "bounded exhaustive reply permutations preserve all completed records and endpoint retirement scope" {
    for (0..4) |retired| {
        for (0..4) |a| for (0..4) |b| for (0..4) |c| for (0..4) |d| {
            const order = [_]usize{ a, b, c, d };
            var mask: u32 = 0;
            for (order) |index| mask |= @as(u32, 1) << @intCast(index);
            if (mask != 15) continue;
            var dispatcher: Dispatcher = .{};
            var indices: [4]usize = undefined;
            for (0..4) |index| {
                indices[index] = dispatcher.begin(0x105 + index, .challenge, 100 + index, 0).?;
                dispatcher.pending[indices[index]].sent(0);
            }
            dispatcher.retire(0x105 + retired);
            for (order) |index| {
                const result = dispatcher.dispatch(answer(dispatcher.pending[indices[index]]), 0);
                try testing.expectEqual(if (index == retired) DispatchResult.rejected else DispatchResult.matched, result);
            }
            // Taking responses in a different order cannot consume another slot.
            for (0..4) |index| {
                if (index == retired) {
                    try testing.expect(dispatcher.take(indices[index]) == null);
                    try testing.expectEqual(Phase.failed, dispatcher.pending[indices[index]].phase);
                } else {
                    const response = dispatcher.take(indices[index]).?;
                    try testing.expectEqual(@as(u64, 100 + index), response.argument);
                    try testing.expectEqual(wire.calculate(100 + index), response.value);
                }
            }
        };
    }
}
