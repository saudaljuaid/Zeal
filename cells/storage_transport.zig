// Bounded IPC transaction state shared by the isolated storage runtime and direct tests.
// Successful enqueue ends the send phase permanently: lost replies never cause retransmission.
const abi = @import("abi.zig");
const wire = @import("storage_wire.zig");
const storage = @import("storage.zig");

pub const send_limit: u8 = 4;
pub const receive_limit: u8 = 8;
pub const receive_ticks: u64 = 10;

pub const Inbox = struct {
    messages: [8]abi.Message = undefined,
    count: usize = 0,

    pub fn push(self: *Inbox, message: abi.Message) bool {
        if (self.count == self.messages.len) return false;
        self.messages[self.count] = message;
        self.count += 1;
        return true;
    }

    pub fn pop(self: *Inbox) ?abi.Message {
        if (self.count == 0) return null;
        const message = self.messages[0];
        self.count -= 1;
        for (0..self.count) |index| self.messages[index] = self.messages[index + 1];
        return message;
    }
};

pub const Phase = enum { sending, waiting, complete, failed };

pub const Request = struct {
    endpoint: u64,
    id: u64,
    reply_operation: abi.Operation,
    handle: u64,
    offset: u32,
    count: u32,
    exact_count: bool,
    phase: Phase = .sending,
    sends: u8 = 0,
    receives: u8 = 0,

    pub fn init(sequence: *wire.Sequence, endpoint: u64, reply_operation: abi.Operation, handle: u64, offset: u32, count: u32, exact_count: bool) ?Request {
        if (endpoint == 0 or count > storage.chunk_size or
            (reply_operation != .block_reply and reply_operation != .file_result)) return null;
        const id = sequence.take() orelse return null;
        return .{ .endpoint = endpoint, .id = id, .reply_operation = reply_operation, .handle = handle, .offset = offset, .count = count, .exact_count = exact_count };
    }

    pub fn canSend(self: *const Request) bool {
        return self.phase == .sending and self.sends < send_limit;
    }

    // Call once for each actual send result. AGAIN permits only a bounded retry before enqueue.
    pub fn sent(self: *Request, result: i32) void {
        if (!self.canSend()) return;
        self.sends += 1;
        if (result == 0) {
            self.phase = .waiting;
        } else if (result != @intFromEnum(abi.Error.again) or self.sends == send_limit) {
            self.phase = .failed;
        }
    }

    pub fn canReceive(self: *const Request) bool {
        return self.phase == .waiting and self.receives < receive_limit;
    }

    pub fn cancel(self: *Request) void {
        if (self.phase != .complete) self.phase = .failed;
    }

    // Receive attempts are finite even under continuous unrelated traffic. Both endpoint
    // generation and request identity are checked before any response can complete a request.
    pub fn received(self: *Request, current_endpoint: u64, result: i32, message: ?*const abi.Message) ?wire.Header {
        if (!self.canReceive()) return null;
        self.receives += 1;
        if (current_endpoint != self.endpoint or result != 0 or message == null) {
            self.cancel();
            return null;
        }
        if (wire.decodeReply(message.?, self.reply_operation, self.endpoint, self.id)) |reply| {
            if (reply.handle != self.handle or reply.offset != self.offset or
                (reply.value >= 0 and (reply.value > self.count or
                    (self.exact_count and reply.value != self.count))))
            {
                self.cancel();
                return null;
            }
            self.phase = .complete;
            return reply;
        }
        if (self.receives == receive_limit) self.cancel();
        return null;
    }
};

const testing = @import("std").testing;

fn delivered(message: abi.Message, sender: u64) abi.Message {
    var result = message;
    result.sender = sender;
    return result;
}

test "storage inbox is bounded FIFO and a rejected push preserves every pending request" {
    var inbox: Inbox = .{};
    try testing.expect(inbox.pop() == null);
    for (0..inbox.messages.len) |index| {
        var message = wire.openRequest(index + 1, "/note");
        message.sender = 0x103;
        try testing.expect(inbox.push(message));
    }
    try testing.expect(!inbox.push(wire.openRequest(9, "/overflow")));
    try testing.expectEqual(@as(usize, 8), inbox.count);
    for (0..8) |index| {
        const message = inbox.pop().?;
        try testing.expectEqual(@as(u64, index + 1), wire.requestId(&message));
        try testing.expectEqual(@as(u64, 0x103), message.sender);
    }
    try testing.expect(inbox.pop() == null);
    try testing.expect(inbox.push(wire.openRequest(10, "/again")));
    try testing.expectEqual(@as(u64, 10), wire.requestId(&inbox.pop().?));
}

test "enqueue backpressure has four attempts and accepted writes are never resent" {
    var sequence: wire.Sequence = .{};
    var request = Request.init(&sequence, 0x101, .block_reply, 0, 128, 8, true).?;
    for (0..3) |_| {
        try testing.expect(request.canSend());
        request.sent(@intFromEnum(abi.Error.again));
    }
    try testing.expect(request.canSend());
    request.sent(0);
    try testing.expectEqual(Phase.waiting, request.phase);
    try testing.expect(!request.canSend());
    request.sent(0);
    try testing.expectEqual(@as(u8, 4), request.sends);
    try testing.expect(request.canReceive());
    var full = Request.init(&sequence, 0x101, .block_reply, 0, 128, 8, true).?;
    for (0..4) |_| full.sent(@intFromEnum(abi.Error.again));
    try testing.expectEqual(Phase.failed, full.phase);
    try testing.expect(!full.canSend() and !full.canReceive());
    var denied = Request.init(&sequence, 0x101, .block_reply, 0, 128, 8, true).?;
    denied.sent(@intFromEnum(abi.Error.denied));
    try testing.expectEqual(Phase.failed, denied.phase);
    try testing.expectEqual(@as(u8, 1), denied.sends);
}

test "lost reply times out without resending and late reply cannot complete the fresh identity" {
    var sequence: wire.Sequence = .{};
    var lost = Request.init(&sequence, 0x101, .block_reply, 0, 128, 8, true).?;
    lost.sent(0);
    // Storage may already contain the write. Timeout conveys uncertainty, not rollback.
    try testing.expect(lost.received(0x101, @intFromEnum(abi.Error.timeout), null) == null);
    try testing.expectEqual(Phase.failed, lost.phase);
    try testing.expect(!lost.canSend() and !lost.canReceive());
    var fresh = Request.init(&sequence, 0x101, .block_reply, 0, 128, 8, true).?;
    try testing.expect(fresh.id != lost.id);
    fresh.sent(0);
    const late = delivered(wire.reply(.block_reply, lost.id, 0, 128, 8, "written!"), 0x101);
    try testing.expect(fresh.received(0x101, 0, &late) == null);
    try testing.expectEqual(Phase.waiting, fresh.phase);
    const valid = delivered(wire.reply(.block_reply, fresh.id, 0, 128, 8, "written!"), 0x101);
    try testing.expect(fresh.received(0x101, 0, &valid) != null);
    try testing.expectEqual(Phase.complete, fresh.phase);
    try testing.expect(!fresh.canSend() and !fresh.canReceive());
    try testing.expect(fresh.received(0x101, 0, &valid) == null);
}

test "dependency restart cancels old request and predecessor replies cannot finish rebound work" {
    var sequence: wire.Sequence = .{};
    var old = Request.init(&sequence, 0x101, .block_reply, 0, 128, 8, true).?;
    old.sent(0);
    const answer = delivered(wire.reply(.block_reply, old.id, 0, 128, 8, "old data"), 0x101);
    try testing.expect(old.received(0x201, 0, &answer) == null);
    try testing.expectEqual(Phase.failed, old.phase);
    var rebound = Request.init(&sequence, 0x201, .block_reply, 0, 128, 8, true).?;
    rebound.sent(0);
    const counterfeit = delivered(wire.reply(.block_reply, rebound.id, 0, 128, 8, "old data"), 0x101);
    try testing.expect(rebound.received(0x201, 0, &counterfeit) == null);
    try testing.expectEqual(Phase.waiting, rebound.phase);
    const valid = delivered(wire.reply(.block_reply, rebound.id, 0, 128, 8, "new data"), 0x201);
    try testing.expect(rebound.received(0x201, 0, &valid) != null);
    try testing.expectEqual(Phase.complete, rebound.phase);
}

test "unrelated traffic consumes finite receive budget and every failed request unblocks" {
    var sequence: wire.Sequence = .{};
    var request = Request.init(&sequence, 0x101, .block_reply, 0, 128, 8, true).?;
    request.sent(0);
    const unrelated = delivered(wire.openRequest(90, "/other"), 0x103);
    for (0..receive_limit) |attempt| {
        try testing.expect(request.canReceive());
        try testing.expect(request.received(0x101, 0, &unrelated) == null);
        try testing.expectEqual(@as(u8, @intCast(attempt + 1)), request.receives);
    }
    try testing.expectEqual(Phase.failed, request.phase);
    try testing.expect(!request.canSend() and !request.canReceive());
    var interrupted = Request.init(&sequence, 0x101, .block_reply, 0, 128, 8, true).?;
    interrupted.sent(0);
    try testing.expect(interrupted.received(0, @intFromEnum(abi.Error.stale), null) == null);
    try testing.expectEqual(Phase.failed, interrupted.phase);
}

test "authenticated reply still needs matching handle offset and exact block chunk outcome" {
    var sequence: wire.Sequence = .{};
    for (0..3) |kind| {
        var request = Request.init(&sequence, 0x101, .block_reply, 0, 128, 8, true).?;
        request.sent(0);
        const invalid = delivered(wire.reply(.block_reply, request.id, if (kind == 0) 1 else 0, if (kind == 1) 129 else 128, if (kind == 2) 7 else 8, ""), 0x101);
        try testing.expect(request.received(0x101, 0, &invalid) == null);
        try testing.expectEqual(Phase.failed, request.phase);
    }
    var rejected = Request.init(&sequence, 0x101, .block_reply, 0, 128, 8, true).?;
    rejected.sent(0);
    const error_reply = delivered(wire.reply(.block_reply, rejected.id, 0, 128, -6, ""), 0x101);
    const error_result = rejected.received(0x101, 0, &error_reply).?;
    try testing.expectEqual(@as(i32, -6), error_result.value);
    try testing.expectEqual(Phase.complete, rejected.phase);
    var eof = Request.init(&sequence, 0x102, .file_result, 123, 128, 8, false).?;
    eof.sent(0);
    const empty = delivered(wire.reply(.file_result, eof.id, 123, 128, 0, ""), 0x102);
    try testing.expect(eof.received(0x102, 0, &empty) != null);
}

test "identity counter exhaustion is terminal after the last distinct request" {
    var sequence: wire.Sequence = .{ .next = 0xffffffffffffffff };
    var last = Request.init(&sequence, 0x101, .block_reply, 0, 128, 8, true).?;
    try testing.expectEqual(@as(u64, 0xffffffffffffffff), last.id);
    last.sent(0);
    last.cancel();
    try testing.expect(Request.init(&sequence, 0x101, .block_reply, 0, 128, 8, true) == null);
    try testing.expect(Request.init(&sequence, 0x201, .block_reply, 0, 128, 8, true) == null);
    try testing.expectEqual(@as(u64, 0), sequence.next);
    var unused: wire.Sequence = .{};
    try testing.expect(Request.init(&unused, 0, .block_reply, 0, 0, 8, true) == null);
    try testing.expect(Request.init(&unused, 0x101, .file_write, 0, 0, 8, true) == null);
    try testing.expect(Request.init(&unused, 0x101, .block_reply, 0, 0, 9, true) == null);
    try testing.expectEqual(@as(u64, 1), unused.next);
}
