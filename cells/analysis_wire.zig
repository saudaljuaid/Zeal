// Profile 2 is a bounded binary-byte computation, not cryptographic attestation.
const abi = @import("abi.zig");
const wire = @import("contract_wire.zig");
pub const profile: u8 = 2;
pub const limit = 128;
pub const Tuple = struct {
    length: u16 = 0,
    newlines: u16 = 0,
    digest: u64 = 14695981039346656037,
    pub fn counts(self: Tuple) u64 {
        return @as(u64, self.length) | (@as(u64, self.newlines) << 16);
    }
    pub fn eql(self: Tuple, other: Tuple) bool {
        return self.length == other.length and self.newlines == other.newlines and self.digest == other.digest;
    }
};
pub fn calculate(bytes: []const u8) ?Tuple {
    if (bytes.len > limit) return null;
    var result: Tuple = .{ .length = @intCast(bytes.len) };
    // FNV-1a 64: iterate captured bytes in increasing offset, xor unsigned byte,
    // multiply by 1099511628211 modulo 2^64. Wire scalars are little endian.
    for (bytes) |byte| {
        result.newlines += @intFromBool(byte == 0x0a);
        result.digest = (result.digest ^ @as(u64, byte)) *% 1099511628211;
    }
    return result;
}
pub const Result = struct { endpoint: u64, id: u64, token: u64, attempt: u8, tuple: Tuple };
pub const Results = struct {
    const Digest = struct { packet: wire.Packet, sender: u64 };
    const Complete = struct { result: Result, remaining: u8 };
    const Entry = union(enum) { free: void, digest: Digest, complete: Complete };
    entries: [2]Entry = .{ .{ .free = {} }, .{ .free = {} } },
    pub fn push(self: *Results, message: *const abi.Message) ?Result {
        const packet = wire.decode(message, message.sender, wire.reply_operation) orelse return null;
        if (packet.kind != .response or packet.detail < 1 or packet.detail > 2) return null;
        const slot = wire.tokenSlot(packet.token) orelse return null;
        if (packet.command == .work) {
            switch (self.entries[slot]) {
                .free => self.entries[slot] = .{ .digest = .{ .packet = packet, .sender = message.sender } },
                .digest => self.entries[slot] = .{ .free = {} },
                .complete => {},
            }
            return null;
        }
        if (packet.command != .analysis_tuple) return null;
        const first = switch (self.entries[slot]) {
            .digest => |first| first,
            else => return null,
        };
        self.entries[slot] = .{ .free = {} };
        if (first.sender != message.sender or first.packet.id != packet.id or first.packet.token != packet.token or first.packet.detail != packet.detail or
            packet.data >> 32 != 0) return null;
        const length: u16 = @truncate(packet.data);
        const newlines: u16 = @truncate(packet.data >> 16);
        if (length > limit or newlines > length) return null;
        return .{ .endpoint = first.sender, .id = packet.id, .token = packet.token, .attempt = packet.detail, .tuple = .{ .length = length, .newlines = newlines, .digest = first.packet.data } };
    }
    pub fn hold(self: *Results, result: Result) bool {
        const slot = wire.tokenSlot(result.token) orelse return false;
        switch (self.entries[slot]) {
            .free => {},
            else => return false,
        }
        self.entries[slot] = .{ .complete = .{ .result = result, .remaining = 8 } };
        return true;
    }
    pub fn advance(self: *Results) [2]?Result {
        var ready: [2]?Result = .{ null, null };
        for (&self.entries, 0..) |*entry, index| switch (entry.*) {
            .complete => |*complete| {
                if (complete.remaining != 0) {
                    complete.remaining -= 1;
                    continue;
                }
                ready[index] = complete.result;
                entry.* = .{ .free = {} };
            },
            else => {},
        };
        return ready;
    }
    pub fn contains(self: *const Results, token: u64) bool {
        const slot = wire.tokenSlot(token) orelse return false;
        return switch (self.entries[slot]) {
            .free => false,
            .digest => |item| item.packet.token == token,
            .complete => |item| item.result.token == token,
        };
    }
    pub fn release(self: *Results, token: u64) void {
        const slot = wire.tokenSlot(token) orelse return;
        const stored = switch (self.entries[slot]) {
            .free => return,
            .digest => |item| item.packet.token,
            .complete => |item| item.result.token,
        };
        if (stored == token) self.entries[slot] = .{ .free = {} };
    }
};
// Scalar snapshots remain exactly eight packets. Byte-profile snapshots append
// two ordered packets, binding the full FS issuer and the full result counters.
pub const Collector = struct {
    base: wire.Collector,
    count: u8 = 0,
    issuer: u64 = 0,
    tuple: u64 = 0,
    pub fn push(self: *Collector, message: *const abi.Message) bool {
        if (self.base.count < wire.snapshot_parts) return self.base.push(message);
        const packet = wire.decode(message, self.base.issuer, wire.reply_operation) orelse return false;
        if (packet.id != self.base.id or packet.command != self.base.command or packet.kind != .snapshot or
            packet.token != self.base.token or packet.detail != wire.snapshot_parts + self.count or self.count >= 2) return false;
        if (self.count == 0) self.issuer = packet.data else self.tuple = packet.data;
        self.count += 1;
        return true;
    }
    pub fn take(self: *const Collector) ?wire.Snapshot {
        if (self.count != 2 or self.tuple >> 32 != 0) return null;
        const snapshot = self.base.takeAnalysis(self.issuer, @truncate(self.tuple), @truncate(self.tuple >> 16)) orelse return null;
        return snapshot;
    }
};

const testing = @import("std").testing;
test "FNV1a binary profile independently known vectors and bounded counters" {
    try testing.expectEqual(@as(u64, 0xcbf29ce484222325), calculate("").?.digest);
    try testing.expectEqual(@as(u64, 0xaf63dc4c8601ec8c), calculate("a").?.digest);
    try testing.expectEqual(@as(u64, 0xa430d84680aabd0b), calculate("hello").?.digest);
    for ([_]usize{ 0, 1, 7, 8, 9, 127, 128 }) |length| {
        const bytes = [_]u8{10} ** 129;
        const result = calculate(bytes[0..length]).?;
        try testing.expectEqual(length, result.length);
        try testing.expectEqual(length, result.newlines);
    }
    const too_long = [_]u8{0} ** 129;
    try testing.expect(calculate(&too_long) == null);
    const binary = calculate(&.{ 0, 255, 10, 128, 0, 10 }).?;
    try testing.expectEqual(@as(u16, 6), binary.length);
    try testing.expectEqual(@as(u16, 2), binary.newlines);
    try testing.expect(!calculate("aaaa").?.eql(calculate("bbbb").?));
}
test "full result tuple collection cannot accept duplicate gaps stale endpoint or changed attempt" {
    const token = wire.token(1, 0, 0x105).?;
    var digest = wire.encode(wire.reply_operation, .{ .id = 1, .command = .work, .kind = .response, .token = token, .detail = 1, .data = 7 });
    digest.sender = 0x106;
    var counts = wire.encode(wire.reply_operation, .{ .id = 1, .command = .analysis_tuple, .kind = .response, .token = token, .detail = 1, .data = 8 | (2 << 16) });
    counts.sender = 0x106;
    var results: Results = .{};
    try testing.expect(results.push(&counts) == null);
    try testing.expect(results.push(&digest) == null);
    const complete = results.push(&counts).?;
    try testing.expectEqual(@as(u16, 8), complete.tuple.length);
    try testing.expectEqual(@as(u16, 2), complete.tuple.newlines);
    try testing.expect(results.push(&digest) == null);
    try testing.expect(results.push(&digest) == null);
    try testing.expect(results.push(&counts) == null);
    try testing.expect(results.push(&digest) == null);
    counts.sender = 0x206;
    try testing.expect(results.push(&counts) == null);
}

fn collectSnapshot(value: wire.Snapshot, newlines: u16) Collector {
    var collected: Collector = .{ .base = .{ .issuer = value.issuer, .requester = value.requester, .id = 3, .command = .status } };
    var messages = value.messages(3, .status);
    for (&messages) |*message| {
        message.sender = value.issuer;
        @import("std").debug.assert(collected.push(message));
    }
    var issuer = wire.encode(wire.reply_operation, .{ .id = 3, .command = .status, .kind = .snapshot, .detail = 8, .token = value.token, .data = value.input_issuer });
    var counts = wire.encode(wire.reply_operation, .{ .id = 3, .command = .status, .kind = .snapshot, .detail = 9, .token = value.token, .data = @as(u64, value.input_length) | (@as(u64, newlines) << 16) });
    issuer.sender = value.issuer;
    counts.sender = value.issuer;
    @import("std").debug.assert(collected.push(&issuer) and collected.push(&counts));
    return collected;
}
test "legacy scalar collector never accepts an incomplete byte profile and only completed byte receipts carry counters" {
    var value: wire.Snapshot = .{ .token = wire.token(1, 0, 0x105).?, .profile_id = 2, .state = .offered, .input = 0x1a1, .input_issuer = 0x102, .input_length = 8, .requester = 0x104, .issuer = 0x105, .instance = 0x141, .endpoint = 0x106, .slots = 1, .pages = 2 };
    for ([_]wire.State{ .offered, .running, .recovering, .cancelled, .failed, .completed }) |state| {
        value.state = state;
        value.attempt = if (state == .offered) 0 else 1;
        value.rpc = if (state == .offered) 0 else 2;
        value.slots = if (state == .offered or state == .running or state == .recovering) 1 else 0;
        value.pages = value.slots * 2;
        value.reason = if (state == .cancelled) .cancelled else if (state == .failed) .transport else .ok;
        value.verified = state == .completed;
        value.result = if (value.verified) calculate("alpha\nx\n").?.digest else 0;
        const valid = collectSnapshot(value, if (value.verified) 2 else 0);
        try testing.expect(valid.take() != null);
        // The original eight-part API must keep its original approved profile.
        try testing.expect(valid.base.take() == null);
        const forged = collectSnapshot(value, if (value.verified) 9 else 1);
        try testing.expect(forged.take() == null);
    }
}
