// ABI v3 storage wire encoding. All chunk packets are exactly one bounded 32-byte payload.
const abi = @import("abi.zig");
const storage = @import("storage.zig");

pub const Header = struct {
    id: u64,
    handle: u64,
    offset: u32,
    value: i32,
    data: [storage.chunk_size]u8,
};

pub const Open = struct { id: u64, name: []const u8 };

fn put64(payload: *[abi.payload_size]u8, index: usize, value: u64) void {
    for (0..8) |byte| payload[index + byte] = @truncate(value >> @intCast(byte * 8));
}
fn put32(payload: *[abi.payload_size]u8, index: usize, value: u32) void {
    for (0..4) |byte| payload[index + byte] = @truncate(value >> @intCast(byte * 8));
}
fn get64(payload: *const [abi.payload_size]u8, index: usize) u64 {
    var value: u64 = 0;
    for (0..8) |byte| value |= @as(u64, payload[index + byte]) << @intCast(byte * 8);
    return value;
}
fn get32(payload: *const [abi.payload_size]u8, index: usize) u32 {
    var value: u32 = 0;
    for (0..4) |byte| value |= @as(u32, payload[index + byte]) << @intCast(byte * 8);
    return value;
}
fn zero(bytes: []const u8) bool {
    for (bytes) |byte| if (byte != 0) return false;
    return true;
}

pub fn request(operation: abi.Operation, id: u64, handle: u64, offset: u32, count: u32, data: []const u8) abi.Message {
    var message = abi.Message.empty(operation);
    if (data.len > storage.chunk_size) return message;
    message.length = 32;
    put64(&message.payload, 0, id);
    put64(&message.payload, 8, handle);
    put32(&message.payload, 16, offset);
    put32(&message.payload, 20, count);
    @memcpy(message.payload[24..][0..data.len], data);
    return message;
}

pub fn openRequest(id: u64, name: []const u8) abi.Message {
    var message = abi.Message.empty(.file_open);
    put64(&message.payload, 0, id);
    if (name.len > storage.name_limit) return message; // Invalid length is never silently truncated into a valid name.
    message.length = @intCast(8 + name.len);
    @memcpy(message.payload[8..][0..name.len], name);
    return message;
}

pub fn reply(operation: abi.Operation, id: u64, handle: u64, offset: u32, result: i32, data: []const u8) abi.Message {
    return request(operation, id, handle, offset, @bitCast(result), data);
}

pub fn decodeOpen(message: *const abi.Message) ?Open {
    if (message.sender == 0 or message.operation != @intFromEnum(abi.Operation.file_open) or
        message.length < 10 or message.length > 8 + storage.name_limit) return null;
    const id = get64(&message.payload, 0);
    const name = message.payload[8..message.length];
    if (id == 0 or !storage.validName(name)) return null;
    return .{ .id = id, .name = name };
}

fn header(message: *const abi.Message) Header {
    var result: Header = .{
        .id = get64(&message.payload, 0),
        .handle = get64(&message.payload, 8),
        .offset = get32(&message.payload, 16),
        .value = @bitCast(get32(&message.payload, 20)),
        .data = undefined,
    };
    @memcpy(&result.data, message.payload[24..32]);
    return result;
}

pub fn decodeRequest(message: *const abi.Message) ?Header {
    if (message.sender == 0 or message.length != 32) return null;
    const result = header(message);
    if (result.id == 0 or result.value < 0 or result.value > storage.chunk_size) return null;
    const count: usize = @intCast(result.value);
    switch (message.operation) {
        @intFromEnum(abi.Operation.block_read) => {
            if (result.handle != 0 or !zero(&result.data)) return null;
        },
        @intFromEnum(abi.Operation.block_write) => {
            if (result.handle != 0 or !zero(result.data[count..])) return null;
        },
        @intFromEnum(abi.Operation.file_chunk_read) => {
            if (result.handle == 0 or !zero(&result.data)) return null;
        },
        @intFromEnum(abi.Operation.file_write) => {
            if (result.handle == 0 or !zero(result.data[count..])) return null;
        },
        @intFromEnum(abi.Operation.file_close) => {
            if (result.handle == 0 or result.offset != 0 or result.value != 0 or !zero(&result.data)) return null;
        },
        else => return null,
    }
    return result;
}

// Request identity and sender generation both have to match. A reply from a predecessor never completes a request.
pub fn decodeReply(message: *const abi.Message, operation: abi.Operation, sender: u64, id: u64) ?Header {
    if (sender == 0 or id == 0 or message.sender != sender or message.operation != @intFromEnum(operation) or
        message.length != 32 or (operation != .block_reply and operation != .file_result)) return null;
    const result = header(message);
    if (result.id != id or result.value < -8 or result.value > storage.chunk_size) return null;
    const used: usize = if (result.value > 0) @intCast(result.value) else 0;
    if (!zero(result.data[used..])) return null;
    return result;
}

pub fn requestId(message: *const abi.Message) u64 {
    return if (message.length >= 8 and message.length <= abi.payload_size) get64(&message.payload, 0) else 0;
}

// Consume a fresh identity even if a request times out. Exhaustion is terminal and cannot alias an old request.
pub const Sequence = struct {
    next: u64 = 1,
    pub fn take(self: *Sequence) ?u64 {
        if (self.next == 0) return null;
        const result = self.next;
        self.next = if (result == 0xffffffffffffffff) 0 else result + 1;
        return result;
    }
};

const testing = @import("std").testing;
fn delivered(message: abi.Message, sender: u64) abi.Message {
    var result = message;
    result.sender = sender;
    return result;
}

test "version three bounded chunk fields round trip and reply matches authenticated identity" {
    try testing.expectEqual(@as(usize, 48), @sizeOf(abi.Message));
    const original = delivered(request(.file_write, 0x52765c083c8aa6e9, 0x01000201, 0xffffffff, 8, "payload!"), 0x103);
    const decoded = decodeRequest(&original).?;
    try testing.expectEqual(@as(u64, 0x52765c083c8aa6e9), decoded.id);
    try testing.expectEqual(@as(u64, 0x01000201), decoded.handle);
    try testing.expectEqual(@as(u32, 0xffffffff), decoded.offset);
    try testing.expectEqual(@as(i32, 8), decoded.value);
    try testing.expectEqualSlices(u8, "payload!", &decoded.data);
    const answer = delivered(reply(.file_result, decoded.id, decoded.handle, decoded.offset, 8, "payload!"), 0x102);
    try testing.expect(decodeReply(&answer, .file_result, 0x102, decoded.id) != null);
    try testing.expect(decodeReply(&answer, .file_result, 0x202, decoded.id) == null);
    try testing.expect(decodeReply(&answer, .file_result, 0x102, decoded.id + 1) == null);
    try testing.expect(decodeReply(&answer, .block_reply, 0x102, decoded.id) == null);
    try testing.expect(decodeReply(&answer, .file_result, 0, decoded.id) == null);
    try testing.expect(decodeReply(&answer, .file_result, 0x102, 0) == null);
}

test "malformed chunk lengths signed counts reserved fields and padding are rejected" {
    var message = delivered(request(.block_write, 1, 0, 128, 3, "abc"), 0x102);
    try testing.expect(decodeRequest(&message) != null);
    for ([_]u32{ 0, 8, 23, 24, 31, 33, 0xffffffff }) |length| {
        message.length = length;
        try testing.expect(decodeRequest(&message) == null);
    }
    message.length = 32;
    for ([_]u32{ 9, 0x7fffffff, 0x80000000, 0xffffffff }) |count| {
        put32(&message.payload, 20, count);
        try testing.expect(decodeRequest(&message) == null);
    }
    put32(&message.payload, 20, 3);
    for (27..32) |at| {
        message.payload[at] = 1;
        try testing.expect(decodeRequest(&message) == null);
        message.payload[at] = 0;
    }
    put64(&message.payload, 8, 1);
    try testing.expect(decodeRequest(&message) == null);
    put64(&message.payload, 8, 0);
    put64(&message.payload, 0, 0);
    try testing.expect(decodeRequest(&message) == null);
    put64(&message.payload, 0, 1);
    message.sender = 0;
    try testing.expect(decodeRequest(&message) == null);
    message = delivered(request(.file_chunk_read, 1, 1, 0, 8, "x"), 0x103);
    try testing.expect(decodeRequest(&message) == null);
    message = delivered(request(.file_close, 1, 1, 0, 0, ""), 0x103);
    try testing.expect(decodeRequest(&message) != null);
    message = delivered(request(.file_close, 1, 1, 1, 0, ""), 0x103);
    try testing.expect(decodeRequest(&message) == null);
    message = delivered(request(.file_close, 1, 1, 0, 1, ""), 0x103);
    try testing.expect(decodeRequest(&message) == null);
    message = delivered(request(.file_write, 1, 0, 0, 1, "x"), 0x103);
    try testing.expect(decodeRequest(&message) == null);
}

test "open names use exact declared length and parser never trusts oversized payload lengths" {
    var message = delivered(openRequest(19, "/note"), 0x103);
    try testing.expectEqual(@as(u32, 13), message.length);
    const opened = decodeOpen(&message).?;
    try testing.expectEqual(@as(u64, 19), opened.id);
    try testing.expectEqualSlices(u8, "/note", opened.name);
    for ([_]u32{ 0, 1, 7, 8, 9, 25, 32, 33, 0xffffffff }) |length| {
        message.length = length;
        try testing.expect(decodeOpen(&message) == null);
    }
    message = delivered(openRequest(1, "/123456789012345"), 0x103);
    try testing.expect(decodeOpen(&message) != null);
    message = delivered(openRequest(1, "/1234567890123456"), 0x103);
    try testing.expect(decodeOpen(&message) == null);
    message = delivered(openRequest(0, "/note"), 0x103);
    try testing.expect(decodeOpen(&message) == null);
    message = delivered(openRequest(1, "/a/b"), 0x103);
    try testing.expect(decodeOpen(&message) == null);
}

test "late or counterfeit replies cannot complete a fresh request after timeout or restart" {
    var sequence: Sequence = .{};
    const first = sequence.take().?;
    const retry = sequence.take().?;
    const stale = delivered(reply(.file_result, first, 1, 0, 8, "verified"), 0x102);
    try testing.expect(decodeReply(&stale, .file_result, 0x102, retry) == null);
    const forged = delivered(reply(.file_result, retry, 1, 0, 8, "verified"), 0x202);
    try testing.expect(decodeReply(&forged, .file_result, 0x102, retry) == null);
    const valid = delivered(reply(.file_result, retry, 1, 0, 8, "verified"), 0x102);
    try testing.expect(decodeReply(&valid, .file_result, 0x102, retry) != null);
    for ([_]i32{ -9, 9, 0x7fffffff, -0x7fffffff }) |value| {
        const malformed = delivered(reply(.file_result, retry, 1, 0, value, ""), 0x102);
        try testing.expect(decodeReply(&malformed, .file_result, 0x102, retry) == null);
    }
    const padded_error = delivered(reply(.file_result, retry, 1, 0, -3, "x"), 0x102);
    try testing.expect(decodeReply(&padded_error, .file_result, 0x102, retry) == null);
    sequence.next = 0xffffffffffffffff;
    try testing.expectEqual(@as(u64, 0xffffffffffffffff), sequence.take().?);
    try testing.expect(sequence.take() == null);
    try testing.expect(sequence.take() == null);
}
