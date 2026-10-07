// Exact 32-byte little-endian hosting packets. Sender endpoints are set by the kernel.
const abi = @import("abi.zig");

pub const request_operation: u32 = 15;
pub const reply_operation: u32 = 16;
pub const Command = enum(u32) {
    challenge = 1,
    nested = 2,
    sleep = 3,
    nested_sleep = 4,
    fault = 5,
    grandchild_fault = 6,
    copied_authority = 7,
    timeout = 8,
    copied_control = 9,
    copied_creation = 10,
    cpu_probe = 11,
};
pub const Packet = struct {
    id: u64,
    command: Command,
    argument: u64,
    value: u64,
};
pub const nested_salt: u64 = 0x8ac91367ef04d2b5;

fn put64(bytes: *[32]u8, at: usize, value: u64) void {
    for (0..8) |index| bytes[at + index] = @truncate(value >> @intCast(index * 8));
}
fn get64(bytes: *const [32]u8, at: usize) u64 {
    var result: u64 = 0;
    for (0..8) |index| result |= @as(u64, bytes[at + index]) << @intCast(index * 8);
    return result;
}
fn put32(bytes: *[32]u8, at: usize, value: u32) void {
    for (0..4) |index| bytes[at + index] = @truncate(value >> @intCast(index * 8));
}
fn get32(bytes: *const [32]u8, at: usize) u32 {
    var result: u32 = 0;
    for (0..4) |index| result |= @as(u32, bytes[at + index]) << @intCast(index * 8);
    return result;
}

pub fn encode(operation: u32, packet: Packet) abi.Message {
    var message: abi.Message = .{ .sender = 0, .operation = operation, .length = 32, .payload = [_]u8{0} ** 32 };
    put64(&message.payload, 0, packet.id);
    put32(&message.payload, 8, @intFromEnum(packet.command));
    put64(&message.payload, 16, packet.argument);
    put64(&message.payload, 24, packet.value);
    return message;
}

fn decode(message: *const abi.Message, sender: u64, operation: u32) ?Packet {
    if (sender == 0 or message.sender != sender or message.operation != operation or
        message.length != 32 or get32(&message.payload, 12) != 0) return null;
    const id = get64(&message.payload, 0);
    const command = get32(&message.payload, 8);
    if (id == 0 or command < 1 or command > @intFromEnum(Command.cpu_probe)) return null;
    return .{ .id = id, .command = @enumFromInt(command), .argument = get64(&message.payload, 16), .value = get64(&message.payload, 24) };
}

pub fn decodeRequest(message: *const abi.Message, parent: u64) ?Packet {
    const packet = decode(message, parent, request_operation) orelse return null;
    switch (packet.command) {
        .sleep, .nested_sleep, .timeout => if (packet.argument == 0 or packet.argument > abi.wait_max_ticks or packet.value != 0) return null,
        .fault, .grandchild_fault => if (packet.argument != 0 or packet.value != 0) return null,
        .challenge, .nested => if (packet.value != 0) return null,
        .copied_authority => if (packet.argument == 0 or packet.value == 0) return null,
        .copied_control, .copied_creation => if (packet.argument == 0 or packet.value != 0) return null,
        .cpu_probe => if (packet.argument < 1 or packet.argument > 5 or packet.value != 0) return null,
    }
    return packet;
}

pub fn decodeReply(message: *const abi.Message, endpoint: u64, id: u64, command: Command, argument: u64) ?Packet {
    const packet = decode(message, endpoint, reply_operation) orelse return null;
    if (packet.id != id or packet.command != command or packet.argument != argument) return null;
    return packet;
}

// The challenge uses every input byte in a fixed number of scalar rounds.
pub fn calculate(challenge: u64) u64 {
    var result: u64 = 0xcbf29ce484222325;
    const label = "Zeal bounded ring-3 worker";
    for (label) |byte| result = (result ^ byte) *% 0x100000001b3;
    for (0..8) |index| result = (result ^ @as(u8, @truncate(challenge >> @intCast(index * 8)))) *% 0x100000001b3;
    return result;
}

pub fn expected(command: Command, argument: u64) ?u64 {
    return switch (command) {
        .challenge => calculate(argument),
        .nested => calculate(argument) ^ calculate(argument ^ nested_salt),
        .sleep, .nested_sleep => argument,
        .copied_authority, .copied_control, .copied_creation => @bitCast(@as(i64, @intFromEnum(abi.Error.denied))),
        .timeout => @bitCast(@as(i64, @intFromEnum(abi.Error.timeout))),
        .fault, .grandchild_fault => 0,
        .cpu_probe => null,
    };
}

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
fn delivered(packet: Packet, sender: u64, operation: u32) abi.Message {
    var result = encode(operation, packet);
    result.sender = sender;
    return result;
}

test "hosting wire authenticates endpoint generation and exact request structure" {
    const packet: Packet = .{ .id = 7, .command = .challenge, .argument = 0x73ab9c52de410689, .value = 0 };
    var message = delivered(packet, 0x105, request_operation);
    const parsed = decodeRequest(&message, 0x105).?;
    try testing.expectEqual(packet, parsed);
    try testing.expect(decodeRequest(&message, 0x205) == null);
    try testing.expect(decodeRequest(&message, 0) == null);
    for ([_]u32{ 0, 8, 31, 33, 0xffffffff }) |length| {
        message.length = length;
        try testing.expect(decodeRequest(&message, 0x105) == null);
    }
    message.length = 32;
    for (12..16) |index| {
        message.payload[index] = 1;
        try testing.expect(decodeRequest(&message, 0x105) == null);
        message.payload[index] = 0;
    }
    put64(&message.payload, 24, 1);
    try testing.expect(decodeRequest(&message, 0x105) == null);
    put64(&message.payload, 24, 0);
    put64(&message.payload, 0, 0);
    try testing.expect(decodeRequest(&message, 0x105) == null);
}

test "hosting replies bind request command challenge and sender incarnation" {
    const packet: Packet = .{ .id = 9, .command = .nested, .argument = 17, .value = expected(.nested, 17).? };
    var message = delivered(packet, 0x205, reply_operation);
    try testing.expect(decodeReply(&message, 0x205, 9, .nested, 17) != null);
    try testing.expect(decodeReply(&message, 0x105, 9, .nested, 17) == null);
    try testing.expect(decodeReply(&message, 0x205, 8, .nested, 17) == null);
    try testing.expect(decodeReply(&message, 0x205, 9, .challenge, 17) == null);
    try testing.expect(decodeReply(&message, 0x205, 9, .nested, 18) == null);
    message.operation = request_operation;
    try testing.expect(decodeReply(&message, 0x205, 9, .nested, 17) == null);
}

test "hosting receive and sleep requests have finite exact limits" {
    for ([_]u64{ 0, 1001, 0xffffffffffffffff }) |duration| {
        const message = delivered(.{ .id = 1, .command = .sleep, .argument = duration, .value = 0 }, 0x104, request_operation);
        try testing.expect(decodeRequest(&message, 0x104) == null);
    }
    for ([_]u64{ 1, 1000 }) |duration| {
        const message = delivered(.{ .id = 1, .command = .sleep, .argument = duration, .value = 0 }, 0x104, request_operation);
        try testing.expect(decodeRequest(&message, 0x104) != null);
    }
}

test "hosting identity exhaustion never aliases an old request" {
    var sequence: Sequence = .{ .next = 0xffffffffffffffff };
    try testing.expectEqual(@as(u64, 0xffffffffffffffff), sequence.take().?);
    try testing.expect(sequence.take() == null);
    try testing.expect(sequence.take() == null);
}

test "hosting deterministic scalar challenge has fixed known vectors" {
    try testing.expectEqual(@as(u64, 0xc56fdba9d66e39cc), calculate(0));
    try testing.expect(calculate(1) != calculate(0));
    try testing.expect(calculate(0x0100000000000000) != calculate(1));
}

test "child CPU probes are authenticated bounded exact commands with no RPC reply" {
    for ([_]u64{ 1, 2, 3, 4, 5 }) |mode| {
        const message = delivered(.{ .id = mode, .command = .cpu_probe, .argument = mode, .value = 0 }, 0x104, request_operation);
        try testing.expect(decodeRequest(&message, 0x104) != null);
        try testing.expect(decodeRequest(&message, 0x204) == null);
        try testing.expect(expected(.cpu_probe, mode) == null);
    }
    for ([_]u64{ 0, 6, 0xffffffffffffffff }) |mode| {
        const message = delivered(.{ .id = 7, .command = .cpu_probe, .argument = mode, .value = 0 }, 0x104, request_operation);
        try testing.expect(decodeRequest(&message, 0x104) == null);
    }
    const message = delivered(.{ .id = 7, .command = .cpu_probe, .argument = 1, .value = 1 }, 0x104, request_operation);
    try testing.expect(decodeRequest(&message, 0x104) == null);
}
