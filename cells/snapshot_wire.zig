// Explicit little-endian, bounded object protocol. ABI operations 17--20.
const abi = @import("abi.zig");
const snapshot = @import("snapshot.zig");
const storage = @import("storage.zig");

pub const Action = enum(u8) { create = 1, status, bind, revoke, close, reap, bind_check, inventory };
pub const Inventory = struct { retained: u8, backing: u16, readers: u8, live: u8, block: u64 };
pub const Control = struct { transaction: u64, subject: u64, peer: u64, action: Action };
pub const ControlReply = struct {
    transaction: u64,
    reference: snapshot.Ref,
    block: u64,
    length: u8,
    status: storage.Status,
    action: Action,
    state: snapshot.State,
};
pub const Read = struct { transaction: u64, reference: snapshot.Ref, offset: u16, count: u8 };
pub const Release = struct { transaction: u64, reference: snapshot.Ref, reader: u64 };
pub const ReadReply = struct { transaction: u64, reference: snapshot.Ref, offset: u16, count: u8, status: storage.Status, data: [8]u8 };

fn put(bytes: *[32]u8, start: usize, width: usize, value: u64) void {
    for (0..width) |at| bytes[start + at] = @truncate(value >> @intCast(at * 8));
}
fn get(bytes: *const [32]u8, start: usize, width: usize) u64 {
    var result: u64 = 0;
    for (0..width) |at| result |= @as(u64, bytes[start + at]) << @intCast(at * 8);
    return result;
}
fn zero(bytes: []const u8) bool {
    for (bytes) |byte| if (byte != 0) return false;
    return true;
}
fn status(value: u8) ?storage.Status {
    const signed: i8 = @bitCast(value);
    return @import("std").meta.intToEnum(storage.Status, @as(i32, signed)) catch null;
}
fn action(value: u8) ?Action {
    return @import("std").meta.intToEnum(Action, value) catch null;
}

pub fn control(transaction: u64, subject: u64, peer: u64, command: Action) abi.Message {
    var message = abi.Message.empty(.snapshot_control);
    message.length = 32;
    put(&message.payload, 0, 8, transaction);
    put(&message.payload, 8, 8, subject);
    put(&message.payload, 16, 8, peer);
    message.payload[24] = @intFromEnum(command);
    return message;
}
pub fn decodeControl(message: *const abi.Message) ?Control {
    if (message.sender == 0 or message.operation != @intFromEnum(abi.Operation.snapshot_control) or
        message.length != 32 or !zero(message.payload[25..32])) return null;
    const command = action(message.payload[24]) orelse return null;
    const transaction = get(&message.payload, 0, 8);
    const subject = get(&message.payload, 8, 8);
    const peer = get(&message.payload, 16, 8);
    if (transaction == 0 or subject == 0) return null;
    if (command == .inventory and subject != 1) return null;
    if (command == .bind or command == .revoke or command == .bind_check) {
        if (peer == 0) return null;
    } else if (peer != 0) return null;
    return .{ .transaction = transaction, .subject = subject, .peer = peer, .action = command };
}
pub fn controlReply(transaction: u64, reference: snapshot.Ref, block: u64, length: u8, result: storage.Status, command: Action, state: snapshot.State) abi.Message {
    var message = abi.Message.empty(.snapshot_reply);
    message.length = 32;
    put(&message.payload, 0, 8, transaction);
    put(&message.payload, 8, 8, reference.token);
    put(&message.payload, 16, 8, block);
    message.payload[24] = length;
    message.payload[25] = @bitCast(@as(i8, @intCast(@intFromEnum(result))));
    message.payload[26] = @intFromEnum(command);
    message.payload[27] = @intFromEnum(state);
    message.payload[31] = 1;
    return message;
}
pub fn decodeControlReply(message: *const abi.Message, issuer: u64, transaction: u64, command: Action) ?ControlReply {
    if (!snapshot.validIssuer(issuer) or transaction == 0 or message.sender != issuer or
        message.operation != @intFromEnum(abi.Operation.snapshot_reply) or message.length != 32 or
        message.payload[31] != 1 or !zero(message.payload[28..31]) or
        get(&message.payload, 0, 8) != transaction or message.payload[26] != @intFromEnum(command) or
        message.payload[24] > snapshot.byte_limit) return null;
    const state = @import("std").meta.intToEnum(snapshot.State, message.payload[27]) catch return null;
    const result = status(message.payload[25]) orelse return null;
    const reference: snapshot.Ref = .{ .issuer = issuer, .token = get(&message.payload, 8, 8) };
    if (command == .inventory) {
        if (state != .empty) return null;
        if (result == .ok) {
            if (reference.token >> 32 != 0 or reference.token & 255 > 2 or
                (reference.token >> 8) & 65535 > 256 or (reference.token >> 24) & 255 > 4 or message.payload[24] > 2) return null;
        } else if (reference.token != 0 or get(&message.payload, 16, 8) != 0 or message.payload[24] != 0) return null;
    } else if ((state == .empty and (reference.token != 0 or get(&message.payload, 16, 8) != 0 or message.payload[24] != 0)) or
        (state != .empty and !snapshot.validRef(reference))) return null;
    return .{
        .transaction = transaction,
        .reference = reference,
        .block = get(&message.payload, 16, 8),
        .length = message.payload[24],
        .status = result,
        .action = command,
        .state = state,
    };
}
pub fn decodeInventoryReply(message: *const abi.Message, issuer: u64, transaction: u64) ?Inventory {
    const reply = decodeControlReply(message, issuer, transaction, .inventory) orelse return null;
    if (reply.status != .ok) return null;
    const summary = reply.reference.token;
    const result: Inventory = .{ .retained = @truncate(summary), .backing = @truncate(summary >> 8), .readers = @truncate(summary >> 24), .live = reply.length, .block = reply.block };
    if (result.live > result.retained or result.backing % 128 != 0 or
        result.backing > @as(u16, result.retained) * 128 or result.backing < @as(u16, result.live) * 128 or
        result.readers > result.live * 2) return null;
    return result;
}
pub fn read(operation: abi.Operation, transaction: u64, reference: snapshot.Ref, offset: u16, count: u8) abi.Message {
    var message = abi.Message.empty(operation);
    message.length = 32;
    put(&message.payload, 0, 8, transaction);
    put(&message.payload, 8, 8, reference.token);
    put(&message.payload, 16, 8, reference.issuer);
    put(&message.payload, 24, 2, offset);
    message.payload[26] = count;
    return message;
}
pub fn decodeRead(message: *const abi.Message) ?Read {
    if (message.sender == 0 or message.length != 32 or !zero(message.payload[27..32]) or
        (message.operation != @intFromEnum(abi.Operation.snapshot_read) and
            message.operation != @intFromEnum(abi.Operation.snapshot_release))) return null;
    const result: Read = .{
        .transaction = get(&message.payload, 0, 8),
        .reference = .{ .issuer = get(&message.payload, 16, 8), .token = get(&message.payload, 8, 8) },
        .offset = @intCast(get(&message.payload, 24, 2)),
        .count = message.payload[26],
    };
    if (result.transaction == 0 or result.reference.issuer == 0 or result.reference.token == 0 or result.count > 8) return null;
    if (message.operation == @intFromEnum(abi.Operation.snapshot_release) and (result.offset != 0 or result.count != 0)) return null;
    return result;
}
pub fn release(transaction: u64, reference: snapshot.Ref, reader: u64) abi.Message {
    var message = abi.Message.empty(.snapshot_release);
    message.length = 32;
    put(&message.payload, 0, 8, transaction);
    put(&message.payload, 8, 8, reference.token);
    put(&message.payload, 16, 8, reference.issuer);
    put(&message.payload, 24, 8, reader);
    return message;
}
pub fn decodeRelease(message: *const abi.Message) ?Release {
    if (message.sender == 0 or message.length != 32 or message.operation != @intFromEnum(abi.Operation.snapshot_release)) return null;
    const result: Release = .{
        .transaction = get(&message.payload, 0, 8),
        .reference = .{ .issuer = get(&message.payload, 16, 8), .token = get(&message.payload, 8, 8) },
        .reader = get(&message.payload, 24, 8),
    };
    if (result.transaction == 0 or !snapshot.validRef(result.reference) or
        (result.reader != 0 and !snapshot.validEndpoint(result.reader))) return null;
    return result;
}
pub fn readReply(transaction: u64, reference: snapshot.Ref, offset: u16, result: i32, data: []const u8) abi.Message {
    var message = abi.Message.empty(.snapshot_reply);
    if (result < -8 or result > 8 or data.len > 8 or (result < 0 and data.len != 0) or (result >= 0 and data.len != result)) return message;
    message.length = 32;
    put(&message.payload, 0, 8, transaction);
    put(&message.payload, 8, 8, reference.token);
    put(&message.payload, 16, 2, offset);
    message.payload[18] = if (result >= 0) @intCast(result) else 0;
    message.payload[19] = @bitCast(@as(i8, @intCast(if (result < 0) result else 0)));
    @memcpy(message.payload[20..][0..data.len], data);
    message.payload[31] = 2;
    return message;
}
pub fn decodeReadReply(message: *const abi.Message, expected: Read) ?ReadReply {
    if (expected.transaction == 0 or !snapshot.validIssuer(expected.reference.issuer) or message.sender != expected.reference.issuer or
        message.operation != @intFromEnum(abi.Operation.snapshot_reply) or message.length != 32 or
        message.payload[31] != 2 or !zero(message.payload[28..31]) or
        get(&message.payload, 0, 8) != expected.transaction or get(&message.payload, 8, 8) != expected.reference.token or
        get(&message.payload, 16, 2) != expected.offset) return null;
    const amount = message.payload[18];
    const result = status(message.payload[19]) orelse return null;
    if (amount > expected.count or amount > 8 or (result != .ok and amount != 0) or !zero(message.payload[20 + @as(usize, amount) .. 28])) return null;
    var data = [_]u8{0} ** 8;
    @memcpy(&data, message.payload[20..28]);
    return .{ .transaction = expected.transaction, .reference = expected.reference, .offset = expected.offset, .count = amount, .status = result, .data = data };
}
