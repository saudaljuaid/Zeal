// Broker-owned service protocol. These references grant no kernel authority.
const abi = @import("abi.zig");
pub const version: u8 = 1;
pub const request_operation: u32 = 15;
pub const reply_operation: u32 = 16;
pub const profile: u8 = 1;
pub const contract_tag: u64 = 0x80;
pub const serial_limit: u64 = (1 << 23) - 1;
pub const generation_limit: u64 = (1 << 24) - 1;
pub const snapshot_parts = 8;
pub const Command = enum(u8) { offer = 1, accept, status, cancel, receipt, reap, work, fault, bootstrap, input, analysis_tuple, input_length, rebind_input, authorize_input, stage };
pub const Kind = enum(u8) { request, response, snapshot, failure };
pub const Packet = struct { id: u64, command: Command, kind: Kind = .request, detail: u8 = 0, token: u64 = 0, data: u64 = 0 };
pub const State = enum(u8) { free, offered, running, recovering, completed, cancelled, failed };
pub const Reason = enum(u8) { ok, cancelled, invalid_result, transport, second_fault, counter_exhausted, lifecycle, resource, rebind };

pub fn put64(bytes: *[32]u8, offset: usize, value: u64) void {
    for (0..8) |index| bytes[offset + index] = @truncate(value >> @intCast(index * 8));
}
pub fn get64(bytes: *const [32]u8, offset: usize) u64 {
    var value: u64 = 0;
    for (0..8) |index| value |= @as(u64, bytes[offset + index]) << @intCast(index * 8);
    return value;
}
pub fn token(serial: u64, slot: usize, issuer: u64) ?u64 {
    const generation = issuer >> 8;
    const endpoint_slot = issuer & 255;
    if (serial == 0 or serial > serial_limit or slot >= 2 or generation == 0 or generation > generation_limit or endpoint_slot < 1 or endpoint_slot > 8) return null;
    return (issuer << 32) | (serial << 9) | (@as(u64, @intCast(slot)) << 8) | contract_tag;
}
pub fn tokenSlot(value: u64) ?usize {
    const endpoint_slot = (value >> 32) & 255;
    if (value & 255 != contract_tag or ((value >> 9) & serial_limit) == 0 or value >> 40 == 0 or endpoint_slot < 1 or endpoint_slot > 8) return null;
    return @intCast((value >> 8) & 1);
}
pub fn tokenIssuer(value: u64) u64 {
    return value >> 32;
}
pub fn tokenGeneration(value: u64) u64 {
    return tokenIssuer(value) >> 8;
}
pub fn tokenSerial(value: u64) u64 {
    return (value >> 9) & serial_limit;
}
pub fn encode(operation: u32, packet: Packet) abi.Message {
    var message: abi.Message = .{ .sender = 0, .operation = operation, .length = 32, .payload = [_]u8{0} ** 32 };
    put64(&message.payload, 0, packet.id);
    message.payload[8] = version;
    message.payload[9] = @intFromEnum(packet.command);
    message.payload[10] = @intFromEnum(packet.kind);
    message.payload[11] = packet.detail;
    put64(&message.payload, 16, packet.token);
    put64(&message.payload, 24, packet.data);
    return message;
}
pub fn decode(message: *const abi.Message, endpoint: u64, operation: u32) ?Packet {
    if (endpoint == 0 or message.sender != endpoint or message.operation != operation or message.length != 32 or
        message.payload[8] != version or message.payload[9] < 1 or message.payload[9] > @intFromEnum(Command.stage) or
        message.payload[10] > @intFromEnum(Kind.failure) or get64(&message.payload, 0) == 0) return null;
    for (12..16) |index| if (message.payload[index] != 0) return null;
    return .{ .id = get64(&message.payload, 0), .command = @enumFromInt(message.payload[9]), .kind = @enumFromInt(message.payload[10]), .detail = message.payload[11], .token = get64(&message.payload, 16), .data = get64(&message.payload, 24) };
}
pub fn decodeRequest(message: *const abi.Message, endpoint: u64) ?Packet {
    const packet = decode(message, endpoint, request_operation) orelse return null;
    if (packet.kind != .request) return null;
    switch (packet.command) {
        .offer => if ((packet.detail != profile and packet.detail != 2) or (packet.detail == profile and packet.token != 0) or (packet.detail == 2 and packet.token == 0)) return null,
        .accept => if ((packet.detail != profile and packet.detail != 2) or tokenSlot(packet.token) == null) return null,
        .stage => if ((packet.detail != 0 and packet.detail != 2) or packet.data == 0 or tokenSlot(packet.token) == null) return null,
        .status => if (packet.detail != 0 or (packet.token == 0 and packet.data == 0) or
            (packet.token != 0 and (packet.data != 0 or tokenSlot(packet.token) == null))) return null,
        .cancel, .receipt, .reap => if (packet.detail != 0 or packet.data != 0 or tokenSlot(packet.token) == null) return null,
        .work, .fault, .bootstrap, .input, .analysis_tuple, .input_length, .rebind_input, .authorize_input => return null,
    }
    return packet;
}
pub fn decodeWork(message: *const abi.Message, endpoint: u64, operation: u32) ?Packet {
    const packet = decode(message, endpoint, operation) orelse return null;
    const kind: Kind = if (operation == request_operation) .request else if (operation == reply_operation) .response else return null;
    if (packet.kind != kind or packet.command != .work or packet.detail < 1 or packet.detail > 2 or tokenSlot(packet.token) == null) return null;
    return packet;
}
pub fn decodeBootstrap(message: *const abi.Message, endpoint: u64, instance: u64) bool {
    const packet = decode(message, endpoint, reply_operation) orelse return false;
    return packet.command == .bootstrap and packet.kind == .response and packet.id == 1 and packet.detail == 0 and packet.token == 0 and packet.data == instance and instance != 0;
}
pub fn calculate(input: u64) u64 {
    // Fixed scalar, input-sensitive work. Verification is recomputation, not attestation.
    return @import("hosting_wire.zig").calculate(input);
}
pub const Sequence = @import("hosting_wire.zig").Sequence;

pub const Snapshot = struct {
    token: u64 = 0,
    state: State = .free,
    profile_id: u8 = 0,
    retries: u8 = 0,
    attempt: u8 = 0,
    reason: Reason = .ok,
    slots: u8 = 0,
    pages: u8 = 0,
    verified: bool = false,
    input_issuer: u64 = 0,
    input_length: u16 = 0,
    newlines: u16 = 0,
    input: u64 = 0,
    requester: u64 = 0,
    issuer: u64 = 0,
    instance: u64 = 0,
    endpoint: u64 = 0,
    rpc: u64 = 0,
    result: u64 = 0,
    pub fn flags(self: Snapshot) u64 {
        return @as(u64, @intFromEnum(self.state)) | (@as(u64, self.profile_id) << 8) | (@as(u64, self.retries) << 16) |
            (@as(u64, self.attempt) << 24) | (@as(u64, @intFromEnum(self.reason)) << 32) | (@as(u64, self.slots) << 40) |
            (@as(u64, self.pages) << 48) | (@as(u64, @intFromBool(self.verified)) << 56);
    }
    pub fn valid(self: Snapshot) bool {
        if (self.profile_id == 2 and (!@import("snapshot.zig").validRef(.{ .issuer = self.input_issuer, .token = self.input }) or
            self.input_length > 128 or self.newlines > self.input_length or (self.state != .completed and self.newlines != 0))) return false;
        if (tokenSlot(self.token) == null or tokenIssuer(self.token) != self.issuer or (self.profile_id != profile and self.profile_id != 2) or self.requester == 0 or self.issuer == 0 or
            self.instance == 0 or self.endpoint == 0 or self.retries > 1 or self.attempt > 2 or self.slots > 1 or self.pages > 2) return false;
        switch (self.state) {
            .free => return false,
            .offered => if (self.attempt != 0 or self.rpc != 0 or self.retries != 0 or self.verified or self.result != 0 or self.reason != .ok or self.slots != 1 or self.pages != 2) return false,
            .running, .recovering => if (self.attempt != self.retries + 1 or self.rpc == 0 or self.verified or self.result != 0 or self.reason != .ok or self.slots != 1 or self.pages != 2) return false,
            .completed => if (!self.verified or (self.profile_id == profile and self.result != calculate(self.input)) or self.attempt != self.retries + 1 or self.rpc == 0 or self.reason != .ok or self.slots != 0 or self.pages != 0) return false,
            .cancelled => if (self.verified or self.result != 0 or self.reason != .cancelled or self.slots != 0 or self.pages != 0) return false,
            .failed => if (self.verified or self.result != 0 or self.reason == .ok) return false,
        }
        return true;
    }
    pub fn messages(self: Snapshot, id: u64, command: Command) [snapshot_parts]abi.Message {
        const fields = [_]u64{ self.flags(), self.input, self.requester, self.issuer, self.instance, self.endpoint, self.rpc, self.result };
        var messages_array: [snapshot_parts]abi.Message = undefined;
        for (fields, 0..) |field, part| messages_array[part] = encode(reply_operation, .{ .id = id, .command = command, .kind = .snapshot, .detail = @intCast(part), .token = self.token, .data = field });
        return messages_array;
    }
};

// A bounded, ordered snapshot is useful only once all eight matching packets arrive.
pub const Collector = struct {
    issuer: u64,
    requester: u64,
    id: u64,
    command: Command,
    token: u64 = 0,
    count: u8 = 0,
    fields: [snapshot_parts]u64 = [_]u64{0} ** snapshot_parts,
    pub fn push(self: *Collector, message: *const abi.Message) bool {
        const packet = decode(message, self.issuer, reply_operation) orelse return false;
        if (packet.kind != .snapshot or packet.id != self.id or packet.command != self.command or packet.detail != self.count or
            packet.detail >= snapshot_parts or tokenSlot(packet.token) == null or (self.token != 0 and packet.token != self.token)) return false;
        self.token = packet.token;
        self.fields[self.count] = packet.data;
        self.count += 1;
        return true;
    }
    // Legacy callers require the complete original scalar profile. A byte
    // caller must explicitly provide both extension fields before validation.
    pub fn take(self: *const Collector) ?Snapshot {
        return self.takeWith(profile, 0, 0, 0);
    }
    pub fn takeAnalysis(self: *const Collector, input_issuer: u64, input_length: u16, newlines: u16) ?Snapshot {
        return self.takeWith(2, input_issuer, input_length, newlines);
    }
    fn takeWith(self: *const Collector, expected_profile: u8, input_issuer: u64, input_length: u16, newlines: u16) ?Snapshot {
        if (self.count != snapshot_parts) return null;
        const flags = self.fields[0];
        const state_byte: u8 = @truncate(flags);
        const reason_byte: u8 = @truncate(flags >> 32);
        if (flags >> 57 != 0 or state_byte > @intFromEnum(State.failed) or reason_byte > @intFromEnum(Reason.rebind)) return null;
        const snapshot: Snapshot = .{ .token = self.token, .state = @enumFromInt(state_byte), .profile_id = @truncate(flags >> 8), .retries = @truncate(flags >> 16), .attempt = @truncate(flags >> 24), .reason = @enumFromInt(reason_byte), .slots = @truncate(flags >> 40), .pages = @truncate(flags >> 48), .verified = ((flags >> 56) & 1) != 0, .input = self.fields[1], .requester = self.fields[2], .issuer = self.fields[3], .instance = self.fields[4], .endpoint = self.fields[5], .rpc = self.fields[6], .result = self.fields[7], .input_issuer = input_issuer, .input_length = input_length, .newlines = newlines };
        if (snapshot.profile_id != expected_profile or snapshot.issuer != self.issuer or snapshot.requester != self.requester or !snapshot.valid()) return null;
        return snapshot;
    }
};

pub const Worker = struct {
    parent: u64,
    last_rpc: u64 = 0,
    pub fn accept(self: *Worker, message: *const abi.Message) ?Packet {
        const packet = decodeWork(message, self.parent, request_operation) orelse return null;
        if (tokenIssuer(packet.token) != self.parent or packet.id <= self.last_rpc) return null;
        self.last_rpc = packet.id;
        return packet;
    }
};
