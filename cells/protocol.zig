pub const abi = @import("abi.zig");
pub const file_path = "/hello";
pub const file_data = "Zeal survives.";

pub const CapabilityOffer = struct {
    phase: u64,
    handle: u64,
    parent: u64,
};

fn putWord(payload: *[abi.payload_size]u8, index: usize, value: u64) void {
    for (0..8) |byte| payload[index + byte] = @truncate(value >> @intCast(byte * 8));
}

fn getWord(payload: *const [abi.payload_size]u8, index: usize) u64 {
    var value: u64 = 0;
    for (0..8) |byte| value |= @as(u64, payload[index + byte]) << @intCast(byte * 8);
    return value;
}

pub fn capabilityMessage(operation: abi.Operation, offer: CapabilityOffer) abi.Message {
    var message = abi.Message.empty(operation);
    message.length = 24;
    putWord(&message.payload, 0, offer.phase);
    putWord(&message.payload, 8, offer.handle);
    putWord(&message.payload, 16, offer.parent);
    return message;
}

pub fn capabilityOffer(message: *const abi.Message, sender: u64, operation: abi.Operation) ?CapabilityOffer {
    if (sender == 0 or message.sender != sender or message.operation != @intFromEnum(operation) or
        message.length != 24) return null;
    const offer: CapabilityOffer = .{
        .phase = getWord(&message.payload, 0),
        .handle = getWord(&message.payload, 8),
        .parent = getWord(&message.payload, 16),
    };
    if ((offer.phase != 1 and offer.phase != 2) or offer.handle == 0 or offer.parent == 0) return null;
    return offer;
}

pub fn payloadEquals(message: *const abi.Message, expected: []const u8) bool {
    if (message.length != expected.len or expected.len > abi.payload_size) return false;
    for (expected, 0..) |value, index| {
        if (message.payload[index] != value) return false;
    }
    return true;
}

pub fn fileRequest() abi.Message {
    var request = abi.Message.empty(.file_read);
    request.length = file_path.len;
    for (file_path, 0..) |value, index| request.payload[index] = value;
    return request;
}

pub fn blockRequest() abi.Message {
    var request = abi.Message.empty(.read);
    request.length = 8;
    return request;
}

pub fn validBlockRequest(request: *const abi.Message, filesystem: u64) bool {
    if (filesystem == 0 or request.sender != filesystem or
        request.operation != @intFromEnum(abi.Operation.read) or request.length != 8) return false;
    for (request.payload[0..8]) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

pub fn dataReply(operation: abi.Operation) abi.Message {
    var reply = abi.Message.empty(operation);
    reply.length = file_data.len;
    for (file_data, 0..) |value, index| reply.payload[index] = value;
    return reply;
}

pub fn validReply(reply: *const abi.Message, sender: u64, operation: abi.Operation) bool {
    return sender != 0 and reply.sender == sender and
        reply.operation == @intFromEnum(operation) and payloadEquals(reply, file_data);
}

pub const Filesystem = struct {
    client: u64 = 0,
    block: u64 = 0,
    sent: bool = false,
    ready: bool = false,

    pub fn rebindBlock(self: *Filesystem, block: u64) void {
        if (self.block == block) return;
        self.block = block;
        self.sent = false;
        self.ready = false;
    }

    pub fn rebindClient(self: *Filesystem, client: u64) void {
        if (self.client != 0 and self.client != client) {
            self.client = 0;
            self.sent = false;
            self.ready = false;
        }
    }

    pub fn acceptRequest(self: *Filesystem, incoming: *const abi.Message, client: u64) bool {
        if (self.client != 0 or client == 0 or incoming.sender != client or
            incoming.operation != @intFromEnum(abi.Operation.file_read) or
            !payloadEquals(incoming, file_path)) return false;
        self.client = client;
        self.sent = false;
        self.ready = false;
        return true;
    }

    pub fn request(self: *const Filesystem) ?abi.Message {
        if (self.client == 0 or self.block == 0 or self.sent) return null;
        return blockRequest();
    }

    pub fn requestSent(self: *Filesystem) void {
        if (self.client != 0 and self.block != 0) self.sent = true;
    }

    pub fn acceptReply(self: *Filesystem, incoming: *const abi.Message) bool {
        if (self.client == 0 or !self.sent or self.ready or
            !validReply(incoming, self.block, .read_reply)) return false;
        self.ready = true;
        return true;
    }

    pub fn reply(self: *const Filesystem) ?abi.Message {
        if (!self.ready) return null;
        return dataReply(.file_reply);
    }

    pub fn replySent(self: *Filesystem) void {
        self.client = 0;
        self.sent = false;
        self.ready = false;
    }
};

pub const Client = struct {
    filesystem: u64 = 0,
    pending: bool = false,

    pub fn rebind(self: *Client, filesystem: u64) void {
        if (self.filesystem == filesystem) return;
        self.filesystem = filesystem;
        self.pending = false;
    }

    pub fn request(self: *const Client) ?abi.Message {
        if (self.filesystem == 0 or self.pending) return null;
        return fileRequest();
    }

    pub fn requestSent(self: *Client) void {
        if (self.filesystem != 0) self.pending = true;
    }

    pub fn acceptReply(self: *Client, reply: *const abi.Message) bool {
        if (!self.pending or !validReply(reply, self.filesystem, .file_reply)) return false;
        self.pending = false;
        return true;
    }
};

const testing = @import("std").testing;

fn delivered(message: abi.Message, sender: u64) abi.Message {
    var copy = message;
    copy.sender = sender;
    return copy;
}

test "wire layout and constants match the version two C contract" {
    try testing.expectEqual(@as(usize, 48), @sizeOf(abi.Message));
    try testing.expectEqual(@as(usize, 8), @alignOf(abi.Message));
    try testing.expectEqual(@as(usize, 16), @offsetOf(abi.Message, "payload"));
    try testing.expectEqual(@as(usize, 24), @sizeOf(abi.BootInfo));
    try testing.expectEqual(@as(u64, 6), @intFromEnum(abi.Call.exit));
    try testing.expectEqual(@as(i64, -5), @intFromEnum(abi.Error.bad_address));
    try testing.expectEqual(@as(usize, 24), @sizeOf(abi.DelegateRequest));
    try testing.expectEqual(@as(usize, 32), @sizeOf(abi.CapabilityInfo));
    try testing.expectEqual(@as(usize, 24), @offsetOf(abi.CapabilityInfo, "parent"));
    try testing.expectEqual(@as(u64, 7), @intFromEnum(abi.Call.find));
    try testing.expectEqual(@as(u64, 10), @intFromEnum(abi.Call.revoke));
    try testing.expectEqual(@as(u32, 4), abi.right(.file_read));
    try testing.expectEqual(@as(u32, 32), abi.right(.cap_ack));
    try testing.expectEqual(@as(i64, -7), @intFromEnum(abi.Error.no_space));
}

test "capability handoff authenticates identities and bounded wire fields" {
    const original = delivered(capabilityMessage(.cap_offer, .{
        .phase = 1, .handle = 0x109, .parent = 0x104,
    }), 0x102);
    const offer = capabilityOffer(&original, 0x102, .cap_offer).?;
    try testing.expectEqual(@as(u64, 1), offer.phase);
    try testing.expectEqual(@as(u64, 0x109), offer.handle);
    try testing.expectEqual(@as(u64, 0x104), offer.parent);
    try testing.expect(capabilityOffer(&original, 0, .cap_offer) == null);
    try testing.expect(capabilityOffer(&original, 0x202, .cap_offer) == null);
    try testing.expect(capabilityOffer(&original, 0x102, .cap_ack) == null);
    for ([_]u32{ 0, 1, 23, 25, 32, 33, 0xffffffff }) |length| {
        var malformed = original;
        malformed.length = length;
        try testing.expect(capabilityOffer(&malformed, 0x102, .cap_offer) == null);
    }
    for ([_]u64{ 0, 3, 0xffffffffffffffff }) |phase| {
        const malformed = delivered(capabilityMessage(.cap_offer, .{
            .phase = phase, .handle = 1, .parent = 2,
        }), 0x102);
        try testing.expect(capabilityOffer(&malformed, 0x102, .cap_offer) == null);
    }
    for (0..2) |which| {
        const malformed = delivered(capabilityMessage(.cap_offer, .{
            .phase = 1, .handle = if (which == 0) 0 else 1,
            .parent = if (which == 1) 0 else 2,
        }), 0x102);
        try testing.expect(capabilityOffer(&malformed, 0x102, .cap_offer) == null);
    }
}

test "RAM block service only exposes sector zero to the current filesystem" {
    const filesystem_handle = 0x102;
    var request = delivered(blockRequest(), filesystem_handle);
    try testing.expect(validBlockRequest(&request, filesystem_handle));
    try testing.expect(!validBlockRequest(&request, 0));
    try testing.expect(!validBlockRequest(&request, 0x202));
    for (0..8) |index| {
        request.payload[index] = 1;
        try testing.expect(!validBlockRequest(&request, filesystem_handle));
        request.payload[index] = 0;
    }
    const lengths = [_]u32{ 0, 1, 7, 9, 32, 33, 0xffffffff };
    for (lengths) |length| {
        request.length = length;
        try testing.expect(!validBlockRequest(&request, filesystem_handle));
    }
    request.length = 8;
    for (0..6) |operation| {
        request.operation = @intCast(operation);
        try testing.expectEqual(operation == 1, validBlockRequest(&request, filesystem_handle));
    }
}

test "file lookup rejects altered paths and malformed lengths without indexing outside payload" {
    const client_handle = 0x103;
    const lengths = [_]u32{ 0, 1, 5, 7, 31, 32, 33, 0x80000000, 0xffffffff };
    for (lengths) |length| {
        var filesystem: Filesystem = .{};
        var request = delivered(fileRequest(), client_handle);
        request.length = length;
        try testing.expect(!filesystem.acceptRequest(&request, client_handle));
        try testing.expectEqual(@as(u64, 0), filesystem.client);
    }
    for (0..file_path.len) |index| {
        var filesystem: Filesystem = .{};
        var request = delivered(fileRequest(), client_handle);
        request.payload[index] ^= 0xff;
        try testing.expect(!filesystem.acceptRequest(&request, client_handle));
    }
    var request = delivered(fileRequest(), client_handle);
    request.payload[file_path.len] = 0xff;
    var filesystem: Filesystem = .{};
    try testing.expect(filesystem.acceptRequest(&request, client_handle));
}

test "filesystem authenticates both request sender and operation" {
    var filesystem: Filesystem = .{};
    var request = delivered(fileRequest(), 0x203);
    try testing.expect(!filesystem.acceptRequest(&request, 0x103));
    request.sender = 0x103;
    try testing.expect(!filesystem.acceptRequest(&request, 0));
    for (0..6) |operation| {
        request.operation = @intCast(operation);
        if (operation == 3) continue;
        try testing.expect(!filesystem.acceptRequest(&request, 0x103));
    }
    request.operation = 3;
    try testing.expect(filesystem.acceptRequest(&request, 0x103));
    try testing.expect(!filesystem.acceptRequest(&request, 0x103));
    try testing.expect(!filesystem.ready);
}

test "unsolicited and corrupt replies never complete a pending file read" {
    var filesystem: Filesystem = .{};
    filesystem.rebindBlock(0x101);
    var reply = delivered(dataReply(.read_reply), 0x101);
    try testing.expect(!filesystem.acceptReply(&reply));
    const request = delivered(fileRequest(), 0x103);
    try testing.expect(filesystem.acceptRequest(&request, 0x103));
    try testing.expect(!filesystem.acceptReply(&reply));
    filesystem.requestSent();
    reply.sender = 0x201;
    try testing.expect(!filesystem.acceptReply(&reply));
    reply.sender = 0x101;
    reply.operation = 4;
    try testing.expect(!filesystem.acceptReply(&reply));
    reply.operation = 2;
    const lengths = [_]u32{ 0, 13, 15, 32, 33, 0xffffffff };
    for (lengths) |length| {
        reply.length = length;
        try testing.expect(!filesystem.acceptReply(&reply));
    }
    reply.length = file_data.len;
    for (0..file_data.len) |index| {
        reply.payload[index] ^= 0x80;
        try testing.expect(!filesystem.acceptReply(&reply));
        reply.payload[index] ^= 0x80;
    }
    try testing.expect(filesystem.acceptReply(&reply));
    try testing.expect(!filesystem.acceptReply(&reply));
}

test "backpressure preserves requests and verified replies until each send succeeds" {
    var filesystem: Filesystem = .{};
    filesystem.rebindBlock(0x101);
    const incoming = delivered(fileRequest(), 0x103);
    try testing.expect(filesystem.acceptRequest(&incoming, 0x103));
    for (0..32) |_| try testing.expect(filesystem.request() != null);
    filesystem.requestSent();
    try testing.expect(filesystem.request() == null);
    const reply = delivered(dataReply(.read_reply), 0x101);
    try testing.expect(filesystem.acceptReply(&reply));
    for (0..32) |_| {
        const outgoing = filesystem.reply().?;
        try testing.expect(payloadEquals(&outgoing, file_data));
        try testing.expectEqual(@as(u64, 0x103), filesystem.client);
    }
    filesystem.replySent();
    try testing.expect(filesystem.reply() == null);
    try testing.expect(filesystem.request() == null);
    try testing.expectEqual(@as(u64, 0), filesystem.client);
}

test "a block restart recovers before send, while awaiting response, and while awaiting client" {
    for (0..3) |phase| {
        var filesystem: Filesystem = .{};
        filesystem.rebindBlock(0x101);
        const incoming = delivered(fileRequest(), 0x103);
        try testing.expect(filesystem.acceptRequest(&incoming, 0x103));
        const old_reply = delivered(dataReply(.read_reply), 0x101);
        if (phase >= 1) filesystem.requestSent();
        if (phase >= 2) try testing.expect(filesystem.acceptReply(&old_reply));
        filesystem.rebindBlock(0);
        try testing.expect(filesystem.request() == null);
        try testing.expect(filesystem.reply() == null);
        filesystem.rebindBlock(0x201);
        try testing.expect(!filesystem.acceptReply(&old_reply));
        try testing.expect(filesystem.request() != null);
        filesystem.requestSent();
        try testing.expect(!filesystem.acceptReply(&old_reply));
        const new_reply = delivered(dataReply(.read_reply), 0x201);
        try testing.expect(filesystem.acceptReply(&new_reply));
        try testing.expect(filesystem.reply() != null);
    }
}

test "provider relookup with the same generation does not discard in-flight work" {
    var filesystem: Filesystem = .{};
    filesystem.rebindBlock(0x101);
    const incoming = delivered(fileRequest(), 0x103);
    try testing.expect(filesystem.acceptRequest(&incoming, 0x103));
    filesystem.requestSent();
    filesystem.rebindBlock(0x101);
    const reply = delivered(dataReply(.read_reply), 0x101);
    try testing.expect(filesystem.acceptReply(&reply));
    filesystem.rebindBlock(0x101);
    try testing.expect(filesystem.reply() != null);
}

test "client replacement cancels a pending or completed response to the old generation" {
    for (0..2) |phase| {
        var filesystem: Filesystem = .{};
        filesystem.rebindBlock(0x101);
        const incoming = delivered(fileRequest(), 0x103);
        try testing.expect(filesystem.acceptRequest(&incoming, 0x103));
        filesystem.requestSent();
        if (phase == 1) {
            const reply = delivered(dataReply(.read_reply), 0x101);
            try testing.expect(filesystem.acceptReply(&reply));
        }
        filesystem.rebindClient(0x203);
        try testing.expectEqual(@as(u64, 0), filesystem.client);
        try testing.expect(filesystem.reply() == null);
        try testing.expect(filesystem.request() == null);
        const replacement = delivered(fileRequest(), 0x203);
        try testing.expect(filesystem.acceptRequest(&replacement, 0x203));
    }
}

test "client rejects unsolicited replies and retries after a filesystem generation changes" {
    var client: Client = .{};
    try testing.expect(client.request() == null);
    client.rebind(0x102);
    const old_reply = delivered(dataReply(.file_reply), 0x102);
    try testing.expect(!client.acceptReply(&old_reply));
    client.requestSent();
    client.rebind(0x102);
    try testing.expect(client.request() == null);
    client.rebind(0);
    try testing.expect(!client.acceptReply(&old_reply));
    client.rebind(0x202);
    try testing.expect(client.request() != null);
    client.requestSent();
    try testing.expect(!client.acceptReply(&old_reply));
    var reply = delivered(dataReply(.file_reply), 0x202);
    reply.payload[0] = 0;
    try testing.expect(!client.acceptReply(&reply));
    reply = delivered(dataReply(.file_reply), 0x202);
    try testing.expect(client.acceptReply(&reply));
    try testing.expect(!client.acceptReply(&reply));
    try testing.expect(client.request() != null);
}

test "deterministic crash campaigns restore complete block to file to client transactions" {
    for (1..1025) |generation| {
        const block: u64 = (generation << 8) | 1;
        const fs: u64 = (generation << 8) | 2;
        const app: u64 = (generation << 8) | 3;
        var filesystem: Filesystem = .{};
        var client: Client = .{};
        filesystem.rebindBlock(block);
        client.rebind(fs);
        const request = delivered(client.request().?, app);
        client.requestSent();
        try testing.expect(filesystem.acceptRequest(&request, app));
        const read = delivered(filesystem.request().?, fs);
        filesystem.requestSent();
        try testing.expect(validBlockRequest(&read, fs));
        const reply = delivered(dataReply(.read_reply), block);
        if (generation % 3 == 0) filesystem.rebindBlock(block + 0x100);
        if (generation % 3 == 0) {
            try testing.expect(!filesystem.acceptReply(&reply));
            try testing.expect(filesystem.request() != null);
            filesystem.requestSent();
        }
        const recovered = delivered(dataReply(.read_reply), filesystem.block);
        try testing.expect(filesystem.acceptReply(&recovered));
        const file_reply = delivered(filesystem.reply().?, fs);
        filesystem.replySent();
        try testing.expect(client.acceptReply(&file_reply));
        try testing.expect(payloadEquals(&file_reply, "Zeal survives."));
    }
}

test "every one-bit mutation of authenticated reply bytes is rejected" {
    const original = delivered(dataReply(.file_reply), 0x102);
    for (0..(16 + file_data.len)) |offset| {
        for (0..8) |bit| {
            var mutated = original;
            const bytes: *[@sizeOf(abi.Message)]u8 = @ptrCast(&mutated);
            bytes[offset] ^= @as(u8, 1) << @intCast(bit);
            try testing.expect(!validReply(&mutated, 0x102, .file_reply));
        }
    }
}
