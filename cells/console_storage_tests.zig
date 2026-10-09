// Console storage tests run the production console client and filesystem
// dispatcher against actual private Block backing through controlled IPC IO.
const std = @import("std");
const testing = std.testing;
const abi = @import("abi.zig");
const storage = @import("storage.zig");
const wire = @import("storage_wire.zig");
const transport = @import("storage_transport.zig");
const runtime = @import("storage_runtime.zig");
const console = @import("console_storage.zig");
const owner: u64 = 0x103;
const filesystem: u64 = 0x102;

fn delivered(message: abi.Message, sender: u64) abi.Message {
    var result = message;
    result.sender = sender;
    return result;
}

const StoreIo = struct {
    block: storage.Block = storage.Block.init(),
    block_endpoint: u64 = 0x101,
    reads: usize = 0,
    writes: usize = 0,
    fail_transfer: bool = false,
    fail_read_at: ?usize = null,

    pub fn refresh(self: *StoreIo, server: *runtime.Server) void {
        _ = server.fs.rebindBlock(self.block_endpoint);
        server.snapshots.invalidateBlock(self.block_endpoint);
    }
    pub fn transfer(self: *StoreIo, server: *runtime.Server, _: u64, operation: abi.Operation, address: u32, count: u32, bytes: []const u8) ?wire.Header {
        if (operation == .block_read) self.reads += 1 else self.writes += 1;
        if (self.fail_transfer or (operation == .block_read and self.fail_read_at == self.reads)) return null;
        var data = [_]u8{0} ** 8;
        const result = if (operation == .block_read) self.block.read(address, count, &data) else self.block.write(address, bytes);
        return .{ .id = server.sequence.take() orelse return null, .handle = 0, .offset = address, .value = result, .data = data };
    }
    pub fn report(_: *StoreIo, _: u64, _: u64, _: u32, _: i32) void {}
};

const Fixture = struct {
    server: runtime.Server = runtime.Server.initAt(1, filesystem),
    store: StoreIo = .{},

    fn init() Fixture {
        var result: Fixture = .{};
        result.store.refresh(&result.server);
        return result;
    }
    fn process(self: *Fixture, message: abi.Message) ?abi.Message {
        const request = delivered(message, owner);
        return delivered(self.server.processWith(&request, &self.store) orelse return null, filesystem);
    }
    fn file(self: *Fixture, name: []const u8, bytes: []const u8) !void {
        const answer = self.process(wire.openRequest(1000, name)).?;
        const opened = wire.decodeReply(&answer, .file_result, filesystem, 1000).?;
        try testing.expectEqual(@as(i32, 0), opened.value);
        var offset: usize = 0;
        while (offset < bytes.len) {
            const count = @min(8, bytes.len - offset);
            const id = 1001 + offset;
            const reply = self.process(wire.request(.file_write, id, opened.handle, @intCast(offset), @intCast(count), bytes[offset..][0..count])).?;
            try testing.expectEqual(@as(i32, @intCast(count)), wire.decodeReply(&reply, .file_result, filesystem, id).?.value);
            offset += count;
        }
        const reply = self.process(wire.request(.file_close, 1200, opened.handle, 0, 0, "")).?;
        try testing.expectEqual(@as(i32, 0), wire.decodeReply(&reply, .file_result, filesystem, 1200).?.value);
    }
};

test "extended open existing is explicit fixed width while legacy create wire remains compatible" {
    for ([_][]const u8{ "/x", "/hello", "/123456789012345" }) |name| {
        const message = delivered(wire.openExistingRequest(0x1020304050607080, name), owner);
        try testing.expectEqual(@as(u32, 32), message.length);
        try testing.expectEqual(@as(u8, @intCast(name.len)), message.payload[24]);
        try testing.expectEqual(@as(u8, 1), message.payload[25]);
        for (message.payload[8 + name.len .. 24]) |byte| try testing.expectEqual(@as(u8, 0), byte);
        for (message.payload[26..32]) |byte| try testing.expectEqual(@as(u8, 0), byte);
        const open = wire.decodeOpen(&message).?;
        try testing.expect(open.existing);
        try testing.expectEqual(@as(u64, 0x1020304050607080), open.id);
        try testing.expectEqualStrings(name, open.name);
        const legacy = delivered(wire.openRequest(9, name), owner);
        try testing.expectEqual(@as(u32, @intCast(8 + name.len)), legacy.length);
        try testing.expect(!wire.decodeOpen(&legacy).?.existing);
        try testing.expectEqualStrings(name, wire.decodeOpen(&legacy).?.name);
    }
    const missing = delivered(wire.reply(.file_result, 1, 0, 0, -9, ""), filesystem);
    try testing.expectEqual(@as(i32, -9), wire.decodeReply(&missing, .file_result, filesystem, 1).?.value);
    const counterfeit = delivered(wire.reply(.file_result, 1, 0, 0, -10, ""), filesystem);
    try testing.expect(wire.decodeReply(&counterfeit, .file_result, filesystem, 1) == null);
}

test "extended open rejects invalid declared name mode padding identity and envelope" {
    const good = delivered(wire.openExistingRequest(1, "/hello"), owner);
    for ([_]u32{ 0, 1, 8, 9, 25, 26, 27, 28, 29, 30, 31, 33, 0xffffffff }) |length| {
        var bad = good;
        bad.length = length;
        try testing.expect(wire.decodeOpen(&bad) == null);
    }
    for ([_]u8{ 0, 1, 17, 32, 255 }) |length| {
        var bad = good;
        bad.payload[24] = length;
        try testing.expect(wire.decodeOpen(&bad) == null);
    }
    for ([_]u8{ 0, 2, 3, 255 }) |mode| {
        var bad = good;
        bad.payload[25] = mode;
        try testing.expect(wire.decodeOpen(&bad) == null);
    }
    for (14..24) |offset| {
        var bad = good;
        bad.payload[offset] = 1;
        try testing.expect(wire.decodeOpen(&bad) == null);
    }
    for (26..32) |offset| {
        var bad = good;
        bad.payload[offset] = 1;
        try testing.expect(wire.decodeOpen(&bad) == null);
    }
    for ([_]u8{ 0, '/', ' ', '\\', 128, 255 }) |byte| {
        var bad = good;
        bad.payload[10] = byte;
        try testing.expect(wire.decodeOpen(&bad) == null);
    }
    var bad = good;
    @memset(bad.payload[0..8], 0);
    try testing.expect(wire.decodeOpen(&bad) == null);
    bad = good;
    bad.sender = 0;
    try testing.expect(wire.decodeOpen(&bad) == null);
    bad = good;
    bad.operation = @intFromEnum(abi.Operation.file_close);
    try testing.expect(wire.decodeOpen(&bad) == null);
    for ([_][]const u8{ "hello", "/", "/a/b", "/1234567890123456", "/bad\x00", "/bad\xff" }) |name| {
        const invalid = delivered(wire.openExistingRequest(1, name), owner);
        try testing.expect(wire.decodeOpen(&invalid) == null);
    }
}

test "missing existing lookup preserves all metadata serial handles and backing while old open creates" {
    var fixture = Fixture.init();
    const before_fs = fixture.server.fs;
    const before_block = fixture.store.block;
    const response = fixture.process(wire.openExistingRequest(1, "/missing")).?;
    const missing = wire.decodeReply(&response, .file_result, filesystem, 1).?;
    try testing.expectEqual(@as(i32, -9), missing.value);
    try testing.expectEqual(@as(u64, 0), missing.handle);
    try testing.expectEqualDeep(before_fs, fixture.server.fs);
    try testing.expectEqualDeep(before_block, fixture.store.block);
    try testing.expectEqual(@as(usize, 0), fixture.store.reads);
    try testing.expectEqual(@as(usize, 0), fixture.store.writes);
    const created = fixture.process(wire.openRequest(2, "/missing")).?;
    const opened = wire.decodeReply(&created, .file_result, filesystem, 2).?;
    try testing.expectEqual(@as(i32, 0), opened.value);
    try testing.expect(opened.handle != 0);
    try testing.expectEqual(@as(usize, 16), fixture.store.writes);
    try testing.expectEqual(@as(u32, 2), fixture.server.fs.next_serial);
    const existing = fixture.process(wire.openExistingRequest(3, "/missing")).?;
    try testing.expect(wire.decodeReply(&existing, .file_result, filesystem, 3).?.handle != opened.handle);
    try testing.expectEqual(@as(usize, 16), fixture.store.writes);
}

test "open transport requires authenticated success handle or zero handle on errors" {
    var sequence: wire.Sequence = .{};
    for (0..4) |kind| {
        var request = transport.Request.init(&sequence, filesystem, .file_result, 0, 0, 0, true).?;
        request.opening = true;
        request.sent(0);
        const valid = kind == 0 or kind == 2;
        const reply = delivered(wire.reply(.file_result, request.id, if (kind == 0 or kind == 3) 123 else 0, 0, if (kind < 2) 0 else -9, ""), filesystem);
        try testing.expectEqual(valid, request.received(filesystem, 0, &reply) != null);
        try testing.expectEqual(if (valid) transport.Phase.complete else transport.Phase.failed, request.phase);
    }
}

const ForgedOpen = enum { zero_handle, error_handle, positive_result };

const ClientIo = struct {
    fixture: Fixture = Fixture.init(),
    current_endpoint: u64 = filesystem,
    pending: ?abi.Message = null,
    sends: usize = 0,
    receives: usize = 0,
    opens: usize = 0,
    reads: usize = 0,
    closes: usize = 0,
    idles: usize = 0,
    chunks: usize = 0,
    previous_id: u64 = 0,
    last_handle: u64 = 0,
    read_offsets: [20]u32 = [_]u32{0} ** 20,
    send_error: i32 = 0,
    error_operation: ?abi.Operation = null,
    again_left: usize = 0,
    receive_error_on: ?usize = null,
    receive_error: i32 = @intFromEnum(abi.Error.timeout),
    unrelated_left: usize = 0,
    forge_sender_once: bool = false,
    forge_identity_once: bool = false,
    restart_on_receive: ?usize = null,
    read_error: i32 = 0,
    close_error: i32 = 0,
    short_read: ?u32 = null,
    forged_open: ?ForgedOpen = null,

    pub fn endpoint(self: *ClientIo) u64 {
        return self.current_endpoint;
    }
    pub fn send(self: *ClientIo, target: u64, message: *const abi.Message, operation: abi.Operation) i32 {
        std.debug.assert(target == self.current_endpoint and message.operation == @intFromEnum(operation));
        self.sends += 1;
        if (self.again_left > 0) {
            self.again_left -= 1;
            return @intFromEnum(abi.Error.again);
        }
        if (self.error_operation == operation and self.send_error != 0) return self.send_error;
        const id = wire.requestId(message);
        std.debug.assert(id > self.previous_id);
        self.previous_id = id;
        switch (operation) {
            .file_open => {
                self.opens += 1;
                std.debug.assert(wire.decodeOpen(&delivered(message.*, owner)).?.existing);
            },
            .file_chunk_read => {
                const parsed = wire.decodeRequest(&delivered(message.*, owner)).?;
                std.debug.assert(self.reads < self.read_offsets.len);
                self.read_offsets[self.reads] = parsed.offset;
                self.reads += 1;
                self.last_handle = parsed.handle;
            },
            .file_close => {
                self.closes += 1;
                self.last_handle = wire.decodeRequest(&delivered(message.*, owner)).?.handle;
            },
            else => unreachable,
        }
        self.pending = self.fixture.process(message.*);
        if (self.pending == null) return @intFromEnum(abi.Error.invalid);
        if (operation == .file_open) {
            if (self.forged_open) |kind| {
                const opened = wire.decodeReply(&self.pending.?, .file_result, filesystem, id).?;
                self.pending = delivered(wire.reply(.file_result, id, if (kind == .zero_handle) 0 else opened.handle, 0, switch (kind) {
                    .zero_handle => 0,
                    .error_handle => -2,
                    .positive_result => 1,
                }, ""), filesystem);
            }
        }
        if (operation == .file_chunk_read) {
            if (self.short_read) |limit| {
                const answer = wire.decodeReply(&self.pending.?, .file_result, filesystem, id).?;
                if (answer.value > limit) {
                    self.pending = delivered(wire.reply(.file_result, id, answer.handle, answer.offset, @intCast(limit), answer.data[0..limit]), filesystem);
                }
            }
        }
        if (operation == .file_chunk_read and self.read_error != 0) {
            const request = wire.decodeRequest(&delivered(message.*, owner)).?;
            self.pending = delivered(wire.reply(.file_result, id, request.handle, request.offset, self.read_error, ""), filesystem);
        }
        if (operation == .file_close and self.close_error != 0) {
            const request = wire.decodeRequest(&delivered(message.*, owner)).?;
            self.pending = delivered(wire.reply(.file_result, id, request.handle, 0, self.close_error, ""), filesystem);
        }
        return 0;
    }
    pub fn receive(self: *ClientIo, message: *abi.Message, ticks: u64) i32 {
        std.debug.assert(ticks == transport.receive_ticks);
        self.receives += 1;
        if (self.restart_on_receive == self.receives) self.current_endpoint = 0x202;
        if (self.receive_error_on == self.receives) return self.receive_error;
        if (self.unrelated_left > 0) {
            self.unrelated_left -= 1;
            message.* = delivered(wire.reply(.file_result, 9000, 0, 0, 0, ""), 0x104);
            return 0;
        }
        const reply = self.pending orelse return @intFromEnum(abi.Error.timeout);
        if (self.forge_sender_once) {
            self.forge_sender_once = false;
            message.* = reply;
            message.sender = 0x202;
            return 0;
        }
        if (self.forge_identity_once) {
            self.forge_identity_once = false;
            message.* = reply;
            message.payload[0] +%= 1;
            return 0;
        }
        message.* = reply;
        self.pending = null;
        return 0;
    }
    pub fn idle(self: *ClientIo) void {
        self.idles += 1;
    }
    pub fn chunk(self: *ClientIo, id: u64, _: *const [8]u8) void {
        std.debug.assert(id == self.previous_id);
        self.chunks += 1;
    }
};

fn openHandleCount(io: *const ClientIo) usize {
    var count: usize = 0;
    for (io.fixture.server.fs.handles) |handle| if (handle.used) {
        count += 1;
    };
    return count;
}

test "production cat client reads actual hello backing in bounded chunks EOF and closes" {
    var io: ClientIo = .{};
    var client: console.Client = .{};
    var buffer = [_]u8{0xa5} ** 128;
    const result = client.read("/hello", &buffer, &io);
    try testing.expectEqual(@as(i32, 0), result.status);
    try testing.expectEqual(@as(i32, 0), result.close_status);
    try testing.expectEqual(@as(u32, storage.hello.len), result.length);
    try testing.expectEqualStrings(storage.hello, buffer[0..result.length]);
    try testing.expectEqual(@as(usize, 1), io.opens);
    try testing.expectEqual(@as(usize, 3), io.reads);
    try testing.expectEqualSlices(u32, &.{ 0, 8, 14 }, io.read_offsets[0..io.reads]);
    try testing.expectEqual(@as(usize, 3), io.fixture.store.reads);
    try testing.expectEqual(@as(usize, 0), io.fixture.store.writes);
    try testing.expectEqual(@as(usize, 1), io.closes);
    try testing.expectEqual(@as(usize, 0), openHandleCount(&io));
    try testing.expectEqual(@as(usize, 2), io.chunks);
    for (buffer[result.length..]) |byte| try testing.expectEqual(@as(u8, 0xa5), byte);
    const old_handle = io.last_handle;
    const again = client.read("/hello", &buffer, &io);
    try testing.expectEqual(@as(i32, 0), again.status);
    try testing.expect(old_handle != io.last_handle);
    try testing.expectEqual(storage.Status.stale, io.fixture.server.fs.close(owner, old_handle));
}

test "production cat client covers binary empty and exact 128 byte extent with real block reads" {
    var source: [128]u8 = undefined;
    for (&source, 0..) |*byte, index| byte.* = @truncate(index * 37);
    for ([_]usize{ 0, 1, 7, 8, 9, 127, 128 }) |length| {
        var io: ClientIo = .{};
        try io.fixture.file("/binary", source[0..length]);
        const old_reads = io.fixture.store.reads;
        const old_writes = io.fixture.store.writes;
        var client: console.Client = .{};
        var buffer = [_]u8{0xa5} ** 128;
        const result = client.read("/binary", &buffer, &io);
        try testing.expectEqual(@as(i32, 0), result.status);
        try testing.expectEqual(@as(i32, 0), result.close_status);
        try testing.expectEqual(@as(u32, @intCast(length)), result.length);
        try testing.expectEqualSlices(u8, source[0..length], buffer[0..result.length]);
        try testing.expectEqual(@as(usize, 0), openHandleCount(&io));
        try testing.expectEqual(old_writes, io.fixture.store.writes);
        try testing.expectEqual(io.reads, io.fixture.store.reads - old_reads);
        try testing.expectEqual(@as(u32, @intCast(length)), io.read_offsets[io.reads - 1]);
        try testing.expectEqual((length + 7) / 8 + 1, io.reads);
        try testing.expectEqual((length + 7) / 8, io.chunks);
    }
}

test "missing or malformed cat never creates writes reads closes or overwrites destination" {
    for ([_][]const u8{ "/missing", "hello", "/", "/a/b", "/1234567890123456" }) |name| {
        var io: ClientIo = .{};
        var client: console.Client = .{};
        const before = io.fixture.server.fs;
        var buffer = [_]u8{0xa5} ** 128;
        const result = client.read(name, &buffer, &io);
        try testing.expectEqual(if (std.mem.eql(u8, name, "/missing")) @as(i32, -9) else @as(i32, -1), result.status);
        try testing.expectEqual(@as(u32, 0), result.length);
        try testing.expectEqualDeep(before, io.fixture.server.fs);
        try testing.expectEqual(@as(usize, 0), io.reads);
        try testing.expectEqual(@as(usize, 0), io.closes);
        try testing.expectEqual(@as(usize, 0), io.fixture.store.writes);
        for (buffer) |byte| try testing.expectEqual(@as(u8, 0xa5), byte);
    }
}

test "denied stale missing service and timeout are bounded without accepted-request retry" {
    for ([_]i32{ -2, -3 }) |failure| {
        var io: ClientIo = .{ .error_operation = .file_open, .send_error = failure };
        var client: console.Client = .{};
        var buffer: [128]u8 = undefined;
        const result = client.read("/hello", &buffer, &io);
        try testing.expectEqual(failure, result.status);
        try testing.expectEqual(@as(usize, 1), io.sends);
        try testing.expectEqual(@as(usize, 0), io.receives);
        try testing.expectEqual(@as(usize, 0), io.closes);
    }
    var absent: ClientIo = .{ .current_endpoint = 0 };
    var client: console.Client = .{};
    var buffer: [128]u8 = undefined;
    const absent_result = client.read("/hello", &buffer, &absent);
    try testing.expect(absent_result.status != 0);
    try testing.expectEqual(@as(usize, 0), absent.sends);
    var timeout: ClientIo = .{ .receive_error_on = 1 };
    const timed_out = client.read("/hello", &buffer, &timeout);
    try testing.expectEqual(@as(i32, -8), timed_out.status);
    try testing.expectEqual(@as(usize, 1), timeout.sends);
    try testing.expectEqual(@as(usize, 1), timeout.receives);
    try testing.expectEqual(@as(usize, 0), timeout.closes);
}

test "four send attempts and eight unrelated receives bound console work and yield" {
    var client: console.Client = .{};
    var buffer: [128]u8 = undefined;
    var pressure: ClientIo = .{ .again_left = 4 };
    const send_result = client.read("/hello", &buffer, &pressure);
    try testing.expectEqual(@as(i32, -8), send_result.status);
    try testing.expectEqual(@as(usize, 4), pressure.sends);
    try testing.expectEqual(@as(usize, 0), pressure.receives);
    try testing.expect(pressure.idles >= 3 and pressure.idles <= 4);
    var traffic: ClientIo = .{ .unrelated_left = 100 };
    const receive_result = client.read("/hello", &buffer, &traffic);
    try testing.expectEqual(@as(i32, -8), receive_result.status);
    try testing.expectEqual(@as(usize, 1), traffic.sends);
    try testing.expectEqual(@as(usize, 8), traffic.receives);
    try testing.expectEqual(@as(usize, 0), traffic.closes);
    try testing.expect(traffic.idles <= 8);
}

test "counterfeit sender and request identity never supply bytes but valid subsequent replies work" {
    for ([_]bool{ false, true }) |wrong_sender| {
        var io: ClientIo = .{ .forge_sender_once = wrong_sender, .forge_identity_once = !wrong_sender };
        var client: console.Client = .{};
        var buffer: [128]u8 = undefined;
        const result = client.read("/hello", &buffer, &io);
        try testing.expectEqual(@as(i32, 0), result.status);
        try testing.expectEqualStrings(storage.hello, buffer[0..result.length]);
        try testing.expectEqual(@as(usize, 5), io.sends);
        try testing.expectEqual(@as(usize, 6), io.receives);
        try testing.expectEqual(@as(usize, 0), openHandleCount(&io));
    }
}

test "read failure and dependency timeout attempt exact handle close then next cat recovers" {
    for ([_]i32{ -2, -3, -8 }) |failure| {
        var io: ClientIo = .{ .read_error = failure };
        var client: console.Client = .{};
        var buffer = [_]u8{0xa5} ** 128;
        const result = client.read("/hello", &buffer, &io);
        try testing.expectEqual(failure, result.status);
        try testing.expectEqual(@as(i32, 0), result.close_status);
        try testing.expectEqual(@as(u32, 0), result.length);
        try testing.expectEqual(@as(usize, 1), io.reads);
        try testing.expectEqual(@as(usize, 1), io.closes);
        try testing.expectEqual(@as(usize, 0), openHandleCount(&io));
        io.read_error = 0;
        const recovered = client.read("/hello", &buffer, &io);
        try testing.expectEqual(@as(i32, 0), recovered.status);
        try testing.expectEqualStrings(storage.hello, buffer[0..recovered.length]);
    }
    var io: ClientIo = .{ .receive_error_on = 2 };
    var client: console.Client = .{};
    var buffer: [128]u8 = undefined;
    const result = client.read("/hello", &buffer, &io);
    try testing.expectEqual(@as(i32, -8), result.status);
    try testing.expectEqual(@as(usize, 1), io.closes);
    try testing.expectEqual(@as(usize, 3), io.sends);
    try testing.expectEqual(@as(usize, 0), openHandleCount(&io));
}

test "close failures remain visible and sequence exhaustion cannot reuse request identities" {
    var io: ClientIo = .{ .close_error = -3 };
    var client: console.Client = .{};
    var buffer: [128]u8 = undefined;
    const result = client.read("/hello", &buffer, &io);
    try testing.expectEqual(@as(i32, -3), result.close_status);
    try testing.expectEqual(@as(usize, 1), io.closes);
    var exhausted: console.Client = .{ .sequence = .{ .next = 0 } };
    var unused: ClientIo = .{};
    const failure = exhausted.read("/hello", &buffer, &unused);
    try testing.expect(failure.status != 0);
    try testing.expectEqual(@as(usize, 0), unused.sends);
}

test "filesystem endpoint change rejects predecessor reply before copying bytes" {
    for ([_]usize{ 1, 2 }) |restart_at| {
        var io: ClientIo = .{ .restart_on_receive = restart_at };
        var client: console.Client = .{};
        var buffer = [_]u8{0xa5} ** 128;
        const result = client.read("/hello", &buffer, &io);
        try testing.expectEqual(@as(i32, -3), result.status);
        try testing.expectEqual(@as(u32, 0), result.length);
        for (buffer) |byte| try testing.expectEqual(@as(u8, 0xa5), byte);
        try testing.expectEqual(@as(usize, restart_at), io.receives);
    }
}

test "malicious short replies exhaust finite read budget with error then close without overflowing destination" {
    var source: [128]u8 = undefined;
    for (&source, 0..) |*byte, index| byte.* = @intCast(index);
    var io: ClientIo = .{ .short_read = 1 };
    try io.fixture.file("/binary", &source);
    const before_block = io.fixture.store.block;
    const before_files = io.fixture.server.fs.files;
    var client: console.Client = .{};
    var buffer = [_]u8{0xa5} ** 128;
    const result = client.read("/binary", &buffer, &io);
    try testing.expectEqual(@as(i32, -6), result.status);
    try testing.expectEqual(@as(u32, 17), result.length);
    try testing.expectEqual(@as(i32, 0), result.close_status);
    try testing.expectEqual(@as(usize, 17), io.reads);
    try testing.expectEqual(@as(usize, 1), io.closes);
    try testing.expectEqual(@as(usize, 0), openHandleCount(&io));
    try testing.expectEqualSlices(u8, source[0..17], buffer[0..17]);
    for (buffer[17..]) |byte| try testing.expectEqual(@as(u8, 0xa5), byte);
    for (io.read_offsets[0..io.reads], 0..) |offset, index| try testing.expectEqual(@as(u32, @intCast(index)), offset);
    try testing.expectEqualDeep(before_block, io.fixture.store.block);
    try testing.expectEqualDeep(before_files, io.fixture.server.fs.files);
}

test "forged successful open without handle error with handle and positive open result never begin reads" {
    for ([_]ForgedOpen{ .zero_handle, .error_handle, .positive_result }) |kind| {
        var io: ClientIo = .{ .forged_open = kind };
        var client: console.Client = .{};
        var buffer = [_]u8{0xa5} ** 128;
        const before_block = io.fixture.store.block;
        const before_files = io.fixture.server.fs.files;
        const result = client.read("/hello", &buffer, &io);
        try testing.expectEqual(@as(i32, -8), result.status);
        try testing.expectEqual(@as(u32, 0), result.length);
        try testing.expectEqual(@as(usize, 1), io.sends);
        try testing.expectEqual(@as(usize, 1), io.receives);
        try testing.expectEqual(@as(usize, 0), io.reads);
        try testing.expectEqual(@as(usize, 0), io.closes);
        for (buffer) |byte| try testing.expectEqual(@as(u8, 0xa5), byte);
        try testing.expectEqualDeep(before_block, io.fixture.store.block);
        try testing.expectEqualDeep(before_files, io.fixture.server.fs.files);
    }
}

test "actual block service failure after accepted prefix reports timeout closes and preserves remaining destination" {
    var io: ClientIo = .{};
    io.fixture.store.fail_read_at = 2;
    const before_block = io.fixture.store.block;
    const before_files = io.fixture.server.fs.files;
    var client: console.Client = .{};
    var buffer = [_]u8{0xa5} ** 128;
    const result = client.read("/hello", &buffer, &io);
    try testing.expectEqual(@as(i32, -8), result.status);
    try testing.expectEqual(@as(u32, 8), result.length);
    try testing.expectEqualStrings(storage.hello[0..8], buffer[0..8]);
    for (buffer[8..]) |byte| try testing.expectEqual(@as(u8, 0xa5), byte);
    try testing.expectEqual(@as(i32, 0), result.close_status);
    try testing.expectEqual(@as(usize, 1), io.closes);
    try testing.expectEqual(@as(usize, 0), openHandleCount(&io));
    try testing.expectEqualDeep(before_block, io.fixture.store.block);
    try testing.expectEqualDeep(before_files, io.fixture.server.fs.files);
}

test "denied close remains observable without changing file data and cannot be silently retried" {
    var io: ClientIo = .{ .error_operation = .file_close, .send_error = -2 };
    const before_block = io.fixture.store.block;
    const before_files = io.fixture.server.fs.files;
    var client: console.Client = .{};
    var buffer: [128]u8 = undefined;
    const result = client.read("/hello", &buffer, &io);
    try testing.expectEqual(@as(i32, 0), result.status);
    try testing.expectEqual(@as(i32, -2), result.close_status);
    try testing.expectEqualStrings(storage.hello, buffer[0..result.length]);
    try testing.expectEqual(@as(usize, 5), io.sends);
    try testing.expectEqual(@as(usize, 1), openHandleCount(&io));
    try testing.expectEqualDeep(before_block, io.fixture.store.block);
    try testing.expectEqualDeep(before_files, io.fixture.server.fs.files);
}
