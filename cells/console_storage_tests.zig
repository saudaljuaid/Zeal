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
    fail_write_at: ?usize = null,

    pub fn refresh(self: *StoreIo, server: *runtime.Server) void {
        _ = server.fs.rebindBlock(self.block_endpoint);
        server.snapshots.invalidateBlock(self.block_endpoint);
    }
    pub fn transfer(self: *StoreIo, server: *runtime.Server, _: u64, operation: abi.Operation, address: u32, count: u32, bytes: []const u8) ?wire.Header {
        if (operation == .block_read) self.reads += 1 else self.writes += 1;
        if (self.fail_transfer or (operation == .block_read and self.fail_read_at == self.reads) or
            (operation == .block_write and self.fail_write_at == self.writes)) return null;
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
        return self.processOwner(message, owner);
    }
    fn processOwner(self: *Fixture, message: abi.Message, sender: u64) ?abi.Message {
        const request = delivered(message, sender);
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
const ForgedWrite = enum { short_count, data, handle, offset };
const Interleave = enum { none, grow, shrink };

const ClientIo = struct {
    fixture: Fixture = Fixture.init(),
    current_endpoint: u64 = filesystem,
    pending: ?abi.Message = null,
    sends: usize = 0,
    receives: usize = 0,
    opens: usize = 0,
    creates: usize = 0,
    reads: usize = 0,
    write_requests: usize = 0,
    truncates: usize = 0,
    lists: usize = 0,
    closes: usize = 0,
    idles: usize = 0,
    chunks: usize = 0,
    previous_id: u64 = 0,
    last_handle: u64 = 0,
    read_offsets: [256]u32 = [_]u32{0} ** 256,
    write_offsets: [128]u32 = [_]u32{0} ** 128,
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
    forged_write: ?ForgedWrite = null,
    interleave: Interleave = .none,
    late_reply: ?abi.Message = null,
    retain_late_reply: bool = false,
    forge_list_index_once: bool = false,

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
                if (!wire.decodeOpen(&delivered(message.*, owner)).?.existing) self.creates += 1;
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
            .file_write => {
                const parsed = wire.decodeRequest(&delivered(message.*, owner)).?;
                std.debug.assert(self.write_requests < self.write_offsets.len);
                self.write_offsets[self.write_requests] = parsed.offset;
                self.write_requests += 1;
                self.last_handle = parsed.handle;
                if (self.interleave != .none) {
                    const changing = self.interleave;
                    self.interleave = .none;
                    const other_owner: u64 = 0x104;
                    const opening = self.fixture.processOwner(wire.openExistingRequest(1, "/note"), other_owner).?;
                    const other = wire.decodeReply(&opening, .file_result, filesystem, 1).?.handle;
                    const concurrent = self.fixture.processOwner(if (changing == .grow)
                        wire.request(.file_write, 2, other, parsed.offset, 2, "XY")
                    else
                        wire.request(.file_truncate, 2, other, 0, 0, ""), other_owner).?;
                    std.debug.assert(wire.decodeReply(&concurrent, .file_result, filesystem, 2).?.value == if (changing == .grow) @as(i32, 2) else @as(i32, 0));
                    _ = self.fixture.processOwner(wire.request(.file_close, 3, other, 0, 0, ""), other_owner).?;
                }
            },
            .file_truncate => {
                self.truncates += 1;
                self.last_handle = wire.decodeRequest(&delivered(message.*, owner)).?.handle;
            },
            .file_list => self.lists += 1,
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
        if (operation == .file_write) if (self.forged_write) |kind| {
            self.forged_write = null;
            const parsed = wire.decodeRequest(&delivered(message.*, owner)).?;
            self.pending = delivered(wire.reply(.file_result, id, parsed.handle + @as(u64, if (kind == .handle) 1 else 0), parsed.offset + @as(u32, if (kind == .offset) 1 else 0), parsed.value - @as(i32, if (kind == .short_count) 1 else 0), if (kind == .data) "x" else ""), filesystem);
        };
        return 0;
    }
    pub fn receive(self: *ClientIo, message: *abi.Message, ticks: u64) i32 {
        std.debug.assert(ticks == transport.receive_ticks);
        self.receives += 1;
        if (self.restart_on_receive == self.receives) self.current_endpoint = 0x202;
        if (self.receive_error_on == self.receives) {
            if (self.retain_late_reply) self.late_reply = self.pending;
            return self.receive_error;
        }
        if (self.unrelated_left > 0) {
            self.unrelated_left -= 1;
            message.* = delivered(wire.reply(.file_result, 9000, 0, 0, 0, ""), 0x104);
            return 0;
        }
        const reply = self.pending orelse return @intFromEnum(abi.Error.timeout);
        if (self.late_reply) |late| {
            self.late_reply = null;
            message.* = late;
            return 0;
        }
        if (self.forge_list_index_once and self.pending.?.payload[8] < 4) {
            self.forge_list_index_once = false;
            message.* = reply;
            message.payload[8] +%= 1;
            return 0;
        }
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

fn expectContents(io: *ClientIo, client: *console.Client, name: []const u8, expected: []const u8) !void {
    var bytes = [_]u8{0xa5} ** 128;
    const read = client.read(name, &bytes, io);
    try testing.expectEqual(@as(i32, 0), read.status);
    try testing.expectEqual(@as(i32, 0), read.close_status);
    try testing.expectEqual(@as(u32, @intCast(expected.len)), read.length);
    try testing.expectEqualSlices(u8, expected, bytes[0..read.length]);
    for (bytes[read.length..]) |byte| try testing.expectEqual(@as(u8, 0xa5), byte);
}

test "production replacement creates writes actual blocks truncates shorter and empty with exact EOF" {
    var io: ClientIo = .{};
    var client: console.Client = .{};
    try io.fixture.file("/other", "unrelated stays");
    const unrelated = io.fixture.store.block.bytes[128..256].*;
    const full = [_]u8{'F'} ** 128;
    for ([_][]const u8{ "Hello Zeal", "longer replacement with  spaces ", &full, "Hi", "", "again" }) |text| {
        const old_writes = io.fixture.store.writes;
        const result = client.replace("/note", text, &io);
        try testing.expectEqual(@as(i32, 0), result.status);
        try testing.expectEqual(@as(u32, @intCast(text.len)), result.length);
        try testing.expectEqual(@as(i32, 0), result.close_status);
        try testing.expect(!result.unknown and !result.open_unknown);
        try testing.expectEqual(@as(usize, 0), openHandleCount(&io));
        try testing.expect(io.fixture.store.writes >= old_writes + (text.len + 7) / 8);
        try expectContents(&io, &client, "/note", text);
        try testing.expectEqualSlices(u8, &unrelated, io.fixture.store.block.bytes[128..256]);
        try testing.expectEqualSlices(u8, storage.hello, io.fixture.store.block.bytes[0..storage.hello.len]);
    }
    try testing.expectEqual(@as(usize, 6), io.truncates);
    try testing.expectEqual(@as(usize, 6), io.creates);
    try testing.expectEqual(@as(u32, 5), io.fixture.server.fs.files[2].length);
}

test "actual EOF append preserves spaces supports empty and grows exactly to 128 bytes" {
    var io: ClientIo = .{};
    var client: console.Client = .{};
    const first = [_]u8{'a'} ** 80;
    const second = [_]u8{'b'} ** 48;
    const created = client.replace("/note", &first, &io);
    try testing.expectEqual(@as(i32, 0), created.status);
    const old_reads = io.reads;
    const appended = client.append("/note", &second, &io);
    try testing.expectEqual(@as(i32, 0), appended.status);
    try testing.expectEqual(@as(u32, 48), appended.length);
    try testing.expectEqual(@as(i32, 0), appended.close_status);
    try testing.expectEqual(@as(usize, 11), io.reads - old_reads);
    try testing.expectEqual(@as(u32, 80), io.write_offsets[10]);
    var expected: [128]u8 = undefined;
    @memcpy(expected[0..80], &first);
    @memcpy(expected[80..], &second);
    try expectContents(&io, &client, "/note", &expected);
    const before = io.fixture.store.block;
    const revision = io.fixture.server.fs.files[1].revision;
    const empty = client.append("/note", "", &io);
    try testing.expectEqual(@as(i32, 0), empty.status);
    try testing.expectEqual(@as(u32, 0), empty.length);
    try testing.expect(!empty.changed and !empty.unknown);
    try testing.expectEqualDeep(before, io.fixture.store.block);
    try testing.expectEqual(revision, io.fixture.server.fs.files[1].revision);
    const short = client.replace("/note", " a  ", &io);
    try testing.expectEqual(@as(i32, 0), short.status);
    const spaced = client.append("/note", " b ", &io);
    try testing.expectEqual(@as(u32, 3), spaced.length);
    try expectContents(&io, &client, "/note", " a   b ");
    try testing.expectEqual(@as(usize, 0), openHandleCount(&io));
}

test "whole payload overflow rejects before creation truncation or any append write prefix" {
    const oversized = [_]u8{'x'} ** 129;
    var io: ClientIo = .{};
    var client: console.Client = .{};
    const before = io.fixture;
    for ([_]bool{ false, true }) |append| {
        const result = if (append) client.append("/note", &oversized, &io) else client.replace("/note", &oversized, &io);
        try testing.expectEqual(@as(i32, -6), result.status);
        try testing.expectEqual(@as(u32, 0), result.length);
        try testing.expectEqualDeep(before, io.fixture);
        try testing.expectEqual(@as(usize, 0), io.sends);
    }
    const initial = [_]u8{'i'} ** 80;
    try testing.expectEqual(@as(i32, 0), client.replace("/note", &initial, &io).status);
    const large = [_]u8{'a'} ** 60;
    const before_block = io.fixture.store.block;
    const before_files = io.fixture.server.fs.files;
    const before_writes = io.fixture.store.writes;
    const before_requests = io.write_requests;
    const result = client.append("/note", &large, &io);
    try testing.expectEqual(@as(i32, -6), result.status);
    try testing.expectEqual(@as(u32, 0), result.length);
    try testing.expect(!result.changed and !result.unknown);
    try testing.expectEqual(before_requests, io.write_requests);
    try testing.expectEqual(before_writes, io.fixture.store.writes);
    try testing.expectEqualDeep(before_block, io.fixture.store.block);
    try testing.expectEqualDeep(before_files, io.fixture.server.fs.files);
    try testing.expectEqual(@as(usize, 0), openHandleCount(&io));
}

test "missing malformed and immutable mutation commands preserve unrelated backing" {
    for ([_][]const u8{ "note", "/", "/a/b", "/1234567890123456" }) |name| {
        var io: ClientIo = .{};
        var client: console.Client = .{};
        const before = io.fixture;
        for ([_]bool{ false, true }) |append| {
            const result = if (append) client.append(name, "data", &io) else client.replace(name, "data", &io);
            try testing.expectEqual(@as(i32, -1), result.status);
            try testing.expectEqualDeep(before, io.fixture);
            try testing.expectEqual(@as(usize, 0), io.sends);
        }
    }
    var missing: ClientIo = .{};
    var client: console.Client = .{};
    const before = missing.fixture;
    try testing.expectEqual(@as(i32, -9), client.append("/missing", "!", &missing).status);
    try testing.expectEqual(@as(i32, -9), client.append("/missing", "", &missing).status);
    try testing.expectEqualDeep(before, missing.fixture);
    for ([_]bool{ false, true }) |append| for ([_][]const u8{ "", "modified" }) |text| {
        var io: ClientIo = .{};
        const block = io.fixture.store.block;
        const files = io.fixture.server.fs.files;
        const result = if (append) client.append("/hello", text, &io) else client.replace("/hello", text, &io);
        try testing.expectEqual(@as(i32, -2), result.status);
        try testing.expectEqual(@as(u32, 0), result.length);
        try testing.expect(!result.changed and !result.unknown);
        try testing.expectEqual(@as(i32, 0), result.close_status);
        try testing.expectEqualDeep(block, io.fixture.store.block);
        try testing.expectEqualDeep(files, io.fixture.server.fs.files);
        try testing.expectEqual(@as(usize, 0), openHandleCount(&io));
    };
}

test "authenticated metadata listing observes actual entries lengths readonly and allocates no handles" {
    var io: ClientIo = .{};
    var client: console.Client = .{};
    try io.fixture.file("/note", "long contents");
    try io.fixture.file("/empty", "");
    const before = io.fixture;
    const listed = client.list(&io);
    try testing.expectEqual(@as(i32, 0), listed.status);
    try testing.expectEqual(@as(usize, 3), listed.length);
    try testing.expectEqualStrings("/hello", listed.entries[0].name[0..listed.entries[0].name_length]);
    try testing.expect(listed.entries[0].readonly);
    try testing.expectEqual(@as(u32, 14), listed.entries[0].length);
    try testing.expectEqualStrings("/note", listed.entries[1].name[0..listed.entries[1].name_length]);
    try testing.expect(!listed.entries[1].readonly);
    try testing.expectEqual(@as(u32, 13), listed.entries[1].length);
    try testing.expectEqual(@as(u32, 0), listed.entries[2].length);
    try testing.expectEqualDeep(before, io.fixture);
    try testing.expectEqual(@as(usize, 4), io.lists);
    try testing.expectEqual(@as(usize, 0), io.opens);
    try testing.expectEqual(@as(usize, 0), openHandleCount(&io));
    try testing.expectEqual(@as(i32, 0), client.replace("/note", "Hi", &io).status);
    const updated = client.list(&io);
    try testing.expectEqual(@as(u32, 2), updated.entries[1].length);
    var forged: ClientIo = .{ .forge_sender_once = true, .forge_list_index_once = true };
    const recovered = client.list(&forged);
    try testing.expectEqual(@as(i32, 0), recovered.status);
    try testing.expectEqual(@as(usize, 6), forged.receives);
}

test "lost mutation acknowledgments report unknown prefix close known handle and next command recovers" {
    for ([_]usize{ 3, 4 }) |lost_at| {
        var io: ClientIo = .{ .receive_error_on = lost_at, .retain_late_reply = true };
        var client: console.Client = .{};
        const result = client.replace("/note", "abcdefghijklmnop", &io);
        try testing.expectEqual(@as(i32, -8), result.status);
        try testing.expectEqual(@as(u32, if (lost_at == 3) 0 else 8), result.length);
        try testing.expect(result.changed and result.unknown and !result.open_unknown);
        try testing.expectEqual(@as(i32, 0), result.close_status);
        try testing.expectEqual(@as(usize, lost_at - 2), io.write_requests);
        try testing.expectEqual(@as(usize, 0), openHandleCount(&io));
        io.receive_error_on = null;
        try expectContents(&io, &client, "/note", "abcdefghijklmnop"[0 .. (lost_at - 2) * 8]);
    }
    var io: ClientIo = .{ .receive_error_on = 1 };
    var client: console.Client = .{};
    const result = client.replace("/note", "data", &io);
    try testing.expect(result.unknown and result.changed and result.open_unknown);
    try testing.expectEqual(@as(u32, 0), result.length);
    try testing.expectEqual(@as(usize, 0), io.closes);
    try testing.expectEqual(@as(usize, 1), openHandleCount(&io));
    io.receive_error_on = null;
    try testing.expectEqual(@as(i32, 0), client.replace("/note", "next", &io).status);
    // The client can close only the later known handle; it neither guesses
    // nor resets resources to erase the genuinely unknown first open.
    try testing.expectEqual(@as(usize, 1), openHandleCount(&io));
}

test "actual block write failure retains acknowledged prefix and exact EOF without old suffix" {
    var io: ClientIo = .{};
    try io.fixture.file("/note", "old old old old old old old");
    io.fixture.store.fail_write_at = io.fixture.store.writes + 2;
    var client: console.Client = .{};
    const result = client.replace("/note", "abcdefghijklmnop", &io);
    try testing.expectEqual(@as(i32, -8), result.status);
    try testing.expectEqual(@as(u32, 8), result.length);
    try testing.expect(result.changed and result.unknown);
    try testing.expectEqual(@as(i32, 0), result.close_status);
    try testing.expectEqual(@as(usize, 0), openHandleCount(&io));
    io.fixture.store.fail_write_at = null;
    try expectContents(&io, &client, "/note", "abcdefgh");
    try testing.expectEqual(@as(i32, 0), client.append("/note", "!", &io).status);
    try expectContents(&io, &client, "/note", "abcdefgh!");
}

test "counterfeit write counts bytes handles offsets never produce false acknowledgments or resend" {
    for ([_]ForgedWrite{ .short_count, .data, .handle, .offset }) |kind| {
        var io: ClientIo = .{ .forged_write = kind };
        var client: console.Client = .{};
        const result = client.replace("/note", "abcdefgh", &io);
        try testing.expectEqual(@as(i32, -8), result.status);
        try testing.expectEqual(@as(u32, 0), result.length);
        try testing.expect(result.unknown and result.changed);
        try testing.expectEqual(@as(usize, 1), io.write_requests);
        try testing.expectEqual(@as(i32, 0), result.close_status);
        try testing.expectEqual(@as(usize, 0), openHandleCount(&io));
        try expectContents(&io, &client, "/note", "abcdefgh");
    }
}

test "mutation queue pressure service replacement and request exhaustion are finite and close failures visible" {
    var pressure: ClientIo = .{ .again_left = 4 };
    var client: console.Client = .{};
    const full = client.replace("/note", "payload", &pressure);
    try testing.expectEqual(@as(i32, -8), full.status);
    try testing.expect(!full.unknown and !full.changed and !full.open_unknown);
    try testing.expectEqual(@as(usize, 4), pressure.sends);
    try testing.expectEqual(@as(usize, 0), pressure.receives);
    try testing.expectEqual(@as(usize, 0), pressure.fixture.store.writes);
    var restarted: ClientIo = .{ .restart_on_receive = 3 };
    const stale = client.replace("/note", "data", &restarted);
    try testing.expectEqual(@as(i32, -3), stale.status);
    try testing.expect(stale.unknown and stale.changed);
    try testing.expectEqual(@as(i32, -3), stale.close_status);
    try testing.expectEqual(@as(usize, 1), restarted.write_requests);
    var exhausted: console.Client = .{ .sequence = .{ .next = 0xfffffffffffffffe } };
    var io: ClientIo = .{};
    const terminal = exhausted.replace("/note", "data", &io);
    try testing.expectEqual(@as(i32, -7), terminal.status);
    try testing.expectEqual(@as(i32, -7), terminal.close_status);
    try testing.expectEqual(@as(u32, 0), terminal.length);
    try testing.expect(terminal.changed and !terminal.unknown);
    try testing.expectEqual(@as(usize, 2), io.sends);
    try testing.expectEqual(@as(usize, 1), openHandleCount(&io));
    const after = exhausted.replace("/later", "data", &io);
    try testing.expectEqual(@as(i32, -7), after.status);
    try testing.expectEqual(@as(usize, 2), io.sends);
    var denied: ClientIo = .{ .error_operation = .file_close, .send_error = -2 };
    const successful = client.replace("/note", "data", &denied);
    try testing.expectEqual(@as(i32, 0), successful.status);
    try testing.expectEqual(@as(u32, 4), successful.length);
    try testing.expectEqual(@as(i32, -2), successful.close_status);
    try testing.expectEqual(@as(usize, 1), openHandleCount(&denied));
}

test "interleaved owners expose documented observed EOF overlap and gap rejection" {
    for ([_]Interleave{ .grow, .shrink }) |change| {
        var io: ClientIo = .{};
        try io.fixture.file("/note", "ABC");
        io.interleave = change;
        var client: console.Client = .{};
        const result = client.append("/note", "!", &io);
        try testing.expectEqual(@as(i32, if (change == .grow) 0 else -1), result.status);
        try testing.expectEqual(@as(u32, if (change == .grow) 1 else 0), result.length);
        try testing.expectEqual(@as(i32, 0), result.close_status);
        try testing.expect(!result.unknown);
        try expectContents(&io, &client, "/note", if (change == .grow) "ABC!Y" else "");
        try testing.expectEqual(@as(usize, 0), openHandleCount(&io));
    }
}

test "repeated production replacements appends and closes never leak known handles" {
    var io: ClientIo = .{};
    var client: console.Client = .{};
    for (0..32) |_| {
        const replaced = client.replace("/note", "one two", &io);
        try testing.expectEqual(@as(i32, 0), replaced.status);
        try testing.expectEqual(@as(i32, 0), replaced.close_status);
        const appended = client.append("/note", "!", &io);
        try testing.expectEqual(@as(i32, 0), appended.status);
        try testing.expectEqual(@as(i32, 0), appended.close_status);
        try testing.expectEqual(@as(usize, 0), openHandleCount(&io));
    }
    try testing.expectEqual(@as(usize, 64), io.closes);
    try expectContents(&io, &client, "/note", "one two!");
}

test "lost truncate acknowledgment stays unknown and late result cannot acknowledge close or next write" {
    var io: ClientIo = .{ .receive_error_on = 2, .retain_late_reply = true };
    try io.fixture.file("/note", "old suffix must disappear");
    var client: console.Client = .{};
    const result = client.replace("/note", "new", &io);
    try testing.expectEqual(@as(i32, -8), result.status);
    try testing.expectEqual(@as(u32, 0), result.length);
    try testing.expect(result.changed and result.unknown and !result.open_unknown);
    try testing.expectEqual(@as(i32, 0), result.close_status);
    try testing.expectEqual(@as(usize, 0), io.write_requests);
    try testing.expectEqual(@as(usize, 1), io.truncates);
    try testing.expectEqual(@as(usize, 0), openHandleCount(&io));
    io.receive_error_on = null;
    try expectContents(&io, &client, "/note", "");
    try testing.expectEqual(@as(i32, 0), client.replace("/note", "recovered", &io).status);
    try expectContents(&io, &client, "/note", "recovered");
}

test "lost append acknowledgment acknowledges no guessed bytes and retained late result cannot finish close" {
    var io: ClientIo = .{ .receive_error_on = 4, .retain_late_reply = true };
    try io.fixture.file("/note", "ABC");
    var client: console.Client = .{};
    const result = client.append("/note", "!", &io);
    try testing.expectEqual(@as(i32, -8), result.status);
    try testing.expectEqual(@as(u32, 0), result.length);
    try testing.expect(result.changed and result.unknown);
    try testing.expectEqual(@as(i32, 0), result.close_status);
    try testing.expectEqual(@as(usize, 1), io.write_requests);
    try testing.expectEqual(@as(usize, 0), openHandleCount(&io));
    io.receive_error_on = null;
    try expectContents(&io, &client, "/note", "ABC!");
}

test "actual service file and handle exhaustion never partially allocate missing write names" {
    var full_files: ClientIo = .{};
    for ([_][]const u8{ "/a", "/b", "/c" }) |name| try full_files.fixture.file(name, "saved");
    const before_files = full_files.fixture;
    var client: console.Client = .{};
    const no_file = client.replace("/fourth", "data", &full_files);
    try testing.expectEqual(@as(i32, -7), no_file.status);
    try testing.expect(!no_file.changed and !no_file.unknown and !no_file.open_unknown);
    try testing.expectEqualDeep(before_files, full_files.fixture);
    try testing.expectEqual(@as(usize, 0), full_files.truncates);
    try testing.expectEqual(@as(usize, 0), full_files.write_requests);
    var full_handles: ClientIo = .{};
    for (0..8) |index| {
        const answer = full_handles.fixture.process(wire.openExistingRequest(1 + index, "/hello")).?;
        try testing.expectEqual(@as(i32, 0), wire.decodeReply(&answer, .file_result, filesystem, 1 + index).?.value);
    }
    const before_handles = full_handles.fixture;
    const no_handle = client.replace("/missing", "data", &full_handles);
    try testing.expectEqual(@as(i32, -7), no_handle.status);
    try testing.expectEqualDeep(before_handles, full_handles.fixture);
    try testing.expectEqual(@as(usize, 0), full_handles.truncates);
    try testing.expectEqual(@as(usize, 0), full_handles.write_requests);
    try testing.expectEqual(@as(usize, 8), openHandleCount(&full_handles));
}

test "metadata listing finite pressure traffic missing service and generation changes never expose partial list" {
    var client: console.Client = .{};
    var pressure: ClientIo = .{ .again_left = 4 };
    try testing.expectEqual(@as(i32, -8), client.list(&pressure).status);
    try testing.expectEqual(@as(usize, 4), pressure.sends);
    try testing.expectEqual(@as(usize, 0), pressure.receives);
    var traffic: ClientIo = .{ .unrelated_left = 20 };
    try testing.expectEqual(@as(i32, -8), client.list(&traffic).status);
    try testing.expectEqual(@as(usize, 1), traffic.sends);
    try testing.expectEqual(@as(usize, 8), traffic.receives);
    var absent: ClientIo = .{ .current_endpoint = 0 };
    try testing.expectEqual(@as(i32, -4), client.list(&absent).status);
    try testing.expectEqual(@as(usize, 0), absent.sends);
    var changed: ClientIo = .{ .restart_on_receive = 2 };
    const rejected = client.list(&changed);
    try testing.expectEqual(@as(i32, -3), rejected.status);
    try testing.expectEqual(@as(usize, 0), rejected.length);
    try testing.expectEqual(@as(usize, 2), changed.receives);
}
