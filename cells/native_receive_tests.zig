// Exercise the actual native client loops. The seam only schedules transport
// outcomes; reply bytes and mutation outcomes come from the production FS/Block.
const std = @import("std");
const testing = std.testing;
const abi = @import("abi.zig");
const storage = @import("storage.zig");
const files = @import("storage_wire.zig");
const server = @import("storage_runtime.zig");
const snapshot = @import("snapshot.zig");
const snapshots = @import("snapshot_wire.zig");
const client = @import("snapshot_client.zig");
const workload = @import("hosting_storage.zig");
const transport = @import("storage_transport.zig");
const owner: u64 = 0x104;
const worker: u64 = 0x207;

const BlockIo = struct {
    backing: storage.Block = storage.Block.init(),
    pub fn refresh(_: *BlockIo, service: *server.Server) void {
        _ = service.fs.rebindBlock(0x101);
        service.snapshots.invalidateBlock(0x101);
        service.rebindOwner(owner);
    }
    pub fn transfer(self: *BlockIo, service: *server.Server, _: u64, operation: abi.Operation, address: u32, count: u32, bytes: []const u8) ?files.Header {
        var data = [_]u8{0} ** 8;
        const result = if (operation == .block_read) self.backing.read(address, count, &data) else self.backing.write(address, bytes);
        return .{ .id = service.sequence.take() orelse return null, .handle = 0, .offset = address, .value = result, .data = data };
    }
    pub fn report(_: *BlockIo, _: u64, _: u64, _: u32, _: i32) void {}
};

const Fixture = struct {
    service: server.Server = server.Server.initAt(1, 0x102),
    io: BlockIo = .{},
    fn init() Fixture {
        var fixture: Fixture = .{};
        fixture.io.refresh(&fixture.service);
        return fixture;
    }
    fn process(self: *Fixture, message: abi.Message, sender: u64) ?abi.Message {
        var request = message;
        request.sender = sender;
        var reply = self.service.processWith(&request, &self.io) orelse return null;
        reply.sender = self.service.snapshots.issuer;
        return reply;
    }
    fn open(self: *Fixture, sender: u64) !u64 {
        const response = self.process(files.openRequest(100, "/hello"), sender).?;
        const opened = files.decodeReply(&response, .file_result, 0x102, 100).?;
        try testing.expectEqual(@as(i32, 0), opened.value);
        return opened.handle;
    }
    fn capture(self: *Fixture) !snapshot.Ref {
        const handle = try self.open(owner);
        const response = self.process(snapshots.control(101, handle, 0, .create), owner).?;
        const captured = snapshots.decodeControlReply(&response, 0x102, 101, .create).?;
        try testing.expectEqual(storage.Status.ok, captured.status);
        try testing.expectEqual(storage.Status.ok, self.service.snapshots.bind(owner, captured.reference, worker));
        return captured.reference;
    }
};

const Changed = enum { none, filesystem, block };
const RpcIo = struct {
    fixture: *Fixture,
    sender: u64 = worker,
    filesystem_endpoint: u64 = 0x102,
    block_endpoint: u64 = 0x101,
    delay: u64 = 18,
    now: u64 = 0,
    ready: u64 = 0,
    pending: ?abi.Message = null,
    old: ?abi.Message = null,
    unrelated: transport.Inbox = .{},
    sends: usize = 0,
    receives: usize = 0,
    ids: [32]u64 = [_]u64{0} ** 32,
    change_on_timeout: Changed = .none,
    receive_error: i32 = 0,
    corrupt_offset: bool = false,
    corrupt_handle: bool = false,

    pub fn filesystem(self: *RpcIo) u64 {
        return self.filesystem_endpoint;
    }
    pub fn block(self: *RpcIo) u64 {
        return self.block_endpoint;
    }
    pub fn send(self: *RpcIo, endpoint: u64, message: *const abi.Message, operation: abi.Operation) i32 {
        std.debug.assert(endpoint == self.filesystem_endpoint and message.operation == @intFromEnum(operation));
        std.debug.assert(self.sends < self.ids.len);
        self.ids[self.sends] = files.requestId(message);
        self.sends += 1;
        // Retain any abandoned result as a genuinely older RPC, never rename it
        // to the next identity. Opening may already have consumed a real slot.
        if (self.pending) |reply| self.old = reply;
        self.pending = self.fixture.process(message.*, self.sender);
        if (self.pending) |*reply| {
            if (self.corrupt_offset) reply.payload[16] ^= 1;
            if (self.corrupt_handle) reply.payload[8] ^= 1;
        }
        self.ready = self.now + self.delay;
        return 0;
    }
    pub fn receive(self: *RpcIo, message: *abi.Message, ticks: u64) i32 {
        std.debug.assert(ticks == transport.receive_ticks);
        self.receives += 1;
        if (self.receive_error != 0) return self.receive_error;
        if (self.unrelated.pop()) |incoming| {
            message.* = incoming;
            return 0;
        }
        if (self.old) |reply| {
            self.old = null;
            message.* = reply;
            return 0;
        }
        if (self.pending != null and self.ready < self.now + ticks) {
            self.now = @max(self.now, self.ready);
            message.* = self.pending.?;
            self.pending = null;
            return 0;
        }
        self.now += ticks;
        if (self.change_on_timeout == .filesystem) self.filesystem_endpoint = 0x202;
        if (self.change_on_timeout == .block) self.block_endpoint = 0x201;
        return @intFromEnum(abi.Error.timeout);
    }
    fn traffic(self: *RpcIo, id: u64) void {
        var message = files.openRequest(id, "/hello");
        message.operation = @intFromEnum(abi.Operation.hosting_request);
        message.sender = owner;
        std.debug.assert(self.unrelated.push(message));
    }
};

test "native snapshot control and complete reader survive the preserved eighteen-tick reply latency" {
    var fixture = Fixture.init();
    const handle = try fixture.open(owner);
    var io: RpcIo = .{ .fixture = &fixture, .sender = owner };
    var reader: client.Client = .{};
    var inbox: transport.Inbox = .{};
    const transaction = reader.sequence.take().?;
    const captured = reader.controlTransactionWithIo(0x102, transaction, handle, 0, .create, &inbox, &io).?;
    try testing.expectEqual(storage.Status.ok, captured.status);
    try testing.expectEqual(@as(usize, 1), io.sends);
    try testing.expectEqual(@as(usize, 2), io.receives);
    try testing.expectEqual(@as(u64, 18), io.now);
    try testing.expectEqual(storage.Status.ok, fixture.service.snapshots.bind(owner, captured.reference, worker));
    io.sender = worker;
    var bytes: [128]u8 = [_]u8{0xcc} ** 128;
    try testing.expect(reader.collectWithIo(captured.reference, captured.length, &bytes, &inbox, &io));
    try testing.expectEqualStrings(storage.hello, bytes[0..captured.length]);
    // Two actual chunks and exact EOF, each with a fresh identity and no resend.
    try testing.expectEqual(@as(usize, 4), io.sends);
    try testing.expectEqual(@as(usize, 8), io.receives);
    try testing.expectEqual(@as(u64, 72), io.now);
    for (1..io.sends) |at| try testing.expect(io.ids[at] > io.ids[at - 1]);
}

test "native preservation workload keeps an enqueued eighteen-tick read and EOF without restarting" {
    var fixture = Fixture.init();
    const handle = try fixture.open(0x103);
    var io: RpcIo = .{ .fixture = &fixture, .sender = 0x103 };
    var native: workload.Workload = .{ .filesystem = 0x102, .block = 0x101 };
    const data = native.callWith(.file_chunk_read, handle, 0, 8, &.{}, &.{}, &io).?;
    try testing.expectEqual(@as(i32, 8), data.value);
    try testing.expectEqualStrings(storage.hello[0..8], &data.data);
    try testing.expectEqual(@as(usize, 1), io.sends);
    try testing.expectEqual(@as(usize, 2), io.receives);
    const eof = native.callWith(.file_chunk_read, handle, storage.hello.len, 8, &.{}, &.{}, &io).?;
    try testing.expectEqual(@as(i32, 0), eof.value);
    try testing.expectEqual(@as(usize, 2), io.sends);
    try testing.expectEqual(@as(usize, 4), io.receives);
    try testing.expect(io.ids[0] != io.ids[1]);
}

test "native adapters accept an exact valid reply on the eighth step without enlarging their budget" {
    var fixture = Fixture.init();
    const reference = try fixture.capture();
    var reader: client.Client = .{};
    var inbox: transport.Inbox = .{};
    var io: RpcIo = .{ .fixture = &fixture, .delay = 71 };
    try testing.expect(reader.readWithIo(reference, 0, 8, &inbox, &io) != null);
    try testing.expectEqual(@as(usize, 8), io.receives);
    try testing.expectEqual(@as(u64, 71), io.now);
    try testing.expectEqual(@as(usize, 1), io.sends);
    var native: workload.Workload = .{ .filesystem = 0x102, .block = 0x101 };
    var native_io: RpcIo = .{ .fixture = &fixture, .sender = 0x103, .delay = 71 };
    const handle = try fixture.open(0x103);
    try testing.expect(native.callWith(.file_chunk_read, handle, 0, 8, &.{}, &.{}, &native_io) != null);
    try testing.expectEqual(@as(usize, 8), native_io.receives);
    try testing.expectEqual(@as(u64, 71), native_io.now);
    try testing.expectEqual(@as(usize, 1), native_io.sends);
}

test "native snapshot exhaustion is eight finite waits and its late result cannot complete a fresh identity" {
    var fixture = Fixture.init();
    const reference = try fixture.capture();
    var io: RpcIo = .{ .fixture = &fixture, .delay = 80 };
    var reader: client.Client = .{};
    var inbox: transport.Inbox = .{};
    try testing.expect(reader.readWithIo(reference, 0, 8, &inbox, &io) == null);
    try testing.expectEqual(@as(usize, 1), io.sends);
    try testing.expectEqual(@as(usize, 8), io.receives);
    try testing.expectEqual(@as(u64, 80), io.now);
    io.delay = 0;
    const fresh = reader.readWithIo(reference, 8, 8, &inbox, &io).?;
    try testing.expectEqual(@as(u16, 8), fresh.offset);
    try testing.expectEqualStrings(storage.hello[8..], fresh.data[0..fresh.count]);
    try testing.expectEqual(@as(usize, 2), io.sends);
    try testing.expectEqual(@as(usize, 10), io.receives);
    try testing.expect(io.ids[0] != io.ids[1]);
    try testing.expectEqual(@as(usize, 0), inbox.count);
}

test "native workload lost open retains its allocated slot and rejects the old reply during fresh open" {
    var fixture = Fixture.init();
    var io: RpcIo = .{ .fixture = &fixture, .sender = 0x103, .delay = 80 };
    var native: workload.Workload = .{ .filesystem = 0x102, .block = 0x101 };
    try testing.expect(native.callWith(.file_open, 0, 0, 0, &.{}, "/hello", &io) == null);
    const committed_old = files.decodeReply(&io.pending.?, .file_result, 0x102, io.ids[0]).?;
    try testing.expect(committed_old.handle != 0);
    try testing.expectEqual(@as(usize, 8), io.receives);
    io.delay = 0;
    const fresh = native.callWith(.file_open, 0, 0, 0, &.{}, "/hello", &io).?;
    try testing.expectEqual(@as(i32, 0), fresh.value);
    try testing.expect(fresh.handle != committed_old.handle);
    try testing.expectEqual(@as(usize, 2), io.sends);
    try testing.expectEqual(@as(usize, 10), io.receives);
    // No fabricated reclamation or reset: both service-owned allocations remain.
    try testing.expectEqual(storage.Status.ok, fixture.service.fs.close(0x103, committed_old.handle));
    try testing.expectEqual(storage.Status.ok, fixture.service.fs.close(0x103, fresh.handle));
}

test "lost native create ends within budget and fresh status recovers the original single record" {
    var fixture = Fixture.init();
    const handle = try fixture.open(owner);
    var reader: client.Client = .{};
    var inbox: transport.Inbox = .{};
    var io: RpcIo = .{ .fixture = &fixture, .sender = owner, .delay = 80 };
    const creation = reader.sequence.take().?;
    try testing.expect(reader.controlTransactionWithIo(0x102, creation, handle, 0, .create, &inbox, &io) == null);
    const committed = snapshots.decodeControlReply(&io.pending.?, 0x102, creation, .create).?;
    try testing.expectEqual(storage.Status.ok, committed.status);
    try testing.expectEqual(@as(usize, 8), io.receives);
    try testing.expectEqual(@as(usize, 1), fixture.service.snapshots.retained());
    io.delay = 0;
    const query = reader.sequence.take().?;
    const recovered = reader.controlTransactionWithIo(0x102, query, creation, 0, .status, &inbox, &io).?;
    try testing.expectEqual(committed.reference, recovered.reference);
    try testing.expectEqual(storage.Status.ok, recovered.status);
    try testing.expectEqual(snapshot.State.live, recovered.state);
    try testing.expectEqual(@as(usize, 1), fixture.service.snapshots.retained());
    try testing.expectEqual(@as(usize, 2), io.sends);
    try testing.expectEqual(@as(usize, 10), io.receives);
    try testing.expect(io.ids[0] != io.ids[1]);
}

test "native generations are fenced before send and after timeout including block-only replacement" {
    var fixture = Fixture.init();
    const reference = try fixture.capture();
    var absent: RpcIo = .{ .fixture = &fixture, .filesystem_endpoint = 0 };
    var absent_reader: client.Client = .{};
    var absent_inbox: transport.Inbox = .{};
    try testing.expect(absent_reader.readWithIo(.{ .issuer = 0, .token = reference.token }, 0, 8, &absent_inbox, &absent) == null);
    try testing.expectEqual(@as(usize, 0), absent.sends);
    for ([_]bool{ false, true }) |before| {
        var io: RpcIo = .{ .fixture = &fixture, .change_on_timeout = .filesystem };
        if (before) io.filesystem_endpoint = 0x202;
        var reader: client.Client = .{};
        var inbox: transport.Inbox = .{};
        try testing.expect(reader.readWithIo(reference, 0, 8, &inbox, &io) == null);
        try testing.expectEqual(if (before) @as(usize, 0) else 1, io.sends);
        try testing.expectEqual(if (before) @as(usize, 0) else 1, io.receives);
        try testing.expect(reader.controlTransactionWithIo(reference.issuer, 200, reference.token, 0, .status, &inbox, &io) == null);
        try testing.expectEqual(if (before) @as(usize, 0) else 1, io.sends);
    }
    const handle = try fixture.open(0x103);
    for ([_]Changed{ .filesystem, .block }) |changed| {
        var io: RpcIo = .{ .fixture = &fixture, .sender = 0x103, .change_on_timeout = changed };
        var native: workload.Workload = .{ .filesystem = 0x102, .block = 0x101 };
        try testing.expect(native.callWith(.file_chunk_read, handle, 0, 8, &.{}, &.{}, &io) == null);
        try testing.expectEqual(@as(usize, 1), io.sends);
        try testing.expectEqual(@as(usize, 1), io.receives);
        try testing.expect(native.callWith(.file_chunk_read, handle, 0, 8, &.{}, &.{}, &io) == null);
        try testing.expectEqual(@as(usize, 1), io.sends);
    }
}

test "unrelated native traffic and timeouts share the same budget and preserve eight-slot FIFO pressure" {
    var fixture = Fixture.init();
    const reference = try fixture.capture();
    var reader: client.Client = .{};
    var inbox: transport.Inbox = .{};
    var mixed: RpcIo = .{ .fixture = &fixture };
    mixed.traffic(901);
    mixed.traffic(902);
    try testing.expect(reader.readWithIo(reference, 0, 8, &inbox, &mixed) != null);
    try testing.expectEqual(@as(usize, 4), mixed.receives);
    try testing.expectEqual(@as(u64, 901), files.requestId(&inbox.pop().?));
    try testing.expectEqual(@as(u64, 902), files.requestId(&inbox.pop().?));
    var pressure: RpcIo = .{ .fixture = &fixture };
    for (0..8) |at| pressure.traffic(1000 + at);
    try testing.expect(reader.readWithIo(reference, 0, 8, &inbox, &pressure) == null);
    try testing.expectEqual(@as(usize, 1), pressure.sends);
    try testing.expectEqual(@as(usize, 8), pressure.receives);
    for (0..8) |at| try testing.expectEqual(@as(u64, 1000 + at), files.requestId(&inbox.pop().?));
    var native: workload.Workload = .{ .filesystem = 0x102, .block = 0x101, .analysis_mode = true };
    var workload_pressure: RpcIo = .{ .fixture = &fixture, .sender = 0x103 };
    for (0..8) |at| workload_pressure.traffic(2000 + at);
    const handle = try fixture.open(0x103);
    try testing.expect(native.callWith(.file_chunk_read, handle, 0, 8, &.{}, &.{}, &workload_pressure) == null);
    try testing.expectEqual(@as(usize, 8), workload_pressure.receives);
    for (0..8) |at| try testing.expectEqual(@as(u64, 2000 + at), files.requestId(&native.deferred.pop().?));
}

test "non-timeout native receive errors remain terminal and authenticated reply matching rejects wrong sender" {
    var fixture = Fixture.init();
    const reference = try fixture.capture();
    var reader: client.Client = .{};
    var inbox: transport.Inbox = .{};
    for ([_]i32{ @intFromEnum(abi.Error.denied), @intFromEnum(abi.Error.bad_address), @intFromEnum(abi.Error.stale) }) |failure| {
        var io: RpcIo = .{ .fixture = &fixture, .receive_error = failure };
        try testing.expect(reader.readWithIo(reference, 0, 8, &inbox, &io) == null);
        try testing.expectEqual(@as(usize, 1), io.sends);
        try testing.expectEqual(@as(usize, 1), io.receives);
    }
    var io: RpcIo = .{ .fixture = &fixture, .delay = 0 };
    var wrong = snapshots.readReply(reader.sequence.next, reference, 0, 8, "forged!!");
    wrong.sender = 0x202;
    io.old = wrong;
    const valid = reader.readWithIo(reference, 0, 8, &inbox, &io).?;
    try testing.expectEqualStrings(storage.hello[0..8], &valid.data);
    try testing.expectEqual(@as(usize, 2), io.receives);
    try testing.expectEqual(@as(usize, 0), inbox.count);
    const handle = try fixture.open(0x103);
    for ([_]bool{ false, true }) |handle_corruption| {
        var native: workload.Workload = .{ .filesystem = 0x102, .block = 0x101 };
        var malformed: RpcIo = .{ .fixture = &fixture, .sender = 0x103, .delay = 0, .corrupt_offset = !handle_corruption, .corrupt_handle = handle_corruption };
        try testing.expect(native.callWith(.file_chunk_read, handle, 0, 8, &.{}, &.{}, &malformed) == null);
        try testing.expectEqual(@as(usize, 1), malformed.sends);
        try testing.expectEqual(@as(usize, 1), malformed.receives);
    }
}
