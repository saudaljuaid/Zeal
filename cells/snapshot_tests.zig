// Tests exercise the production filesystem dispatcher, capture table, wire,
// ordered reader, and actual Block/Fs path through a controlled IO seam.
const std = @import("std");
const testing = std.testing;
const abi = @import("abi.zig");
const storage = @import("storage.zig");
const runtime = @import("storage_runtime.zig");
const wire = @import("snapshot_wire.zig");
const snapshot = @import("snapshot.zig");
const client = @import("snapshot_client.zig");
const storage_wire = @import("storage_wire.zig");
const owner: u64 = 0x104;
const checker: u64 = 0x105;
const worker: u64 = 0x106;

test {
    _ = @import("native_receive_tests.zig");
}

const Io = struct {
    block: storage.Block = storage.Block.init(),
    endpoint: u64 = 0x101,
    owner_endpoint: u64 = owner,
    reads: usize = 0,
    fail_at: ?usize = null,
    restart_at: ?usize = null,
    mutate_at: ?usize = null,
    defer_at: ?usize = null,
    pressure_at: ?usize = null,
    retire_at: ?usize = null,
    lose_write_reply: bool = false,
    source: u64 = 0,
    admitted: [8]u64 = .{ 0, 0, 0, 0, checker, worker, 0, 0 },

    pub fn refresh(self: *Io, server: *runtime.Server) void {
        _ = server.fs.rebindBlock(self.endpoint);
        server.snapshots.invalidateBlock(self.endpoint);
        server.rebindOwner(self.owner_endpoint);
    }
    pub fn transfer(self: *Io, server: *runtime.Server, _: u64, operation: abi.Operation, address: u32, count: u32, bytes: []const u8) ?storage_wire.Header {
        if (operation == .block_read) {
            self.reads += 1;
            if (self.pressure_at == self.reads) {
                for (0..8) |index| {
                    var queued = storage_wire.request(.file_write, 901 + index, self.source, 0, 8, "changed!");
                    queued.sender = owner;
                    if (!server.inbox.push(queued)) return null;
                }
                return null;
            }
            if (self.retire_at == self.reads) {
                self.owner_endpoint = 0x204;
                self.refresh(server);
            }
            if (self.defer_at == self.reads) {
                var queued = storage_wire.request(.file_write, 900, self.source, 0, 8, "changed!");
                queued.sender = owner;
                if (!server.inbox.push(queued)) return null;
            }
            if (self.fail_at == self.reads) return null;
            if (self.restart_at == self.reads) {
                self.endpoint = 0x201;
                self.block = storage.Block.init();
                self.refresh(server);
                return null;
            }
            if (self.mutate_at == self.reads) {
                const plan = server.fs.prepareWrite(owner, self.source, 0, 1);
                _ = self.block.write(plan.address, "!");
                _ = server.fs.commitWrite(plan);
            }
        }
        var data = [_]u8{0} ** 8;
        const result = if (operation == .block_read) self.block.read(address, count, &data) else self.block.write(address, bytes);
        if (operation == .block_write and self.lose_write_reply) {
            self.lose_write_reply = false;
            return null;
        }
        const id = server.sequence.take() orelse return null;
        return .{ .id = id, .handle = 0, .offset = address, .value = result, .data = data };
    }
    pub fn report(_: *Io, _: u64, _: u64, _: u32, _: i32) void {}
    pub fn readerValid(self: *Io, _: *runtime.Server, endpoint: u64) bool {
        if (!snapshot.validEndpoint(endpoint)) return false;
        return self.admitted[(endpoint & 255) - 1] == endpoint;
    }
};
const Fixture = struct {
    server: runtime.Server = runtime.Server.initAt(1, 0x102),
    io: Io = .{},

    fn init() Fixture {
        var fixture: Fixture = .{};
        fixture.io.refresh(&fixture.server);
        return fixture;
    }
    fn process(self: *Fixture, message: abi.Message, sender: u64) ?abi.Message {
        var request = message;
        request.sender = sender;
        var reply = self.server.processWith(&request, &self.io) orelse return null;
        reply.sender = self.server.snapshots.issuer;
        return reply;
    }
    fn file(self: *Fixture, name: []const u8, bytes: []const u8) !u64 {
        const open = self.process(storage_wire.openRequest(1, name), owner).?;
        const opened = storage_wire.decodeReply(&open, .file_result, 0x102, 1).?;
        try testing.expectEqual(@as(i32, 0), opened.value);
        var offset: usize = 0;
        while (offset < bytes.len) {
            const count = @min(8, bytes.len - offset);
            const response = self.process(storage_wire.request(.file_write, offset + 2, opened.handle, @intCast(offset), @intCast(count), bytes[offset..][0..count]), owner).?;
            try testing.expectEqual(@as(i32, @intCast(count)), storage_wire.decodeReply(&response, .file_result, 0x102, offset + 2).?.value);
            offset += count;
        }
        self.io.source = opened.handle;
        return opened.handle;
    }
    fn control(self: *Fixture, transaction: u64, subject: u64, peer: u64, action: wire.Action, sender: u64) wire.ControlReply {
        const response = self.process(wire.control(transaction, subject, peer, action), sender).?;
        return wire.decodeControlReply(&response, 0x102, transaction, action).?;
    }
    fn capture(self: *Fixture, handle: u64, transaction: u64) wire.ControlReply {
        return self.control(transaction, handle, 0, .create, owner);
    }
    fn read(self: *Fixture, reference: snapshot.Ref, offset: u16, count: u8, sender: u64) wire.ReadReply {
        const expected: wire.Read = .{ .transaction = 77, .reference = reference, .offset = offset, .count = count };
        const response = self.process(wire.read(.snapshot_read, expected.transaction, reference, offset, count), sender).?;
        return wire.decodeReadReply(&response, expected).?;
    }
};

test "binary captured lengths complete exact ordered reads and EOF through production dispatcher" {
    for ([_]usize{ 0, 1, 7, 8, 9, 127, 128 }) |length| {
        var fixture = Fixture.init();
        var bytes: [128]u8 = undefined;
        for (&bytes, 0..) |*byte, at| byte.* = @truncate(at * 97);
        bytes[0] = 0;
        bytes[1] = 0xff;
        bytes[2] = '\n';
        const handle = try fixture.file("/alpha", bytes[0..length]);
        const captured = fixture.capture(handle, 19);
        try testing.expectEqual(storage.Status.ok, captured.status);
        try testing.expectEqual(snapshot.State.live, captured.state);
        try testing.expectEqual(length, captured.length);
        try testing.expectEqual(@as(usize, (length + 7) / 8), fixture.io.reads);
        try testing.expectEqual(storage.Status.ok, fixture.control(20, captured.reference.token, worker, .bind, owner).status);
        var reader = client.Reader.init(captured.reference, captured.length).?;
        while (reader.next()) |chunk| {
            const response = fixture.read(captured.reference, chunk.offset, chunk.count, worker);
            try testing.expect(reader.accept(&response));
        }
        try testing.expect(reader.complete);
        try testing.expectEqualSlices(u8, bytes[0..length], reader.bytes[0..length]);
        try testing.expectEqual(@as(u8, 0), fixture.read(captured.reference, 128, 8, worker).count);
        try testing.expectEqual(storage.Status.too_large, fixture.read(captured.reference, 129, 1, worker).status);
    }
}

test "capture barrier defers real writable source mutation and immutable bytes remain original" {
    var fixture = Fixture.init();
    const original = "abcdefghABCDEFGHijklmnop\n";
    const handle = try fixture.file("/alpha", original);
    fixture.io.defer_at = 2;
    const captured = fixture.capture(handle, 21);
    try testing.expectEqual(storage.Status.ok, captured.status);
    try testing.expectEqual(@as(usize, 1), fixture.server.inbox.count);
    try testing.expectEqualSlices(u8, original, fixture.io.block.bytes[128..][0..original.len]);
    const queued = fixture.server.inbox.pop().?;
    const write_result = fixture.server.processWith(&queued, &fixture.io).?;
    try testing.expectEqual(@as(u8, 8), write_result.payload[20]);
    try testing.expectEqualSlices(u8, "changed!", fixture.io.block.bytes[128..136]);
    try testing.expectEqualSlices(u8, original[0..8], fixture.read(captured.reference, 0, 8, owner).data[0..8]);
    // Source handle close is independent from the immutable object lifetime.
    try testing.expectEqual(storage.Status.ok, fixture.server.fs.close(owner, handle));
    try testing.expectEqual(storage.Status.ok, fixture.capture(handle, 21).status);
    try testing.expectEqual(@as(u64, 2), fixture.server.snapshots.next_serial);
}

test "lost prior block write acknowledgement captures actual overwrite but excludes unacknowledged growth" {
    var fixture = Fixture.init();
    const handle = try fixture.file("/alpha", "abcdefghABCDEFGH");
    const revision = fixture.server.fs.files[1].revision;
    fixture.io.lose_write_reply = true;
    const overwrite = fixture.process(storage_wire.request(.file_write, 81, handle, 0, 8, "changed!"), owner).?;
    try testing.expectEqual(@as(i32, -8), storage_wire.decodeReply(&overwrite, .file_result, 0x102, 81).?.value);
    try testing.expectEqual(revision, fixture.server.fs.files[1].revision);
    try testing.expectEqualSlices(u8, "changed!ABCDEFGH", fixture.io.block.bytes[128..144]);
    const captured = fixture.capture(handle, 82);
    try testing.expectEqual(storage.Status.ok, captured.status);
    try testing.expectEqual(@as(u8, 16), captured.length);
    try testing.expectEqualSlices(u8, "changed!ABCDEFGH", fixture.server.snapshots.records[0].bytes[0..16]);
    fixture.io.lose_write_reply = true;
    const growth = fixture.process(storage_wire.request(.file_write, 83, handle, 16, 8, "hidden!!"), owner).?;
    try testing.expectEqual(@as(i32, -8), storage_wire.decodeReply(&growth, .file_result, 0x102, 83).?.value);
    try testing.expectEqual(@as(u32, 16), fixture.server.fs.files[1].length);
    try testing.expectEqual(revision, fixture.server.fs.files[1].revision);
    try testing.expectEqualSlices(u8, "hidden!!", fixture.io.block.bytes[144..152]);
    const second = fixture.capture(handle, 84);
    try testing.expectEqual(storage.Status.ok, second.status);
    try testing.expectEqual(@as(u8, 16), second.length);
    try testing.expectEqualSlices(u8, "changed!ABCDEFGH", fixture.server.snapshots.records[1].bytes[0..16]);
    try testing.expectEqualSlices(u8, &([_]u8{0} ** 112), fixture.server.snapshots.records[1].bytes[16..128]);
    try testing.expectEqual(@as(u8, 0), fixture.read(second.reference, 16, 8, owner).count);
}

test "midcapture dependency revision lost chunk and owner retirement never publish a mixed object" {
    for (0..3) |fault| {
        var fixture = Fixture.init();
        const handle = try fixture.file("/alpha", "12345678abcdefghIJKLMNOP");
        if (fault == 0) fixture.io.restart_at = 2;
        if (fault == 1) fixture.io.mutate_at = 2;
        if (fault == 2) fixture.io.fail_at = 2;
        const captured = fixture.capture(handle, 22);
        try testing.expect(captured.status == .stale or captured.status == .timeout);
        try testing.expectEqual(snapshot.State.failed, captured.state);
        try testing.expectEqual(@as(usize, 0), fixture.server.snapshots.backing());
        try testing.expectEqualSlices(u8, &([_]u8{0} ** 128), &fixture.server.snapshots.records[0].bytes);
        const recovered = fixture.control(23, 22, 0, .status, owner);
        try testing.expectEqual(captured.reference.token, recovered.reference.token);
        try testing.expectEqual(captured.status, recovered.status);
        fixture.io.owner_endpoint = 0x204;
        const old = fixture.control(24, handle, 0, .create, owner);
        try testing.expectEqual(storage.Status.denied, old.status);
        try testing.expectEqual(@as(usize, 0), fixture.server.snapshots.retained());
    }
}

test "capture pressure and midcapture owner retirement erase partial backing and preserve finite FIFO" {
    var fixture = Fixture.init();
    const handle = try fixture.file("/alpha", "abcdefghABCDEFGHijklmnop");
    fixture.io.pressure_at = 2;
    const capture = fixture.capture(handle, 71);
    try testing.expectEqual(storage.Status.timeout, capture.status);
    try testing.expectEqual(snapshot.State.failed, capture.state);
    try testing.expectEqual(@as(u64, 2), fixture.server.snapshots.next_serial);
    try testing.expectEqual(@as(usize, 1), fixture.server.snapshots.retained());
    try testing.expectEqual(@as(usize, 0), fixture.server.snapshots.backing());
    try testing.expectEqual(@as(usize, 8), fixture.server.inbox.count);
    try testing.expectEqualSlices(u8, &([_]u8{0} ** 128), &fixture.server.snapshots.records[0].bytes);
    try testing.expect(!fixture.server.inbox.push(storage_wire.openRequest(999, "/overflow")));
    const status = fixture.control(72, 71, 0, .status, owner);
    try testing.expectEqual(capture.reference.token, status.reference.token);
    try testing.expectEqual(snapshot.State.failed, status.state);
    for (0..8) |index| {
        const queued = fixture.server.inbox.pop().?;
        try testing.expectEqual(@as(u64, 901 + index), storage_wire.requestId(&queued));
        _ = fixture.server.processWith(&queued, &fixture.io).?;
    }
    try testing.expect(fixture.server.inbox.pop() == null);
    try testing.expectEqualSlices(u8, "changed!", fixture.io.block.bytes[128..136]);
    try testing.expectEqual(storage.Status.ok, fixture.control(73, capture.reference.token, 0, .reap, owner).status);
    fixture.io.pressure_at = null;
    fixture.io.reads = 0;
    fixture.io.retire_at = 2;
    const retired_capture = fixture.capture(handle, 74);
    try testing.expectEqual(storage.Status.stale, retired_capture.status);
    try testing.expectEqual(snapshot.State.empty, retired_capture.state);
    try testing.expectEqual(@as(usize, 0), fixture.server.snapshots.retained());
    try testing.expectEqual(@as(usize, 0), fixture.server.snapshots.backing());
    try testing.expectEqual(@as(u64, 3), fixture.server.snapshots.next_serial);
    try testing.expectEqual(storage.Status.stale, fixture.control(75, handle, 0, .create, 0x204).status);
    try testing.expectEqual(@as(u64, 3), fixture.server.snapshots.next_serial);
}

test "owner scoped lost creation recovery typed generations capacity and fresh reuse" {
    var fixture = Fixture.init();
    const first = try fixture.file("/alpha", "same repeated same repeated");
    const second = try fixture.file("/beta", "DIFF repeated DIFF repeated");
    const a = fixture.capture(first, 31);
    const reads = fixture.io.reads;
    // Ignore/loss of initial reply does not create another record on retry.
    try testing.expectEqual(a.reference.token, fixture.capture(first, 31).reference.token);
    try testing.expectEqual(reads, fixture.io.reads);
    try testing.expectEqual(storage.Status.invalid, fixture.capture(second, 31).status);
    const b = fixture.capture(second, 32);
    try testing.expect(a.reference.token != b.reference.token);
    try testing.expectEqual(storage.Status.no_space, fixture.capture(first, 33).status);
    try testing.expectEqual(@as(u64, 3), fixture.server.snapshots.next_serial);
    try testing.expectEqual(storage.Status.denied, fixture.control(34, a.reference.token, worker, .bind, 0x204).status);
    try testing.expectEqual(storage.Status.denied, fixture.read(a.reference, 0, 8, worker).status);
    const wrong: wire.Read = .{ .transaction = 78, .reference = .{ .issuer = 0x202, .token = a.reference.token }, .offset = 0, .count = 8 };
    const wrong_response = fixture.process(wire.read(.snapshot_read, wrong.transaction, wrong.reference, wrong.offset, wrong.count), owner).?;
    try testing.expect(wire.decodeReadReply(&wrong_response, wrong) == null);
    try testing.expectEqual(storage.Status.stale, fixture.read(.{ .issuer = 0x102, .token = first }, 0, 8, owner).status);
    try testing.expectEqual(storage.Status.ok, fixture.control(35, a.reference.token, 0, .close, owner).status);
    try testing.expectEqual(storage.Status.ok, fixture.control(36, a.reference.token, 0, .close, owner).status);
    try testing.expectEqual(storage.Status.ok, fixture.control(37, a.reference.token, 0, .reap, owner).status);
    const replay_before = fixture.server.snapshots.next_serial;
    try testing.expectEqual(storage.Status.stale, fixture.capture(first, 31).status);
    try testing.expectEqual(replay_before, fixture.server.snapshots.next_serial);
    const successor = fixture.capture(first, 38);
    try testing.expectEqual(a.reference.token & 255, successor.reference.token & 255);
    try testing.expect(a.reference.token != successor.reference.token);
    try testing.expectEqual(storage.Status.stale, fixture.control(39, a.reference.token, 0, .close, owner).status);
    try testing.expectEqual(snapshot.State.live, fixture.server.snapshots.records[0].state);
}

test "owner generation retirement denies deferred creation using valid predecessor handle and permits fresh scoped owner" {
    var fixture = Fixture.init();
    const old_handle = try fixture.file("/alpha", "actual source bytes");
    const input = fixture.capture(old_handle, 131);
    var old_create = wire.control(132, old_handle, 0, .create);
    old_create.sender = owner;
    try testing.expect(fixture.server.inbox.push(old_create));
    fixture.io.owner_endpoint = 0x204;
    fixture.io.refresh(&fixture.server);
    // File handles are a separate lifetime; the old one still passes Fs's
    // isolated policy, while the authenticated current-owner service guard
    // refuses to let its privately deferred creation revive input records.
    try testing.expectEqual(storage.Status.ok, fixture.server.fs.prepareRead(owner, old_handle, 0, 1).status);
    const old_sequence = fixture.server.snapshots.next_serial;
    const queued = fixture.server.inbox.pop().?;
    var denied = fixture.server.processWith(&queued, &fixture.io).?;
    denied.sender = 0x102;
    try testing.expectEqual(storage.Status.denied, wire.decodeControlReply(&denied, 0x102, 132, .create).?.status);
    try testing.expectEqual(@as(usize, 0), fixture.server.snapshots.retained());
    try testing.expectEqual(old_sequence, fixture.server.snapshots.next_serial);
    try testing.expectEqual(storage.Status.stale, fixture.server.snapshots.begin(&fixture.server.fs, owner, 133, old_handle).status);
    try testing.expectEqual(storage.Status.stale, fixture.server.snapshots.close(owner, input.reference));
    const opened = fixture.process(storage_wire.openRequest(134, "/alpha"), 0x204).?;
    const fresh_handle = storage_wire.decodeReply(&opened, .file_result, 0x102, 134).?.handle;
    const fresh = fixture.control(1, fresh_handle, 0, .create, 0x204);
    try testing.expectEqual(storage.Status.ok, fresh.status);
    try testing.expectEqual(@as(u64, 0x204), fixture.server.snapshots.owner_watermarks[3].endpoint);
    try testing.expectEqual(@as(u64, 1), fixture.server.snapshots.owner_watermarks[3].transaction);
    try testing.expect(fresh.reference.token != input.reference.token);
    const before = fixture.server.snapshots.owner_watermarks;
    try testing.expectEqual(storage.Status.stale, fixture.server.snapshots.begin(&fixture.server.fs, owner, 0xffffffffffffffff, old_handle).status);
    try testing.expectEqualDeep(before, fixture.server.snapshots.owner_watermarks);
}

test "creation transaction high water advances only on reserved captures and active duplicates survive terminal counter" {
    var fixture = Fixture.init();
    const handle = try fixture.file("/alpha", "bounded transaction input");
    const zero = fixture.server.snapshots.owner_watermarks;
    try testing.expectEqual(storage.Status.stale, fixture.capture(handle ^ 0x100, 151).status);
    try testing.expectEqualDeep(zero, fixture.server.snapshots.owner_watermarks);
    const first = fixture.capture(handle, 151);
    const second = fixture.capture(handle, 152);
    const full = fixture.server.snapshots.owner_watermarks;
    try testing.expectEqual(storage.Status.no_space, fixture.capture(handle, 153).status);
    try testing.expectEqualDeep(full, fixture.server.snapshots.owner_watermarks);
    try testing.expectEqual(first.reference.token, fixture.capture(handle, 151).reference.token);
    try testing.expectEqual(storage.Status.ok, fixture.control(154, first.reference.token, 0, .close, owner).status);
    try testing.expectEqual(first.reference.token, fixture.capture(handle, 151).reference.token);
    try testing.expectEqual(storage.Status.ok, fixture.control(155, first.reference.token, 0, .reap, owner).status);
    try testing.expectEqual(storage.Status.stale, fixture.capture(handle, 151).status);
    try testing.expectEqual(storage.Status.ok, fixture.control(156, second.reference.token, 0, .close, owner).status);
    try testing.expectEqual(storage.Status.ok, fixture.control(157, second.reference.token, 0, .reap, owner).status);
    const terminal = fixture.capture(handle, 0xffffffffffffffff);
    try testing.expectEqual(storage.Status.ok, terminal.status);
    try testing.expectEqual(terminal.reference.token, fixture.capture(handle, 0xffffffffffffffff).reference.token);
    try testing.expectEqual(storage.Status.ok, fixture.control(158, terminal.reference.token, 0, .close, owner).status);
    try testing.expectEqual(storage.Status.ok, fixture.control(159, terminal.reference.token, 0, .reap, owner).status);
    try testing.expectEqual(storage.Status.stale, fixture.capture(handle, 153).status);
    try testing.expectEqual(@as(usize, 0), fixture.server.snapshots.retained());
}

test "dispatcher binding requires exact currently admitted endpoint and rejects guessed future and stale routes" {
    var fixture = Fixture.init();
    const handle = try fixture.file("/alpha", "input\nbytes");
    const capture = fixture.capture(handle, 121);
    const initial = fixture.server.snapshots.records;
    try testing.expectEqual(storage.Status.denied, fixture.control(122, capture.reference.token, 0x206, .bind, owner).status);
    try testing.expectEqual(storage.Status.denied, fixture.control(123, capture.reference.token, 0x207, .bind_check, owner).status);
    try testing.expectEqualDeep(initial, fixture.server.snapshots.records);
    try testing.expectEqual(storage.Status.ok, fixture.control(124, capture.reference.token, worker, .bind, owner).status);
    fixture.io.admitted[5] = 0x206;
    const before = fixture.server.snapshots.records;
    try testing.expectEqual(storage.Status.denied, fixture.control(125, capture.reference.token, worker, .bind, owner).status);
    try testing.expectEqualDeep(before, fixture.server.snapshots.records);
    try testing.expectEqual(storage.Status.ok, fixture.control(126, capture.reference.token, worker, .revoke, owner).status);
    try testing.expectEqual(storage.Status.ok, fixture.control(127, capture.reference.token, 0x206, .bind, owner).status);
    try testing.expectEqual(storage.Status.denied, fixture.read(capture.reference, 0, 8, worker).status);
    try testing.expectEqual(storage.Status.ok, fixture.read(capture.reference, 0, 8, 0x206).status);
    try testing.expectEqual(@as(u64, 2), fixture.server.snapshots.next_serial);
}

test "checker release is scoped observable idempotent and owner revocation wins before publication" {
    var fixture = Fixture.init();
    const handle = try fixture.file("/alpha", "binary\x00\xff\n123456789");
    const capture = fixture.capture(handle, 41);
    try testing.expectEqual(storage.Status.ok, fixture.control(42, capture.reference.token, checker, .bind_check, owner).status);
    try testing.expectEqual(storage.Status.ok, fixture.control(43, capture.reference.token, worker, .bind, owner).status);
    try testing.expectEqual(storage.Status.denied, fixture.server.snapshots.release(worker, capture.reference));
    try testing.expectEqual(storage.Status.ok, fixture.control(44, capture.reference.token, worker, .revoke, owner).status);
    try testing.expectEqual(storage.Status.denied, fixture.server.snapshots.releaseBound(checker, capture.reference, worker));
    fixture.io.admitted[5] = 0x206;
    try testing.expectEqual(storage.Status.ok, fixture.control(45, capture.reference.token, 0x206, .bind, owner).status);
    const release_reply = fixture.process(wire.release(52, capture.reference, 0x206), checker).?;
    const release_expected: wire.Read = .{ .transaction = 52, .reference = capture.reference, .offset = 0, .count = 0 };
    try testing.expectEqual(storage.Status.ok, wire.decodeReadReply(&release_reply, release_expected).?.status);
    try testing.expectEqual(@as(usize, 0), fixture.server.snapshots.backing());
    try testing.expectEqualSlices(u64, &.{ 0, 0 }, &fixture.server.snapshots.records[0].readers);
    try testing.expectEqual(storage.Status.ok, fixture.server.snapshots.releaseBound(checker, capture.reference, 0x206));
    // A later partial worker-resource cleanup retry may request cleanup zero;
    // it preserves the already committed exact successful release identity.
    try testing.expectEqual(storage.Status.ok, fixture.server.snapshots.release(checker, capture.reference));
    try testing.expectEqual(@as(u64, 0x206), fixture.server.snapshots.records[0].settled_reader);
    try testing.expectEqual(storage.Status.invalid, fixture.server.snapshots.releaseBound(checker, capture.reference, worker));
    try testing.expectEqual(storage.Status.denied, fixture.read(capture.reference, 0, 1, 0x206).status);
    try testing.expectEqual(snapshot.State.settled, fixture.control(46, 41, 0, .status, owner).state);
    try testing.expectEqual(snapshot.State.settled, fixture.control(47, capture.reference.token, 0, .close, owner).state);
    try testing.expectEqual(storage.Status.ok, fixture.control(48, capture.reference.token, 0, .reap, owner).status);
    const next = fixture.capture(handle, 49);
    try testing.expectEqual(storage.Status.ok, fixture.control(50, next.reference.token, checker, .bind_check, owner).status);
    try testing.expectEqual(storage.Status.ok, fixture.control(51, next.reference.token, 0, .close, owner).status);
    try testing.expectEqual(storage.Status.stale, fixture.server.snapshots.release(checker, next.reference));
}

test "snapshot packet fields are exact little endian and malformed actions peers kinds endpoints never mutate" {
    var fixture = Fixture.init();
    const handle = try fixture.file("/alpha", "\n\n\n\n\n\n\n\n\n");
    const captured = fixture.capture(handle, 0x0807060504030201);
    try testing.expectEqual(storage.Status.ok, captured.status);
    var message = wire.control(0x0807060504030201, captured.reference.token, 0x206, .bind);
    message.sender = owner;
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, message.payload[0..8]);
    const before = fixture.server.snapshots.records;
    for ([_]u32{ 0, 24, 31, 33, 0xffffffff }) |length| {
        message.length = length;
        try testing.expect(fixture.server.processWith(&message, &fixture.io) == null);
    }
    message.length = 32;
    for (25..32) |at| {
        message.payload[at] = 1;
        try testing.expect(wire.decodeControl(&message) == null);
        message.payload[at] = 0;
    }
    for ([_]u8{ 0, 8, 255 }) |action| {
        message.payload[24] = action;
        try testing.expect(wire.decodeControl(&message) == null);
    }
    try testing.expectEqualDeep(before, fixture.server.snapshots.records);
    try testing.expectEqual(storage.Status.invalid, fixture.server.snapshots.bind(owner, captured.reference, 0x100));
    var invalid_read = wire.read(.snapshot_read, 7, captured.reference, 0, 9);
    invalid_read.sender = owner;
    try testing.expect(fixture.server.processWith(&invalid_read, &fixture.io) == null);
    var invalid_release = wire.release(8, captured.reference, 0xffffffffffffffff);
    invalid_release.sender = checker;
    try testing.expect(fixture.server.processWith(&invalid_release, &fixture.io) == null);
    var scratch: [8]u8 = undefined;
    try testing.expectEqual(@as(i32, -1), fixture.server.snapshots.read(owner, captured.reference, 0xffffffff, 1, &scratch));
    try testing.expectEqual(@as(i32, -6), fixture.server.snapshots.read(owner, captured.reference, 0, 9, &scratch));
    const header = wire.readReply(7, captured.reference, 0, 8, "\n\n\n\n\n\n\n\n");
    var delivered = header;
    delivered.sender = 0x102;
    const expected: wire.Read = .{ .transaction = 7, .reference = captured.reference, .offset = 0, .count = 8 };
    try testing.expect(wire.decodeReadReply(&delivered, expected) != null);
    delivered.sender = 0x202;
    try testing.expect(wire.decodeReadReply(&delivered, expected) == null);
    delivered.sender = 0x102;
    delivered.payload[0] = 8;
    try testing.expect(wire.decodeReadReply(&delivered, expected) == null);
}

test "nonwrapping source and snapshot counters reject before mutation and rejected 129 length" {
    var fixture = Fixture.init();
    const handle = try fixture.file("/alpha", "content!");
    fixture.server.fs.files[1].revision = 0xffffffffffffffff;
    const unchanged = fixture.io.block.bytes;
    const plan = fixture.server.fs.prepareWrite(owner, handle, 0, 1);
    try testing.expectEqual(storage.Status.no_space, plan.status);
    try testing.expectEqualSlices(u8, &unchanged, &fixture.io.block.bytes);
    fixture.server.fs.files[1].length = 129;
    try testing.expectEqual(storage.Status.too_large, fixture.capture(handle, 60).status);
    fixture.server.fs.files[1].length = 8;
    fixture.server.snapshots.next_serial = snapshot.serial_max;
    const last = fixture.capture(handle, 61);
    try testing.expectEqual(storage.Status.ok, last.status);
    try testing.expectEqual(@as(u64, 0), fixture.server.snapshots.next_serial);
    try testing.expectEqual(storage.Status.no_space, fixture.capture(handle, 62).status);
    fixture.server.snapshots.issuer = 0xffffffffffffffff;
    try testing.expectEqual(storage.Status.invalid, fixture.server.snapshots.begin(&fixture.server.fs, owner, 63, handle).status);
}

test "owner inventory independently reports retained backing binding and live conservation without consuming identity" {
    var fixture = Fixture.init();
    const handle = try fixture.file("/alpha", "data\ninput");
    const first = fixture.capture(handle, 91);
    const second = fixture.capture(handle, 92);
    for ([_]snapshot.Ref{ first.reference, second.reference }) |reference| {
        try testing.expectEqual(storage.Status.ok, fixture.server.snapshots.bindChecker(owner, reference, checker));
        try testing.expectEqual(storage.Status.ok, fixture.server.snapshots.bind(owner, reference, worker));
    }
    const sequence = fixture.server.snapshots.next_serial;
    const before = fixture.server.snapshots.records;
    const response = fixture.process(wire.control(93, 1, 0, .inventory), owner).?;
    const inventory = wire.decodeInventoryReply(&response, 0x102, 93).?;
    try testing.expectEqual(@as(u8, 2), inventory.retained);
    try testing.expectEqual(@as(u16, 256), inventory.backing);
    try testing.expectEqual(@as(u8, 4), inventory.readers);
    try testing.expectEqual(@as(u8, 2), inventory.live);
    try testing.expectEqual(@as(u64, 0x101), inventory.block);
    try testing.expectEqual(sequence, fixture.server.snapshots.next_serial);
    try testing.expectEqualDeep(before, fixture.server.snapshots.records);
    try testing.expectEqual(storage.Status.denied, fixture.control(94, 1, 0, .inventory, worker).status);
    try testing.expectEqual(storage.Status.ok, fixture.control(95, first.reference.token, 0, .close, owner).status);
    try testing.expectEqual(storage.Status.ok, fixture.control(96, first.reference.token, 0, .reap, owner).status);
    try testing.expectEqual(storage.Status.ok, fixture.control(97, second.reference.token, 0, .close, owner).status);
    try testing.expectEqual(storage.Status.ok, fixture.control(98, second.reference.token, 0, .reap, owner).status);
    const final = fixture.control(99, 1, 0, .inventory, owner);
    try testing.expectEqual(@as(u64, 0), final.reference.token);
    try testing.expectEqual(@as(u8, 0), final.length);
    try testing.expectEqual(@as(u64, 0x101), final.block);
    try testing.expectEqual(sequence, fixture.server.snapshots.next_serial);
    var malformed = wire.control(100, 2, 0, .inventory);
    malformed.sender = owner;
    try testing.expect(fixture.server.processWith(&malformed, &fixture.io) == null);
    var invalid_reply = response;
    invalid_reply.payload[11] = 5; // Five bindings cannot fit the four-slot table.
    try testing.expect(wire.decodeInventoryReply(&invalid_reply, 0x102, 93) == null);
}

test "reader rejects duplicate overlap gap prefix EOF wrong tuple identity and malformed binary padding" {
    const reference: snapshot.Ref = .{ .issuer = 0x102, .token = 0x1a1 };
    for (0..7) |fault| {
        var reader = client.Reader.init(reference, 9).?;
        var response: wire.ReadReply = .{ .transaction = 1, .reference = reference, .offset = 0, .count = 8, .status = .ok, .data = .{ 0, 255, 10, 0, 1, 2, 3, 4 } };
        if (fault == 0) response.count = 7;
        if (fault == 1) response.offset = 1;
        if (fault == 2) response.reference.issuer = 0x202;
        if (fault == 3) response.reference.token = 0x2a1;
        if (fault == 4) response.status = .stale;
        if (fault <= 4) {
            try testing.expect(!reader.accept(&response));
            try testing.expect(reader.failed);
        } else {
            try testing.expect(reader.accept(&response));
            if (fault == 5) try testing.expect(!reader.accept(&response)) else {
                response.offset = 8;
                response.count = 1;
                try testing.expect(reader.accept(&response));
                response.offset = 9;
                response.count = 1;
                try testing.expect(!reader.accept(&response));
            }
        }
    }
    var message = wire.readReply(1, reference, 0, 1, "\x00");
    message.sender = 0x102;
    const expected: wire.Read = .{ .transaction = 1, .reference = reference, .offset = 0, .count = 1 };
    try testing.expect(wire.decodeReadReply(&message, expected) != null);
    for ([_]usize{ 21, 27, 28, 29, 30 }) |at| {
        message.payload[at] = 1;
        try testing.expect(wire.decodeReadReply(&message, expected) == null);
        message.payload[at] = 0;
    }
    message.payload[31] = 1;
    try testing.expect(wire.decodeReadReply(&message, expected) == null);
}
