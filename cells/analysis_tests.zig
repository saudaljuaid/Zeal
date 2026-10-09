// Integration of the production capture dispatcher, ordered reader, worker
// descriptor collector, byte profile, contract core and private result stage.
// The finite lifecycle fake supplies only the existing kernel-call seam.
const std = @import("std");
const testing = std.testing;
const abi = @import("abi.zig");
const storage = @import("storage.zig");
const fs_runtime = @import("storage_runtime.zig");
const storage_wire = @import("storage_wire.zig");
const snapshot = @import("snapshot.zig");
const snapshot_wire = @import("snapshot_wire.zig");
const reader = @import("snapshot_client.zig");
const analysis = @import("analysis_wire.zig");
const worker_runtime = @import("analysis_runtime.zig");
const staging = @import("analysis_staging.zig");
const dispatcher = @import("contract_dispatch.zig");
const support = @import("contract_test_support.zig");
const core = support.core;
const wire = support.wire;
const owner: u64 = 0x104;
const broker_endpoint: u64 = 0x108;

const Io = struct {
    block: storage.Block = storage.Block.init(),
    pub fn refresh(_: *Io, server: *fs_runtime.Server) void {
        _ = server.fs.rebindBlock(0x101);
        server.snapshots.invalidateBlock(0x101);
        server.rebindOwner(owner);
    }
    pub fn transfer(self: *Io, server: *fs_runtime.Server, _: u64, operation: abi.Operation, address: u32, count: u32, bytes: []const u8) ?storage_wire.Header {
        var data = [_]u8{0} ** 8;
        const count_or_error = if (operation == .block_read) self.block.read(address, count, &data) else self.block.write(address, bytes);
        return .{ .id = server.sequence.take() orelse return null, .handle = 0, .offset = address, .value = count_or_error, .data = data };
    }
    pub fn report(_: *Io, _: u64, _: u64, _: u32, _: i32) void {}
};
const Input = struct { handle: u64, reference: snapshot.Ref, length: u8 };
const Fixture = struct {
    server: fs_runtime.Server = fs_runtime.Server.initAt(1, 0x102),
    io: Io = .{},
    sequence: u64 = 1,
    fn init() Fixture {
        var result: Fixture = .{};
        result.io.refresh(&result.server);
        return result;
    }
    fn process(self: *Fixture, request: abi.Message, sender: u64) ?abi.Message {
        var incoming = request;
        incoming.sender = sender;
        var result = self.server.processWith(&incoming, &self.io) orelse return null;
        result.sender = self.server.snapshots.issuer;
        return result;
    }
    fn id(self: *Fixture) u64 {
        const result = self.sequence;
        self.sequence += 1;
        return result;
    }
    fn write(self: *Fixture, handle: u64, offset: u32, bytes: []const u8) !void {
        const transaction = self.id();
        const response = self.process(storage_wire.request(.file_write, transaction, handle, offset, @intCast(bytes.len), bytes), owner).?;
        const decoded = storage_wire.decodeReply(&response, .file_result, self.server.snapshots.issuer, transaction).?;
        try testing.expectEqual(@as(i32, @intCast(bytes.len)), decoded.value);
    }
    fn input(self: *Fixture, name: []const u8, bytes: []const u8) !Input {
        const transaction = self.id();
        const opened = self.process(storage_wire.openRequest(transaction, name), owner).?;
        const handle = storage_wire.decodeReply(&opened, .file_result, self.server.snapshots.issuer, transaction).?.handle;
        var offset: usize = 0;
        while (offset < bytes.len) {
            const count = @min(8, bytes.len - offset);
            try self.write(handle, @intCast(offset), bytes[offset..][0..count]);
            offset += count;
        }
        const capture_transaction = self.id();
        const response = self.process(snapshot_wire.control(capture_transaction, handle, 0, .create), owner).?;
        const captured = snapshot_wire.decodeControlReply(&response, self.server.snapshots.issuer, capture_transaction, .create).?;
        try testing.expectEqual(storage.Status.ok, captured.status);
        try testing.expectEqual(bytes.len, captured.length);
        try testing.expectEqual(snapshot.State.live, captured.state);
        try testing.expectEqual(storage.Status.ok, self.server.snapshots.bindChecker(owner, captured.reference, broker_endpoint));
        return .{ .handle = handle, .reference = captured.reference, .length = captured.length };
    }
    fn collect(self: *Fixture, peer: u64, reference: snapshot.Ref, length: u8) ?analysis.Tuple {
        var ordered = reader.Reader.init(reference, length) orelse return null;
        while (!ordered.complete) {
            const chunk = ordered.next().?;
            const transaction = self.id();
            const response = self.process(snapshot_wire.read(.snapshot_read, transaction, reference, chunk.offset, chunk.count), peer) orelse return null;
            const expected: snapshot_wire.Read = .{ .transaction = transaction, .reference = reference, .offset = chunk.offset, .count = chunk.count };
            const reply = snapshot_wire.decodeReadReply(&response, expected) orelse return null;
            if (!ordered.accept(&reply)) return null;
        }
        return analysis.calculate(ordered.bytes[0..length]);
    }
    fn close(self: *Fixture, reference: snapshot.Ref) !void {
        try testing.expectEqual(storage.Status.ok, self.server.snapshots.close(owner, reference));
        try testing.expectEqual(storage.Status.ok, self.server.snapshots.reap(owner, reference));
    }
};
const Seam = struct {
    fixture: *Fixture,
    stages: staging.Staging = .{},
    fake: support.Fake = .{},
    bindings: [2]?snapshot.Ref = .{ null, null },
    workers: [2]worker_runtime.Worker = .{ .{ .parent = broker_endpoint }, .{ .parent = broker_endpoint } },
    broker_reads: u64 = 0,
    worker_reads: u64 = 0,
    allow_retry: bool = false,
    revoke_at_release: bool = false,
    release_calls: u64 = 0,
    pending_token: u64 = 0,
    cancel_target: u64 = 0,
    cancel_during_verify: bool = false,
    cancel_during_release: bool = false,
    cancel_in_rebind: bool = false,
    broker: ?*core.Broker = null,
    pub fn stage(self: *Seam, table: *core.Broker, message: *const abi.Message) core.Error!?wire.Snapshot {
        return self.stages.request(table, message, self);
    }
    pub fn domain(self: *Seam) ?core.Domain {
        return self.fake.domain();
    }
    pub fn create(self: *Seam) ?core.Backing {
        return self.fake.create();
    }
    pub fn send(self: *Seam, backing: core.Backing, message: abi.Message) bool {
        return self.fake.send(backing, message);
    }
    pub fn admit(self: *Seam, backing: core.Backing) ?core.Fence {
        return self.fake.admit(backing);
    }
    pub fn settle(self: *Seam, backing: core.Backing) bool {
        return self.fake.settle(backing);
    }
    pub fn settleCandidate(self: *Seam, backing: core.Backing, fence: core.Fence) core.Settlement {
        return self.fake.settleCandidate(backing, fence);
    }
    pub fn prepareInput(self: *Seam, issuer: u64, token: u64) ?u16 {
        const result = self.verifyInput(issuer, token) orelse return null;
        return result.length;
    }
    pub fn verifyInput(self: *Seam, issuer: u64, token: u64) ?analysis.Tuple {
        const reference: snapshot.Ref = .{ .issuer = issuer, .token = token };
        const slot = self.fixture.server.snapshots.index(reference) orelse return null;
        self.broker_reads += 1;
        const tuple = self.fixture.collect(broker_endpoint, reference, self.fixture.server.snapshots.records[slot].length);
        if (self.cancel_during_verify) {
            self.pending_token = self.cancel_target;
            self.cancel_during_verify = false;
        }
        return tuple;
    }
    pub fn cancellationPending(self: *Seam, token: u64) bool {
        return self.pending_token == token;
    }
    pub fn releaseInput(self: *Seam, record: core.Record, successful: bool) bool {
        self.release_calls += 1;
        const reference: snapshot.Ref = .{ .issuer = record.input_issuer, .token = record.input };
        if (self.revoke_at_release) {
            _ = self.fixture.server.snapshots.revoke(owner, reference, record.worker.endpoint);
            self.revoke_at_release = false;
        }
        const transaction = self.fixture.id();
        const response = self.fixture.process(snapshot_wire.release(transaction, reference, if (successful) record.worker.endpoint else 0), broker_endpoint) orelse return false;
        const expected: snapshot_wire.Read = .{ .transaction = transaction, .reference = reference, .offset = 0, .count = 0 };
        const reply = snapshot_wire.decodeReadReply(&response, expected) orelse return false;
        if (self.cancel_during_release) {
            self.pending_token = self.cancel_target;
            self.cancel_during_release = false;
        }
        return reply.status == .ok and reply.count == 0;
    }
    pub fn validatedAnalysis(self: *Seam, record: core.Record, tuple: analysis.Tuple) void {
        self.fake.validated(record.token, record.worker, record.rpc, record.attempt, record.input, tuple.digest);
    }
    pub fn rebind(self: *Seam, old: core.Backing) ?core.Backing {
        if (!self.allow_retry) return null;
        const slot: usize = @intCast(old.slot - 4);
        const reference = self.bindings[slot] orelse return null;
        const replacement = self.fake.rebind(old) orelse return null;
        if (self.cancel_in_rebind) {
            const broker = self.broker orelse return null;
            for (broker.records) |record| if (record.worker.control == old.control) {
                _ = broker.cancel(owner, record.token, self) catch return null;
                return null;
            };
            return null;
        }
        if (self.fixture.server.snapshots.revoke(owner, reference, old.endpoint) != .ok or
            self.fixture.server.snapshots.bind(owner, reference, replacement.endpoint) != .ok) return null;
        self.workers[slot] = .{ .parent = broker_endpoint };
        return replacement;
    }
    fn bind(self: *Seam, record: *const core.Record) !void {
        const reference: snapshot.Ref = .{ .issuer = record.input_issuer, .token = record.input };
        try testing.expectEqual(storage.Status.ok, self.fixture.server.snapshots.bind(owner, reference, record.worker.endpoint));
        self.bindings[record.worker.slot - 4] = reference;
    }
    fn execute(self: *Seam, record: *const core.Record) ?analysis.Result {
        const state = &self.workers[record.worker.slot - 4];
        var descriptor = wire.encode(wire.request_operation, .{ .id = record.rpc, .command = .input, .detail = record.attempt, .token = record.token, .data = record.input_issuer });
        descriptor.sender = broker_endpoint;
        var length = wire.encode(wire.request_operation, .{ .id = record.rpc, .command = .input_length, .detail = record.attempt, .token = record.token, .data = record.input_length });
        length.sender = broker_endpoint;
        var work = self.fake.last[record.worker.slot - 4] orelse return null;
        work.sender = broker_endpoint;
        if (state.accept(&descriptor) != null or state.accept(&length) != null) return null;
        const accepted = state.accept(&work) orelse return null;
        self.worker_reads += 1;
        const tuple = self.fixture.collect(record.worker.endpoint, accepted.reference, accepted.length) orelse return null;
        return .{ .endpoint = record.worker.endpoint, .id = accepted.id, .token = accepted.contract, .attempt = accepted.attempt, .tuple = tuple };
    }
};
fn stage(results: *analysis.Results, candidate: analysis.Result) !void {
    var digest = wire.encode(wire.reply_operation, .{ .id = candidate.id, .command = .work, .kind = .response, .detail = candidate.attempt, .token = candidate.token, .data = candidate.tuple.digest });
    digest.sender = candidate.endpoint;
    var counts = wire.encode(wire.reply_operation, .{ .id = candidate.id, .command = .analysis_tuple, .kind = .response, .detail = candidate.attempt, .token = candidate.token, .data = candidate.tuple.counts() });
    counts.sender = candidate.endpoint;
    try testing.expect(results.push(&digest) == null);
    try testing.expect(results.hold(results.push(&counts).?));
}

test "actual capture accepted worker and independent full tuple survive original source mutation" {
    var fixture = Fixture.init();
    const bytes = "first\nline\x00\xff\nthird\nline!";
    const input = try fixture.input("/alpha", bytes);
    var seam: Seam = .{ .fixture = &fixture };
    var broker = core.Broker.init(broker_endpoint, owner);
    const record = try broker.offerAnalysis(owner, 1, input.reference.token, input.reference.issuer, &seam);
    try seam.bind(record);
    try testing.expectEqual(@as(u64, 0), seam.worker_reads);
    try testing.expectEqual(@as(u64, 0), seam.fake.send_calls);
    try testing.expectEqual(@as(u64, 1), seam.fake.create_calls);
    try fixture.write(input.handle, 0, "changed!");
    _ = try broker.accept(owner, record.token, input.reference.token, 2, &seam);
    const candidate = seam.execute(record).?;
    try testing.expect(analysis.calculate(bytes).?.eql(candidate.tuple));
    _ = try broker.deliverAnalysis(candidate, &seam);
    try testing.expect(record.verified and record.state == .completed);
    try testing.expectEqual(candidate.tuple.digest, record.result);
    try testing.expectEqual(candidate.tuple.newlines, record.newlines);
    try testing.expectEqual(@as(usize, 0), fixture.server.snapshots.backing());
    try testing.expectEqual(@as(usize, 1), fixture.server.snapshots.retained());
    try testing.expect(broker.conserved(seam.domain().?) and record.backing_slots == 0 and record.backing_pages == 0);
    try testing.expect(seam.broker_reads == 3 and seam.worker_reads == 1);
    try fixture.close(input.reference);
    try broker.reap(owner, record.token);
    try testing.expectEqual(@as(usize, 0), fixture.server.snapshots.retained());
}

test "every altered result component fails independently and returns worker and byte backing" {
    for (0..3) |field| {
        var fixture = Fixture.init();
        const input = try fixture.input("/alpha", "\n\x00same\xfflen\n");
        var seam: Seam = .{ .fixture = &fixture };
        var broker = core.Broker.init(broker_endpoint, owner);
        const record = try broker.offerAnalysis(owner, 1, input.reference.token, input.reference.issuer, &seam);
        try seam.bind(record);
        _ = try broker.accept(owner, record.token, input.reference.token, 2, &seam);
        var candidate = seam.execute(record).?;
        switch (field) {
            0 => candidate.tuple.length += 1,
            1 => candidate.tuple.newlines += 1,
            2 => candidate.tuple.digest ^= 1,
            else => unreachable,
        }
        try testing.expectError(core.Error.invalid, broker.deliverAnalysis(candidate, &seam));
        try testing.expect(record.state == .failed and !record.verified and record.result == 0);
        try testing.expect(broker.conserved(seam.domain().?) and record.backing_slots == 0 and record.backing_pages == 0);
        try testing.expectEqual(@as(usize, 0), fixture.server.snapshots.backing());
        try fixture.close(input.reference);
    }
}

test "release binding revocation before stop and changed retirement fence both prevent success" {
    for (0..3) |race| {
        var fixture = Fixture.init();
        const input = try fixture.input("/alpha", "actualbytes\n");
        var seam: Seam = .{ .fixture = &fixture };
        var broker = core.Broker.init(broker_endpoint, owner);
        const record = try broker.offerAnalysis(owner, 1, input.reference.token, input.reference.issuer, &seam);
        try seam.bind(record);
        _ = try broker.accept(owner, record.token, input.reference.token, 2, &seam);
        const candidate = seam.execute(record).?;
        if (race == 0) seam.revoke_at_release = true else if (race == 1) seam.fake.fault_during_settle = true else seam.fake.restart_during_settle = true;
        if (race == 0) try testing.expectError(core.Error.cleanup, broker.deliverAnalysis(candidate, &seam)) else try testing.expectError(core.Error.stale, broker.deliverAnalysis(candidate, &seam));
        try testing.expect(record.state == .failed and !record.verified and record.result == 0);
        try testing.expect(broker.conserved(seam.domain().?) and record.backing_slots == 0 and record.backing_pages == 0);
        try testing.expectEqual(if (race == 0) @as(usize, 128) else @as(usize, 0), fixture.server.snapshots.backing());
        try fixture.close(input.reference);
    }
}

test "old private attempt staging retirement preserves sibling and retry reads same captured bytes" {
    var fixture = Fixture.init();
    const a = try fixture.input("/alpha", "retry immutable\n\x00\xff");
    const b = try fixture.input("/beta", "separate live\n");
    var seam: Seam = .{ .fixture = &fixture };
    var broker = core.Broker.init(broker_endpoint, owner);
    const affected = try broker.offerAnalysis(owner, 1, a.reference.token, a.reference.issuer, &seam);
    const sibling = try broker.offerAnalysis(owner, 2, b.reference.token, b.reference.issuer, &seam);
    try seam.bind(affected);
    try seam.bind(sibling);
    _ = try broker.accept(owner, affected.token, a.reference.token, 2, &seam);
    _ = try broker.accept(owner, sibling.token, b.reference.token, 2, &seam);
    const old = seam.execute(affected).?;
    const other = seam.execute(sibling).?;
    var staged: analysis.Results = .{};
    try stage(&staged, old);
    try stage(&staged, other);
    _ = try broker.workerFault(affected.worker.endpoint, &seam);
    staged.release(affected.token);
    try fixture.write(a.handle, 0, "mutated!");
    seam.allow_retry = true;
    _ = try broker.retry(affected.token, &seam);
    try testing.expectError(core.Error.stale, broker.deliverAnalysis(old, &seam));
    const current = seam.execute(affected).?;
    try testing.expect(current.endpoint != old.endpoint and current.attempt == 2 and current.tuple.eql(old.tuple));
    try stage(&staged, current);
    var completed: usize = 0;
    for (0..9) |_| for (staged.advance()) |pending| if (pending) |candidate| {
        _ = try broker.deliverAnalysis(candidate, &seam);
        completed += 1;
    };
    try testing.expectEqual(@as(usize, 2), completed);
    try testing.expect(affected.verified and sibling.verified and broker.conserved(seam.domain().?));
    try testing.expectEqual(@as(u64, 1), seam.fake.rebind_calls);
    try testing.expectEqual(@as(usize, 0), fixture.server.snapshots.backing());
    try fixture.close(a.reference);
    try fixture.close(b.reference);
}

test "retry without explicit input authorization fails finite cleanup and second failure exhausts one retry" {
    for ([_]bool{ false, true }) |authorized| {
        var fixture = Fixture.init();
        const input = try fixture.input("/alpha", "input\n");
        var seam: Seam = .{ .fixture = &fixture, .allow_retry = authorized };
        var broker = core.Broker.init(broker_endpoint, owner);
        const record = try broker.offerAnalysis(owner, 1, input.reference.token, input.reference.issuer, &seam);
        try seam.bind(record);
        _ = try broker.accept(owner, record.token, input.reference.token, 2, &seam);
        _ = try broker.workerFault(record.worker.endpoint, &seam);
        if (!authorized) {
            try testing.expectError(core.Error.resource, broker.retry(record.token, &seam));
            try testing.expectEqual(@as(u8, 0), record.retries);
        } else {
            _ = try broker.retry(record.token, &seam);
            _ = try broker.workerFault(record.worker.endpoint, &seam);
            try testing.expectEqual(@as(u8, 1), record.retries);
            try testing.expectEqual(core.Reason.second_fault, record.reason);
        }
        try testing.expect(record.state == .failed and !record.verified);
        try testing.expect(broker.conserved(seam.domain().?) and record.backing_slots == 0 and record.backing_pages == 0);
        try testing.expectEqual(@as(usize, 0), fixture.server.snapshots.backing());
        try fixture.close(input.reference);
    }
}

test "dependency cold retirement rejects a privately computed candidate without substitute capture" {
    var fixture = Fixture.init();
    const input = try fixture.input("/alpha", "old dependency bytes");
    var seam: Seam = .{ .fixture = &fixture };
    var broker = core.Broker.init(broker_endpoint, owner);
    const record = try broker.offerAnalysis(owner, 1, input.reference.token, input.reference.issuer, &seam);
    try seam.bind(record);
    _ = try broker.accept(owner, record.token, input.reference.token, 2, &seam);
    const candidate = seam.execute(record).?;
    fixture.server = fs_runtime.Server.initAt(2, 0x202);
    fixture.io.refresh(&fixture.server);
    try testing.expectError(core.Error.cleanup, broker.deliverAnalysis(candidate, &seam));
    try testing.expect(record.state == .failed and !record.verified and record.result == 0);
    try testing.expectEqual(@as(usize, 0), fixture.server.snapshots.retained());
    try testing.expectEqual(@as(u64, 1), seam.fake.create_calls);
    try testing.expect(broker.conserved(seam.domain().?) and record.backing_slots == 0 and record.backing_pages == 0);
}

test "ordered work descriptor malformed duplicate gap wrong owner attempt and replay never reads" {
    const token = wire.token(1, 0, broker_endpoint).?;
    var input = wire.encode(wire.request_operation, .{ .id = 1, .command = .input, .detail = 1, .token = token, .data = 0x102 });
    input.sender = broker_endpoint;
    var length = wire.encode(wire.request_operation, .{ .id = 1, .command = .input_length, .detail = 1, .token = token, .data = 9 });
    length.sender = broker_endpoint;
    var work = wire.encode(wire.request_operation, .{ .id = 1, .command = .work, .detail = 1, .token = token, .data = 0x1a1 });
    work.sender = broker_endpoint;
    for (0..7) |mutation| {
        var state: worker_runtime.Worker = .{ .parent = broker_endpoint };
        var changed = length;
        if (mutation == 0) try testing.expect(state.accept(&work) == null);
        try testing.expect(state.accept(&input) == null);
        switch (mutation) {
            0 => changed.payload[24] = 129,
            1 => changed.sender += 0x100,
            2 => changed.payload[11] = 2,
            3 => changed.payload[0] += 1,
            4 => changed.payload[27] = 2,
            5 => {
                try testing.expect(state.accept(&input) == null);
            },
            6 => {
                try testing.expect(state.accept(&length) == null);
            },
            else => unreachable,
        }
        try testing.expect(state.accept(&changed) == null);
        try testing.expect(state.accept(&work) == null);
    }
    var current: worker_runtime.Worker = .{ .parent = broker_endpoint };
    try testing.expect(current.accept(&input) == null and current.accept(&length) == null);
    const accepted = current.accept(&work).?;
    try testing.expectEqual(@as(u8, 9), accepted.length);
    try testing.expectEqual(@as(u64, 0x102), accepted.reference.issuer);
    try testing.expect(current.accept(&input) == null and current.accept(&length) == null and current.accept(&work) == null);
}

test "offered and running cancellation retire exact input while sibling and fresh reused records survive" {
    for ([_]bool{ false, true }) |running| {
        var fixture = Fixture.init();
        const a = try fixture.input("/alpha", "cancel-a\n");
        const b = try fixture.input("/beta", "live-b\n");
        var seam: Seam = .{ .fixture = &fixture };
        var broker = core.Broker.init(broker_endpoint, owner);
        const affected = try broker.offerAnalysis(owner, 1, a.reference.token, a.reference.issuer, &seam);
        const sibling = try broker.offerAnalysis(owner, 2, b.reference.token, b.reference.issuer, &seam);
        try seam.bind(affected);
        try seam.bind(sibling);
        _ = try broker.accept(owner, sibling.token, b.reference.token, 2, &seam);
        const other = seam.execute(sibling).?;
        var old: ?analysis.Result = null;
        if (running) {
            _ = try broker.accept(owner, affected.token, a.reference.token, 2, &seam);
            old = seam.execute(affected);
        }
        const predecessor = affected.*;
        _ = try broker.cancel(owner, affected.token, &seam);
        try testing.expect(affected.state == .cancelled and !affected.verified and affected.result == 0);
        try testing.expectEqual(@as(usize, 128), fixture.server.snapshots.backing());
        if (old) |candidate| try testing.expectError(core.Error.stale, broker.deliverAnalysis(candidate, &seam));
        const cancelled = affected.*;
        _ = try broker.cancel(owner, affected.token, &seam);
        try testing.expectEqual(cancelled, affected.*);
        _ = try broker.deliverAnalysis(other, &seam);
        try testing.expect(sibling.verified and sibling.state == .completed);
        try fixture.close(a.reference);
        try broker.reap(owner, affected.token);
        const fresh = try fixture.input("/alpha", "renew-a!\n");
        const successor = try broker.offerAnalysis(owner, 3, fresh.reference.token, fresh.reference.issuer, &seam);
        try seam.bind(successor);
        try testing.expect(successor.token != predecessor.token and successor.worker.endpoint != predecessor.worker.endpoint);
        try testing.expect(fresh.reference.token != a.reference.token);
        try testing.expect(fixture.collect(predecessor.worker.endpoint, fresh.reference, fresh.length) == null);
        try testing.expectEqual(storage.Status.stale, fixture.server.snapshots.close(owner, a.reference));
        _ = try broker.accept(owner, successor.token, fresh.reference.token, 2, &seam);
        const candidate = seam.execute(successor).?;
        var stages: analysis.Results = .{};
        try stage(&stages, candidate);
        stages.release(predecessor.token);
        var published = false;
        for (0..9) |_| for (stages.advance()) |pending| if (pending) |ready| {
            _ = try broker.deliverAnalysis(ready, &seam);
            published = true;
        };
        try testing.expect(published and successor.verified and broker.conserved(seam.domain().?));
        try testing.expectError(core.Error.stale, broker.status(owner, predecessor.token));
        try fixture.close(fresh.reference);
        try fixture.close(b.reference);
        try testing.expectEqual(@as(usize, 0), fixture.server.snapshots.retained());
    }
}

test "full binary profile covers empty and exact chunk boundaries through capture worker and verifier" {
    const lengths = [_]usize{ 0, 1, 7, 8, 9, 127, 128 };
    var bytes: [128]u8 = undefined;
    for (&bytes, 0..) |*byte, index| byte.* = switch (index % 3) {
        0 => 0x0a,
        1 => 0,
        else => 0xff,
    };
    for (lengths) |length| {
        var fixture = Fixture.init();
        const input = try fixture.input("/alpha", bytes[0..length]);
        var seam: Seam = .{ .fixture = &fixture };
        var broker = core.Broker.init(broker_endpoint, owner);
        const record = try broker.offerAnalysis(owner, 1, input.reference.token, input.reference.issuer, &seam);
        try seam.bind(record);
        _ = try broker.accept(owner, record.token, input.reference.token, 2, &seam);
        const candidate = seam.execute(record).?;
        try testing.expect(analysis.calculate(bytes[0..length]).?.eql(candidate.tuple));
        _ = try broker.deliverAnalysis(candidate, &seam);
        try testing.expect(record.verified and record.input_length == length);
        try testing.expectEqual(@as(usize, 0), fixture.server.snapshots.backing());
        try fixture.close(input.reference);
        if (length == 128) {
            const transaction = fixture.id();
            const response = fixture.process(storage_wire.request(.file_write, transaction, input.handle, 128, 1, "!"), owner).?;
            try testing.expectEqual(@as(i32, -6), storage_wire.decodeReply(&response, .file_result, 0x102, transaction).?.value);
            try testing.expectEqual(@as(u32, 128), fixture.server.fs.files[1].length);
        }
    }
}

test "exact pending cancellation during verifier or committed input release wins without second success and preserves sibling" {
    for (0..4) |phase| {
        var fixture = Fixture.init();
        const a = try fixture.input("/alpha", "cancel race\n");
        const b = try fixture.input("/beta", "unrelated\n");
        var seam: Seam = .{ .fixture = &fixture };
        var broker = core.Broker.init(broker_endpoint, owner);
        const affected = try broker.offerAnalysis(owner, 1, a.reference.token, a.reference.issuer, &seam);
        const sibling = try broker.offerAnalysis(owner, 2, b.reference.token, b.reference.issuer, &seam);
        try seam.bind(affected);
        try seam.bind(sibling);
        _ = try broker.accept(owner, affected.token, a.reference.token, 2, &seam);
        _ = try broker.accept(owner, sibling.token, b.reference.token, 2, &seam);
        const candidate = seam.execute(affected).?;
        const other = seam.execute(sibling).?;
        seam.cancel_target = affected.token;
        if (phase == 0) seam.cancel_during_verify = true else seam.cancel_during_release = true;
        if (phase == 2) seam.fake.fault_during_settle = true;
        if (phase == 3) seam.fake.restart_during_settle = true;
        try testing.expectError(core.Error.stale, broker.deliverAnalysis(candidate, &seam));
        try testing.expect(affected.state == .cancelled and affected.reason == .cancelled and !affected.verified and affected.result == 0);
        try testing.expectEqual(@as(u64, 1), seam.release_calls);
        const committed = affected.*;
        _ = try broker.cancel(owner, affected.token, &seam);
        try testing.expectEqual(committed, affected.*);
        try testing.expectError(core.Error.stale, broker.deliverAnalysis(candidate, &seam));
        try testing.expectEqual(@as(u64, 1), seam.release_calls);
        seam.fake.fault_during_settle = false;
        seam.fake.restart_during_settle = false;
        _ = try broker.deliverAnalysis(other, &seam);
        try testing.expect(sibling.verified and broker.conserved(seam.domain().?));
        try testing.expectEqual(@as(usize, 0), fixture.server.snapshots.backing());
        try fixture.close(a.reference);
        try fixture.close(b.reference);
    }
}

test "dequeued exact owner cancellation during rebind preserves terminal decision and never dispatches retry" {
    var fixture = Fixture.init();
    const a = try fixture.input("/alpha", "retry cancelled\n");
    const b = try fixture.input("/beta", "sibling\n");
    var seam: Seam = .{ .fixture = &fixture, .allow_retry = true, .cancel_in_rebind = true };
    var broker = core.Broker.init(broker_endpoint, owner);
    seam.broker = &broker;
    const affected = try broker.offerAnalysis(owner, 1, a.reference.token, a.reference.issuer, &seam);
    const sibling = try broker.offerAnalysis(owner, 2, b.reference.token, b.reference.issuer, &seam);
    try seam.bind(affected);
    try seam.bind(sibling);
    _ = try broker.accept(owner, affected.token, a.reference.token, 2, &seam);
    _ = try broker.accept(owner, sibling.token, b.reference.token, 2, &seam);
    const other = seam.execute(sibling).?;
    _ = try broker.workerFault(affected.worker.endpoint, &seam);
    const sends_before = seam.fake.send_calls;
    _ = try broker.retry(affected.token, &seam);
    try testing.expect(affected.state == .cancelled and affected.reason == .cancelled and !affected.verified and affected.retries == 0);
    try testing.expectEqual(sends_before, seam.fake.send_calls);
    try testing.expectEqual(@as(u64, 1), seam.fake.rebind_calls);
    try testing.expectEqual(@as(u8, 0), affected.backing_slots);
    try testing.expectEqual(@as(u8, 0), affected.backing_pages);
    _ = try broker.deliverAnalysis(other, &seam);
    try testing.expect(sibling.verified and broker.conserved(seam.domain().?));
    try fixture.close(a.reference);
    try fixture.close(b.reference);
}

test "one snapshot client sequence separates boot denial and accepted reads and exhausts without alias" {
    var client: reader.Client = .{};
    const reference: snapshot.Ref = .{ .issuer = 0x102, .token = 0x1a1 };
    const boot_id = client.sequence.take().?;
    var denied = snapshot_wire.readReply(boot_id, reference, 0, @intFromEnum(storage.Status.denied), &.{});
    denied.sender = reference.issuer;
    const boot: snapshot_wire.Read = .{ .transaction = boot_id, .reference = reference, .offset = 0, .count = 8 };
    try testing.expectEqual(storage.Status.denied, snapshot_wire.decodeReadReply(&denied, boot).?.status);
    const accepted_id = client.sequence.take().?;
    try testing.expect(accepted_id > boot_id);
    const accepted: snapshot_wire.Read = .{ .transaction = accepted_id, .reference = reference, .offset = 0, .count = 8 };
    try testing.expect(snapshot_wire.decodeReadReply(&denied, accepted) == null);
    var bytes = snapshot_wire.readReply(accepted_id, reference, 0, 8, "12345678");
    bytes.sender = reference.issuer;
    try testing.expectEqual(@as(u8, 8), snapshot_wire.decodeReadReply(&bytes, accepted).?.count);
    client.sequence.next = std.math.maxInt(u64);
    try testing.expectEqual(std.math.maxInt(u64), client.sequence.take().?);
    try testing.expect(client.sequence.take() == null and client.sequence.next == 0);
}

test "closed or checker-revoked input before acceptance never dispatches and reports honest cleanup" {
    for ([_]bool{ false, true }) |revoked| {
        var fixture = Fixture.init();
        const input = try fixture.input("/alpha", "prepared then invalid\n");
        var seam: Seam = .{ .fixture = &fixture };
        var broker = core.Broker.init(broker_endpoint, owner);
        const record = try broker.offerAnalysis(owner, 1, input.reference.token, input.reference.issuer, &seam);
        try seam.bind(record);
        if (revoked) try testing.expectEqual(storage.Status.ok, fixture.server.snapshots.revoke(owner, input.reference, broker_endpoint)) else try testing.expectEqual(storage.Status.ok, fixture.server.snapshots.close(owner, input.reference));
        try testing.expectError(core.Error.cleanup, broker.accept(owner, record.token, input.reference.token, 2, &seam));
        try testing.expect(record.state == .failed and !record.verified and record.attempt == 0 and record.rpc == 0);
        try testing.expectEqual(@as(u64, 0), seam.worker_reads);
        try testing.expectEqual(@as(u64, 0), seam.fake.send_calls);
        try testing.expectEqual(@as(u8, 0), record.backing_slots);
        try testing.expectEqual(@as(u8, 0), record.backing_pages);
        try testing.expectEqual(if (revoked) @as(usize, 128) else @as(usize, 0), fixture.server.snapshots.backing());
        try testing.expectEqual(@as(usize, 1), fixture.server.snapshots.retained());
        try fixture.close(input.reference);
        try broker.reap(owner, record.token);
        try testing.expect(broker.conserved(seam.domain().?) and fixture.server.snapshots.retained() == 0);
    }
}

test "pure offer highwater table serial and domain errors spend no input read or allocation identity" {
    var fixture = Fixture.init();
    const input = try fixture.input("/alpha", "bounded input");
    var seam: Seam = .{ .fixture = &fixture };
    var broker = core.Broker.init(broker_endpoint, owner);
    const first = try broker.offerAnalysis(owner, 1, input.reference.token, input.reference.issuer, &seam);
    const second = try broker.offerAnalysis(owner, 2, input.reference.token, input.reference.issuer, &seam);
    const reads = seam.broker_reads;
    const serial = broker.next_serial;
    const creates = seam.fake.create_calls;
    try testing.expectError(error.no_space, broker.offerAnalysis(owner, 3, input.reference.token, input.reference.issuer, &seam));
    try testing.expectEqual(reads, seam.broker_reads);
    try testing.expectEqual(serial, broker.next_serial);
    try testing.expectEqual(creates, seam.fake.create_calls);
    const token = first.token;
    _ = try broker.cancel(owner, first.token, &seam);
    try broker.reap(owner, token);
    try testing.expectError(error.stale, broker.offerAnalysis(owner, 1, input.reference.token, input.reference.issuer, &seam));
    try testing.expectEqual(reads, seam.broker_reads);
    // Cancelled input is already settled; counter/domain prevalidation still
    // wins before an attempted read of that unusable object.
    broker.next_serial = 0;
    try testing.expectError(error.exhausted, broker.offerAnalysis(owner, 4, input.reference.token, input.reference.issuer, &seam));
    try testing.expectEqual(reads, seam.broker_reads);
    broker.next_serial = serial;
    seam.fake.bad_domain = true;
    try testing.expectError(error.resource, broker.offerAnalysis(owner, 4, input.reference.token, input.reference.issuer, &seam));
    try testing.expectEqual(reads, seam.broker_reads);
    seam.fake.bad_domain = false;
    _ = try broker.cancel(owner, second.token, &seam);
}

fn stageRequest(table: *core.Broker, seam: *Seam, packet: wire.Packet, sender: u64) dispatcher.Dispatch {
    var message = wire.encode(wire.request_operation, packet);
    message.sender = sender;
    return dispatcher.dispatch(table, &message, seam);
}
fn stageFailure(value: dispatcher.Dispatch, expected: core.Error) !void {
    switch (value) {
        .failure => |failure| try testing.expectEqual(expected, failure.reason),
        else => return error.UnexpectedStageReply,
    }
}
fn stageTuple(seam: *Seam, table: *const core.Broker, candidate: analysis.Result) !void {
    var digest = wire.encode(wire.reply_operation, .{ .id = candidate.id, .command = .work, .kind = .response,
        .detail = candidate.attempt, .token = candidate.token, .data = candidate.tuple.digest });
    digest.sender = candidate.endpoint;
    var counts = wire.encode(wire.reply_operation, .{ .id = candidate.id, .command = .analysis_tuple, .kind = .response,
        .detail = candidate.attempt, .token = candidate.token, .data = candidate.tuple.counts() });
    counts.sender = candidate.endpoint;
    try testing.expectEqual(std.meta.Tag(staging.Deferred).ignored, std.meta.activeTag(seam.stages.push(table, &digest)));
    try testing.expectEqual(std.meta.Tag(staging.Deferred).held, std.meta.activeTag(seam.stages.push(table, &counts)));
}

test "production staged dispatch authenticates owner input profile and pending identity without repeating work" {
    var fixture = Fixture.init();
    const input = try fixture.input("/alpha", "staged bytes\n");
    var seam: Seam = .{ .fixture = &fixture };
    var table = core.Broker.init(broker_endpoint, owner);
    const record = try table.offerAnalysis(owner, 1, input.reference.token, input.reference.issuer, &seam);
    try seam.bind(record);
    const request: wire.Packet = .{ .id = 2, .command = .stage, .detail = 2, .token = record.token, .data = record.input };
    try testing.expectEqual(std.meta.Tag(dispatcher.Dispatch).ignored, std.meta.activeTag(stageRequest(&table, &seam, request, owner + 256)));
    var wrong = request;
    wrong.data ^= 1;
    try stageFailure(stageRequest(&table, &seam, wrong, owner), error.invalid);
    wrong = request;
    wrong.detail = 1;
    try stageFailure(stageRequest(&table, &seam, wrong, owner), error.invalid);
    wrong = request;
    wrong.token += @as(u64, 256) << 32;
    try stageFailure(stageRequest(&table, &seam, wrong, owner), error.stale);
    try testing.expectEqual(@as(u64, 0), seam.fake.send_calls);
    try testing.expectEqual(std.meta.Tag(dispatcher.Dispatch).pending, std.meta.activeTag(stageRequest(&table, &seam, request, owner)));
    const assigned = record.*;
    try testing.expectEqual(std.meta.Tag(dispatcher.Dispatch).pending, std.meta.activeTag(stageRequest(&table, &seam, request, owner)));
    wrong = request;
    wrong.id += 1;
    try stageFailure(stageRequest(&table, &seam, wrong, owner), error.invalid);
    try testing.expectEqual(assigned, record.*);
    try testing.expectEqual(@as(u64, 1), seam.fake.send_calls);
    for (0..18) |_| {
        _ = seam.stages.advance(&table);
        try testing.expect(seam.stages.ready(&table)[0] == null and seam.stages.ready(&table)[1] == null);
    }
    try stageFailure(stageRequest(&table, &seam, .{ .id = 4, .command = .stage, .token = record.token, .data = record.rpc }, owner), error.not_ready);
    _ = try table.cancel(owner, record.token, &seam);
    _ = seam.stages.advance(&table);
    try fixture.close(input.reference);
    try testing.expect(table.conserved(seam.domain().?));
}

test "staging readiness requires full real tuple pins only exact candidates and late cancellation preserves sibling FIFO progress" {
    var fixture = Fixture.init();
    const a = try fixture.input("/alpha", "active\nbytes");
    const b = try fixture.input("/beta", "sibling\nbytes");
    var seam: Seam = .{ .fixture = &fixture };
    var table = core.Broker.init(broker_endpoint, owner);
    const active = try table.offerAnalysis(owner, 1, a.reference.token, a.reference.issuer, &seam);
    const sibling = try table.offerAnalysis(owner, 2, b.reference.token, b.reference.issuer, &seam);
    try seam.bind(active);
    try seam.bind(sibling);
    const first: wire.Packet = .{ .id = 3, .command = .stage, .detail = 2, .token = active.token, .data = active.input };
    const second: wire.Packet = .{ .id = 4, .command = .stage, .detail = 2, .token = sibling.token, .data = sibling.input };
    try testing.expectEqual(std.meta.Tag(dispatcher.Dispatch).pending, std.meta.activeTag(stageRequest(&table, &seam, first, owner)));
    try testing.expectEqual(std.meta.Tag(dispatcher.Dispatch).pending, std.meta.activeTag(stageRequest(&table, &seam, second, owner)));
    const candidate = seam.execute(active).?;
    const other = seam.execute(sibling).?;
    var digest = wire.encode(wire.reply_operation, .{ .id = candidate.id, .command = .work, .kind = .response,
        .detail = candidate.attempt, .token = candidate.token, .data = candidate.tuple.digest });
    digest.sender = candidate.endpoint;
    _ = seam.stages.push(&table, &digest);
    for (0..9) |_| { _ = seam.stages.advance(&table); try testing.expect(seam.stages.ready(&table)[wire.tokenSlot(active.token).?] == null); }
    var counts = wire.encode(wire.reply_operation, .{ .id = candidate.id, .command = .analysis_tuple, .kind = .response,
        .detail = candidate.attempt, .token = candidate.token, .data = candidate.tuple.counts() });
    counts.sender = candidate.endpoint;
    for (0..4) |mutation| {
        var forged = counts;
        switch (mutation) { 0 => forged.sender += 256, 1 => forged.payload[0] += 1, 2 => forged.payload[11] += 1,
            3 => wire.put64(&forged.payload, 16, sibling.token), else => unreachable }
        try testing.expectEqual(std.meta.Tag(staging.Deferred).rejected, std.meta.activeTag(seam.stages.push(&table, &forged)));
        try testing.expect(seam.stages.ready(&table)[wire.tokenSlot(active.token).?] == null);
    }
    try testing.expectEqual(std.meta.Tag(staging.Deferred).held, std.meta.activeTag(seam.stages.push(&table, &counts)));
    try stageTuple(&seam, &table, other);
    const ready = seam.stages.ready(&table);
    for (ready) |ack| { try testing.expect(ack != null and ack.?.snapshot.state == .running and !ack.?.snapshot.verified); }
    try testing.expectEqual(candidate.id, ready[wire.tokenSlot(active.token).?].?.snapshot.rpc);
    try testing.expectEqual(std.meta.Tag(dispatcher.Dispatch).pending, std.meta.activeTag(stageRequest(&table, &seam, first, owner)));
    try testing.expect(seam.stages.ready(&table)[wire.tokenSlot(active.token).?] != null);
    // Full inbox pressure and FIFO contents remain independent of the two pins.
    var inbox: @import("hosting_transport.zig").Inbox = .{};
    for (0..8) |index| { var message = wire.encode(wire.request_operation, .{ .id = index + 1, .command = .status, .token = sibling.token }); message.sender = owner; try testing.expect(inbox.push(message)); }
    try testing.expect(!inbox.push(digest));
    for (0..24) |_| for (seam.stages.advance(&table)) |result| try testing.expect(result == null);
    try testing.expectEqual(wire.State.running, sibling.state);
    try testing.expectEqual(storage.Status.ok, fixture.server.snapshots.revoke(owner, a.reference, active.worker.endpoint));
    _ = try table.cancel(owner, active.token, &seam);
    const late = seam.stages.advance(&table)[wire.tokenSlot(active.token).?].?;
    try testing.expectError(error.stale, table.deliverAnalysis(late, &seam));
    try testing.expect(active.state == .cancelled and sibling.state == .running and !active.verified);
    try stageFailure(stageRequest(&table, &seam, .{ .id = 5, .command = .stage, .token = sibling.token, .data = active.rpc }, owner), error.stale);
    const released = stageRequest(&table, &seam, .{ .id = 6, .command = .stage, .token = sibling.token, .data = sibling.rpc }, owner);
    try testing.expectEqual(std.meta.Tag(dispatcher.Dispatch).snapshot, std.meta.activeTag(released));
    try stageFailure(stageRequest(&table, &seam, .{ .id = 7, .command = .stage, .token = sibling.token, .data = sibling.rpc }, owner), error.not_ready);
    for (0..9) |_| for (seam.stages.advance(&table)) |result| if (result) |value| { _ = try table.deliverAnalysis(value, &seam); };
    try testing.expect(sibling.verified and sibling.state == .completed and table.conserved(seam.domain().?));
    for (0..8) |index| { const message = inbox.pop().?; try testing.expectEqual(@as(u64, index + 1), wire.get64(&message.payload, 0)); }
    try testing.expect(inbox.pop() == null);
    try fixture.close(a.reference);
    try fixture.close(b.reference);
    try testing.expectEqual(@as(usize, 0), fixture.server.snapshots.backing());
    std.debug.print("staging gate metadata bytes={d}; staged pair bytes={d}; old collector bytes={d}\n",
        .{ staging.gate_metadata_bytes, @sizeOf(analysis.StagePair), @sizeOf(analysis.Collector) });
}

test "staging cancellation before full result expiry and generation retirement cannot acknowledge or retain successor scope" {
    for (0..3) |boundary| {
        var fixture = Fixture.init();
        const input = try fixture.input("/alpha", "retired\nbytes");
        var seam: Seam = .{ .fixture = &fixture, .allow_retry = true };
        var table = core.Broker.init(broker_endpoint, owner);
        const record = try table.offerAnalysis(owner, 1, input.reference.token, input.reference.issuer, &seam);
        try seam.bind(record);
        const request: wire.Packet = .{ .id = 2, .command = .stage, .detail = 2, .token = record.token, .data = record.input };
        _ = stageRequest(&table, &seam, request, owner);
        const old = seam.execute(record).?;
        if (boundary != 0) { try stageTuple(&seam, &table, old); try testing.expect(seam.stages.ready(&table)[wire.tokenSlot(record.token).?] != null); }
        if (boundary == 0) {
            var partial = wire.encode(wire.reply_operation, .{ .id = old.id, .command = .work, .kind = .response,
                .detail = old.attempt, .token = old.token, .data = old.tuple.digest });
            partial.sender = old.endpoint;
            _ = seam.stages.push(&table, &partial);
            _ = try table.cancel(owner, record.token, &seam);
        } else if (boundary == 1) {
            // Pin does not extend the runtime's existing160iteration expiry.
            for (0..159) |_| for (seam.stages.advance(&table)) |candidate| try testing.expect(candidate == null);
            _ = try table.expire(record.token, &seam);
        } else { _ = try table.workerFault(record.worker.endpoint, &seam); }
        const removed = seam.stages.advance(&table)[wire.tokenSlot(record.token).?];
        if (boundary != 0) { try testing.expect(removed != null); try testing.expectError(error.stale, table.deliverAnalysis(removed.?, &seam)); }
        try testing.expect(seam.stages.ready(&table)[wire.tokenSlot(record.token).?] == null);
        if (boundary == 2) {
            _ = try table.retry(record.token, &seam);
            try testing.expect(record.worker.endpoint != old.endpoint and record.rpc != old.id and record.attempt == 2);
            try stageFailure(stageRequest(&table, &seam, request, owner), error.not_ready);
            _ = try table.deliverAnalysis(seam.execute(record).?, &seam);
        } else { try stageFailure(stageRequest(&table, &seam, request, owner), error.not_ready); }
        try testing.expectError(error.stale, table.deliverAnalysis(old, &seam));
        try testing.expect(table.conserved(seam.domain().?));
        try fixture.close(input.reference);
    }
}

test "production staged pair collectors independently bind full copies and keep original per-RPC receive bounds" {
    var fixture = Fixture.init();
    const a = try fixture.input("/alpha", "pair alpha\n");
    const b = try fixture.input("/beta", "pair beta\n");
    var seam: Seam = .{ .fixture = &fixture };
    var table = core.Broker.init(broker_endpoint, owner);
    const first = try table.offerAnalysis(owner, 1, a.reference.token, a.reference.issuer, &seam);
    const second = try table.offerAnalysis(owner, 2, b.reference.token, b.reference.issuer, &seam);
    try seam.bind(first);
    try seam.bind(second);
    const packets: [2]wire.Packet = .{ .{ .id = 3, .command = .stage, .detail = 2, .token = first.token, .data = first.input },
        .{ .id = 4, .command = .stage, .detail = 2, .token = second.token, .data = second.input } };
    for (packets) |packet| _ = stageRequest(&table, &seam, packet, owner);
    try stageTuple(&seam, &table, seam.execute(first).?);
    try stageTuple(&seam, &table, seam.execute(second).?);
    const ready = seam.stages.ready(&table);
    var messages: [2][10]abi.Message = undefined;
    for (ready, 0..) |ack, index| {
        messages[index][0..8].* = ack.?.snapshot.messages(packets[index].id, .stage);
        messages[index][8] = wire.encode(wire.reply_operation, .{ .id = packets[index].id, .command = .stage, .kind = .snapshot,
            .detail = 8, .token = ack.?.snapshot.token, .data = ack.?.snapshot.input_issuer });
        messages[index][9] = wire.encode(wire.reply_operation, .{ .id = packets[index].id, .command = .stage, .kind = .snapshot,
            .detail = 9, .token = ack.?.snapshot.token, .data = ack.?.snapshot.input_length });
        for (&messages[index]) |*message| message.sender = broker_endpoint;
    }
    var pair = analysis.StagePair.init(broker_endpoint, owner, packets);
    // Twelve timeout/unrelated wakes plus twenty actual parts use exactly32.
    for (0..12) |_| try testing.expect(pair.step());
    for (0..10) |part| for (0..2) |index| {
        try testing.expect(pair.step());
        try testing.expect(pair.push(&messages[index][part]));
        if (part != 9 or index != 1) try testing.expect(pair.take() == null);
    };
    try testing.expect(pair.take() != null and !pair.step());
    try testing.expectEqual(@as(u8, 0), pair.remaining[1]);
    var exhausted = analysis.StagePair.init(broker_endpoint, owner, packets);
    for (messages[0]) |message| { try testing.expect(exhausted.step()); try testing.expect(exhausted.push(&message)); }
    for (0..22) |_| try testing.expect(exhausted.step());
    try testing.expect(!exhausted.step() and exhausted.take() == null and exhausted.remaining[1] == 0);
    var partial = analysis.StagePair.init(broker_endpoint, owner, packets);
    try testing.expect(partial.step() and partial.push(&messages[0][0]));
    try testing.expect(!partial.push(&messages[0][0]));
    var wrong = messages[1][0];
    wrong.sender += 256;
    var fenced = analysis.StagePair.init(broker_endpoint, owner, packets);
    try testing.expect(fenced.step() and fenced.push(&wrong) and fenced.take() == null and fenced.collectors[1].base.count == 0);
    wrong = messages[1][0];
    wire.put64(&wrong.payload, 16, first.token);
    try testing.expect(!fenced.push(&wrong));
    _ = try table.cancel(owner, first.token, &seam);
    _ = try table.cancel(owner, second.token, &seam);
    for (seam.stages.advance(&table)) |candidate| if (candidate) |late| try testing.expectError(error.stale, table.deliverAnalysis(late, &seam));
    try fixture.close(a.reference);
    try fixture.close(b.reference);
}


test "staged predecessor reap and late traffic cannot clear or acknowledge a fresh reused slot" {
    var fixture = Fixture.init();
    const input = try fixture.input("/alpha", "predecessor\n");
    var seam: Seam = .{ .fixture = &fixture };
    var table = core.Broker.init(broker_endpoint, owner);
    const first = try table.offerAnalysis(owner, 1, input.reference.token, input.reference.issuer, &seam);
    try seam.bind(first);
    const old_token = first.token;
    _ = stageRequest(&table, &seam, .{ .id = 2, .command = .stage, .detail = 2, .token = first.token, .data = first.input }, owner);
    const old = seam.execute(first).?;
    try stageTuple(&seam, &table, old);
    _ = seam.stages.ready(&table);
    _ = try table.cancel(owner, old_token, &seam);
    const late = seam.stages.advance(&table)[wire.tokenSlot(old_token).?].?;
    try testing.expectError(error.stale, table.deliverAnalysis(late, &seam));
    try fixture.close(input.reference);
    try table.reap(owner, old_token);
    const fresh = try fixture.input("/alpha", "replacement\n");
    const successor = try table.offerAnalysis(owner, 3, fresh.reference.token, fresh.reference.issuer, &seam);
    try seam.bind(successor);
    _ = stageRequest(&table, &seam, .{ .id = 4, .command = .stage, .detail = 2, .token = successor.token, .data = successor.input }, owner);
    const current = seam.execute(successor).?;
    try stageTuple(&seam, &table, current);
    seam.stages.release(old_token);
    var stale = wire.encode(wire.reply_operation, .{ .id = old.id, .command = .work, .kind = .response,
        .detail = old.attempt, .token = old.token, .data = old.tuple.digest });
    stale.sender = old.endpoint;
    try testing.expectEqual(std.meta.Tag(staging.Deferred).rejected, std.meta.activeTag(seam.stages.push(&table, &stale)));
    const ready = seam.stages.ready(&table)[wire.tokenSlot(successor.token).?].?;
    try testing.expectEqual(successor.token, ready.snapshot.token);
    try testing.expectEqual(current.endpoint, ready.snapshot.endpoint);
    try stageFailure(stageRequest(&table, &seam, .{ .id = 5, .command = .stage, .token = old_token, .data = old.id }, owner), error.stale);
    _ = stageRequest(&table, &seam, .{ .id = 6, .command = .stage, .token = successor.token, .data = successor.rpc }, owner);
    for (0..9) |_| for (seam.stages.advance(&table)) |candidate| if (candidate) |result| { _ = try table.deliverAnalysis(result, &seam); };
    try testing.expect(successor.verified and table.conserved(seam.domain().?));
    try fixture.close(fresh.reference);
}
