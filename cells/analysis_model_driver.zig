// Host sequence driver: every action invokes the production finite storage core.
const std = @import("std");
const storage = @import("storage.zig");
const snap = @import("snapshot.zig");
const support = @import("contract_test_support.zig");
const core = support.core;
const analysis = @import("analysis_wire.zig");
const wire = support.wire;
const storage_runtime = @import("storage_runtime.zig");
const snapshot_wire = @import("snapshot_wire.zig");
const Seam = struct {
    fake: support.Fake = .{},
    table: *snap.Table,
    route_live: [2]bool = .{ false, false },
    release_peer: u64 = 0,
    fail_release: bool = false,
    input_reads: u64 = 0,
    pub fn domain(self: *Seam) ?core.Domain {
        return self.fake.domain();
    }
    pub fn create(self: *Seam) ?core.Backing {
        const worker = self.fake.create() orelse return null;
        self.route_live[worker.slot - 4] = true;
        return worker;
    }
    pub fn send(self: *Seam, worker: core.Backing, message: @import("abi.zig").Message) bool {
        return self.fake.send(worker, message);
    }
    pub fn settle(self: *Seam, worker: core.Backing) bool {
        const result = self.fake.settle(worker);
        self.refreshRoute(worker);
        return result;
    }
    fn refreshRoute(self: *Seam, worker: core.Backing) void {
        const index = worker.slot - 4;
        if (self.fake.objects[index] == null or self.fake.pages[index] == 0) self.route_live[index] = false;
    }
    pub fn admit(self: *Seam, worker: core.Backing) ?core.Fence {
        return self.fake.admit(worker);
    }
    pub fn settleCandidate(self: *Seam, worker: core.Backing, fence: core.Fence) core.Settlement {
        const result = self.fake.settleCandidate(worker, fence);
        self.refreshRoute(worker);
        return result;
    }
    pub fn rebind(self: *Seam, worker: core.Backing) ?core.Backing {
        const rebound = self.fake.rebind(worker) orelse return null;
        self.route_live[worker.slot - 4] = true;
        return rebound;
    }
    fn currentReader(self: *Seam, reader: u64, issuer: u64) bool {
        if (issuer != 0x102) return false;
        if (reader == 0x104) return true;
        for (self.fake.objects, 0..) |object, index| if (object != null and object.?.endpoint == reader and self.route_live[index]) return true;
        return false;
    }
    pub fn validated(self: *Seam, token: u64, worker: core.Backing, rpc: u64, attempt: u8, input: u64, result: u64) void {
        self.fake.validated(token, worker, rpc, attempt, input, result);
    }
    fn collect(self: *Seam, reader: u64, issuer: u64, token: u64) ?analysis.Tuple {
        if (!self.currentReader(reader, issuer)) {
            self.input_reads += 1;
            return null;
        }
        var collected = [_]u8{0} ** 128;
        var at: u32 = 0;
        while (at <= 128) {
            var data = [_]u8{0} ** 8;
            self.input_reads += 1;
            const count = self.table.read(reader, .{ .issuer = issuer, .token = token }, at, 8, &data);
            if (count < 0 or count > 8) return null;
            if (count == 0) return analysis.calculate(collected[0..at]);
            if (at + @as(u32, @intCast(count)) > 128) return null;
            @memcpy(collected[at..][0..@intCast(count)], data[0..@intCast(count)]);
            at += @intCast(count);
        }
        return null;
    }
    pub fn prepareInput(self: *Seam, issuer: u64, token: u64) ?u16 {
        const tuple = self.collect(0x104, issuer, token) orelse return null;
        return tuple.length;
    }
    pub fn verifyInput(self: *Seam, issuer: u64, token: u64) ?analysis.Tuple {
        return self.collect(0x104, issuer, token);
    }
    pub fn releaseInput(self: *Seam, record: core.Record, success: bool) bool {
        return !self.fail_release and self.table.releaseBound(0x104, .{ .issuer = record.input_issuer, .token = record.input }, if (success) record.worker.endpoint else 0) == .ok;
    }
    pub fn validatedAnalysis(self: *Seam, record: core.Record, tuple: analysis.Tuple) void {
        self.fake.validated(record.token, record.worker, record.rpc, record.attempt, record.input, tuple.digest);
    }
};
const BindIo = struct {
    seam: *Seam,
    pub fn refresh(_: *BindIo, _: *storage_runtime.Server) void {}
    pub fn transfer(_: *BindIo, _: *storage_runtime.Server, _: u64, _: @import("abi.zig").Operation, _: u32, _: u32, _: []const u8) ?@import("storage_wire.zig").Header {
        return null;
    }
    pub fn report(_: *BindIo, _: u64, _: u64, _: u32, _: i32) void {}
    pub fn readerValid(self: *BindIo, server: *storage_runtime.Server, reader: u64) bool {
        return self.seam.currentReader(reader, server.snapshots.issuer);
    }
};
fn bindCurrent(fs: *storage.Fs, table: *snap.Table, seam: *Seam, owner: u64, token: u64, reader: u64, checker: bool) i32 {
    var server: storage_runtime.Server = .{ .fs = fs.*, .snapshots = table.*, .owner_endpoint = 0x103 };
    var io: BindIo = .{ .seam = seam };
    var message = snapshot_wire.control(1, token, reader, if (checker) .bind_check else .bind);
    message.sender = owner;
    var answer = server.processWith(&message, &io) orelse return -1;
    answer.sender = table.issuer;
    const parsed = snapshot_wire.decodeControlReply(&answer, table.issuer, 1, if (checker) .bind_check else .bind) orelse return -1;
    fs.* = server.fs;
    table.* = server.snapshots;
    return @intFromEnum(parsed.status);
}
extern "c" fn printf(format: [*:0]const u8, ...) c_int;
fn bytes(data: []const u8) void {
    for (data) |byte| {
        _ = printf("%02x", @as(c_uint, byte));
    }
}
fn report(fs: *const storage.Fs, block: *const storage.Block, table: *const snap.Table, result: i32, value: u64, output: [8]u8) void {
    _ = printf("%d;%llu;%llu;%llu;%llu;%llu;%u;%u;%u;", result, value, table.next_serial, table.block, fs.generation, fs.block, fs.next_serial, @as(c_uint, @intCast(table.retained())), @as(c_uint, @intCast(table.backing())));
    bytes(&output);
    _ = printf(";");
    bytes(&block.bytes);
    for (fs.files, 0..) |file, i| {
        if (!file.used) continue;
        _ = printf("|F,%u,%u,%u,%llu,", @as(c_uint, @intCast(i)), @as(c_uint, @intFromBool(file.readonly)), file.length, file.revision);
        bytes(file.name[0..file.name_length]);
    }
    for (fs.handles) |handle| {
        if (!handle.used) continue;
        _ = printf("|H,%llu,%llu,%u", handle.token, handle.owner, @as(c_uint, handle.file));
    }
    for (table.records, 0..) |record, i| {
        if (record.state == .empty) continue;
        _ = printf("|S,%u,%u,%llu,%llu,%llu,%llu,%llu,%u,%llu,%u,%u,%d,%llu,%llu,%llu,%llu,", @as(c_uint, @intCast(i)), @as(c_uint, @intFromEnum(record.state)), record.token, record.owner, record.transaction, record.handle, record.block, @as(c_uint, record.file), record.revision, @as(c_uint, record.length), @as(c_uint, record.captured), @as(c_int, @intFromEnum(record.last_status)), record.readers[0], record.readers[1], record.checker, record.settled_reader);
        bytes(&record.bytes);
    }
    for (table.owner_watermarks, 0..) |mark, slot| {
        if (mark.endpoint == 0) continue;
        _ = printf("|M,%u,%llu,%llu", @as(c_uint, @intCast(slot)), mark.endpoint, mark.transaction);
    }
    _ = printf("\n");
}
fn contractReport(broker: *const core.Broker, seam: *Seam, outcome: []const u8) void {
    const fake = &seam.fake;
    const d = fake.domain().?;
    _ = printf("%.*s;%llu;%llu;%llu;%llu;%llu;%llu;%llu;%llu;%u;%u;%llu;%llu;%llu;%u", @as(c_int, @intCast(outcome.len)), outcome.ptr, broker.next_serial, broker.offer_highwater, broker.rpc_sequence.next, fake.create_calls, fake.send_calls, fake.settle_calls, fake.rebind_calls, fake.validated_calls, d.owned_slots, d.owned_pages, broker.issuer, broker.requester, seam.input_reads, @as(c_uint, @intFromBool(seam.route_live[0])) | (@as(c_uint, @intFromBool(seam.route_live[1])) << 1));
    for (broker.records) |r| {
        if (r.state == .free) continue;
        _ = printf("|%llu,%llu,%llu,%u,%u,%u,%llu,%llu,%llu,%llu,%llu,%u,%u,%u,%u,%u,%llu,%u,%llu,%llu,%u,%u", r.token, r.offer_id, r.input, @as(c_uint, @intFromEnum(r.state)), @as(c_uint, r.retries), @as(c_uint, r.attempt), r.rpc, r.worker.instance, r.worker.control, r.worker.endpoint, r.worker.channel, r.worker.slot, @as(c_uint, r.backing_slots), @as(c_uint, r.backing_pages), @as(c_uint, @intFromEnum(r.reason)), @as(c_uint, @intFromBool(r.verified)), r.result, @as(c_uint, r.cleanup_attempts), broker.snapshot(&r).endpoint, r.input_issuer, @as(c_uint, r.input_length), @as(c_uint, r.newlines));
    }
    _ = printf("\n");
}
fn open(fs: *storage.Fs, block: *storage.Block, owner: u64, name: []const u8) struct { status: i32, token: u64 } {
    const plan = fs.prepareOpen(owner, name);
    if (plan.status != .ok) return .{ .status = @intFromEnum(plan.status), .token = 0 };
    if (plan.needs_zero) {
        const zeros = [_]u8{0} ** storage.chunk_size;
        var at: u32 = 0;
        while (at < storage.file_size) : (at += storage.chunk_size) {
            if (block.write(plan.address + at, &zeros) != storage.chunk_size) return .{ .status = -8, .token = 0 };
        }
    }
    const status = fs.commitOpen(plan);
    return .{ .status = @intFromEnum(status), .token = if (status == .ok) plan.token else 0 };
}
pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const arguments = try std.process.argsAlloc(allocator);
    if (arguments.len != 2) return error.Arguments;
    const source = try std.fs.cwd().readFileAlloc(allocator, arguments[1], 4 * 1024 * 1024);
    var fs = storage.Fs.init(1);
    _ = fs.rebindBlock(0x101);
    var block = storage.Block.init();
    var table = snap.Table.init(0x102);
    table.invalidateBlock(0x101);
    var broker = core.Broker.init(0x104, 0x103);
    var seam: Seam = .{ .table = &table };
    var lines = std.mem.tokenizeScalar(u8, source, '\n');
    while (lines.next()) |line| {
        var parts = std.mem.tokenizeScalar(u8, line, ' ');
        const operation = parts.next().?[0];
        var a: [6]u64 = undefined;
        for (&a) |*argument| {
            argument.* = try std.fmt.parseInt(u64, parts.next().?, 10);
        }
        const owner = a[0];
        const token = a[1];
        const reference: snap.Ref = .{ .issuer = if (a[5] == 0) table.issuer else a[5], .token = token };
        var result: i32 = 0;
        var value: u64 = 0;
        var output = [_]u8{0} ** 8;
        var outcome: []const u8 = "ok";
        seam.release_peer = 0;
        switch (operation) {
            'o' => {
                seam.fake.fail_create = a[4] == 1;
                _ = broker.offerAnalysis(owner, token, a[2], if (a[3] == 0) table.issuer else a[3], &seam) catch |err| {
                    outcome = @errorName(err);
                };
                seam.fake.fail_create = false;
            },
            'a' => {
                const record = broker.status(0x103, token) catch |err| {
                    outcome = @errorName(err);
                    contractReport(&broker, &seam, outcome);
                    report(&fs, &block, &table, result, value, output);
                    continue;
                };
                seam.fake.fail_send = a[3] != 0;
                _ = broker.accept(owner, token, record.input ^ a[2], 2, &seam) catch |err| {
                    outcome = @errorName(err);
                };
                seam.fake.fail_send = false;
            },
            'c' => {
                _ = broker.cancel(owner, token, &seam) catch |err| {
                    outcome = @errorName(err);
                };
            },
            'r' => {
                broker.reap(owner, token) catch |err| {
                    outcome = @errorName(err);
                };
            },
            'q' => {
                _ = broker.status(owner, token) catch |err| {
                    outcome = @errorName(err);
                };
            },
            'f' => {
                const record = broker.status(owner, token) catch |err| {
                    outcome = @errorName(err);
                    contractReport(&broker, &seam, outcome);
                    report(&fs, &block, &table, result, value, output);
                    continue;
                };
                if (record.state == .running) seam.route_live[record.worker.slot - 4] = false;
                _ = broker.workerFault(record.worker.endpoint, &seam) catch |err| {
                    outcome = @errorName(err);
                };
            },
            't' => {
                seam.fake.fail_rebind = a[2] != 0;
                _ = broker.retry(token, &seam) catch |err| {
                    outcome = @errorName(err);
                };
                seam.fake.fail_rebind = false;
            },
            'd' => {
                const record = broker.status(owner, token) catch |err| {
                    outcome = @errorName(err);
                    contractReport(&broker, &seam, outcome);
                    report(&fs, &block, &table, result, value, output);
                    continue;
                };
                const tuple = seam.collect(record.worker.endpoint, record.input_issuer, record.input);
                if (tuple == null) outcome = "unreadable" else {
                    var candidate: analysis.Result = .{ .endpoint = record.worker.endpoint, .id = record.rpc, .token = record.token, .attempt = record.attempt, .tuple = tuple.? };
                    switch (a[2]) {
                        1 => candidate.tuple.digest ^= 1,
                        2 => candidate.tuple.length +%= 1,
                        3 => candidate.tuple.newlines +%= 1,
                        4 => candidate.endpoint +%= 0x100,
                        5 => candidate.attempt +%= 1,
                        6 => candidate.id +%= 1,
                        else => {},
                    }
                    seam.release_peer = record.worker.endpoint;
                    _ = broker.deliverAnalysis(candidate, &seam) catch |err| {
                        outcome = @errorName(err);
                    };
                }
            },
            'y' => {
                seam.fake.partial_settle = owner == 1;
                seam.fake.false_refund = owner == 2;
                seam.fail_release = owner == 3;
            },
            'v' => {
                seam.fake.fault_during_settle = owner == 1;
                seam.fake.restart_during_settle = owner == 2;
                seam.fake.admission_failure = owner == 3;
                seam.fake.saturated_faults = owner == 4;
            },
            'x' => {
                broker.next_serial = owner;
                broker.rpc_sequence.next = token;
            },
            'O' => {
                const names = [_][]const u8{ "/hello", "/alpha", "/beta", "/gamma", "/overflow" };
                const answer = open(&fs, &block, owner, names[@intCast(a[1] % names.len)]);
                result = answer.status;
                value = answer.token;
            },
            'H' => {
                result = @intFromEnum(fs.close(owner, token));
            },
            'W' => {
                const plan = fs.prepareWrite(owner, token, @intCast(a[2]), @intCast(a[3]));
                result = @intFromEnum(plan.status);
                if (plan.status == .ok) {
                    var data: [8]u8 = undefined;
                    for (&data, 0..) |*byte, i| {
                        byte.* = @truncate(a[4] >> @intCast(i * 8));
                    }
                    result = block.write(plan.address, data[0..plan.count]);
                    if (result >= 0) result = if (a[5] == 1) -8 else @intFromEnum(fs.commitWrite(plan));
                    if (result == 0 and a[5] != 1) result = @intCast(plan.count);
                }
            },
            'A' => {
                const capture = table.begin(&fs, owner, token, a[2]);
                result = @intFromEnum(capture.status);
                value = capture.reference.token;
            },
            'C' => {
                const slot = table.index(reference);
                if (slot) |index| {
                    const record = table.records[index];
                    const transfer = fs.prepareRead(record.owner, record.handle, @intCast(a[2]), @intCast(a[3]));
                    result = @intFromEnum(transfer.status);
                    if (transfer.status == .ok) {
                        result = block.read(transfer.address, transfer.count, &output);
                        if (result >= 0) {
                            if (a[4] != 0) output[0] ^= @truncate(a[4]);
                            result = @intFromEnum(table.append(&fs, owner, reference, @intCast(a[2]), output[0..@intCast(result)]));
                        }
                    }
                } else result = -3;
            },
            'P' => {
                result = @intFromEnum(table.publish(&fs, owner, reference));
            },
            'F' => {
                const reasons = [_]snap.Status{ .timeout, .stale, .invalid, .ok };
                result = @intFromEnum(table.fail(owner, reference, reasons[@intCast(a[2] % reasons.len)]));
            },
            'B' => {
                result = bindCurrent(&fs, &table, &seam, owner, token, a[2], false);
            },
            'L' => {
                result = bindCurrent(&fs, &table, &seam, owner, token, a[2], true);
            },
            'Z' => {
                result = @intFromEnum(table.releaseBound(owner, reference, a[2]));
            },
            'V' => {
                result = @intFromEnum(table.revoke(owner, reference, a[2]));
            },
            'R' => {
                result = table.read(owner, reference, @intCast(a[2]), @intCast(a[3]), &output);
            },
            'T' => {
                result = @intFromEnum(table.close(owner, reference));
            },
            'E' => {
                result = @intFromEnum(table.reap(owner, reference));
            },
            'Q' => {
                if (table.status(owner, token)) |record| {
                    value = record.token;
                    result = @intFromEnum(record.last_status);
                } else result = -3;
            },
            'K' => {
                value = table.retireOwner(owner);
            },
            'I' => {
                _ = fs.rebindBlock(owner);
                table.invalidateBlock(owner);
            },
            'G' => {
                fs = storage.Fs.init(owner >> 8);
                _ = fs.rebindBlock(token);
                table = snap.Table.init(owner);
                table.invalidateBlock(token);
                if (a[2] != 0) block = storage.Block.init();
            },
            'X' => {
                table.next_serial = owner;
                fs.next_serial = @intCast(token);
                if (a[2] < storage.file_limit) fs.files[@intCast(a[2])].revision = a[3];
            },
            'D' => {
                if (a[0] < storage.file_limit) fs.files[@intCast(a[0])].length = @intCast(a[1]);
            },
            else => return error.Operation,
        }
        if (!broker.conserved(seam.domain().?)) return error.Conservation;
        contractReport(&broker, &seam, outcome);
        report(&fs, &block, &table, result, value, output);
    }
}
