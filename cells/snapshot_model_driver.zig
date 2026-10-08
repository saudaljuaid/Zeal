// Host sequence driver: every action invokes the production finite storage core.
const std = @import("std");
const storage = @import("storage.zig");
const snap = @import("snapshot.zig");
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
        switch (operation) {
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
                result = @intFromEnum(table.bind(owner, reference, a[2]));
            },
            'L' => {
                result = @intFromEnum(table.bindChecker(owner, reference, a[2]));
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
        report(&fs, &block, &table, result, value, output);
    }
}
