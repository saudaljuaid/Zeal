// Volatile service-private storage. No allocator, global cache, or syscall dependencies.
pub const chunk_size: u32 = 8;
pub const capacity: u32 = 512;
pub const file_limit: usize = 4;
pub const name_limit: usize = 16;
pub const file_size: u32 = 128;
pub const handle_limit: usize = 8;
pub const serial_max: u32 = 0xffffff;
pub const hello = "Zeal survives.";

pub const Status = enum(i32) {
    ok = 0,
    invalid = -1,
    denied = -2,
    stale = -3,
    again = -4,
    too_large = -6,
    no_space = -7,
    timeout = -8,
};

fn rangeEnd(offset: u32, count: u32) ?u32 {
    const sum = @addWithOverflow(offset, count);
    return if (sum[1] == 0) sum[0] else null;
}

pub const Block = struct {
    bytes: [capacity]u8,

    pub fn init() Block {
        var result: Block = .{ .bytes = [_]u8{0} ** capacity };
        @memcpy(result.bytes[0..hello.len], hello);
        return result;
    }

    // A chunk either succeeds entirely or changes nothing. Empty operations at capacity are valid.
    pub fn read(self: *const Block, offset: u32, count: u32, out: *[chunk_size]u8) i32 {
        if (count > chunk_size) return @intFromEnum(Status.too_large);
        const end = rangeEnd(offset, count) orelse return @intFromEnum(Status.invalid);
        if (offset > capacity or end > capacity) return @intFromEnum(Status.too_large);
        out.* = [_]u8{0} ** chunk_size;
        @memcpy(out[0..count], self.bytes[offset..end]);
        return @intCast(count);
    }

    pub fn write(self: *Block, offset: u32, data: []const u8) i32 {
        if (data.len > chunk_size) return @intFromEnum(Status.too_large);
        const end = rangeEnd(offset, @intCast(data.len)) orelse return @intFromEnum(Status.invalid);
        if (offset > capacity or end > capacity) return @intFromEnum(Status.too_large);
        @memcpy(self.bytes[offset..end], data);
        return @intCast(data.len);
    }
};

pub fn validName(name: []const u8) bool {
    if (name.len < 2 or name.len > name_limit or name[0] != '/') return false;
    for (name[1..]) |byte| {
        if (!((byte >= 'a' and byte <= 'z') or (byte >= 'A' and byte <= 'Z') or
            (byte >= '0' and byte <= '9') or byte == '_' or byte == '-' or byte == '.')) return false;
    }
    return true;
}

pub const File = struct {
    used: bool = false,
    readonly: bool = false,
    name_length: u8 = 0,
    name: [name_limit]u8 = [_]u8{0} ** name_limit,
    length: u32 = 0,
};

pub const Handle = struct {
    used: bool = false,
    owner: u64 = 0,
    token: u64 = 0,
    file: u8 = 0,
};

pub const OpenPlan = struct {
    status: Status = .invalid,
    owner: u64 = 0,
    token: u64 = 0,
    file: u8 = 0,
    slot: u8 = 0,
    needs_zero: bool = false,
    address: u32 = 0,
    block: u64 = 0,
    generation: u64 = 0,
    name_length: u8 = 0,
    name: [name_limit]u8 = [_]u8{0} ** name_limit,
};

pub const Transfer = struct {
    status: Status = .invalid,
    owner: u64 = 0,
    token: u64 = 0,
    file: u8 = 0,
    address: u32 = 0,
    count: u32 = 0,
    end: u32 = 0,
    block: u64 = 0,
    write: bool = false,
};

pub const Fs = struct {
    generation: u64,
    block: u64 = 0,
    next_serial: u32 = 1,
    files: [file_limit]File = [_]File{.{}} ** file_limit,
    handles: [handle_limit]Handle = [_]Handle{.{}} ** handle_limit,

    pub fn init(generation: u64) Fs {
        var result: Fs = .{ .generation = generation };
        result.resetMetadata();
        return result;
    }

    fn resetMetadata(self: *Fs) void {
        self.files = [_]File{.{}} ** file_limit;
        self.handles = [_]Handle{.{}} ** handle_limit;
        self.files[0] = .{ .used = true, .readonly = true, .name_length = 6, .length = hello.len };
        @memcpy(self.files[0].name[0..6], "/hello");
    }

    // Any dependency generation change abandons metadata and handles. Serial is never reset here.
    pub fn rebindBlock(self: *Fs, endpoint: u64) bool {
        if (self.block == endpoint) return false;
        if (self.block != 0) self.resetMetadata();
        self.block = endpoint;
        return true;
    }

    pub fn prepareOpen(self: *const Fs, owner: u64, name: []const u8) OpenPlan {
        if (owner == 0 or !validName(name)) return .{ .status = .invalid };
        if (self.block == 0) return .{ .status = .stale };
        if (self.generation == 0 or self.generation > 0xffffffff or self.next_serial > serial_max)
            return .{ .status = .no_space };
        var available_file: ?usize = null;
        var found_file: ?usize = null;
        for (self.files, 0..) |file, index| {
            if (!file.used and available_file == null) available_file = index;
            if (file.used and file.name_length == name.len) {
                var equal = true;
                for (name, 0..) |byte, pos| if (file.name[pos] != byte) {
                    equal = false;
                };
                if (equal) found_file = index;
            }
        }
        const file = found_file orelse available_file orelse return .{ .status = .no_space };
        var slot: ?usize = null;
        for (self.handles, 0..) |entry, index| {
            if (!entry.used) {
                slot = index;
                break;
            }
        }
        const handle_slot = slot orelse return .{ .status = .no_space };
        var plan: OpenPlan = .{
            .status = .ok,
            .owner = owner,
            .file = @intCast(file),
            .slot = @intCast(handle_slot),
            .token = (self.generation << 32) | (@as(u64, self.next_serial) << 8) | (handle_slot + 1),
            .needs_zero = found_file == null,
            .address = @as(u32, @intCast(file)) * file_size,
            .block = self.block,
            .generation = self.generation,
            .name_length = @intCast(name.len),
        };
        @memcpy(plan.name[0..name.len], name);
        return plan;
    }

    // For a new file the caller must first acknowledge every zero chunk through the block service.
    // An interrupted zero or failed send never publishes the file or consumes a handle.
    pub fn commitOpen(self: *Fs, plan: OpenPlan) Status {
        if (plan.status != .ok or plan.generation != self.generation or plan.block != self.block or
            plan.owner == 0 or plan.file >= file_limit or plan.slot >= handle_limit or
            plan.name_length < 2 or plan.name_length > name_limit) return .stale;
        const checked = self.prepareOpen(plan.owner, plan.name[0..plan.name_length]);
        if (checked.status != .ok or checked.token != plan.token or checked.file != plan.file or
            checked.slot != plan.slot or checked.needs_zero != plan.needs_zero) return .stale;
        if (plan.needs_zero) {
            self.files[plan.file] = .{ .used = true, .name_length = plan.name_length, .name = plan.name };
        }
        self.handles[plan.slot] = .{ .used = true, .owner = plan.owner, .token = plan.token, .file = plan.file };
        self.next_serial += 1; // 0x1000000 is a terminal exhausted value, never a wrapped serial.
        return .ok;
    }

    fn handle(self: *const Fs, owner: u64, token: u64) ?Handle {
        const slot = token & 0xff;
        if (owner == 0 or slot == 0 or slot > handle_limit or token >> 32 != self.generation) return null;
        const result = self.handles[slot - 1];
        if (!result.used or result.owner != owner or result.token != token) return null;
        return result;
    }

    pub fn close(self: *Fs, owner: u64, token: u64) Status {
        _ = self.handle(owner, token) orelse return .stale;
        self.handles[(token & 0xff) - 1] = .{};
        return .ok;
    }

    pub fn prepareRead(self: *const Fs, owner: u64, token: u64, offset: u32, count: u32) Transfer {
        const active = self.handle(owner, token) orelse return .{ .status = .stale };
        if (self.block == 0) return .{ .status = .stale };
        if (count > chunk_size) return .{ .status = .too_large };
        _ = rangeEnd(offset, count) orelse return .{ .status = .invalid };
        if (offset > file_size) return .{ .status = .too_large };
        const length = self.files[active.file].length;
        const amount = if (offset >= length) 0 else @min(count, length - offset);
        return .{
            .status = .ok,
            .owner = owner,
            .token = token,
            .file = active.file,
            .address = @as(u32, active.file) * file_size + offset,
            .count = amount,
            .end = offset + amount,
            .block = self.block,
        };
    }

    pub fn prepareWrite(self: *const Fs, owner: u64, token: u64, offset: u32, count: u32) Transfer {
        const active = self.handle(owner, token) orelse return .{ .status = .stale };
        if (self.block == 0) return .{ .status = .stale };
        if (self.files[active.file].readonly) return .{ .status = .denied };
        if (count > chunk_size) return .{ .status = .too_large };
        const end = rangeEnd(offset, count) orelse return .{ .status = .invalid };
        if (offset > file_size or end > file_size) return .{ .status = .too_large };
        if (offset > self.files[active.file].length) return .{ .status = .invalid };
        return .{
            .status = .ok,
            .owner = owner,
            .token = token,
            .file = active.file,
            .address = @as(u32, active.file) * file_size + offset,
            .count = count,
            .end = end,
            .block = self.block,
            .write = true,
        };
    }

    pub fn commitWrite(self: *Fs, transfer: Transfer) Status {
        if (transfer.status != .ok or !transfer.write or transfer.block != self.block or
            transfer.count > chunk_size or transfer.end > file_size) return .stale;
        const active = self.handle(transfer.owner, transfer.token) orelse return .stale;
        if (active.file != transfer.file or self.files[active.file].readonly or
            transfer.address < @as(u32, active.file) * file_size) return .stale;
        const offset = transfer.address - @as(u32, active.file) * file_size;
        const check = self.prepareWrite(transfer.owner, transfer.token, offset, transfer.count);
        if (check.status != .ok or check.end != transfer.end or check.address != transfer.address) return .stale;
        self.files[active.file].length = @max(self.files[active.file].length, transfer.end);
        return .ok;
    }
};

const testing = @import("std").testing;

fn opened(fs: *Fs, block: *Block, owner: u64, name: []const u8) !u64 {
    const plan = fs.prepareOpen(owner, name);
    try testing.expectEqual(Status.ok, plan.status);
    if (plan.needs_zero) {
        const zeros = [_]u8{0} ** chunk_size;
        var offset: u32 = 0;
        while (offset < file_size) : (offset += chunk_size)
            try testing.expectEqual(@as(i32, chunk_size), block.write(plan.address + offset, &zeros));
    }
    try testing.expectEqual(Status.ok, fs.commitOpen(plan));
    return plan.token;
}

fn writeAll(fs: *Fs, block: *Block, owner: u64, token: u64, offset: u32, data: []const u8) !void {
    var at: usize = 0;
    while (at < data.len) {
        const count: u32 = @intCast(@min(chunk_size, data.len - at));
        const transfer = fs.prepareWrite(owner, token, offset + @as(u32, @intCast(at)), count);
        try testing.expectEqual(Status.ok, transfer.status);
        try testing.expectEqual(@as(i32, @intCast(count)), block.write(transfer.address, data[at..][0..count]));
        try testing.expectEqual(Status.ok, fs.commitWrite(transfer));
        at += count;
    }
}

test "private RAM begins with verified hello and rejects invalid chunks before mutation" {
    var block = Block.init();
    const before = block.bytes;
    var out: [chunk_size]u8 = undefined;
    try testing.expectEqual(@as(i32, 8), block.read(0, 8, &out));
    try testing.expectEqualSlices(u8, "Zeal sur", &out);
    try testing.expectEqual(@as(i32, 0), block.read(capacity, 0, &out));
    try testing.expectEqual(@as(i32, -6), block.read(capacity, 1, &out));
    try testing.expectEqual(@as(i32, -1), block.read(0xffffffff, 1, &out));
    try testing.expectEqual(@as(i32, -6), block.write(0, "123456789"));
    try testing.expectEqual(@as(i32, -1), block.write(0xffffffff, "x"));
    try testing.expectEqual(@as(i32, -6), block.write(capacity, "x"));
    try testing.expectEqualSlices(u8, &before, &block.bytes);
    try testing.expectEqual(@as(i32, 1), block.write(capacity - 1, "x"));
    try testing.expectEqual(@as(u8, 'x'), block.bytes[capacity - 1]);
}

test "canonical flat filenames are bounded and reject ambiguous names" {
    for ([_][]const u8{ "/hello", "/note", "/a_b-1.txt", "/123456789012345" }) |name|
        try testing.expect(validName(name));
    for ([_][]const u8{ "", "/", "hello", "/1234567890123456", "/a/b", "/a\x00", "/a b", "/a\xff" }) |name|
        try testing.expect(!validName(name));
}

test "empty EOF overwrite contiguous growth exact extent boundary and unrelated files" {
    var fs = Fs.init(1);
    _ = fs.rebindBlock(0x101);
    var block = Block.init();
    const a = try opened(&fs, &block, 0x103, "/note");
    const b = try opened(&fs, &block, 0x103, "/other");
    try testing.expectEqual(@as(u32, 0), fs.prepareRead(0x103, a, 0, 8).count);
    try testing.expectEqual(@as(u32, 0), fs.prepareRead(0x103, a, 128, 8).count);
    try testing.expectEqual(Status.invalid, fs.prepareWrite(0x103, a, 1, 1).status);
    try writeAll(&fs, &block, 0x103, b, 0, "unrelated stays");
    try writeAll(&fs, &block, 0x103, a, 0, "abcdefghijklmnop");
    try writeAll(&fs, &block, 0x103, a, 3, "XYZ");
    try testing.expectEqualSlices(u8, "abcXYZghijklmnop", block.bytes[128..144]);
    const more = [_]u8{'q'} ** 112;
    try writeAll(&fs, &block, 0x103, a, 16, &more);
    try testing.expectEqual(@as(u32, 128), fs.files[1].length);
    try testing.expectEqual(@as(u32, 1), fs.prepareRead(0x103, a, 127, 8).count);
    try testing.expectEqual(@as(u32, 0), fs.prepareRead(0x103, a, 128, 8).count);
    try testing.expectEqual(Status.too_large, fs.prepareWrite(0x103, a, 128, 1).status);
    try testing.expectEqual(Status.invalid, fs.prepareWrite(0x103, a, 0xffffffff, 1).status);
    try testing.expectEqual(Status.too_large, fs.prepareRead(0x103, a, 0, 9).status);
    try testing.expectEqualSlices(u8, "unrelated stays", block.bytes[256..271]);
    try testing.expectEqualSlices(u8, hello, block.bytes[0..hello.len]);
    const hello_handle = try opened(&fs, &block, 0x103, "/hello");
    try testing.expectEqual(Status.denied, fs.prepareWrite(0x103, hello_handle, 0, 1).status);
}

test "file table handles storage capacity and serial exhaustion are bounded" {
    var fs = Fs.init(1);
    _ = fs.rebindBlock(0x101);
    var block = Block.init();
    _ = try opened(&fs, &block, 0x103, "/a");
    _ = try opened(&fs, &block, 0x103, "/b");
    _ = try opened(&fs, &block, 0x103, "/c");
    try testing.expectEqual(Status.no_space, fs.prepareOpen(0x103, "/d").status);
    for (0..5) |_| _ = try opened(&fs, &block, 0x103, "/a");
    try testing.expectEqual(Status.no_space, fs.prepareOpen(0x103, "/a").status);
    try testing.expectEqual(@as(u32, capacity), file_size * file_limit);
    fs = Fs.init(1);
    _ = fs.rebindBlock(0x101);
    fs.next_serial = serial_max;
    const last = try opened(&fs, &block, 0x103, "/a");
    try testing.expectEqual(Status.ok, fs.close(0x103, last));
    try testing.expectEqual(Status.no_space, fs.prepareOpen(0x103, "/a").status);
    _ = fs.rebindBlock(0x201);
    try testing.expectEqual(Status.no_space, fs.prepareOpen(0x103, "/a").status);
    fs = Fs.init(0x100000000);
    _ = fs.rebindBlock(0x101);
    try testing.expectEqual(Status.no_space, fs.prepareOpen(0x103, "/a").status);
}

test "forged cross-owner closed reused slot and restarted generation handles stay stale" {
    var fs = Fs.init(1);
    _ = fs.rebindBlock(0x101);
    var block = Block.init();
    const first = try opened(&fs, &block, 0x103, "/a");
    try testing.expectEqual(Status.stale, fs.prepareRead(0x104, first, 0, 1).status);
    try testing.expectEqual(Status.stale, fs.prepareRead(0x203, first, 0, 1).status);
    for ([_]u64{ 0, first ^ 0x100, first ^ (@as(u64, 1) << 32), first ^ 0xff }) |token|
        try testing.expectEqual(Status.stale, fs.prepareRead(0x103, token, 0, 1).status);
    try testing.expectEqual(Status.stale, fs.close(0x104, first));
    try testing.expectEqual(Status.ok, fs.close(0x103, first));
    try testing.expectEqual(Status.stale, fs.close(0x103, first));
    const reused = try opened(&fs, &block, 0x103, "/a");
    try testing.expectEqual(first & 0xff, reused & 0xff);
    try testing.expect(first != reused);
    try testing.expectEqual(Status.stale, fs.prepareRead(0x103, first, 0, 1).status);
    _ = fs.rebindBlock(0x201);
    try testing.expectEqual(Status.stale, fs.prepareRead(0x103, reused, 0, 1).status);
    const newer = try opened(&fs, &block, 0x103, "/a");
    try testing.expect(newer != reused);
    fs = Fs.init(2);
    _ = fs.rebindBlock(0x201);
    try testing.expectEqual(Status.stale, fs.prepareRead(0x103, newer, 0, 1).status);
}

test "interrupted zero and writes publish only after block acknowledgment; restart clears stale contents" {
    var fs = Fs.init(1);
    _ = fs.rebindBlock(0x101);
    var block = Block.init();
    const plan = fs.prepareOpen(0x103, "/a");
    try testing.expect(plan.needs_zero);
    try testing.expectEqual(@as(u32, 1), fs.next_serial);
    try testing.expect(!fs.files[1].used);
    _ = fs.rebindBlock(0x201);
    try testing.expectEqual(Status.stale, fs.commitOpen(plan));
    const token = try opened(&fs, &block, 0x103, "/a");
    const write = fs.prepareWrite(0x103, token, 0, 8);
    try testing.expectEqual(@as(u32, 0), fs.files[1].length);
    try testing.expectEqual(@as(i32, 8), block.write(write.address, "sensitive"[0..8]));
    // Lost write reply leaves a possibly changed extent, but the old length hides an unacknowledged growth.
    try testing.expectEqual(@as(u32, 0), fs.prepareRead(0x103, token, 0, 8).count);
    try testing.expectEqual(Status.ok, fs.commitWrite(write));
    _ = fs.rebindBlock(0);
    try testing.expectEqual(Status.stale, fs.commitWrite(write));
    _ = fs.rebindBlock(0x301);
    const replacement = try opened(&fs, &block, 0x103, "/b");
    try testing.expectEqual(@as(u32, 0), fs.prepareRead(0x103, replacement, 0, 8).count);
    try testing.expectEqualSlices(u8, &([_]u8{0} ** 128), block.bytes[128..256]);
    try testing.expectEqualSlices(u8, hello, block.bytes[0..hello.len]);
    block = Block.init();
    try testing.expectEqualSlices(u8, &([_]u8{0} ** 384), block.bytes[128..512]);
}

test "independent bounded model agrees across deterministic chunk overwrites reads closes and resets" {
    var fs = Fs.init(1);
    _ = fs.rebindBlock(0x101);
    var block = Block.init();
    var token = try opened(&fs, &block, 0x103, "/model");
    var expected = [_]u8{0} ** file_size;
    var length: usize = 0;
    var seed: u32 = 0x52765c08;
    for (0..4096) |step| {
        seed = seed *% 1664525 +% 1013904223;
        const kind = seed % 5;
        if (kind <= 1) {
            const offset: usize = (seed >> 8) % (length + 1);
            const count: usize = @min(@as(usize, (seed >> 24) % 9), file_size - offset);
            var bytes: [chunk_size]u8 = undefined;
            for (&bytes, 0..) |*byte, at| byte.* = @truncate(seed +% @as(u32, @intCast(at)));
            const write = fs.prepareWrite(0x103, token, @intCast(offset), @intCast(count));
            try testing.expectEqual(Status.ok, write.status);
            try testing.expectEqual(@as(i32, @intCast(count)), block.write(write.address, bytes[0..count]));
            try testing.expectEqual(Status.ok, fs.commitWrite(write));
            @memcpy(expected[offset..][0..count], bytes[0..count]);
            length = @max(length, offset + count);
        } else if (kind == 2) {
            const offset: usize = (seed >> 8) % 129;
            const requested: usize = (seed >> 24) % 9;
            const expected_count = if (offset >= length) 0 else @min(requested, length - offset);
            const read = fs.prepareRead(0x103, token, @intCast(offset), @intCast(requested));
            try testing.expectEqual(Status.ok, read.status);
            try testing.expectEqual(@as(u32, @intCast(expected_count)), read.count);
            var bytes: [chunk_size]u8 = undefined;
            try testing.expectEqual(@as(i32, @intCast(expected_count)), block.read(read.address, read.count, &bytes));
            try testing.expectEqualSlices(u8, expected[@min(offset, length)..][0..expected_count], bytes[0..expected_count]);
        } else if (kind == 3) {
            const old = token;
            try testing.expectEqual(Status.ok, fs.close(0x103, token));
            token = try opened(&fs, &block, 0x103, "/model");
            try testing.expectEqual(Status.stale, fs.prepareWrite(0x103, old, 0, 0).status);
        } else {
            _ = fs.rebindBlock((@as(u64, @intCast(step)) + 2) << 8 | 1);
            token = try opened(&fs, &block, 0x103, "/model");
            expected = [_]u8{0} ** file_size;
            length = 0;
        }
        try testing.expectEqual(@as(u32, @intCast(length)), fs.files[1].length);
        try testing.expectEqualSlices(u8, &expected, block.bytes[128..256]);
        try testing.expectEqualSlices(u8, hello, block.bytes[0..hello.len]);
    }
}

test "close reopen multi-chunk read verifies full boundary contents and stable dependency preserves handles" {
    var fs = Fs.init(7);
    _ = fs.rebindBlock(0x901);
    var block = Block.init();
    var data: [file_size]u8 = undefined;
    for (&data, 0..) |*byte, index| byte.* = @truncate(index * 37 + 11);
    const first = try opened(&fs, &block, 0x503, "/roundtrip");
    try writeAll(&fs, &block, 0x503, first, 0, &data);
    try testing.expectEqual(Status.ok, fs.close(0x503, first));
    const second = try opened(&fs, &block, 0x503, "/roundtrip");
    try testing.expect(!fs.rebindBlock(0x901));
    var at: u32 = 0;
    while (at < file_size) : (at += chunk_size) {
        const read = fs.prepareRead(0x503, second, at, chunk_size);
        try testing.expectEqual(Status.ok, read.status);
        try testing.expectEqual(chunk_size, read.count);
        var got: [chunk_size]u8 = undefined;
        try testing.expectEqual(@as(i32, chunk_size), block.read(read.address, read.count, &got));
        try testing.expectEqualSlices(u8, data[at..][0..chunk_size], &got);
    }
    try testing.expectEqual(Status.stale, fs.prepareRead(0x503, first, 0, 8).status);
    try testing.expectEqual(@as(u32, 0), fs.prepareRead(0x503, second, file_size, 8).count);
}

test "independent handle model agrees over generated owners slots close and dependency restarts" {
    var fs = Fs.init(1);
    _ = fs.rebindBlock(0x101);
    const ModelHandle = struct { token: u64 = 0, owner: u64 = 0 };
    var model = [_]ModelHandle{.{}} ** handle_limit;
    var serial: u64 = 1;
    var seed: u32 = 0x3c8aa6e9;
    for (0..4096) |step| {
        seed = seed *% 1103515245 +% 12345;
        const owner: u64 = 0x103 + ((seed >> 20) % 3);
        const slot: usize = (seed >> 8) % handle_limit;
        switch (seed % 4) {
            0, 1 => {
                var free: ?usize = null;
                for (model, 0..) |entry, index| if (entry.token == 0) {
                    free = index;
                    break;
                };
                const plan = fs.prepareOpen(owner, "/hello");
                if (free) |index| {
                    const token = (@as(u64, 1) << 32) | (serial << 8) | (index + 1);
                    try testing.expectEqual(Status.ok, plan.status);
                    try testing.expectEqual(token, plan.token);
                    // Backpressure while waiting to transmit a reply cannot alter the reserved plan.
                    for (0..3) |_| try testing.expectEqual(token, fs.prepareOpen(owner, "/hello").token);
                    try testing.expectEqual(Status.ok, fs.commitOpen(plan));
                    model[index] = .{ .token = token, .owner = owner };
                    serial += 1;
                } else try testing.expectEqual(Status.no_space, plan.status);
            },
            2 => {
                const entry = model[slot];
                const permitted = entry.token != 0 and entry.owner == owner;
                try testing.expectEqual(if (permitted) Status.ok else Status.stale, fs.close(owner, entry.token));
                if (permitted) {
                    try testing.expectEqual(Status.stale, fs.prepareRead(owner, entry.token, 0, 1).status);
                    model[slot] = .{};
                }
            },
            3 => {
                _ = fs.rebindBlock((@as(u64, @intCast(step)) + 2) << 8 | 1);
                for (model) |entry| if (entry.token != 0)
                    try testing.expectEqual(Status.stale, fs.prepareRead(entry.owner, entry.token, 0, 1).status);
                model = [_]ModelHandle{.{}} ** handle_limit;
            },
            else => unreachable,
        }
        try testing.expectEqual(@as(u32, @intCast(serial)), fs.next_serial);
        for (model, 0..) |entry, index| {
            try testing.expectEqual(entry.token != 0, fs.handles[index].used);
            for ([_]u64{ 0x103, 0x104, 0x105 }) |candidate| {
                const permitted = entry.token != 0 and entry.owner == candidate;
                try testing.expectEqual(if (permitted) Status.ok else Status.stale, fs.prepareRead(candidate, entry.token, 0, 1).status);
            }
        }
    }
}
