// Filesystem-private immutable input records. No allocator or kernel objects.
const storage = @import("storage.zig");
pub const Status = storage.Status;
pub const record_limit: usize = 2;
pub const reader_limit: usize = 2;
pub const byte_limit: usize = 128;
pub const serial_max: u64 = 0x00ffffffffffffff;

// The full issuer endpoint is part of the reference, not a truncated generation.
// The low-byte type is distinct from file slots and kernel/contract references.
pub const Ref = struct { issuer: u64 = 0, token: u64 = 0 };
pub fn validEndpoint(endpoint: u64) bool {
    return endpoint & 0xff >= 1 and endpoint & 0xff <= 8 and endpoint >> 8 != 0 and endpoint <= 0x7fffffffffffffff;
}
pub fn validIssuer(issuer: u64) bool {
    return validEndpoint(issuer) and issuer & 0xff == 2;
}
pub fn validRef(reference: Ref) bool {
    return validIssuer(reference.issuer) and reference.token >> 8 != 0 and
        reference.token & 0xff >= 0xa1 and reference.token & 0xff < 0xa1 + record_limit;
}
pub const State = enum(u8) { empty, capturing, live, closed, failed, settled };
pub const Record = struct {
    state: State = .empty,
    token: u64 = 0,
    owner: u64 = 0,
    transaction: u64 = 0,
    handle: u64 = 0,
    block: u64 = 0,
    file: u8 = 0,
    revision: u64 = 0,
    length: u8 = 0,
    captured: u8 = 0,
    last_status: Status = .ok,
    readers: [reader_limit]u64 = [_]u64{0} ** reader_limit,
    checker: u64 = 0,
    settled_reader: u64 = 0,
    bytes: [byte_limit]u8 = [_]u8{0} ** byte_limit,
};
pub const Capture = struct {
    status: Status = .invalid,
    reference: Ref = .{},
    length: u8 = 0,
    block: u64 = 0,
    slot: u8 = 0,
    fresh: bool = false,
};
pub const OwnerWatermark = struct { endpoint: u64 = 0, transaction: u64 = 0 };

pub const Table = struct {
    issuer: u64,
    block: u64 = 0,
    next_serial: u64 = 1,
    records: [record_limit]Record = [_]Record{.{}} ** record_limit,
    owner_watermarks: [8]OwnerWatermark = [_]OwnerWatermark{.{}} ** 8,

    pub fn init(issuer: u64) Table {
        return .{ .issuer = issuer };
    }

    pub fn index(self: *const Table, reference: Ref) ?usize {
        if (!validIssuer(self.issuer) or reference.issuer != self.issuer) return null;
        const tag = reference.token & 0xff;
        if (tag < 0xa1 or tag >= 0xa1 + record_limit or reference.token >> 8 == 0) return null;
        const slot: usize = @intCast(tag - 0xa1);
        const record = &self.records[slot];
        return if (record.state != .empty and record.token == reference.token) slot else null;
    }

    pub fn status(self: *const Table, owner: u64, transaction: u64) ?Record {
        if (owner == 0 or transaction == 0) return null;
        for (self.records) |record|
            if (record.state != .empty and record.owner == owner and record.transaction == transaction) return record;
        return null;
    }

    fn capture(self: *const Table, slot: usize, fresh: bool) Capture {
        const record = self.records[slot];
        return .{
            .status = if (record.state == .capturing and !fresh) .again else record.last_status,
            .reference = .{ .issuer = self.issuer, .token = record.token },
            .length = record.length,
            .block = record.block,
            .slot = @intCast(slot),
            .fresh = fresh,
        };
    }

    // A duplicate creation transaction recovers the original record, even after
    // the source handle closes. Altering its handle is never idempotent.
    // Invalid prevalidation, exhausted serial, and full table consume nothing.
    pub fn begin(self: *Table, fs: *const storage.Fs, owner: u64, transaction: u64, handle: u64) Capture {
        if (!validEndpoint(owner) or transaction == 0 or handle == 0 or !validIssuer(self.issuer) or self.issuer >> 8 != fs.generation) return .{};
        for (self.records, 0..) |record, slot| {
            if (record.state != .empty and record.owner == owner and record.transaction == transaction) {
                if (record.handle != handle) return .{};
                return self.capture(slot, false);
            }
        }
        const owner_slot: usize = @intCast((owner & 255) - 1);
        const previous = self.owner_watermarks[owner_slot];
        if (owner >> 8 < previous.endpoint >> 8 or
            (owner == previous.endpoint and transaction <= previous.transaction)) return .{ .status = .stale };
        const source = fs.prepareRead(owner, handle, 0, 0);
        if (source.status != .ok) return .{ .status = source.status };
        const file = fs.files[source.file];
        if (file.length > byte_limit) return .{ .status = .too_large };
        if (self.block == 0 or self.block != fs.block) return .{ .status = .stale };
        if (self.next_serial == 0 or self.next_serial > serial_max) return .{ .status = .no_space };
        var free: ?usize = null;
        for (self.records, 0..) |record, slot| if (record.state == .empty) {
            free = slot;
            break;
        };
        const slot = free orelse return .{ .status = .no_space };
        const token = (self.next_serial << 8) | (0xa1 + @as(u64, @intCast(slot)));
        self.next_serial = if (self.next_serial == serial_max) 0 else self.next_serial + 1;
        self.records[slot] = .{
            .state = .capturing,
            .token = token,
            .owner = owner,
            .transaction = transaction,
            .handle = handle,
            .block = fs.block,
            .file = source.file,
            .revision = file.revision,
            .length = @intCast(file.length),
        };
        self.owner_watermarks[owner_slot] = .{ .endpoint = owner, .transaction = transaction };
        return self.capture(slot, true);
    }

    fn coherent(self: *const Table, fs: *const storage.Fs, record: *const Record) bool {
        if (self.block == 0 or self.block != record.block or fs.block != record.block) return false;
        const source = fs.prepareRead(record.owner, record.handle, 0, 0);
        return source.status == .ok and source.file == record.file and
            fs.files[source.file].length == record.length and fs.files[source.file].revision == record.revision;
    }

    pub fn append(self: *Table, fs: *const storage.Fs, owner: u64, reference: Ref, offset: u32, data: []const u8) Status {
        const slot = self.index(reference) orelse return .stale;
        const record = &self.records[slot];
        if (record.owner != owner or record.state != .capturing) return .stale;
        if (!self.coherent(fs, record)) return self.fail(owner, reference, .stale);
        const remaining = @as(usize, record.length) - record.captured;
        const amount = @min(@as(usize, storage.chunk_size), remaining);
        if (offset != record.captured or data.len != amount or amount == 0) return .invalid;
        @memcpy(record.bytes[offset..][0..amount], data);
        record.captured += @intCast(amount);
        return .ok;
    }

    pub fn publish(self: *Table, fs: *const storage.Fs, owner: u64, reference: Ref) Status {
        const slot = self.index(reference) orelse return .stale;
        const record = &self.records[slot];
        if (record.owner != owner or record.state != .capturing) return .stale;
        if (!self.coherent(fs, record)) return self.fail(owner, reference, .stale);
        if (record.captured != record.length) return .again;
        record.state = .live;
        record.last_status = .ok;
        return .ok;
    }

    pub fn fail(self: *Table, owner: u64, reference: Ref, reason: Status) Status {
        const slot = self.index(reference) orelse return .stale;
        const record = &self.records[slot];
        if (record.owner != owner or record.state != .capturing or reason == .ok) return .stale;
        record.bytes = [_]u8{0} ** byte_limit;
        record.captured = 0;
        record.readers = [_]u64{0} ** reader_limit;
        record.state = .failed;
        record.last_status = reason;
        return reason;
    }

    pub fn bind(self: *Table, owner: u64, reference: Ref, reader: u64) Status {
        const slot = self.index(reference) orelse return .stale;
        const record = &self.records[slot];
        if (record.owner != owner or record.state != .live) return .stale;
        if (!validEndpoint(reader) or reader == owner) return .invalid;
        for (record.readers) |endpoint| if (endpoint == reader) return .ok;
        for (&record.readers) |*endpoint| if (endpoint.* == 0) {
            endpoint.* = reader;
            return .ok;
        };
        return .no_space;
    }

    pub fn revoke(self: *Table, owner: u64, reference: Ref, reader: u64) Status {
        const slot = self.index(reference) orelse return .stale;
        const record = &self.records[slot];
        if (record.owner != owner or record.state != .live) return .stale;
        if (!validEndpoint(reader) or reader == owner) return .invalid;
        // Repeated revocation of the exact object/endpoint is harmless.
        for (&record.readers) |*endpoint| if (endpoint.* == reader) {
            endpoint.* = 0;
        };
        if (record.checker == reader) record.checker = 0;
        return .ok;
    }

    pub fn bindChecker(self: *Table, owner: u64, reference: Ref, reader: u64) Status {
        const slot = self.index(reference) orelse return .stale;
        const record = &self.records[slot];
        if (record.owner != owner or record.state != .live) return .stale;
        if (record.checker != 0 and record.checker != reader) return .denied;
        const result = self.bind(owner, reference, reader);
        if (result == .ok) record.checker = reader;
        return result;
    }

    // Release authority is separately kernel-admitted and separately granted
    // by the owner for this exact object/checker endpoint. A worker read bind
    // never authorizes release. Owner close/revoke before settlement wins.
    pub fn release(self: *Table, checker: u64, reference: Ref) Status {
        return self.releaseBound(checker, reference, 0);
    }

    pub fn releaseBound(self: *Table, checker: u64, reference: Ref, reader: u64) Status {
        const slot = self.index(reference) orelse return .stale;
        const record = &self.records[slot];
        if (checker == 0 or record.checker != checker) return .denied;
        if (record.state == .settled) return if (reader == 0 or record.settled_reader == reader) .ok else .invalid;
        if (record.state != .live or !self.bindingValid(checker, reference)) return .stale;
        if (reader != 0 and (reader == checker or reader == record.owner or !self.bindingValid(reader, reference))) return .denied;
        record.bytes = [_]u8{0} ** byte_limit;
        record.captured = 0;
        record.readers = [_]u64{0} ** reader_limit;
        record.state = .settled;
        record.settled_reader = reader;
        record.last_status = .ok;
        return .ok;
    }

    pub fn bindingValid(self: *const Table, reader: u64, reference: Ref) bool {
        const slot = self.index(reference) orelse return false;
        const record = &self.records[slot];
        if (reader == 0 or record.state != .live or record.block != self.block or self.block == 0) return false;
        if (record.owner == reader) return true;
        for (record.readers) |endpoint| if (endpoint == reader) return true;
        return false;
    }

    pub fn read(self: *const Table, reader: u64, reference: Ref, offset: u32, count: u32, out: *[storage.chunk_size]u8) i32 {
        out.* = [_]u8{0} ** storage.chunk_size;
        const slot = self.index(reference) orelse return @intFromEnum(Status.stale);
        if (!self.bindingValid(reader, reference)) return @intFromEnum(Status.denied);
        if (count > storage.chunk_size) return @intFromEnum(Status.too_large);
        const end = @addWithOverflow(offset, count);
        if (end[1] != 0) return @intFromEnum(Status.invalid);
        if (offset > byte_limit) return @intFromEnum(Status.too_large);
        const record = &self.records[slot];
        const amount = if (offset >= record.length) 0 else @min(count, @as(u32, record.length) - offset);
        @memcpy(out[0..amount], record.bytes[offset..][0..amount]);
        return @intCast(amount);
    }

    pub fn close(self: *Table, owner: u64, reference: Ref) Status {
        const slot = self.index(reference) orelse return .stale;
        const record = &self.records[slot];
        if (record.owner != owner) return .stale;
        record.bytes = [_]u8{0} ** byte_limit;
        record.captured = 0;
        record.readers = [_]u64{0} ** reader_limit;
        if (record.state != .settled) record.state = .closed;
        record.last_status = .ok;
        return .ok;
    }

    pub fn reap(self: *Table, owner: u64, reference: Ref) Status {
        const slot = self.index(reference) orelse return .stale;
        const record = &self.records[slot];
        if (record.owner != owner) return .stale;
        if (record.state != .closed and record.state != .failed and record.state != .settled) return .again;
        record.* = .{};
        return .ok;
    }

    // Explicit owner retirement is finite; cold service boot creates an empty
    // table. Serial is preserved during live service dependency retirement.
    pub fn retireOwner(self: *Table, owner: u64) usize {
        if (!validEndpoint(owner)) return 0;
        var retired: usize = 0;
        for (&self.records) |*record| if (record.state != .empty and record.owner == owner) {
            record.* = .{};
            retired += 1;
        };
        const slot: usize = @intCast((owner & 255) - 1);
        if (owner >> 8 >= self.owner_watermarks[slot].endpoint >> 8)
            self.owner_watermarks[slot] = .{ .endpoint = owner, .transaction = 0xffffffffffffffff };
        return retired;
    }

    pub fn invalidateBlock(self: *Table, block: u64) void {
        if (self.block == block) return;
        self.block = block;
        for (&self.records) |*record| if (record.state != .empty and record.state != .closed and record.state != .settled) {
            record.bytes = [_]u8{0} ** byte_limit;
            record.captured = 0;
            record.readers = [_]u64{0} ** reader_limit;
            record.state = .failed;
            record.last_status = .stale;
        };
    }

    pub fn retained(self: *const Table) usize {
        var count: usize = 0;
        for (self.records) |record| if (record.state != .empty) {
            count += 1;
        };
        return count;
    }
    pub fn backing(self: *const Table) usize {
        var count: usize = 0;
        for (self.records) |record| if (record.state == .capturing or record.state == .live) {
            count += byte_limit;
        };
        return count;
    }
    pub fn readerCount(self: *const Table) usize {
        var count: usize = 0;
        for (self.records) |record| for (record.readers) |reader| {
            if (reader != 0) count += 1;
        };
        return count;
    }
    pub fn liveCount(self: *const Table) usize {
        var count: usize = 0;
        for (self.records) |record| if (record.state == .live) {
            count += 1;
        };
        return count;
    }
};
