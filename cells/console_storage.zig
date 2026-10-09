// Authenticated, bounded console file operations using the production transport.
const abi = @import("abi.zig");
const storage = @import("storage.zig");
const wire = @import("storage_wire.zig");
const transport = @import("storage_transport.zig");

pub const ReadResult = struct { status: i32 = 0, length: u32 = 0, close_status: i32 = 0, open_unknown: bool = false };
pub const MutationResult = struct {
    status: i32 = 0,
    // Only bytes with a matching full-count acknowledgment are included.
    length: u32 = 0,
    close_status: i32 = 0,
    changed: bool = false,
    unknown: bool = false,
    open_unknown: bool = false,
};
pub const ListResult = struct {
    status: i32 = 0,
    length: usize = 0,
    entries: [storage.file_limit]wire.ListEntry = undefined,
};
const Outcome = struct {
    reply: ?wire.Header = null,
    failure: i32 = @intFromEnum(abi.Error.timeout),
    enqueued: bool = false,
};

pub const Client = struct {
    sequence: wire.Sequence = .{},

    fn transaction(self: *Client, endpoint: u64, operation: abi.Operation, handle: u64, offset: u32, count: u32, name: []const u8, data: []const u8, create: bool, io: anytype) Outcome {
        if (endpoint == 0) return .{ .failure = @intFromEnum(abi.Error.again) };
        var pending = transport.Request.init(&self.sequence, endpoint, .file_result, handle, offset, count, operation != .file_chunk_read) orelse
            return .{ .failure = @intFromEnum(abi.Error.no_space) };
        pending.opening = operation == .file_open;
        const request = if (pending.opening)
            (if (create) wire.openRequest(pending.id, name) else wire.openExistingRequest(pending.id, name))
        else
            wire.request(operation, pending.id, handle, offset, count, data);
        var enqueued = false;
        while (pending.canSend()) {
            if (io.endpoint() != endpoint) return .{ .failure = @intFromEnum(abi.Error.stale), .enqueued = enqueued };
            const result = io.send(endpoint, &request, operation);
            pending.sent(result);
            if (result == 0) enqueued = true;
            if (result != 0 and result != @intFromEnum(abi.Error.again)) return .{ .failure = result, .enqueued = enqueued };
            if (pending.canSend()) io.idle();
        }
        while (pending.canReceive()) {
            var reply: abi.Message = undefined;
            const result = io.receive(&reply, transport.receive_ticks);
            const current = io.endpoint();
            if (current != endpoint) return .{ .failure = @intFromEnum(abi.Error.stale), .enqueued = enqueued };
            if (pending.received(current, result, if (result == 0) &reply else null)) |answer| {
                // Write acknowledgments carry no data, unlike read replies.
                if (operation == .file_write) for (answer.data) |byte| {
                    if (byte != 0) return .{ .enqueued = enqueued };
                };
                return .{ .reply = answer, .enqueued = enqueued };
            }
            if (result != 0) return .{ .failure = result, .enqueued = enqueued };
        }
        return .{ .enqueued = enqueued };
    }

    fn close(self: *Client, endpoint: u64, handle: u64, io: anytype) i32 {
        const outcome = self.transaction(endpoint, .file_close, handle, 0, 0, &.{}, &.{}, false, io);
        return if (outcome.reply) |answer| answer.value else outcome.failure;
    }

    // Captures actual bytes or just observes actual EOF on this same handle.
    // The bounded count and EOF rules are identical for cat and append.
    fn collect(self: *Client, endpoint: u64, handle: u64, bytes: ?*[storage.file_size]u8, io: anytype) ReadResult {
        var result: ReadResult = .{};
        var eof = false;
        for (0..storage.file_size / storage.chunk_size + 1) |_| {
            const count = @min(storage.chunk_size, storage.file_size - result.length);
            const outcome = self.transaction(endpoint, .file_chunk_read, handle, result.length, count, &.{}, &.{}, false, io);
            const answer = outcome.reply orelse {
                result.status = outcome.failure;
                break;
            };
            if (answer.value < 0) {
                result.status = answer.value;
                break;
            }
            if (answer.value == 0) {
                eof = true;
                break;
            }
            const got: u32 = @intCast(answer.value);
            if (bytes) |destination| @memcpy(destination[result.length..][0..got], answer.data[0..got]);
            result.length += got;
            io.chunk(answer.id, &answer.data);
            io.idle();
        }
        if (result.status == 0 and !eof) result.status = @intFromEnum(abi.Error.too_large);
        return result;
    }

    pub fn read(self: *Client, name: []const u8, bytes: *[storage.file_size]u8, io: anytype) ReadResult {
        if (!storage.validName(name)) return .{ .status = @intFromEnum(abi.Error.invalid) };
        const endpoint = io.endpoint();
        const opening = self.transaction(endpoint, .file_open, 0, 0, 0, name, &.{}, false, io);
        const opened = opening.reply orelse return .{ .status = opening.failure, .open_unknown = opening.enqueued };
        if (opened.value != 0) return .{ .status = opened.value };
        var result = self.collect(endpoint, opened.handle, bytes, io);
        // Exactly one bounded close path for every known opened handle.
        result.close_status = self.close(endpoint, opened.handle, io);
        return result;
    }

    fn failedMutation(result: *MutationResult, outcome: Outcome) void {
        result.status = if (outcome.reply) |answer| answer.value else outcome.failure;
        result.unknown = if (outcome.reply) |answer| answer.value == @intFromEnum(abi.Error.timeout) else outcome.enqueued;
        result.changed = result.changed or result.unknown;
    }

    fn writeChunks(self: *Client, endpoint: u64, handle: u64, offset: u32, text: []const u8, empty_write: bool, result: *MutationResult, io: anytype) void {
        var at: usize = 0;
        while (at < text.len or (empty_write and at == 0)) {
            const count: u32 = @intCast(@min(storage.chunk_size, text.len - at));
            const outcome = self.transaction(endpoint, .file_write, handle, offset + @as(u32, @intCast(at)), count, &.{}, text[at..][0..count], false, io);
            const answer = outcome.reply orelse {
                failedMutation(result, outcome);
                return;
            };
            if (answer.value != count) {
                failedMutation(result, outcome);
                return;
            }
            result.length += count;
            if (count != 0) result.changed = true;
            at += count;
            if (count == 0) break;
            io.idle();
        }
    }

    pub fn replace(self: *Client, name: []const u8, text: []const u8, io: anytype) MutationResult {
        if (!storage.validName(name)) return .{ .status = @intFromEnum(abi.Error.invalid) };
        if (text.len > storage.file_size) return .{ .status = @intFromEnum(abi.Error.too_large) };
        const endpoint = io.endpoint();
        const opening = self.transaction(endpoint, .file_open, 0, 0, 0, name, &.{}, true, io);
        const opened = opening.reply orelse return .{
            .status = opening.failure,
            .changed = opening.enqueued,
            .unknown = opening.enqueued,
            .open_unknown = opening.enqueued,
        };
        if (opened.value != 0) return .{ .status = opened.value, .changed = opened.value == -8, .unknown = opened.value == -8 };
        // Legacy create-on-open can itself publish an empty new file. Do not
        // claim no changes if a subsequent truncate or write fails.
        var result: MutationResult = .{ .changed = true };
        const truncating = self.transaction(endpoint, .file_truncate, opened.handle, 0, 0, &.{}, &.{}, false, io);
        if (truncating.reply) |answer| {
            if (answer.value == 0) {
                self.writeChunks(endpoint, opened.handle, 0, text, false, &result, io);
            } else {
                failedMutation(&result, truncating);
                // An authenticated filesystem DENIED here proves readonly;
                // that existing file was not created or truncated by open.
                if (answer.value == @intFromEnum(abi.Error.denied)) result.changed = false;
            }
        } else failedMutation(&result, truncating);
        result.close_status = self.close(endpoint, opened.handle, io);
        return result;
    }

    pub fn append(self: *Client, name: []const u8, text: []const u8, io: anytype) MutationResult {
        if (!storage.validName(name)) return .{ .status = @intFromEnum(abi.Error.invalid) };
        if (text.len > storage.file_size) return .{ .status = @intFromEnum(abi.Error.too_large) };
        const endpoint = io.endpoint();
        const opening = self.transaction(endpoint, .file_open, 0, 0, 0, name, &.{}, false, io);
        const opened = opening.reply orelse return .{ .status = opening.failure, .unknown = opening.enqueued, .open_unknown = opening.enqueued };
        if (opened.value != 0) return .{ .status = opened.value };
        var result: MutationResult = .{};
        const observed = self.collect(endpoint, opened.handle, null, io);
        if (observed.status != 0) {
            result.status = observed.status;
        } else if (text.len > storage.file_size - observed.length) {
            // Check the complete payload against actual observed EOF before
            // sending any data write. Overflow never commits a valid prefix.
            result.status = @intFromEnum(abi.Error.too_large);
        } else {
            // Concurrent writers may alter EOF after collection. These are
            // ordinary explicit-offset chunks, not atomic append or replay.
            self.writeChunks(endpoint, opened.handle, observed.length, text, text.len == 0, &result, io);
        }
        result.close_status = self.close(endpoint, opened.handle, io);
        return result;
    }

    pub fn list(self: *Client, io: anytype) ListResult {
        const endpoint = io.endpoint();
        if (endpoint == 0) return .{ .status = @intFromEnum(abi.Error.again) };
        var result: ListResult = .{};
        // Each slot is observed separately; this is not a coherent snapshot
        // of all four metadata entries under concurrent mutation.
        for (0..storage.file_limit) |slot| {
            const index: u32 = @intCast(slot);
            var pending = transport.Request.init(&self.sequence, endpoint, .file_result, 0, index, 0, true) orelse
                return .{ .status = @intFromEnum(abi.Error.no_space) };
            const request = wire.listRequest(pending.id, index);
            while (pending.canSend()) {
                if (io.endpoint() != endpoint) return .{ .status = @intFromEnum(abi.Error.stale) };
                const status = io.send(endpoint, &request, .file_list);
                pending.sent(status);
                if (status != 0 and status != @intFromEnum(abi.Error.again)) return .{ .status = status };
                if (pending.canSend()) io.idle();
            }
            if (!pending.canReceive()) return .{ .status = @intFromEnum(abi.Error.timeout) };
            var entry: ?wire.ListEntry = null;
            for (0..transport.receive_limit) |_| {
                var message: abi.Message = undefined;
                const status = io.receive(&message, transport.receive_ticks);
                if (io.endpoint() != endpoint) return .{ .status = @intFromEnum(abi.Error.stale) };
                if (status != 0) return .{ .status = status };
                entry = wire.decodeListReply(&message, endpoint, pending.id, index);
                if (entry != null) break;
            }
            const observed = entry orelse return .{ .status = @intFromEnum(abi.Error.timeout) };
            if (observed.status == @intFromEnum(abi.Error.not_found)) continue;
            if (observed.status != 0) return .{ .status = observed.status };
            result.entries[result.length] = observed;
            result.length += 1;
        }
        return result;
    }
};
