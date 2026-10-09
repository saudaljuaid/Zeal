// The console uses the same authenticated storage packets and bounded
// transaction state as the existing filesystem client. No fixture file bytes.
const abi = @import("abi.zig");
const storage = @import("storage.zig");
const wire = @import("storage_wire.zig");
const transport = @import("storage_transport.zig");

pub const ReadResult = struct { status: i32 = 0, length: u32 = 0, close_status: i32 = 0 };
const Outcome = struct { reply: ?wire.Header = null, failure: i32 = @intFromEnum(abi.Error.timeout) };

pub const Client = struct {
    sequence: wire.Sequence = .{},

    fn transaction(self: *Client, endpoint: u64, operation: abi.Operation, handle: u64, offset: u32, count: u32, name: []const u8, io: anytype) Outcome {
        if (endpoint == 0) return .{ .failure = @intFromEnum(abi.Error.again) };
        var pending = transport.Request.init(&self.sequence, endpoint, .file_result, handle, offset, count, false) orelse
            return .{ .failure = @intFromEnum(abi.Error.no_space) };
        pending.opening = operation == .file_open;
        var request = if (pending.opening) wire.openExistingRequest(pending.id, name) else wire.request(operation, pending.id, handle, offset, count, &.{});
        while (pending.canSend()) {
            if (io.endpoint() != endpoint) return .{ .failure = @intFromEnum(abi.Error.stale) };
            const result = io.send(endpoint, &request, operation);
            pending.sent(result);
            if (result != 0 and result != @intFromEnum(abi.Error.again)) return .{ .failure = result };
            if (pending.canSend()) io.idle();
        }
        while (pending.canReceive()) {
            var reply: abi.Message = undefined;
            const result = io.receive(&reply, transport.receive_ticks);
            const current = io.endpoint();
            if (current != endpoint) return .{ .failure = @intFromEnum(abi.Error.stale) };
            if (pending.received(current, result, if (result == 0) &reply else null)) |answer|
                return .{ .reply = answer };
            if (result != 0) return .{ .failure = result };
        }
        return .{};
    }

    pub fn read(self: *Client, name: []const u8, bytes: *[storage.file_size]u8, io: anytype) ReadResult {
        if (!storage.validName(name)) return .{ .status = @intFromEnum(abi.Error.invalid) };
        const endpoint = io.endpoint();
        const opening = self.transaction(endpoint, .file_open, 0, 0, 0, name, io);
        const opened = opening.reply orelse return .{ .status = opening.failure };
        if (opened.value != 0) return .{ .status = opened.value };
        var result: ReadResult = .{};
        var eof = false;
        // At most sixteen data chunks plus one EOF request. Offsets never
        // exceed the service's 128-byte extent, even under malicious replies.
        for (0..storage.file_size / storage.chunk_size + 1) |_| {
            const count = @min(storage.chunk_size, storage.file_size - result.length);
            const outcome = self.transaction(endpoint, .file_chunk_read, opened.handle, result.length, count, &.{}, io);
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
            @memcpy(bytes[result.length..][0..got], answer.data[0..got]);
            result.length += got;
            io.chunk(answer.id, &answer.data);
            io.idle();
        }
        if (result.status == 0 and !eof) result.status = @intFromEnum(abi.Error.too_large);
        // Attempt exactly one bounded close even after a read failure. A lost
        // open reply cannot be closed because its unknown handle is unavailable.
        const closing = self.transaction(endpoint, .file_close, opened.handle, 0, 0, &.{}, io);
        result.close_status = if (closing.reply) |answer| answer.value else closing.failure;
        return result;
    }
};
