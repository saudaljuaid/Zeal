const abi = @import("abi.zig");
const wire = @import("storage_wire.zig");
const syscall = @import("syscall.zig");
const runtime = @import("storage_runtime.zig");
pub const payload = "Zeal writable RAM storage.";

fn require(condition: bool) void {
    if (!condition) {
        syscall.report(255);
        syscall.exit();
    }
}

fn word(bytes: *const [8]u8) u64 {
    var value: u64 = 0;
    for (bytes, 0..) |byte, index| value |= @as(u64, byte) << @intCast(index * 8);
    return value;
}

pub const Demo = struct {
    sequence: wire.Sequence = .{ .next = 2 },
    phase: u8 = 0,
    handle: u64 = 0,
    block: u64 = 0,
    filesystem: u64 = 0,

    fn call(self: *Demo, endpoint: u64, operation: abi.Operation, handle: u64, offset: u32, count: u32, data: []const u8) ?wire.Header {
        const id = self.sequence.take() orelse return null;
        var request = if (operation == .file_open) wire.openRequest(id, "/note") else wire.request(operation, id, handle, offset, count, data);
        if (runtime.sendBounded(endpoint, &request, operation) != 0) return null;
        for (0..8) |_| {
            var message: abi.Message = undefined;
            if (syscall.receiveWait(&message, 10) != 0 or syscall.lookup(.filesystem) != endpoint) return null;
            if (wire.decodeReply(&message, .file_result, endpoint, id)) |reply| {
                if (reply.offset != offset or (operation != .file_open and reply.handle != handle)) return null;
                return reply;
            }
        }
        return null;
    }

    fn cycle(self: *Demo, endpoint: u64) void {
        const opened = self.call(endpoint, .file_open, 0, 0, 0, &.{}) orelse {
            require(false);
            unreachable;
        };
        require(opened.value == 0 and opened.handle != 0);
        const empty = self.call(endpoint, .file_chunk_read, opened.handle, 0, 8, &.{}) orelse {
            require(false);
            unreachable;
        };
        require(empty.value == 0);
        const gap = self.call(endpoint, .file_write, opened.handle, 1, 1, "x") orelse {
            require(false);
            unreachable;
        };
        require(gap.value == @intFromEnum(abi.Error.invalid));
        var offset: u32 = 0;
        while (offset < payload.len) {
            const count: u32 = @intCast(@min(8, payload.len - offset));
            const written = self.call(endpoint, .file_write, opened.handle, offset, count, payload[offset..][0..count]) orelse {
                require(false);
                unreachable;
            };
            require(written.value == count);
            offset += count;
        }
        const closed = self.call(endpoint, .file_close, opened.handle, 0, 0, &.{}) orelse {
            require(false);
            unreachable;
        };
        require(closed.value == 0);
        const reopened = self.call(endpoint, .file_open, 0, 0, 0, &.{}) orelse {
            require(false);
            unreachable;
        };
        require(reopened.value == 0 and reopened.handle != opened.handle and reopened.handle != 0);
        self.handle = reopened.handle;
        offset = 0;
        while (offset < payload.len) {
            const count: u32 = @intCast(@min(8, payload.len - offset));
            const read = self.call(endpoint, .file_chunk_read, self.handle, offset, count, &.{}) orelse {
                require(false);
                unreachable;
            };
            require(read.value == count);
            for (payload[offset..][0..count], 0..) |byte, index| require(read.data[index] == byte);
            syscall.reportValues(32, read.id, word(&read.data));
            offset += count;
        }
        const eof = self.call(endpoint, .file_chunk_read, self.handle, payload.len, 8, &.{}) orelse {
            require(false);
            unreachable;
        };
        require(eof.value == 0);
    }

    pub fn advance(self: *Demo, endpoint: u64) void {
        const block = syscall.lookup(.block);
        if (endpoint == 0 or block == 0 or self.phase == 3) return;
        if (self.phase == 0) {
            self.cycle(endpoint);
            self.filesystem = endpoint;
            self.block = block;
            self.phase = 1;
            syscall.reportValues(35, 1, self.handle);
        } else if ((self.phase == 1 and block != self.block) or (self.phase == 2 and endpoint != self.filesystem)) {
            if (self.phase == 2) syscall.reportValues(38, self.filesystem, endpoint);
            const stale = self.call(endpoint, .file_chunk_read, self.handle, 0, 8, &.{}) orelse {
                require(false);
                unreachable;
            };
            require(stale.value == @intFromEnum(abi.Error.stale));
            syscall.reportValues(33, stale.id, self.handle);
            self.cycle(endpoint);
            self.block = block;
            self.filesystem = endpoint;
            self.phase += 1;
            if (self.phase == 2) syscall.reportValues(35, 2, self.handle) else syscall.reportValues(36, 3, payload.len);
        }
    }
};
