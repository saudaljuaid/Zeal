// Independent identity-300 preservation workload. Its mailbox contains storage replies only.
const abi = @import("abi.zig");
const wire = @import("storage_wire.zig");
const storage = @import("storage.zig");
const syscall = @import("syscall.zig");
const runtime = @import("storage_runtime.zig");
const receive = @import("native_receive.zig");

pub const alpha = "Zeal alpha private file 01.";
pub const beta = "Distinct beta bytes survive.";

fn require(condition: bool) void {
    if (!condition) {
        syscall.report(255);
        syscall.exit();
    }
}
fn word(bytes: *const [8]u8) u64 {
    var result: u64 = 0;
    for (bytes, 0..) |byte, index| result |= @as(u64, byte) << @intCast(index * 8);
    return result;
}

pub const Workload = struct {
    sequence: wire.Sequence = .{},
    alpha_expected: []const u8 = alpha,
    analysis_mode: bool = false,
    deferred: @import("hosting_transport.zig").Inbox = .{},
    filesystem: u64,
    block: u64,
    handles: [3]u64 = .{ 0, 0, 0 },

    pub fn call(self: *Workload, operation: abi.Operation, handle: u64, offset: u32, count: u32, data: []const u8, name: []const u8) wire.Header {
        var io: KernelIo = .{};
        return self.callWith(operation, handle, offset, count, data, name, &io) orelse {
            require(false);
            unreachable;
        };
    }

    pub fn callWith(self: *Workload, operation: abi.Operation, handle: u64, offset: u32, count: u32, data: []const u8, name: []const u8, io: anytype) ?wire.Header {
        if (self.filesystem == 0 or self.block == 0 or io.filesystem() != self.filesystem or io.block() != self.block) return null;
        const id = self.sequence.take() orelse return null;
        var request = if (operation == .file_open) wire.openRequest(id, name) else wire.request(operation, id, handle, offset, count, data);
        if (io.send(self.filesystem, &request, operation) != 0) return null;
        var pending: receive.Budget = .{ .endpoint = self.filesystem };
        while (pending.canReceive()) {
            if (self.analysis_mode and self.deferred.count == self.deferred.messages.len) return null;
            var message: abi.Message = undefined;
            const result = io.receive(&message, receive.ticks);
            if (io.block() != self.block) return null;
            switch (pending.received(io.filesystem(), result)) {
                .retry => continue,
                .failed => return null,
                .message => {},
            }
            if (self.analysis_mode and message.operation == @intFromEnum(abi.Operation.hosting_request)) {
                if (!self.deferred.push(message)) return null;
                continue;
            }
            if (wire.decodeReply(&message, .file_result, self.filesystem, id)) |reply| {
                if (reply.offset != offset or (operation != .file_open and reply.handle != handle)) return null;
                return reply;
            }
        }
        return null;
    }

    pub fn open(self: *Workload, name: []const u8) u64 {
        const reply = self.call(.file_open, 0, 0, 0, &.{}, name);
        require(reply.value == 0 and reply.handle != 0);
        return reply.handle;
    }

    pub fn writeFile(self: *Workload, handle: u64, bytes: []const u8) void {
        var offset: u32 = 0;
        while (offset < bytes.len) {
            const count: u32 = @intCast(@min(8, bytes.len - offset));
            const written = self.call(.file_write, handle, offset, count, bytes[offset..][0..count], &.{});
            require(written.value == count);
            offset += count;
        }
    }

    pub fn readFile(self: *Workload, handle: u64, bytes: []const u8, pause: bool) void {
        var offset: u32 = 0;
        while (offset < bytes.len) {
            const count: u32 = @intCast(@min(8, bytes.len - offset));
            const read = self.call(.file_chunk_read, handle, offset, count, &.{}, &.{});
            require(read.value == count);
            for (bytes[offset..][0..count], 0..) |byte, index| require(read.data[index] == byte);
            syscall.reportValues(32, read.id, word(&read.data));
            if (pause) require(syscall.sleep(1) == 0);
            offset += count;
        }
        const eof = self.call(.file_chunk_read, handle, @intCast(bytes.len), 8, &.{}, &.{});
        require(eof.value == 0);
    }

    pub fn cycle(self: *Workload, serial: u64, pause: bool) void {
        self.readFile(self.handles[0], storage.hello, pause);
        self.readFile(self.handles[1], self.alpha_expected, pause);
        self.readFile(self.handles[2], beta, pause);
        syscall.reportValues(65, serial, 7);
    }
};

const KernelIo = struct {
    pub fn filesystem(_: *KernelIo) u64 {
        return syscall.lookup(.filesystem);
    }
    pub fn block(_: *KernelIo) u64 {
        return syscall.lookup(.block);
    }
    pub fn send(_: *KernelIo, endpoint: u64, request: *const abi.Message, operation: abi.Operation) i32 {
        return runtime.sendBounded(endpoint, request, operation);
    }
    pub fn receive(_: *KernelIo, message: *abi.Message, ticks: u64) i32 {
        return @intCast(syscall.receiveWait(message, ticks));
    }
};

pub fn run() noreturn {
    const stack: *volatile u64 = @ptrFromInt(abi.stack_base + 128);
    const memory: *volatile u64 = @ptrFromInt(abi.memory_base);
    require(stack.* == 0 and memory.* == 0);
    stack.* = 0x710bf391ad42c865;
    memory.* = 0x38d126ef8a905b47;
    syscall.reportValues(8, stack.*, memory.*);
    var workload: Workload = .{ .filesystem = syscall.lookup(.filesystem), .block = syscall.lookup(.block) };
    require(workload.filesystem != 0 and workload.block != 0);
    workload.handles[0] = workload.open("/hello");
    workload.handles[1] = workload.open("/alpha");
    workload.handles[2] = workload.open("/beta");
    workload.writeFile(workload.handles[1], alpha);
    workload.writeFile(workload.handles[2], beta);
    syscall.reportValues(64, workload.handles[1], workload.handles[2]);
    workload.cycle(0, false);
    var cycle: u64 = 1;
    while (true) {
        require(stack.* == 0x710bf391ad42c865 and memory.* == 0x38d126ef8a905b47);
        workload.cycle(cycle, true);
        if (cycle == 0xffffffffffffffff) syscall.exit();
        cycle += 1;
    }
}

test "hosting storage payloads are distinct multi-chunk bounded files" {
    const testing = @import("std").testing;
    try testing.expect(alpha.len > 8 and alpha.len < storage.file_size);
    try testing.expect(beta.len > 8 and beta.len < storage.file_size);
    try testing.expect(!@import("std").mem.eql(u8, alpha, beta));
    try testing.expectEqual(@as(u64, 0x0807060504030201), word(&.{ 1, 2, 3, 4, 5, 6, 7, 8 }));
}
