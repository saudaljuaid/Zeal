const abi = @import("abi.zig");
const wire = @import("storage_wire.zig");
const storage = @import("storage.zig");
const syscall = @import("syscall.zig");

const transport = @import("storage_transport.zig");
pub const Inbox = transport.Inbox;

fn outcome(code: u64, id: u64, operation: u32, result: i32) void {
    syscall.reportValues(code, id, (@as(u64, operation) << 32) | @as(u32, @bitCast(result)));
}

// Bounded retries apply only before enqueue. An enqueued write is never retransmitted here.
pub fn sendBounded(endpoint: u64, message: *const abi.Message, operation: abi.Operation) i32 {
    for (0..4) |_| {
        const result = syscall.sendGranted(endpoint, message, operation);
        if (result != @intFromEnum(abi.Error.again)) return @intCast(result);
        _ = syscall.sleep(1);
    }
    return @intFromEnum(abi.Error.timeout);
}

pub fn block() noreturn {
    const backing: *storage.Block = @ptrFromInt(abi.memory_base + 4096);
    backing.* = storage.Block.init();
    while (true) {
        var request: abi.Message = undefined;
        if (syscall.receiveWait(&request, 10) != 0) continue;
        const filesystem = syscall.lookup(.filesystem);
        if (filesystem == 0 or request.sender != filesystem) continue;
        if (@import("protocol.zig").validBlockRequest(&request, filesystem)) {
            var reply = abi.Message.empty(.read_reply);
            reply.length = storage.hello.len;
            @memcpy(reply.payload[0..storage.hello.len], backing.bytes[0..storage.hello.len]);
            _ = sendBounded(filesystem, &reply, .read_reply);
            continue;
        }
        const parsed = wire.decodeRequest(&request) orelse continue;
        var data = [_]u8{0} ** 8;
        const result = switch (request.operation) {
            @intFromEnum(abi.Operation.block_read) => backing.read(parsed.offset, @intCast(parsed.value), &data),
            @intFromEnum(abi.Operation.block_write) => backing.write(parsed.offset, parsed.data[0..@intCast(parsed.value)]),
            else => continue,
        };
        outcome(30, parsed.id, request.operation, result);
        var reply = wire.reply(.block_reply, parsed.id, 0, parsed.offset, result, if (request.operation == @intFromEnum(abi.Operation.block_read) and result > 0) data[0..@intCast(result)] else &.{});
        _ = sendBounded(filesystem, &reply, .block_reply);
    }
}

pub const Server = struct {
    fs: storage.Fs,
    sequence: wire.Sequence = .{},
    inbox: Inbox = .{},

    pub fn init(generation: u64) Server {
        return .{ .fs = storage.Fs.init(generation) };
    }
    pub fn rebind(self: *Server) void {
        _ = self.fs.rebindBlock(syscall.lookup(.block));
    }

    fn transfer(self: *Server, app_id: u64, operation: abi.Operation, address: u32, count: u32, data: []const u8) ?wire.Header {
        var pending = transport.Request.init(&self.sequence, self.fs.block, .block_reply, 0, address, count, true) orelse return null;
        var request = wire.request(operation, pending.id, 0, address, count, data);
        syscall.reportValues(37, app_id, pending.id);
        while (pending.canSend()) {
            const result: i32 = @intCast(syscall.sendGranted(pending.endpoint, &request, operation));
            pending.sent(result);
            if (pending.canSend()) _ = syscall.sleep(1);
        }
        while (pending.canReceive()) {
            if (self.inbox.count == self.inbox.messages.len) {
                pending.cancel();
                break;
            }
            var message: abi.Message = undefined;
            const result: i32 = @intCast(syscall.receiveWait(&message, transport.receive_ticks));
            self.rebind();
            if (pending.received(self.fs.block, result, if (result == 0) &message else null)) |reply| return reply;
            // Late block replies cannot become client requests. Other dequeued traffic retains FIFO order.
            if (result == 0 and message.operation != @intFromEnum(abi.Operation.block_reply)) _ = self.inbox.push(message);
        }
        return null;
    }

    pub fn accepts(operation: u32) bool {
        return operation >= @intFromEnum(abi.Operation.file_open) and operation <= @intFromEnum(abi.Operation.file_close);
    }

    pub fn process(self: *Server, request: *const abi.Message) void {
        self.rebind();
        var id: u64 = 0;
        var token: u64 = 0;
        var offset: u32 = 0;
        var result: i32 = @intFromEnum(storage.Status.invalid);
        var bytes = [_]u8{0} ** 8;
        var read_data = false;
        if (request.operation == @intFromEnum(abi.Operation.file_open)) {
            const open = wire.decodeOpen(request) orelse return;
            id = open.id;
            const plan = self.fs.prepareOpen(request.sender, open.name);
            result = @intFromEnum(plan.status);
            if (plan.status == .ok) {
                var cleared = true;
                if (plan.needs_zero) {
                    var at: u32 = 0;
                    while (at < storage.file_size) : (at += storage.chunk_size) {
                        const answer = self.transfer(id, .block_write, plan.address + at, storage.chunk_size, &bytes);
                        if (answer == null or answer.?.value != storage.chunk_size) {
                            cleared = false;
                            break;
                        }
                    }
                }
                result = if (cleared) @intFromEnum(self.fs.commitOpen(plan)) else @intFromEnum(storage.Status.timeout);
                if (result == 0) token = plan.token;
            }
        } else {
            const parsed = wire.decodeRequest(request) orelse return;
            id = parsed.id;
            token = parsed.handle;
            offset = parsed.offset;
            if (request.operation == @intFromEnum(abi.Operation.file_close)) {
                result = @intFromEnum(self.fs.close(request.sender, token));
            } else {
                const write = request.operation == @intFromEnum(abi.Operation.file_write);
                const plan = if (write) self.fs.prepareWrite(request.sender, token, offset, @intCast(parsed.value)) else self.fs.prepareRead(request.sender, token, offset, @intCast(parsed.value));
                result = @intFromEnum(plan.status);
                if (plan.status == .ok) {
                    const answer = self.transfer(id, if (write) .block_write else .block_read, plan.address, plan.count, if (write) parsed.data[0..plan.count] else &.{});
                    if (answer) |value| {
                        result = value.value;
                        if (result >= 0) {
                            if (write) {
                                const committed = self.fs.commitWrite(plan);
                                if (committed != .ok) result = @intFromEnum(committed);
                            } else {
                                bytes = value.data;
                                read_data = true;
                            }
                        }
                    } else result = @intFromEnum(storage.Status.timeout);
                }
            }
        }
        outcome(31, id, request.operation, result);
        var reply = wire.reply(.file_result, id, token, offset, result, if (read_data and result > 0) bytes[0..@intCast(result)] else &.{});
        _ = sendBounded(request.sender, &reply, .file_result);
    }
};
