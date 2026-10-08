// Root300 retains an independent actual filesystem/block workload. Mutation
// happens only while it has acknowledged a pause at a fully checked boundary.
const abi = @import("abi.zig");
const syscall = @import("syscall.zig");
const hosting = @import("hosting_runtime.zig");
const require = hosting.require;
const wire = @import("contract_wire.zig");
const source = @import("hosting_storage.zig");
pub const alpha = "Zeal\x00A\n\xfffile bytes\nold.";
pub const changed = "\n\x00new\xfe!\n" ++ alpha[8..];
pub fn run() noreturn {
    const stack: *volatile u64 = @ptrFromInt(abi.stack_base + 128);
    const memory: *volatile u64 = @ptrFromInt(abi.memory_base);
    require(stack.* == 0 and memory.* == 0);
    stack.* = 0x710bf391ad42c865;
    memory.* = 0x38d126ef8a905b47;
    syscall.reportValues(8, stack.*, memory.*);
    var workload: source.Workload = .{ .filesystem = syscall.lookup(.filesystem), .block = syscall.lookup(.block), .alpha_expected = alpha, .analysis_mode = true };
    const owner = syscall.lookup(.probe);
    require(owner != 0 and workload.filesystem != 0 and workload.block != 0);
    workload.handles[0] = workload.open("/hello");
    workload.handles[1] = workload.open("/alpha");
    workload.handles[2] = workload.open("/beta");
    workload.writeFile(workload.handles[1], alpha);
    workload.writeFile(workload.handles[2], source.beta);
    syscall.reportValues(64, workload.handles[1], workload.handles[2]);
    var cycle: u64 = 0;
    var mutated = false;
    while (true) {
        require(stack.* == 0x710bf391ad42c865 and memory.* == 0x38d126ef8a905b47);
        workload.cycle(cycle, cycle != 0);
        require(cycle != 0xffffffffffffffff);
        cycle += 1;
        var message: abi.Message = undefined;
        const received = if (workload.deferred.pop()) |queued| blk: {
            message = queued;
            break :blk @as(i64, 0);
        } else syscall.receiveWait(&message, 0);
        if (received != 0) continue;
        const packet = wire.decode(&message, owner, wire.request_operation) orelse continue;
        require(packet.command == .input and packet.kind == .request and packet.detail == 1 and packet.token == 0 and packet.data == 1 and !mutated);
        var ack = wire.encode(wire.reply_operation, .{ .id = packet.id, .command = .input, .kind = .response, .detail = 1, .data = 1 });
        require(syscall.sendGranted(owner, &ack, .hosting_reply) == 0);
        var complete = false;
        for (0..16) |_| {
            var finish: abi.Message = undefined;
            if (syscall.receiveWait(&finish, 10) != 0) continue;
            const next = wire.decode(&finish, owner, wire.request_operation) orelse continue;
            require(next.command == .input and next.kind == .request and next.id == packet.id and next.token == 0 and next.detail == 2 and next.data == 2);
            workload.alpha_expected = changed;
            mutated = true;
            ack = wire.encode(wire.reply_operation, .{ .id = packet.id, .command = .input, .kind = .response, .detail = 2, .data = 2 });
            require(syscall.sendGranted(owner, &ack, .hosting_reply) == 0);
            complete = true;
            break;
        }
        require(complete);
    }
}
