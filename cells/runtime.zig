const abi = @import("abi.zig");
const protocol = @import("protocol.zig");
const syscall = @import("syscall.zig");

pub fn run(comptime role: abi.Role) noreturn {
    var info: abi.BootInfo = undefined;
    if (syscall.boot(&info) != 0 or info.abi != abi.version or
        info.role != @intFromEnum(role) or info.generation == 0) syscall.exit();
    syscall.report(switch (role) {
        .block => 3,
        .filesystem => 4,
        .client => 5,
        .probe => 6,
    });
    if (role == .probe) {
        const sentinel: *volatile u64 = @ptrFromInt(abi.stack_base + 64);
        if (sentinel.* != 0) {
            syscall.report(255);
            syscall.exit();
        }
        sentinel.* = 0x52ea19a780de3b61;
        syscall.report(7);
    }
    switch (role) {
        .block => block(),
        .filesystem => filesystem(),
        .client => client(),
        .probe => @import("probe_runtime.zig").run(info.scenario),
    }
}

fn block() noreturn {
    var reply = protocol.dataReply(.read_reply);
    var destination: u64 = 0;
    while (true) {
        const filesystem_handle = syscall.lookup(.filesystem);
        if (destination != 0 and destination != filesystem_handle) destination = 0;
        if (destination != 0) {
            const result = syscall.send(destination, &reply);
            if (result == 0 or result == @intFromEnum(abi.Error.stale)) destination = 0;
        } else {
            var request: abi.Message = undefined;
            if (syscall.receive(&request) == 0 and
                protocol.validBlockRequest(&request, filesystem_handle)) destination = request.sender;
        }
        syscall.yield();
    }
}

fn filesystem() noreturn {
    var state: protocol.Filesystem = .{};
    while (true) {
        state.rebindBlock(syscall.lookup(.block));
        const client_handle = syscall.lookup(.client);
        state.rebindClient(client_handle);
        if (state.reply()) |value| {
            var reply = value;
            if (syscall.send(state.client, &reply) == 0) state.replySent();
        } else if (state.request()) |value| {
            var request = value;
            if (syscall.send(state.block, &request) == 0) state.requestSent();
        }
        var received: abi.Message = undefined;
        if (syscall.receive(&received) == 0) {
            if (!state.acceptReply(&received)) _ = state.acceptRequest(&received, client_handle);
        }
        syscall.yield();
    }
}

fn client() noreturn {
    var state: protocol.Client = .{};
    while (true) {
        state.rebind(syscall.lookup(.filesystem));
        if (state.request()) |value| {
            var request = value;
            if (syscall.send(state.filesystem, &request) == 0) state.requestSent();
        }
        var reply: abi.Message = undefined;
        if (syscall.receive(&reply) == 0 and state.acceptReply(&reply)) syscall.report(1);
        syscall.yield();
    }
}
