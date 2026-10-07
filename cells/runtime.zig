const abi = @import("abi.zig");
const protocol = @import("protocol.zig");
const syscall = @import("syscall.zig");
comptime {
    _ = @import("memory.zig");
}

fn require(condition: bool) void {
    if (!condition) {
        syscall.report(255);
        syscall.exit();
    }
}

pub fn run(comptime role: abi.Role) noreturn {
    var info: abi.BootInfo = undefined;
    if (syscall.boot(&info) != 0 or info.abi != abi.version or
        info.role != @intFromEnum(role) or info.generation == 0) syscall.exit();
    syscall.report(switch (role) {
        .block => 3,
        .filesystem => 4,
        .client => 5,
        .probe => 6,
        .supervisor, .worker => 255,
    });
    if (role == .probe) {
        const sentinel: *volatile u64 = @ptrFromInt(abi.stack_base + 64);
        require(sentinel.* == 0);
        sentinel.* = 0x52ea19a780de3b61;
        const writable: *volatile u64 = @ptrFromInt(abi.memory_base);
        require(writable.* == 0);
        writable.* = 0x193cd871aa46de02;
        syscall.report(7);
    }
    switch (role) {
        .block => @import("storage_runtime.zig").block(),
        .filesystem => filesystem(info.generation),
        .client => client(info.scenario),
        .probe => if (info.scenario >= 21 and info.scenario <= 23)
            @import("hosting_controller.zig").run(info)
        else
            @import("probe_runtime.zig").run(if (info.scenario == 20) 7 else info.scenario),
        .supervisor, .worker => syscall.exit(),
    }
}

fn filesystem(generation: u64) noreturn {
    var state: protocol.Filesystem = .{};
    var storage_server = @import("storage_runtime.zig").Server.init(generation);
    var demo_phase: u8 = if (generation == 1) 0 else 4;
    var child: u64 = 0;
    var parent: u64 = 0;
    while (true) {
        state.rebindBlock(syscall.lookup(.block));
        storage_server.rebind();
        const client_handle = syscall.lookup(.client);
        state.rebindClient(client_handle);
        if (demo_phase == 0 and client_handle != 0) {
            const own = syscall.lookup(.filesystem);
            const authority = syscall.find(own, abi.right(.file_read) | abi.delegate_right);
            if (authority > 0) {
                parent = @intCast(authority);
                const request: abi.DelegateRequest = .{
                    .parent = parent,
                    .holder_endpoint = client_handle,
                    .rights = abi.right(.file_read),
                };
                const result = syscall.delegate(&request);
                require(result > 0);
                child = @intCast(result);
                demo_phase = 1;
            }
        }
        if (demo_phase == 1 or demo_phase == 3) {
            var offer = protocol.capabilityMessage(.cap_offer, .{
                .phase = if (demo_phase == 1) 1 else 2,
                .handle = child,
                .parent = parent,
            });
            if (syscall.sendGranted(client_handle, &offer, .cap_offer) == 0)
                demo_phase = if (demo_phase == 1) 5 else 4;
        }
        if (demo_phase == 2) {
            require(syscall.revoke(child) == 0);
            demo_phase = 3;
        }
        if (state.reply()) |value| {
            var reply = value;
            if (syscall.sendGranted(state.client, &reply, .file_reply) == 0) state.replySent();
        } else if (state.request()) |value| {
            var request = value;
            if (syscall.sendGranted(state.block, &request, .read) == 0) state.requestSent();
        }
        var received: abi.Message = undefined;
        const incoming = storage_server.inbox.pop();
        const receive_result = if (incoming) |message| blk: {
            received = message;
            break :blk @as(i64, 0);
        } else syscall.receiveWait(&received, 10);
        if (receive_result == 0) {
            // A dependency can restart while this receive is suspended.
            state.rebindBlock(syscall.lookup(.block));
            storage_server.rebind();
            const receiving_client = syscall.lookup(.client);
            state.rebindClient(receiving_client);
            if (protocol.capabilityOffer(&received, receiving_client, .cap_ack)) |ack| {
                if (demo_phase == 5 and ack.phase == 1 and ack.handle == child and ack.parent == parent)
                    demo_phase = 2;
            } else if (@import("storage_runtime.zig").Server.accepts(received.operation)) {
                storage_server.process(&received);
            } else if (!state.acceptReply(&received)) _ = state.acceptRequest(&received, receiving_client);
        } else if (receive_result == @intFromEnum(abi.Error.timeout) and state.sent and !state.ready) {
            state.sent = false;
        }
        syscall.yield();
    }
}

const stack_value = 0x710bf391ad42c865;
const memory_value = 0x38d126ef8a905b47;

fn observeMemory() void {
    const stack: *volatile u64 = @ptrFromInt(abi.stack_base + 128);
    const writable: *volatile u64 = @ptrFromInt(abi.memory_base);
    require(stack.* == stack_value and writable.* == memory_value);
    syscall.reportValues(8, stack.*, writable.*);
}

fn client(scenario: u64) noreturn {
    if (scenario >= 21 and scenario <= 23) @import("hosting_storage.zig").run();
    const stack: *volatile u64 = @ptrFromInt(abi.stack_base + 128);
    const writable: *volatile u64 = @ptrFromInt(abi.memory_base);
    require(stack.* == 0 and writable.* == 0);
    stack.* = stack_value;
    writable.* = memory_value;
    observeMemory();
    var state: protocol.Client = .{};
    var demo_phase: u8 = 0;
    var child: u64 = 0;
    var parent: u64 = 0;
    var last_endpoint: u64 = 0;
    var normal_cap: u64 = 0;
    var wait_message_sent = false;
    var storage_demo: @import("storage_client.zig").Demo = .{};
    while (true) {
        const endpoint = syscall.lookup(.filesystem);
        if (endpoint != 0 and last_endpoint != 0 and endpoint != last_endpoint) {
            var old_request = protocol.fileRequest();
            require(syscall.send(last_endpoint, &old_request, normal_cap) == @intFromEnum(abi.Error.stale));
            const fresh = syscall.find(endpoint, abi.right(.file_read));
            require(fresh > 0 and @as(u64, @intCast(fresh)) != normal_cap);
            normal_cap = @intCast(fresh);
            var info: abi.CapabilityInfo = undefined;
            require(syscall.query(normal_cap, &info) == 0 and info.target == endpoint and
                info.holder == syscall.lookup(.client) and info.parent == 0 and
                info.rights & abi.right(.file_read) != 0);
            syscall.reportValues(11, last_endpoint, endpoint);
            observeMemory();
            demo_phase = 4;
        }
        if (scenario == 20 and storage_demo.phase > 0 and storage_demo.phase < 3) {
            const previous_phase = storage_demo.phase;
            storage_demo.advance(endpoint);
            if (storage_demo.phase != previous_phase) demo_phase = 4;
        }
        if (endpoint != 0) last_endpoint = endpoint;
        state.rebind(endpoint);
        if (demo_phase == 2) {
            var ack = protocol.capabilityMessage(.cap_ack, .{ .phase = 1, .handle = child, .parent = parent });
            if (syscall.sendGranted(endpoint, &ack, .cap_ack) == 0) demo_phase = 3;
        }
        if (demo_phase == 4) {
            if (state.request()) |value| {
                var request = value;
                const result = syscall.find(endpoint, abi.right(.file_read));
                if (result > 0) {
                    normal_cap = @intCast(result);
                    if (syscall.send(endpoint, &request, normal_cap) == 0) {
                        state.requestSent();
                        syscall.reportValues(13, endpoint, normal_cap);
                        demo_phase = 5;
                    }
                }
            }
        }
        var reply: abi.Message = undefined;
        const receive_result = syscall.receiveWait(&reply, 10);
        if (receive_result == 0) {
            if (protocol.capabilityOffer(&reply, endpoint, .cap_offer)) |offer| {
                if (demo_phase == 0 and offer.phase == 1) {
                    child = offer.handle;
                    parent = offer.parent;
                    var info: abi.CapabilityInfo = undefined;
                    require(syscall.query(child, &info) == 0 and info.holder == syscall.lookup(.client) and
                        info.target == endpoint and info.rights == abi.right(.file_read) and
                        info.reserved == 0 and info.parent == parent);
                    var forbidden = protocol.blockRequest();
                    const denied = syscall.send(endpoint, &forbidden, child);
                    require(denied == @intFromEnum(abi.Error.denied));
                    syscall.reportValues(12, abi.right(.read), @bitCast(denied));
                    if (scenario == 20) {
                        var forbidden_write = @import("storage_wire.zig").request(.file_write, 1, 1, 0, 1, "x");
                        const denied_write = syscall.send(endpoint, &forbidden_write, child);
                        require(denied_write == @intFromEnum(abi.Error.denied));
                        syscall.reportValues(34, 1, @bitCast(denied_write));
                    }
                    var allowed = protocol.fileRequest();
                    require(syscall.send(endpoint, &allowed, child) == 0);
                    state.requestSent();
                    demo_phase = 1;
                } else if (demo_phase == 3 and offer.phase == 2 and offer.handle == child and offer.parent == parent) {
                    var request = protocol.fileRequest();
                    require(syscall.send(endpoint, &request, child) == @intFromEnum(abi.Error.stale));
                    syscall.reportValues(10, child, endpoint);
                    demo_phase = 4;
                }
            } else if (state.acceptReply(&reply)) {
                syscall.report(1);
                if (scenario == 20 and demo_phase == 5) storage_demo.advance(endpoint);
                if (scenario == 19 and !wait_message_sent) {
                    require(syscall.sleep(3) == 0);
                    syscall.report(14);
                    var wake_message = abi.Message.empty(.cap_offer);
                    wake_message.length = 8;
                    const value: u64 = 0x7a65616c77616b65;
                    @memcpy(wake_message.payload[0..8], @as([*]const u8, @ptrCast(&value))[0..8]);
                    require(syscall.sendGranted(syscall.lookup(.probe), &wake_message, .cap_offer) == 0);
                    wait_message_sent = true;
                }
                if (demo_phase == 1) {
                    syscall.reportValues(9, child, parent);
                    demo_phase = 2;
                }
                require(syscall.sleep(1) == 0);
            }
        } else if (receive_result == @intFromEnum(abi.Error.timeout) and state.pending) {
            state.pending = false;
            if (demo_phase == 5) demo_phase = 4;
            if (demo_phase == 1) {
                var retry = protocol.fileRequest();
                if (syscall.send(endpoint, &retry, child) == 0) state.requestSent();
            }
        }
        syscall.yield();
    }
}
