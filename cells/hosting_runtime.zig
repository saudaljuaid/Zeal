const abi = @import("abi.zig");
const syscall = @import("syscall.zig");
const wire = @import("hosting_wire.zig");
const transport = @import("hosting_transport.zig");
const app = @import("hosting_app.zig");
comptime {
    _ = @import("memory.zig");
}

pub fn require(condition: bool) void {
    if (!condition) {
        syscall.report(255);
        syscall.exit();
    }
}
pub fn bits(result: i64) u64 {
    return @bitCast(result);
}

pub fn sendBounded(endpoint: u64, message: *const abi.Message, channel: u64) i64 {
    for (0..transport.send_limit) |_| {
        const result = syscall.send(endpoint, message, channel);
        if (result != @intFromEnum(abi.Error.again)) return result;
        require(syscall.sleep(1) == 0);
    }
    return @intFromEnum(abi.Error.timeout);
}

pub fn enqueue(dispatcher: *transport.Dispatcher, index: usize, channel: u64) bool {
    const pending = &dispatcher.pending[index];
    while (pending.phase == .enqueue) {
        var message = pending.message();
        pending.sent(syscall.send(pending.endpoint, &message, channel));
        if (pending.phase == .enqueue) require(syscall.sleep(1) == 0);
    }
    return pending.phase == .waiting;
}

pub fn awaitReply(dispatcher: *transport.Dispatcher, index: usize, parent: u64) ?wire.Packet {
    while (dispatcher.pending[index].phase == .waiting) {
        var message: abi.Message = undefined;
        const result = syscall.receiveWait(&message, transport.receive_ticks);
        if (result == 0 and dispatcher.dispatch(message, parent) == .full) {
            dispatcher.retire(dispatcher.pending[index].endpoint);
            break;
        }
        dispatcher.receiveStep(result);
    }
    const response = dispatcher.take(index);
    if (response == null) dispatcher.release(index);
    return response;
}

pub fn call(dispatcher: *transport.Dispatcher, child: abi.CreateResult, command: wire.Command, argument: u64, value: u64, parent: u64) ?wire.Packet {
    const index = dispatcher.begin(child.endpoint, command, argument, value) orelse return null;
    if (!enqueue(dispatcher, index, child.channel)) {
        dispatcher.release(index);
        return null;
    }
    return awaitReply(dispatcher, index, parent);
}

pub fn create(authority: u64, sequence: *wire.Sequence, template: u32, slots: u32, pages: u32) abi.CreateResult {
    const request: abi.CreateRequest = .{ .authority = authority, .request = sequence.take() orelse {
        require(false);
        unreachable;
    }, .template_id = template, .descendant_slots = slots, .descendant_pages = pages };
    var result: abi.CreateResult = undefined;
    require(syscall.create(&request, &result) == 0);
    require(result.instance != 0 and result.control != 0 and result.endpoint != 0 and result.channel != 0 and result.slot >= 4 and result.slot < 8);
    return result;
}

pub fn checkLedger(domain: u64, own_slots: u32, own_pages: u32, reserved_slots: u32, reserved_pages: u32, available_slots: u32, available_pages: u32) void {
    var status: abi.DomainStatus = undefined;
    require(syscall.domainStatus(domain, &status) == 0);
    require(status.owned_slots == own_slots and status.owned_pages == own_pages and
        status.reserved_slots == reserved_slots and status.reserved_pages == reserved_pages and
        status.available_slots == available_slots and status.available_pages == available_pages);
    require(status.owned_slots + status.reserved_slots + status.available_slots == status.slot_limit and
        status.owned_pages + status.reserved_pages + status.available_pages == status.page_limit);
    syscall.reportValues(53, @as(u64, own_slots) | (@as(u64, reserved_slots) << 16) | (@as(u64, available_slots) << 32), @as(u64, own_pages) | (@as(u64, reserved_pages) << 16) | (@as(u64, available_pages) << 32));
}

fn boot(role: u32) abi.BootInfo {
    var info: abi.BootInfo = undefined;
    require(syscall.boot(&info) == 0 and info.abi == abi.version and info.role == role and
        info.endpoint != 0 and info.generation != 0 and info.instance != 0 and info.parent_endpoint != 0 and info.reserved == 0);
    return info;
}

fn bind(info: *abi.BootInfo, needs_creation: bool) void {
    var bootstrap: app.Bootstrap = .{ .endpoint = info.endpoint, .parent = info.parent_endpoint, .instance = info.instance, .needs_creation = needs_creation };
    while (true) {
        switch (bootstrap.inspect(info.*)) {
            .ready => break,
            .failed => {
                require(false);
                unreachable;
            },
            .waiting => {
                require(syscall.sleep(1) == 0);
                info.* = boot(info.role);
            },
        }
    }
    var channel: abi.CapabilityInfo = undefined;
    require(syscall.query(info.parent_channel, &channel) == 0 and channel.holder == info.endpoint and
        channel.target == info.parent_endpoint and channel.rights == abi.right(.hosting_reply) and channel.reserved == 0);
}

fn initializeMemory(info: abi.BootInfo) u64 {
    const stack: *volatile u64 = @ptrFromInt(abi.stack_base + 64);
    const heap: *volatile [2]u64 = @ptrFromInt(abi.memory_base);
    require(stack.* == 0 and heap[0] == 0 and heap[1] == 0);
    syscall.reportValues(40, info.endpoint, info.instance);
    syscall.reportValues(41, stack.*, heap[0]);
    const sentinel = app.memory_salt ^ info.endpoint;
    stack.* = app.guard_salt ^ info.endpoint;
    heap[0] = sentinel;
    heap[1] = ~sentinel;
    syscall.reportValues(42, heap[0], heap[1]);
    return sentinel;
}
fn observeMemory(info: abi.BootInfo, sentinel: u64) void {
    const stack: *volatile u64 = @ptrFromInt(abi.stack_base + 64);
    const heap: *volatile [2]u64 = @ptrFromInt(abi.memory_base);
    require(stack.* == app.guard_salt ^ info.endpoint and heap[0] == sentinel and heap[1] == ~sentinel);
    syscall.reportValues(42, heap[0], heap[1]);
}
fn deniedStorage(info: abi.BootInfo) void {
    const filesystem = syscall.lookup(.filesystem);
    const block = syscall.lookup(.block);
    require(filesystem != 0 and block != 0);
    var file_request = @import("storage_wire.zig").openRequest(1, "/forbidden");
    var block_request = @import("storage_wire.zig").request(.block_read, 1, 0, 0, 8, &.{});
    const fs_result = syscall.send(filesystem, &file_request, info.parent_channel);
    const block_result = syscall.send(block, &block_request, info.parent_channel);
    require(fs_result == @intFromEnum(abi.Error.denied) and block_result == @intFromEnum(abi.Error.denied));
    require(syscall.find(filesystem, abi.right(.file_open)) == @intFromEnum(abi.Error.denied) and
        syscall.find(block, abi.right(.block_read)) == @intFromEnum(abi.Error.denied));
    syscall.reportValues(49, bits(fs_result), bits(block_result));
}
fn reply(info: abi.BootInfo, packet: wire.Packet, value: u64) void {
    var response = packet;
    response.value = value;
    var message = wire.encode(wire.reply_operation, response);
    require(sendBounded(info.parent_endpoint, &message, info.parent_channel) == 0);
}

pub fn worker() noreturn {
    var info = boot(5);
    const sentinel = initializeMemory(info);
    require(info.depth > 0 and info.depth <= 2 and info.template_id == abi.worker_template and info.creation == 0);
    bind(&info, false);
    deniedStorage(info);
    var state: app.Worker = .{ .endpoint = info.endpoint, .parent = info.parent_endpoint };
    var inbox: transport.Inbox = .{};
    while (true) {
        var message: abi.Message = undefined;
        if (inbox.pop()) |pending| message = pending else if (syscall.receiveWait(&message, 10) != 0) continue;
        const packet = state.accept(&message) orelse continue;
        observeMemory(info, sentinel);
        switch (packet.command) {
            .challenge => {
                const result = wire.calculate(packet.argument);
                syscall.reportValues(43, packet.id, result);
                reply(info, packet, result);
            },
            .sleep => {
                syscall.reportValues(46, packet.argument, info.endpoint);
                reply(info, packet, packet.argument);
                require(syscall.sleep(packet.argument) == 0);
                observeMemory(info, sentinel);
                syscall.reportValues(47, sentinel, packet.argument);
            },
            .timeout => {
                var unexpected: abi.Message = undefined;
                const result = syscall.receiveWait(&unexpected, packet.argument);
                if (result == 0) {
                    require(wire.decodeRequest(&unexpected, info.parent_endpoint) != null and inbox.push(unexpected));
                }
                require(result == @intFromEnum(abi.Error.timeout));
                syscall.reportValues(48, packet.argument, bits(result));
                reply(info, packet, bits(result));
            },
            .fault => asm volatile ("ud2"),
            .copied_authority => {
                var copied = wire.encode(wire.request_operation, .{ .id = packet.id, .command = .challenge, .argument = 1, .value = 0 });
                const result = syscall.send(packet.value, &copied, packet.argument);
                require(result == @intFromEnum(abi.Error.denied));
                syscall.reportValues(57, packet.argument, bits(result));
                reply(info, packet, bits(result));
            },
            .copied_control => {
                const result = syscall.stop(packet.argument);
                require(result == @intFromEnum(abi.Error.denied));
                syscall.reportValues(57, packet.argument, bits(result));
                reply(info, packet, bits(result));
            },
            .copied_creation => {
                const request: abi.CreateRequest = .{ .authority = packet.argument, .request = 1, .template_id = abi.worker_template };
                var result_data: abi.CreateResult = undefined;
                const result = syscall.create(&request, &result_data);
                require(result == @intFromEnum(abi.Error.denied));
                syscall.reportValues(57, packet.argument, bits(result));
                reply(info, packet, bits(result));
            },
            .cpu_probe => switch (packet.argument) {
                1 => {
                    const address: *volatile u8 = @ptrFromInt(abi.image_base);
                    address.* = 0x5a;
                },
                2 => {
                    const address: *const volatile u8 = @ptrFromInt(0x10000);
                    _ = address.*;
                },
                3 => asm volatile ("outb %%al, %%dx"
                    :
                    : [value] "{al}" (@as(u8, 0)),
                      [port] "{dx}" (@as(u16, 0x80)),
                ),
                4 => {
                    const address: *volatile u64 = @ptrFromInt(abi.stack_base - 8);
                    address.* = 0x5a;
                },
                5 => {
                    const address: *volatile u8 = @ptrFromInt(abi.memory_base + 128);
                    address.* = 0xc3;
                    asm volatile ("call *%[target]"
                        :
                        : [target] "r" (abi.memory_base + 128),
                        : .{ .memory = true });
                },
                else => unreachable,
            },
            else => unreachable,
        }
    }
}

pub fn supervisor() noreturn {
    var info = boot(4);
    const sentinel = initializeMemory(info);
    require(info.depth == 1 and info.template_id == abi.supervisor_template);
    // A recovering supervisor starts without execution-scoped creation or channels.
    bind(&info, true);
    deniedStorage(info);
    var management: wire.Sequence = .{};
    var domain: abi.DomainStatus = undefined;
    require(syscall.domainStatus(info.creation, &domain) == 0 and domain.slot_limit <= 4 and domain.page_limit <= 128);
    const child_count: usize = app.workerCount(domain.slot_limit, domain.page_limit);
    var children: [4]abi.CreateResult = undefined;
    for (children[0..child_count]) |*child| child.* = create(info.creation, &management, abi.worker_template, 0, 0);
    const count: u32 = @intCast(child_count);
    checkLedger(info.creation, count, count * 2, 0, 0, domain.slot_limit - count, domain.page_limit - count * 2);
    var dispatcher: transport.Dispatcher = .{};
    var last_request: u64 = 0;
    while (true) {
        var message: abi.Message = undefined;
        if (dispatcher.inbox.pop()) |pending| message = pending else if (syscall.receiveWait(&message, 10) != 0) continue;
        const packet = wire.decodeRequest(&message, info.parent_endpoint) orelse continue;
        if (packet.id <= last_request) continue;
        last_request = packet.id;
        observeMemory(info, sentinel);
        switch (packet.command) {
            .challenge => {
                const result = wire.calculate(packet.argument);
                syscall.reportValues(43, packet.id, result);
                reply(info, packet, result);
            },
            .nested => {
                if (child_count == 0) continue;
                var pending: [4]usize = undefined;
                for (children[0..child_count], 0..) |worker_child, index| {
                    pending[index] = dispatcher.begin(worker_child.endpoint, .challenge, packet.argument ^ wire.nested_salt, 0) orelse {
                        require(false);
                        unreachable;
                    };
                    require(enqueue(&dispatcher, pending[index], worker_child.channel));
                }
                var result: u64 = 0;
                for (pending[0..child_count], 0..) |index, position| {
                    const processed = awaitReply(&dispatcher, index, info.parent_endpoint) orelse {
                        require(false);
                        unreachable;
                    };
                    syscall.reportValues(45, processed.id, processed.value);
                    if (position == 0) result = processed.value else require(result == processed.value);
                }
                reply(info, packet, wire.calculate(packet.argument) ^ result);
            },
            .nested_sleep => {
                if (child_count == 0) continue;
                const child = children[0];
                _ = call(&dispatcher, child, .sleep, packet.argument, 0, info.parent_endpoint) orelse {
                    require(false);
                    unreachable;
                };
                // The acknowledgement is sent before the worker blocks. A finite
                // owner sleep gives it a user turn to install the actual sleep wait.
                require(syscall.sleep(1) == 0);
                // This authorized request stays queued while the grandchild sleeps.
                const queued = dispatcher.begin(child.endpoint, .challenge, 0xab734ef19c620d58, 0) orelse {
                    require(false);
                    unreachable;
                };
                require(enqueue(&dispatcher, queued, child.channel));
                reply(info, packet, packet.argument);
            },
            .grandchild_fault => {
                if (child_count == 0) continue;
                const child = children[0];
                const index = dispatcher.begin(child.endpoint, .fault, 0, 0) orelse {
                    require(false);
                    unreachable;
                };
                require(enqueue(&dispatcher, index, child.channel));
                dispatcher.release(index);
                var status: abi.CellStatus = undefined;
                for (0..40) |_| {
                    require(syscall.status(child.control, &status) == 0);
                    if (status.phase == 2) break;
                    require(syscall.sleep(1) == 0);
                }
                require(status.phase == 2);
                syscall.reportValues(58, child.endpoint, status.phase);
                reply(info, packet, 0);
            },
            .fault => asm volatile ("ud2"),
            else => {},
        }
    }
}
