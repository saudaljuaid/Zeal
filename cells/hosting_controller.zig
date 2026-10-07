const abi = @import("abi.zig");
const syscall = @import("syscall.zig");
const wire = @import("hosting_wire.zig");
const transport = @import("hosting_transport.zig");
const runtime = @import("hosting_runtime.zig");
const require = runtime.require;

const Manager = struct {
    info: abi.BootInfo,
    management: wire.Sequence = .{},
    dispatcher: transport.Dispatcher = .{},

    fn create(self: *Manager, template: u32, slots: u32, pages: u32) abi.CreateResult {
        return runtime.create(self.info.creation, &self.management, template, slots, pages);
    }
    fn verify(self: *Manager, child: abi.CreateResult, command: wire.Command, argument: u64, value: u64) wire.Packet {
        const response = runtime.call(&self.dispatcher, child, command, argument, value, 0) orelse {
            require(false);
            unreachable;
        };
        syscall.reportValues(44, response.id, response.value);
        return response;
    }
    fn enqueue(self: *Manager, child: abi.CreateResult, command: wire.Command, argument: u64) usize {
        const index = self.dispatcher.begin(child.endpoint, command, argument, 0) orelse {
            require(false);
            unreachable;
        };
        require(runtime.enqueue(&self.dispatcher, index, child.channel));
        return index;
    }
    fn stop(self: *Manager, child: abi.CreateResult) void {
        self.dispatcher.retire(child.endpoint);
        require(syscall.stop(child.control) == 0);
        require(syscall.stop(child.control) == 0);
        var status: abi.CellStatus = undefined;
        require(syscall.status(child.control, &status) == 0 and status.phase == 4 and status.own_pages == 0);
        require(syscall.reap(child.control) == 0);
        syscall.reportValues(55, child.control, child.instance);
    }
    fn recoverLeaf(self: *Manager, child: abi.CreateResult) abi.CreateResult {
        const fault = self.enqueue(child, .fault, 0);
        self.dispatcher.release(fault);
        var status: abi.CellStatus = undefined;
        var saw_backoff = false;
        for (0..80) |_| {
            require(syscall.status(child.control, &status) == 0);
            if (status.phase == 2) saw_backoff = true;
            if (status.phase == 1 and status.generation > child.endpoint >> 8) break;
            require(syscall.sleep(1) == 0);
        }
        require(saw_backoff and status.phase == 1 and status.instance == child.instance and
            status.control == child.control and status.generation > child.endpoint >> 8 and status.restarts == 1);
        var stale = wire.encode(wire.request_operation, .{ .id = 0x7fffffff, .command = .challenge, .argument = 1, .value = 0 });
        const old_endpoint = syscall.send(child.endpoint, &stale, child.channel);
        require(old_endpoint == @intFromEnum(abi.Error.stale));
        syscall.reportValues(51, child.endpoint, runtime.bits(old_endpoint));
        const old_capability = syscall.send(status.endpoint, &stale, child.channel);
        require(old_capability == @intFromEnum(abi.Error.stale));
        syscall.reportValues(51, child.channel, runtime.bits(old_capability));
        const request: abi.RebindRequest = .{ .authority = self.info.creation, .control = child.control, .request = self.management.take() orelse {
            require(false);
            unreachable;
        } };
        var result: abi.CreateResult = undefined;
        require(syscall.rebind(&request, &result) == 0 and result.instance == child.instance and
            result.control == child.control and result.endpoint == status.endpoint and result.channel != child.channel and
            result.creation == 0 and child.creation == 0);
        syscall.reportValues(50, child.endpoint, result.endpoint);
        return result;
    }
    fn cpuProbe(self: *Manager, mode: u64) void {
        const child = self.create(abi.worker_template, 0, 0);
        _ = self.verify(child, .challenge, 0x6f49a721d385e0bc ^ mode, 0);
        const fault = self.enqueue(child, .cpu_probe, mode);
        self.dispatcher.release(fault);
        var status: abi.CellStatus = undefined;
        for (0..80) |_| {
            require(syscall.status(child.control, &status) == 0);
            if (status.phase == 2) break;
            require(syscall.sleep(1) == 0);
        }
        const vector: u32 = if (mode == 3) 13 else 14;
        require(status.phase == 2 and status.reason == 0x10000 | vector and status.instance == child.instance);
        syscall.reportValues(59, mode, vector);
        self.stop(child);
        runtime.checkLedger(self.info.creation, 2, 6, 1, 2, 1, 40);
    }
    fn finish(self: *Manager) noreturn {
        runtime.checkLedger(self.info.creation, 0, 0, 0, 0, 4, 48);
        syscall.reportValues(56, self.info.scenario, 0);
        while (true) require(syscall.sleep(1) == 0);
    }
};

fn normal(manager: *Manager, supervisor: abi.CreateResult, sibling: abi.CreateResult) noreturn {
    _ = manager.verify(supervisor, .nested, 0x1029384756abcdef, 0);
    _ = manager.verify(sibling, .challenge, 0xfedcba6547382910, 0);
    _ = manager.verify(sibling, .timeout, 2, 0);
    runtime.checkLedger(manager.info.creation, 2, 6, 2, 4, 0, 38);
    // Leave the hierarchy running while the independent storage owner completes files.
    require(syscall.sleep(30) == 0);
    _ = manager.verify(supervisor, .nested, 0x3141592653589793, 0);
    _ = manager.verify(sibling, .challenge, 0x2718281828459045, 0);
    manager.stop(supervisor);
    manager.stop(sibling);
    manager.finish();
}

fn recovery(manager: *Manager, initial_supervisor: abi.CreateResult, sibling: abi.CreateResult) noreturn {
    _ = manager.verify(initial_supervisor, .nested, 0x1029384756abcdef, 0);
    _ = manager.verify(sibling, .challenge, 0xfedcba6547382910, 0);
    _ = manager.verify(sibling, .timeout, 2, 0);
    runtime.checkLedger(manager.info.creation, 2, 6, 2, 4, 0, 38);
    require(syscall.sleep(30) == 0);
    _ = manager.verify(sibling, .sleep, 20, 0);
    require(syscall.sleep(1) == 0);
    _ = manager.verify(initial_supervisor, .nested_sleep, 30, 0);
    const first = manager.enqueue(sibling, .challenge, 0x1133557799bbddff);
    const second = manager.enqueue(sibling, .challenge, 0x22446688aaccee00);
    const first_id = manager.dispatcher.pending[first].packet.id;
    const second_id = manager.dispatcher.pending[second].packet.id;
    const fault = manager.enqueue(initial_supervisor, .fault, 0);
    manager.dispatcher.release(fault);
    var status: abi.CellStatus = undefined;
    var saw_backoff = false;
    for (0..80) |_| {
        require(syscall.status(initial_supervisor.control, &status) == 0);
        if (status.phase == 2) saw_backoff = true;
        if (status.phase == 1 and status.generation > initial_supervisor.endpoint >> 8) break;
        require(syscall.sleep(1) == 0);
    }
    require(saw_backoff and status.phase == 1 and status.instance == initial_supervisor.instance and
        status.control == initial_supervisor.control and status.endpoint != initial_supervisor.endpoint and
        status.generation > initial_supervisor.endpoint >> 8 and status.restarts == 1);
    var stale_request = wire.encode(wire.request_operation, .{ .id = 0x7fffffff, .command = .challenge, .argument = 1, .value = 0 });
    const old_endpoint = syscall.send(initial_supervisor.endpoint, &stale_request, initial_supervisor.channel);
    require(old_endpoint == @intFromEnum(abi.Error.stale));
    syscall.reportValues(51, initial_supervisor.endpoint, runtime.bits(old_endpoint));
    const old_capability = syscall.send(status.endpoint, &stale_request, initial_supervisor.channel);
    require(old_capability == @intFromEnum(abi.Error.stale));
    syscall.reportValues(51, initial_supervisor.channel, runtime.bits(old_capability));
    const request: abi.RebindRequest = .{ .authority = manager.info.creation, .control = initial_supervisor.control, .request = manager.management.take() orelse {
        require(false);
        unreachable;
    } };
    var supervisor: abi.CreateResult = undefined;
    require(syscall.rebind(&request, &supervisor) == 0 and supervisor.instance == initial_supervisor.instance and
        supervisor.control == initial_supervisor.control and supervisor.endpoint == status.endpoint and
        supervisor.channel != initial_supervisor.channel and supervisor.creation != initial_supervisor.creation);
    syscall.reportValues(50, initial_supervisor.endpoint, supervisor.endpoint);
    _ = manager.verify(supervisor, .nested, 0x3141592653589793, 0);
    const first_reply = runtime.awaitReply(&manager.dispatcher, first, 0) orelse {
        require(false);
        unreachable;
    };
    syscall.reportValues(44, first_reply.id, first_reply.value);
    const second_reply = runtime.awaitReply(&manager.dispatcher, second, 0) orelse {
        require(false);
        unreachable;
    };
    syscall.reportValues(44, second_reply.id, second_reply.value);
    require(first_reply.id == first_id and second_reply.id == second_id and first_id < second_id);
    syscall.reportValues(54, first_id, second_id);
    runtime.checkLedger(manager.info.creation, 2, 6, 2, 4, 0, 38);
    // The child observes its worker in delayed BACKOFF before asking the owner to stop it.
    _ = manager.verify(supervisor, .grandchild_fault, 0, 0);
    manager.stop(supervisor);
    require(syscall.sleep(10) == 0);
    _ = manager.verify(sibling, .challenge, 0x2718281828459045, 0);
    manager.stop(sibling);
    manager.finish();
}

fn rejected(check: u64, result: i64, expected: abi.Error) void {
    require(result == @intFromEnum(expected));
    syscall.reportValues(52, check, runtime.bits(result));
}

fn authority(manager: *Manager, supervisor: abi.CreateResult, initial_sibling: abi.CreateResult) noreturn {
    _ = manager.verify(supervisor, .nested, 0x1029384756abcdef, 0);
    _ = manager.verify(initial_sibling, .challenge, 0xfedcba6547382910, 0);
    _ = manager.verify(initial_sibling, .timeout, 2, 0);
    runtime.checkLedger(manager.info.creation, 2, 6, 1, 2, 1, 40);
    // Establish both complete storage payloads before stop/reuse and teardown.
    require(syscall.sleep(30) == 0);
    var output: abi.CreateResult = undefined;
    var request: abi.CreateRequest = .{ .authority = 0, .request = manager.management.take() orelse {
        require(false);
        unreachable;
    }, .template_id = abi.worker_template };
    rejected(1, syscall.create(&request, &output), .invalid);
    request.authority = supervisor.control;
    request.request = manager.management.take() orelse {
        require(false);
        unreachable;
    };
    rejected(2, syscall.create(&request, &output), .invalid);
    request.authority = manager.info.creation;
    request.template_id = 7;
    request.request = manager.management.take() orelse {
        require(false);
        unreachable;
    };
    rejected(3, syscall.create(&request, &output), .invalid);
    request.template_id = abi.supervisor_template;
    request.descendant_slots = 1;
    request.descendant_pages = 49;
    request.request = manager.management.take() orelse {
        require(false);
        unreachable;
    };
    rejected(4, syscall.create(&request, &output), .no_space);
    request.descendant_slots = 0xffffffff;
    request.descendant_pages = 0xffffffff;
    request.request = manager.management.take() orelse {
        require(false);
        unreachable;
    };
    rejected(5, syscall.create(&request, &output), .invalid);
    request.descendant_slots = 0;
    request.descendant_pages = 0;
    request.template_id = abi.worker_template;
    rejected(6, syscall.raw(@intFromEnum(abi.Call.create), 0, @sizeOf(abi.CreateRequest), @intFromPtr(&output)), .bad_address);
    rejected(7, syscall.raw(@intFromEnum(abi.Call.create), @intFromPtr(&request), 31, @intFromPtr(&output)), .invalid);
    rejected(8, syscall.raw(@intFromEnum(abi.Call.create), @intFromPtr(&request), @sizeOf(abi.CreateRequest), abi.image_base), .bad_address);
    rejected(9, syscall.raw(@intFromEnum(abi.Call.create), @intFromPtr(&request), @sizeOf(abi.CreateRequest), abi.memory_base + 65536 - 47), .bad_address);
    rejected(10, syscall.stop(syscall.lookup(.filesystem)), .invalid);
    _ = manager.verify(initial_sibling, .copied_authority, supervisor.channel, supervisor.endpoint);
    _ = manager.verify(initial_sibling, .copied_control, supervisor.control, 0);
    _ = manager.verify(initial_sibling, .copied_creation, manager.info.creation, 0);
    const pressure = manager.create(abi.worker_template, 0, 0);
    _ = manager.verify(pressure, .challenge, 0x5a83e19c74620fb1, 0);
    runtime.checkLedger(manager.info.creation, 3, 8, 1, 2, 0, 38);
    request.request = manager.management.take() orelse {
        require(false);
        unreachable;
    };
    rejected(11, syscall.create(&request, &output), .no_space);
    runtime.checkLedger(manager.info.creation, 3, 8, 1, 2, 0, 38);
    manager.stop(initial_sibling);
    var old_status: abi.CellStatus = undefined;
    rejected(12, syscall.status(initial_sibling.control, &old_status), .stale);
    rejected(13, syscall.reap(initial_sibling.control), .stale);
    const sibling = manager.create(abi.worker_template, 0, 0);
    require(sibling.slot == initial_sibling.slot and sibling.instance != initial_sibling.instance and
        sibling.control != initial_sibling.control and sibling.endpoint >> 8 > initial_sibling.endpoint >> 8 and sibling.channel != initial_sibling.channel);
    var message = wire.encode(wire.request_operation, .{ .id = 0x7fffffff, .command = .challenge, .argument = 1, .value = 0 });
    rejected(14, syscall.send(initial_sibling.endpoint, &message, initial_sibling.channel), .stale);
    syscall.reportValues(51, initial_sibling.endpoint, runtime.bits(@intFromEnum(abi.Error.stale)));
    rejected(15, syscall.send(sibling.endpoint, &message, initial_sibling.channel), .stale);
    syscall.reportValues(51, initial_sibling.channel, runtime.bits(@intFromEnum(abi.Error.stale)));
    _ = manager.verify(sibling, .challenge, 0x2718281828459045, 0);
    rejected(16, syscall.status(initial_sibling.control, &old_status), .stale);
    syscall.reportValues(51, initial_sibling.control, runtime.bits(@intFromEnum(abi.Error.stale)));
    manager.stop(pressure);
    const recovered_sibling = manager.recoverLeaf(sibling);
    _ = manager.verify(recovered_sibling, .challenge, 0x713bc50892e6ad4f, 0);
    runtime.checkLedger(manager.info.creation, 2, 6, 1, 2, 1, 40);
    for (1..6) |mode| manager.cpuProbe(mode);
    // Privilege faults in other cells leave the live hierarchy and sibling working.
    _ = manager.verify(supervisor, .nested, 0x4268ab13ef75cd90, 0);
    _ = manager.verify(recovered_sibling, .challenge, 0x529c7de831a604bf, 0);
    require(syscall.creationRevoke(manager.info.creation) == 0);
    request.request = manager.management.take() orelse {
        require(false);
        unreachable;
    };
    rejected(17, syscall.create(&request, &output), .denied);
    require(syscall.status(supervisor.control, &old_status) == 0);
    // Lifecycle controls stay usable after the distinct creation domain is revoked.
    manager.stop(supervisor);
    manager.stop(recovered_sibling);
    require(syscall.sleep(30) == 0);
    manager.finish();
}

pub fn run(info: abi.BootInfo) noreturn {
    require(info.abi == abi.version and info.role == @intFromEnum(abi.Role.probe) and info.identity == 400 and
        info.endpoint != 0 and info.creation != 0 and info.parent_endpoint == 0 and info.instance == 0 and info.depth == 0);
    var manager: Manager = .{ .info = info };
    runtime.checkLedger(info.creation, 0, 0, 0, 0, 4, 48);
    const descendant_slots: u32 = if (info.scenario == 23) 1 else 2;
    const supervisor = manager.create(abi.supervisor_template, descendant_slots, descendant_slots * 2);
    const sibling = manager.create(abi.worker_template, 0, 0);
    switch (info.scenario) {
        21 => normal(&manager, supervisor, sibling),
        22 => recovery(&manager, supervisor, sibling),
        23 => authority(&manager, supervisor, sibling),
        else => {
            require(false);
            unreachable;
        },
    }
}
