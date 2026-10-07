// Pure application state shared by the emitted worker and its host tests.
const abi = @import("abi.zig");
const wire = @import("hosting_wire.zig");
pub const memory_salt: u64 = 0x9e60328ab74fc1d5;
pub const guard_salt: u64 = 0x736a21c45e98bd02;

pub fn workerCount(slot_limit: u32, page_limit: u32) u32 {
    return @min(4, @min(slot_limit, page_limit / 2));
}

pub const Worker = struct {
    endpoint: u64,
    parent: u64,
    last_request: u64 = 0,
    accepted: u64 = 0,

    pub fn accept(self: *Worker, message: *const abi.Message) ?wire.Packet {
        const packet = wire.decodeRequest(message, self.parent) orelse return null;
        if (packet.id <= self.last_request or self.accepted == 0xffffffffffffffff) return null;
        switch (packet.command) {
            .challenge, .sleep, .timeout, .fault, .copied_authority, .copied_control, .copied_creation, .cpu_probe => {},
            else => return null,
        }
        self.last_request = packet.id;
        self.accepted += 1;
        return packet;
    }
};

pub const Bootstrap = struct {
    endpoint: u64,
    parent: u64,
    instance: u64,
    needs_creation: bool,
    attempts: u16 = 0,
    pub const Result = enum { waiting, ready, failed };

    // A generation may become runnable before its live owner rebinds channels.
    // Waiting never makes a previous endpoint or caller-supplied token current.
    pub fn inspect(self: *Bootstrap, info: abi.BootInfo) Result {
        if (self.endpoint == 0 or self.parent == 0 or self.instance == 0 or
            info.endpoint != self.endpoint or info.parent_endpoint != self.parent or info.instance != self.instance or
            self.attempts == 160) return .failed;
        self.attempts += 1;
        if (info.parent_channel == 0 or (self.needs_creation and info.creation == 0)) return .waiting;
        return .ready;
    }
};

const testing = @import("std").testing;
fn delivered(id: u64, sender: u64, command: wire.Command) abi.Message {
    var message = wire.encode(wire.request_operation, .{ .id = id, .command = command, .argument = 17, .value = 0 });
    message.sender = sender;
    return message;
}

test "worker validates exact parent generation before changing request state" {
    var worker: Worker = .{ .endpoint = 0x105, .parent = 0x104 };
    var message = delivered(1, 0x204, .challenge);
    try testing.expect(worker.accept(&message) == null);
    try testing.expectEqual(@as(u64, 0), worker.last_request);
    message.sender = 0x104;
    try testing.expect(worker.accept(&message) != null);
    try testing.expectEqual(@as(u64, 1), worker.accepted);
    try testing.expect(worker.accept(&message) == null);
    message = delivered(2, 0x104, .nested);
    try testing.expect(worker.accept(&message) == null);
    try testing.expectEqual(@as(u64, 1), worker.last_request);
}

test "worker replay late malformed and counter exhaustion preserve completed state" {
    var worker: Worker = .{ .endpoint = 0x105, .parent = 0x104 };
    var message = delivered(3, 0x104, .challenge);
    try testing.expect(worker.accept(&message) != null);
    message = delivered(2, 0x104, .challenge);
    try testing.expect(worker.accept(&message) == null);
    message = delivered(4, 0x104, .challenge);
    message.length = 31;
    try testing.expect(worker.accept(&message) == null);
    worker.accepted = 0xffffffffffffffff;
    message.length = 32;
    try testing.expect(worker.accept(&message) == null);
    try testing.expectEqual(@as(u64, 3), worker.last_request);
}

test "two workers using one image have distinct sentinels and request histories" {
    var first: Worker = .{ .endpoint = 0x105, .parent = 0x104 };
    var second: Worker = .{ .endpoint = 0x106, .parent = 0x104 };
    const message = delivered(1, 0x104, .challenge);
    try testing.expect(first.accept(&message) != null);
    try testing.expect(second.accept(&message) != null);
    try testing.expect((memory_salt ^ first.endpoint) != (memory_salt ^ second.endpoint));
    first.last_request = 9;
    try testing.expectEqual(@as(u64, 1), second.last_request);
}

test "cold restarted worker waits for explicit current-generation parent channel" {
    var info: abi.BootInfo = @import("std").mem.zeroes(abi.BootInfo);
    info.endpoint = 0x205;
    info.parent_endpoint = 0x104;
    info.instance = 0x241;
    var bootstrap: Bootstrap = .{ .endpoint = info.endpoint, .parent = info.parent_endpoint, .instance = info.instance, .needs_creation = false };
    try testing.expectEqual(Bootstrap.Result.waiting, bootstrap.inspect(info));
    info.parent_channel = 0x1910;
    try testing.expectEqual(Bootstrap.Result.ready, bootstrap.inspect(info));
    info.endpoint = 0x105;
    try testing.expectEqual(Bootstrap.Result.failed, bootstrap.inspect(info));
}

test "supervisor bootstrap requires both current channel and delegated creation and remains finite" {
    var info: abi.BootInfo = @import("std").mem.zeroes(abi.BootInfo);
    info.endpoint = 0x205;
    info.parent_endpoint = 0x104;
    info.instance = 0x241;
    info.parent_channel = 0x1910;
    var bootstrap: Bootstrap = .{ .endpoint = info.endpoint, .parent = info.parent_endpoint, .instance = info.instance, .needs_creation = true };
    try testing.expectEqual(Bootstrap.Result.waiting, bootstrap.inspect(info));
    info.creation = 0x1060;
    try testing.expectEqual(Bootstrap.Result.ready, bootstrap.inspect(info));
    info.creation = 0;
    var exhausted: Bootstrap = .{ .endpoint = info.endpoint, .parent = info.parent_endpoint, .instance = info.instance, .needs_creation = true };
    for (0..160) |_| try testing.expectEqual(Bootstrap.Result.waiting, exhausted.inspect(info));
    info.creation = 0x1060;
    try testing.expectEqual(Bootstrap.Result.failed, exhausted.inspect(info));
}

test "supervisor consumes only whole worker allocations inside its bounded descendant allowance" {
    try testing.expectEqual(@as(u32, 0), workerCount(0, 0));
    try testing.expectEqual(@as(u32, 0), workerCount(1, 0));
    try testing.expectEqual(@as(u32, 0), workerCount(4, 1));
    try testing.expectEqual(@as(u32, 1), workerCount(1, 48));
    try testing.expectEqual(@as(u32, 2), workerCount(3, 5));
    try testing.expectEqual(@as(u32, 3), workerCount(3, 6));
    try testing.expectEqual(@as(u32, 4), workerCount(4, 128));
}
