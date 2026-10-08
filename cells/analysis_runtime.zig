const abi = @import("abi.zig");
const syscall = @import("syscall.zig");
const wire = @import("contract_wire.zig");
const analysis = @import("analysis_wire.zig");
const snapshot = @import("snapshot.zig");
const client = @import("snapshot_client.zig");
const hosting = @import("hosting_runtime.zig");
const require = hosting.require;
const runtime = @import("contract_runtime.zig");

// Only a complete ordered accepted-work descriptor can cause a read. Descriptor
// collection retains no bytes and cannot choose any filename or block address.
pub const Work = struct { id: u64, contract: u64, attempt: u8, reference: snapshot.Ref, length: u8, delay: u8, fault: bool };
pub const Worker = struct {
    parent: u64,
    last_rpc: u64 = 0,
    descriptor: ?wire.Packet = null,
    length: ?wire.Packet = null,
    pub fn accept(self: *Worker, message: *const abi.Message) ?Work {
        const packet = wire.decode(message, self.parent, wire.request_operation) orelse return null;
        if (packet.kind != .request or packet.detail < 1 or packet.detail > 2 or wire.tokenIssuer(packet.token) != self.parent or
            wire.tokenSlot(packet.token) == null or packet.id <= self.last_rpc) return null;
        if (packet.command == .input) {
            if (self.descriptor != null or packet.data == 0) {
                self.descriptor = null;
                self.length = null;
                return null;
            }
            self.descriptor = packet;
            return null;
        }
        const descriptor = self.descriptor orelse return null;
        if (descriptor.id != packet.id or descriptor.token != packet.token or descriptor.detail != packet.detail) {
            self.descriptor = null;
            self.length = null;
            return null;
        }
        if (packet.command == .input_length) {
            if (self.length != null or packet.data >> 25 != 0 or (packet.data & 0xffff) > 128 or
                ((packet.data >> 16) & 255) > 32)
            {
                self.descriptor = null;
                self.length = null;
                return null;
            }
            self.length = packet;
            return null;
        }
        if (packet.command != .work) return null;
        const length = self.length orelse {
            self.descriptor = null;
            return null;
        };
        self.descriptor = null;
        self.length = null;
        const tag = packet.data & 255;
        if ((tag != 0xa1 and tag != 0xa2) or packet.data >> 8 == 0) return null;
        self.last_rpc = packet.id;
        return .{ .id = packet.id, .contract = packet.token, .attempt = packet.detail, .reference = .{ .issuer = descriptor.data, .token = packet.data }, .length = @truncate(length.data), .delay = @truncate(length.data >> 16), .fault = ((length.data >> 24) & 1) != 0 };
    }
};
pub fn worker() noreturn {
    var info: abi.BootInfo = undefined;
    require(syscall.boot(&info) == 0 and info.scenario == 25 and info.template_id == 6 and info.depth == 2 and info.creation == 0);
    const stack: *volatile u64 = @ptrFromInt(abi.stack_base + 64);
    const memory: *volatile [2]u64 = @ptrFromInt(abi.memory_base);
    require(stack.* == 0 and memory[0] == 0 and memory[1] == 0);
    runtime.report(40, info.endpoint, info.instance);
    runtime.report(41, stack.*, memory[0]);
    stack.* = 0x937621a453fbc880 ^ info.endpoint;
    memory[0] = 0x029a814ef734bc71 ^ info.endpoint;
    memory[1] = ~memory[0];
    runtime.report(42, memory[0], memory[1]);
    // New incarnations wait finitely for the owner's explicit checked rebind.
    for (0..64) |_| {
        if (info.parent_channel != 0) break;
        require(syscall.sleep(1) == 0 and syscall.boot(&info) == 0);
    }
    require(info.parent_channel != 0);
    var cap: abi.CapabilityInfo = undefined;
    require(syscall.query(info.parent_channel, &cap) == 0 and cap.holder == info.endpoint and cap.target == info.parent_endpoint and cap.rights == abi.right(.hosting_reply));
    const fs = syscall.lookup(.filesystem);
    const route = syscall.find(fs, abi.right(.snapshot_read));
    require(route > 0 and syscall.query(@intCast(route), &cap) == 0 and cap.holder == info.endpoint and cap.target == fs and
        cap.rights == abi.right(.snapshot_read) and cap.parent != 0);
    var file = @import("storage_wire.zig").openRequest(1, "/alpha");
    var block = @import("storage_wire.zig").request(.block_read, 1, 0, 0, 8, &.{});
    require(syscall.send(fs, &file, @intCast(route)) == @intFromEnum(abi.Error.denied));
    require(syscall.send(syscall.lookup(.block), &block, @intCast(route)) == @intFromEnum(abi.Error.denied));
    var write = @import("storage_wire.zig").request(.file_write, 1, 1, 0, 1, "x");
    require(syscall.send(fs, &write, @intCast(route)) == @intFromEnum(abi.Error.denied));
    var file_read = @import("storage_wire.zig").request(.file_chunk_read, 1, 0x100000101, 0, 8, &.{});
    require(syscall.send(fs, &file_read, @intCast(route)) == @intFromEnum(abi.Error.denied));
    runtime.report(49, @bitCast(@as(i64, -2)), @bitCast(@as(i64, -2)));
    var reader: client.Client = .{};
    const rejected = reader.read(.{ .issuer = fs, .token = 0x1a1 }, 0, 8) orelse {
        require(false);
        unreachable;
    };
    require(rejected.status != .ok);
    runtime.report(99, 0x1a1, @bitCast(@as(i64, @intFromEnum(rejected.status))));
    var ready = wire.encode(wire.reply_operation, .{ .id = 1, .command = .bootstrap, .kind = .response, .data = info.instance });
    require(hosting.sendBounded(info.parent_endpoint, &ready, info.parent_channel) == 0);
    var state: Worker = .{ .parent = info.parent_endpoint };
    while (true) {
        var message: abi.Message = undefined;
        if (syscall.receiveWait(&message, 10) != 0) continue;
        const work = state.accept(&message) orelse continue;
        require(work.reference.issuer == fs);
        if (work.fault and work.attempt == 1) asm volatile ("ud2");
        if (work.reference.token == 0x3a1) {
            const sibling = reader.read(.{ .issuer = fs, .token = 0x4a2 }, 0, 8) orelse {
                require(false);
                unreachable;
            };
            require(sibling.status == .denied and sibling.count == 0);
            runtime.report(99, 0x4a2, @bitCast(@as(i64, -2)));
        }
        if (work.delay != 0) {
            runtime.report(46, work.delay, info.endpoint);
            require(syscall.sleep(work.delay) == 0);
            runtime.report(47, memory[0], work.delay);
        }
        var bytes: [128]u8 = undefined;
        if (!reader.collect(work.reference, work.length, &bytes)) continue;
        const result = analysis.calculate(bytes[0..work.length]).?;
        require(stack.* == 0x937621a453fbc880 ^ info.endpoint and memory[0] == 0x029a814ef734bc71 ^ info.endpoint and memory[1] == ~memory[0]);
        runtime.report(43, work.id, result.digest);
        runtime.report(92, work.contract, result.counts());
        var digest = wire.encode(wire.reply_operation, .{ .id = work.id, .command = .work, .kind = .response, .detail = work.attempt, .token = work.contract, .data = result.digest });
        var counts = wire.encode(wire.reply_operation, .{ .id = work.id, .command = .analysis_tuple, .kind = .response, .detail = work.attempt, .token = work.contract, .data = result.counts() });
        require(hosting.sendBounded(info.parent_endpoint, &digest, info.parent_channel) == 0 and hosting.sendBounded(info.parent_endpoint, &counts, info.parent_channel) == 0);
    }
}
