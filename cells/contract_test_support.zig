// Host-only implementation of the small seam exercised by production Broker.
// Kernel create/copy/capability rollback remains tested by tests/hosting.c.
const abi = @import("abi.zig");
pub const core = @import("contract_core.zig");
pub const wire = @import("contract_wire.zig");
pub const Fake = struct {
    objects: [2]?core.Backing = .{ null, null }, pages: [2]u8 = .{ 0, 0 },
    epoch: u64 = 1, channel_epoch: u64 = 1, generations: [2]u64 = .{ 0, 0 },
    faults: [2]u32 = .{ 0, 0 }, restarts: [2]u32 = .{ 0, 0 },
    create_calls: u64 = 0, settle_calls: u64 = 0, send_calls: u64 = 0, rebind_calls: u64 = 0, validated_calls: u64 = 0,
    last: [2]?abi.Message = .{ null, null },
    fail_create: bool = false, fail_send: bool = false, fail_rebind: bool = false,
    partial_settle: bool = false, false_refund: bool = false, bad_domain: bool = false, bad_backing: bool = false,
    alias_create: bool = false,
    admission_failure: bool = false, fault_during_settle: bool = false, restart_during_settle: bool = false,
    saturated_faults: bool = false,
    pub fn stage(_: *Fake, _: *core.Broker, _: *const abi.Message) core.Error!?wire.Snapshot {
        // This scalar seam has no byte-profile staging service.
        return error.invalid;
    }
    pub fn domain(self: *Fake) ?core.Domain {
        if (self.bad_domain) return null;
        var slots: u32 = 0;
        var pages: u32 = 0;
        for (self.objects, 0..) |object, index| if (object != null) { slots += 1; pages += self.pages[index]; };
        return .{ .owned_slots = slots, .owned_pages = pages, .available_slots = 2 - slots, .available_pages = 4 - pages };
    }
    pub fn create(self: *Fake) ?core.Backing {
        self.create_calls += 1;
        if (self.fail_create) return null;
        if (self.alias_create) for (self.objects) |object| if (object != null) { return object; };
        for (&self.objects, 0..) |*object, index| {
            if (object.* != null) continue;
            const epoch = self.epoch;
            self.epoch += 1;
            self.generations[index] += 1;
            const channel_epoch = self.channel_epoch;
            self.channel_epoch += 1;
            const backing: core.Backing = .{ .instance = (epoch << 8) | 0x40, .control = (epoch << 8) | 0x50,
                .endpoint = (self.generations[index] << 8) | @as(u64, @intCast(index + 5)), .channel = (channel_epoch << 8) | 0x10,
                .creation = 0, .slot = @intCast(index + 4), .identity = @intCast(500 + index) };
            object.* = backing;
            self.pages[index] = 2;
            self.faults[index] = 0;
            self.restarts[index] = 0;
            self.last[index] = null;
            var returned = backing;
            if (self.bad_backing) returned.channel = 0;
            return returned;
        }
        return null;
    }
    pub fn send(self: *Fake, worker: core.Backing, message: abi.Message) bool {
        self.send_calls += 1;
        if (self.fail_send) return false;
        for (self.objects, 0..) |object, index| if (object != null and object.?.control == worker.control and object.?.endpoint == worker.endpoint) {
            self.last[index] = message;
            return true;
        };
        return false;
    }
    pub fn settle(self: *Fake, worker: core.Backing) bool {
        self.settle_calls += 1;
        for (&self.objects, 0..) |*object, index| if (object.* != null and object.*.?.control == worker.control) {
            if (self.false_refund) return true;
            self.pages[index] = 0;
            if (self.partial_settle) return false;
            object.* = null;
            return true;
        };
        return true;
    }
    pub fn admit(self: *Fake, worker: core.Backing) ?core.Fence {
        if (self.admission_failure) return null;
        for (self.objects, 0..) |object, index| if (object != null and object.?.control == worker.control and
            object.?.endpoint == worker.endpoint and self.pages[index] == 2) {
            if (self.saturated_faults) self.faults[index] = @import("std").math.maxInt(u32);
            if (self.faults[index] == @import("std").math.maxInt(u32)) return null;
            return .{ .generation = object.?.endpoint >> 8, .faults = self.faults[index], .restarts = self.restarts[index] };
        };
        return null;
    }
    pub fn settleCandidate(self: *Fake, worker: core.Backing, fence: core.Fence) core.Settlement {
        var stable = false;
        for (self.objects, 0..) |object, index| if (object != null and object.?.control == worker.control) {
            if (self.fault_during_settle) self.faults[index] += 1;
            if (self.restart_during_settle) {
                self.faults[index] += 1;
                self.restarts[index] += 1;
                self.generations[index] += 1;
                self.objects[index].?.endpoint += 0x100;
            }
            stable = self.objects[index].?.endpoint >> 8 == fence.generation and
                self.faults[index] == fence.faults and self.restarts[index] == fence.restarts;
        };
        return .{ .cleaned = self.settle(worker), .stable = stable };
    }
    pub fn rebind(self: *Fake, worker: core.Backing) ?core.Backing {
        self.rebind_calls += 1;
        if (self.fail_rebind) return null;
        for (&self.objects, 0..) |*object, index| if (object.* != null and object.*.?.control == worker.control) {
            self.generations[index] += 1;
            self.faults[index] += 1;
            self.restarts[index] += 1;
            object.*.?.endpoint += 0x100;
            object.*.?.channel = (self.channel_epoch << 8) | 0x10;
            self.channel_epoch += 1;
            return object.*.?;
        };
        return null;
    }
    pub fn validated(self: *Fake, token: u64, worker: core.Backing, rpc: u64, attempt: u8, input: u64, result: u64) void {
        _ = token; _ = worker; _ = rpc; _ = attempt; _ = input; _ = result;
        self.validated_calls += 1;
    }
};
pub fn answer(record: *const core.Record) abi.Message {
    var message = wire.encode(wire.reply_operation, .{ .id = record.rpc, .command = .work, .kind = .response,
        .detail = record.attempt, .token = record.token, .data = wire.calculate(record.input) });
    message.sender = record.worker.endpoint;
    return message;
}
