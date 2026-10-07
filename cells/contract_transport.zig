// The broker's bounded private delivery stage. The authenticated kernel copy
// has already occurred; no entry here is authority to settle a service record.
const abi = @import("abi.zig");
const core = @import("contract_core.zig");
const wire = core.wire;
pub const Inbox = @import("hosting_transport.zig").Inbox;
pub const delivery_windows: u8 = 8;
pub const Hold = enum { accepted, rejected, full };
const Entry = struct { occupied: bool = false, remaining: u8 = 0, message: abi.Message = undefined };
pub const Replies = struct {
    entries: [core.capacity]Entry = [_]Entry{.{}} ** core.capacity,

    pub fn hold(self: *Replies, broker: *const core.Broker, message: abi.Message) Hold {
        const packet = wire.decodeWork(&message, message.sender, wire.reply_operation) orelse return .rejected;
        const record = broker.status(broker.requester, packet.token) catch return .rejected;
        if (record.state != .running or record.worker.endpoint != message.sender or record.rpc != packet.id or
            record.attempt != packet.detail) return .rejected;
        const slot = wire.tokenSlot(packet.token).?;
        if (self.entries[slot].occupied) return .full;
        self.entries[slot] = .{ .occupied = true, .remaining = delivery_windows, .message = message };
        return .accepted;
    }

    pub fn advance(self: *Replies) [core.capacity]?abi.Message {
        var ready: [core.capacity]?abi.Message = [_]?abi.Message{null} ** core.capacity;
        for (&self.entries, 0..) |*entry, index| {
            if (!entry.occupied) continue;
            if (entry.remaining != 0) {
                entry.remaining -= 1;
                continue;
            }
            ready[index] = entry.message;
            entry.occupied = false;
        }
        return ready;
    }

    pub fn release(self: *Replies, token: u64) ?abi.Message {
        const slot = wire.tokenSlot(token) orelse return null;
        const entry = &self.entries[slot];
        if (!entry.occupied) return null;
        const packet = wire.decodeWork(&entry.message, entry.message.sender, wire.reply_operation).?;
        if (packet.token != token) return null;
        const result = entry.message;
        entry.occupied = false;
        return result;
    }
};
