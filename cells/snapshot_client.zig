// Bounded production snapshot RPC and ordered reader. The caller owns the
// finite deferred inbox and must drain it before waiting for new requests.
const abi = @import("abi.zig");
const syscall = @import("syscall.zig");
const runtime = @import("storage_runtime.zig");
const storage_wire = @import("storage_wire.zig");
const wire = @import("snapshot_wire.zig");
const snapshot = @import("snapshot.zig");
const storage = @import("storage.zig");

pub const Client = struct {
    sequence: storage_wire.Sequence = .{},

    pub fn control(self: *Client, issuer: u64, subject: u64, peer: u64, action: wire.Action) ?wire.ControlReply {
        const transaction = self.sequence.take() orelse return null;
        return self.controlTransaction(issuer, transaction, subject, peer, action);
    }

    // Owner operations retain the original reference issuer as their exact
    // route target. Never replace it with a fresh lookup on an old token.
    pub fn objectControl(self: *Client, reference: snapshot.Ref, peer: u64, action: wire.Action) ?wire.ControlReply {
        if (!snapshot.validRef(reference) or action == .create or action == .status or action == .inventory) return null;
        return self.control(reference.issuer, reference.token, peer, action);
    }
    pub fn objectControlTransactionWith(self: *Client, reference: snapshot.Ref, transaction: u64, peer: u64, action: wire.Action, inbox: anytype) ?wire.ControlReply {
        if (!snapshot.validRef(reference) or action == .create or action == .status or action == .inventory) return null;
        return self.controlTransactionWith(reference.issuer, transaction, reference.token, peer, action, inbox);
    }

    // Retrying a possibly committed create uses its original transaction;
    // status names that creation transaction as the subject of a fresh query.
    pub fn controlTransaction(self: *Client, issuer: u64, transaction: u64, subject: u64, peer: u64, action: wire.Action) ?wire.ControlReply {
        var inbox: RejectInbox = .{};
        return self.controlTransactionWith(issuer, transaction, subject, peer, action, &inbox);
    }

    pub fn controlTransactionWith(_: *Client, issuer: u64, transaction: u64, subject: u64, peer: u64, action: wire.Action, inbox: anytype) ?wire.ControlReply {
        if (issuer == 0 or transaction == 0) return null;
        var request = wire.control(transaction, subject, peer, action);
        if (runtime.sendBounded(issuer, &request, .snapshot_control) != 0) return null;
        for (0..8) |_| {
            if (inbox.messages.len != 0 and inbox.count == inbox.messages.len) return null;
            var message: abi.Message = undefined;
            if (syscall.receiveWait(&message, 10) != 0 or syscall.lookup(.filesystem) != issuer) return null;
            if (wire.decodeControlReply(&message, issuer, transaction, action)) |reply| return reply;
            // A stale service reply is discarded, never reinterpreted as work.
            if (message.operation != @intFromEnum(abi.Operation.snapshot_reply) and !inbox.push(message)) return null;
        }
        return null;
    }

    pub fn read(self: *Client, reference: snapshot.Ref, offset: u16, count: u8) ?wire.ReadReply {
        var inbox: RejectInbox = .{};
        return self.readOperationWith(.snapshot_read, reference, offset, count, 0, &inbox);
    }
    pub fn release(self: *Client, reference: snapshot.Ref) ?wire.ReadReply {
        var inbox: RejectInbox = .{};
        return self.readOperationWith(.snapshot_release, reference, 0, 0, 0, &inbox);
    }
    pub fn readWith(self: *Client, reference: snapshot.Ref, offset: u16, count: u8, inbox: anytype) ?wire.ReadReply {
        return self.readOperationWith(.snapshot_read, reference, offset, count, 0, inbox);
    }
    pub fn releaseWith(self: *Client, reference: snapshot.Ref, inbox: anytype) ?wire.ReadReply {
        return self.readOperationWith(.snapshot_release, reference, 0, 0, 0, inbox);
    }
    pub fn releaseWithBound(self: *Client, reference: snapshot.Ref, reader: u64, inbox: anytype) ?wire.ReadReply {
        return self.readOperationWith(.snapshot_release, reference, 0, 0, reader, inbox);
    }
    pub fn releaseBound(self: *Client, reference: snapshot.Ref, reader: u64) ?wire.ReadReply {
        var inbox: RejectInbox = .{};
        return self.releaseWithBound(reference, reader, &inbox);
    }
    fn readOperationWith(self: *Client, operation: abi.Operation, reference: snapshot.Ref, offset: u16, count: u8, reader: u64, inbox: anytype) ?wire.ReadReply {
        const transaction = self.sequence.take() orelse return null;
        const expected: wire.Read = .{ .transaction = transaction, .reference = reference, .offset = offset, .count = count };
        var request = if (operation == .snapshot_release) wire.release(transaction, reference, reader) else wire.read(operation, transaction, reference, offset, count);
        if (runtime.sendBounded(reference.issuer, &request, operation) != 0) return null;
        for (0..8) |_| {
            if (inbox.messages.len != 0 and inbox.count == inbox.messages.len) return null;
            var message: abi.Message = undefined;
            if (syscall.receiveWait(&message, 10) != 0 or syscall.lookup(.filesystem) != reference.issuer) return null;
            if (wire.decodeReadReply(&message, expected)) |reply| return reply;
            if (message.operation != @intFromEnum(abi.Operation.snapshot_reply) and !inbox.push(message)) return null;
        }
        return null;
    }

    pub fn collect(self: *Client, reference: snapshot.Ref, length: u8, out: *[snapshot.byte_limit]u8) bool {
        var inbox: RejectInbox = .{};
        return self.collectWith(reference, length, out, &inbox);
    }
    pub fn collectWith(self: *Client, reference: snapshot.Ref, length: u8, out: *[snapshot.byte_limit]u8, inbox: anytype) bool {
        var reader = Reader.init(reference, length) orelse return false;
        while (!reader.complete) {
            const planned = reader.next().?;
            const reply = self.readWith(reference, planned.offset, planned.count, inbox) orelse return false;
            if (!reader.accept(&reply)) return false;
        }
        out.* = reader.bytes;
        return true;
    }
};

pub const Chunk = struct { offset: u16, count: u8 };
// The declared capture length is checked through all full chunks and one
// exact EOF request. No successful partial prefix is treated as a result.
pub const Reader = struct {
    reference: snapshot.Ref,
    length: u8,
    offset: u16 = 0,
    complete: bool = false,
    failed: bool = false,
    bytes: [snapshot.byte_limit]u8 = [_]u8{0} ** snapshot.byte_limit,

    pub fn init(reference: snapshot.Ref, length: u8) ?Reader {
        if (!snapshot.validRef(reference) or length > snapshot.byte_limit) return null;
        return .{ .reference = reference, .length = length };
    }
    pub fn next(self: *const Reader) ?Chunk {
        if (self.complete or self.failed) return null;
        return .{ .offset = self.offset, .count = if (self.offset == self.length) 8 else @intCast(@min(8, @as(u16, self.length) - self.offset)) };
    }
    pub fn accept(self: *Reader, reply: *const wire.ReadReply) bool {
        const chunk = self.next() orelse return false;
        if (reply.reference.issuer != self.reference.issuer or reply.reference.token != self.reference.token or
            reply.offset != chunk.offset or reply.status != .ok or
            (self.offset == self.length and reply.count != 0) or (self.offset != self.length and reply.count != chunk.count))
        {
            self.failed = true;
            return false;
        }
        if (self.offset == self.length) {
            self.complete = true;
            return true;
        }
        @memcpy(self.bytes[self.offset..][0..reply.count], reply.data[0..reply.count]);
        self.offset += reply.count;
        return true;
    }
};

const RejectInbox = struct {
    messages: [0]abi.Message = .{},
    count: usize = 0,
    pub fn push(_: *RejectInbox, _: abi.Message) bool {
        return false;
    }
};
