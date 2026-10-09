const std = @import("std");
const testing = std.testing;
const support = @import("contract_test_support.zig");
const core = support.core;
const wire = support.wire;
const abi = @import("abi.zig");
const dispatcher = @import("contract_dispatch.zig");
const transport = @import("contract_transport.zig");
const owner: u64 = 0x104;
const issuer: u64 = 0x105;
fn delivered(packet: wire.Packet) abi.Message {
    var message = wire.encode(wire.request_operation, packet);
    message.sender = owner;
    return message;
}
fn call(table: *core.Broker, seam: *support.Fake, packet: wire.Packet) dispatcher.Dispatch {
    var message = delivered(packet);
    return dispatcher.dispatch(table, &message, seam);
}
fn snapshot(result: dispatcher.Dispatch) !wire.Snapshot {
    return switch (result) {
        .snapshot => |reply| reply.value,
        else => error.UnexpectedReply,
    };
}
fn fails(result: dispatcher.Dispatch, reason: core.Error) !void {
    switch (result) {
        .failure => |reply| try testing.expectEqual(reason, reply.reason),
        else => return error.UnexpectedReply,
    }
}

test "actual service dispatcher rejects malformed issuer operation version and reserved fields before mutation" {
    var table = core.Broker.init(issuer, owner);
    var seam: support.Fake = .{};
    const packet: wire.Packet = .{ .id = 1, .command = .offer, .detail = 1, .data = 17 };
    for (0..4) |variation| {
        var message = delivered(packet);
        switch (variation) {
            0 => message.sender = owner + 0x100,
            1 => message.operation = wire.reply_operation,
            2 => message.payload[8] = 2,
            3 => message.payload[12] = 1,
            else => unreachable,
        }
        try testing.expectEqual(std.meta.Tag(dispatcher.Dispatch).ignored, std.meta.activeTag(dispatcher.dispatch(&table, &message, &seam)));
    }
    try testing.expectEqual(@as(u64, 0), seam.create_calls);
    try testing.expectEqual(@as(u64, 0), table.offer_highwater);
    try fails(call(&table, &seam, .{ .id = 1, .command = .offer, .detail = 2, .data = 17 }), error.invalid);
    try fails(call(&table, &seam, .{ .id = 1, .command = .work, .detail = 1, .token = wire.token(1, 0, issuer).?, .data = 17 }), error.invalid);
    try testing.expectEqual(@as(u64, 0), seam.create_calls);
}
test "actual dispatcher recovers lost offered reply by transaction without allocating or executing again" {
    var table = core.Broker.init(issuer, owner);
    var seam: support.Fake = .{};
    _ = call(&table, &seam, .{ .id = 1, .command = .offer, .detail = 1, .data = 17 });
    const found = try snapshot(call(&table, &seam, .{ .id = 2, .command = .status, .data = 1 }));
    const replay = try snapshot(call(&table, &seam, .{ .id = 1, .command = .offer, .detail = 1, .data = 17 }));
    try testing.expectEqual(found, replay);
    try testing.expectEqual(@as(u64, 1), seam.create_calls);
    try testing.expectEqual(@as(u64, 0), seam.send_calls);
    try fails(call(&table, &seam, .{ .id = 1, .command = .offer, .detail = 1, .data = 18 }), error.invalid);
}
test "production dispatch preserves two worker replies and exact cancellation terminal retention reap reuse" {
    var table = core.Broker.init(issuer, owner);
    var seam: support.Fake = .{};
    const first = try snapshot(call(&table, &seam, .{ .id = 1, .command = .offer, .detail = 1, .data = 17 }));
    const second = try snapshot(call(&table, &seam, .{ .id = 2, .command = .offer, .detail = 1, .data = 18 }));
    try fails(call(&table, &seam, .{ .id = 3, .command = .offer, .detail = 1, .data = 19 }), error.no_space);
    _ = call(&table, &seam, .{ .id = 4, .command = .accept, .detail = 1, .token = first.token, .data = first.input });
    _ = call(&table, &seam, .{ .id = 5, .command = .accept, .detail = 1, .token = second.token, .data = second.input });
    var first_reply = support.answer(&table.records[wire.tokenSlot(first.token).?]);
    var second_reply = support.answer(&table.records[wire.tokenSlot(second.token).?]);
    const cancelled = try snapshot(call(&table, &seam, .{ .id = 6, .command = .cancel, .token = first.token }));
    try testing.expectEqual(wire.State.cancelled, cancelled.state);
    try testing.expectError(error.stale, table.deliver(&first_reply, &seam));
    _ = try table.deliver(&second_reply, &seam);
    const receipt = try snapshot(call(&table, &seam, .{ .id = 7, .command = .receipt, .token = second.token }));
    try testing.expect(receipt.verified and receipt.result == wire.calculate(second.input));
    _ = call(&table, &seam, .{ .id = 8, .command = .receipt, .token = second.token });
    try testing.expectEqual(@as(u64, 2), seam.send_calls);
    try fails(call(&table, &seam, .{ .id = 9, .command = .offer, .detail = 1, .data = 19 }), error.no_space);
    try testing.expectEqual(std.meta.Tag(dispatcher.Dispatch).reaped, std.meta.activeTag(call(&table, &seam, .{ .id = 10, .command = .reap, .token = first.token })));
    const replacement = try snapshot(call(&table, &seam, .{ .id = 11, .command = .offer, .detail = 1, .data = 19 }));
    try testing.expect(replacement.token != first.token and replacement.instance != first.instance);
    try fails(call(&table, &seam, .{ .id = 12, .command = .status, .token = first.token }), error.stale);
    try testing.expect(table.conserved(seam.domain().?));
}
test "service failure code is bounded exact and work cannot start through query receipt or malformed accept" {
    var table = core.Broker.init(issuer, owner);
    var seam: support.Fake = .{};
    const offered = try snapshot(call(&table, &seam, .{ .id = 1, .command = .offer, .detail = 1, .data = 17 }));
    _ = call(&table, &seam, .{ .id = 2, .command = .status, .token = offered.token });
    try fails(call(&table, &seam, .{ .id = 3, .command = .receipt, .token = offered.token }), error.not_terminal);
    try fails(call(&table, &seam, .{ .id = 4, .command = .accept, .detail = 1, .token = offered.token, .data = 18 }), error.invalid);
    try testing.expectEqual(@as(u64, 0), seam.send_calls);
    try testing.expectEqual(@as(u64, 10), dispatcher.failureCode(error.not_ready));
    try testing.expectEqual(@as(u64, 1), dispatcher.failureCode(error.denied));
}
test "real lifecycle observation notices a restarted execution even after bounded backoff was missed" {
    var status: abi.CellStatus = std.mem.zeroes(abi.CellStatus);
    status.phase = 1;
    status.endpoint = 0x105;
    try testing.expect(!dispatcher.attemptRetired(0x105, status));
    status.phase = 2;
    try testing.expect(dispatcher.attemptRetired(0x105, status));
    status.phase = 1;
    status.endpoint = 0x205;
    try testing.expect(dispatcher.attemptRetired(0x105, status));
    status.phase = 4;
    try testing.expect(!dispatcher.attemptRetired(0x105, status));
}
test "production cleanup accepts stopped and quarantined zero backing and rejects live or mismatched identities" {
    const worker: abi.CreateResult = .{ .instance = 0x240, .control = 0x350, .endpoint = 0x106, .channel = 0x510, .creation = 0, .slot = 5, .identity = 1001 };
    var status: abi.CellStatus = std.mem.zeroes(abi.CellStatus);
    status.instance = worker.instance;
    status.control = worker.control;
    for ([_]u32{ 0, 1, 2, 5, 0xffffffff }) |phase| {
        status.phase = phase;
        try testing.expect(!dispatcher.backingReleased(worker, status));
    }
    for ([_]u32{ 3, 4 }) |phase| {
        status.phase = phase;
        try testing.expect(dispatcher.backingReleased(worker, status));
        var changed = status;
        changed.instance ^= 1;
        try testing.expect(!dispatcher.backingReleased(worker, changed));
        changed = status;
        changed.control ^= 1;
        try testing.expect(!dispatcher.backingReleased(worker, changed));
        changed = status;
        changed.own_pages = 2;
        try testing.expect(!dispatcher.backingReleased(worker, changed));
        changed = status;
        changed.reserved_slots = 1;
        try testing.expect(!dispatcher.backingReleased(worker, changed));
        changed = status;
        changed.reserved_pages = 2;
        try testing.expect(!dispatcher.backingReleased(worker, changed));
    }
}
test "production lifecycle reconciliation authenticates exact checked worker identity and parent before mutation" {
    var table = core.Broker.init(issuer, owner);
    var seam: support.Fake = .{};
    const offered = try table.offer(owner, 1, 17, 1, &seam);
    const preserved = offered.*;
    var status: abi.CellStatus = std.mem.zeroes(abi.CellStatus);
    status.instance = offered.worker.instance;
    status.control = offered.worker.control;
    status.slot = offered.worker.slot;
    status.parent_endpoint = issuer;
    status.phase = 3;
    for (0..4) |variation| {
        var changed = status;
        switch (variation) {
            0 => changed.instance ^= 1,
            1 => changed.control ^= 1,
            2 => changed.slot ^= 1,
            3 => changed.parent_endpoint += 0x100,
            else => unreachable,
        }
        try testing.expectError(error.invalid, dispatcher.reconcile(&table, offered.token, changed, &seam));
        try testing.expectEqual(preserved, offered.*);
        try testing.expectEqual(@as(u64, 0), seam.settle_calls);
        try testing.expectEqual(@as(u64, 0), seam.send_calls);
        try testing.expect(table.conserved(seam.domain().?));
    }
    _ = try dispatcher.reconcile(&table, offered.token, status, &seam);
    try testing.expectEqual(wire.State.failed, offered.state);
    try testing.expectEqual(wire.Reason.lifecycle, offered.reason);
    try testing.expectEqual(@as(u64, 0), seam.send_calls);
    try testing.expectEqual(@as(u32, 0), seam.domain().?.owned_pages);
}
test "dequeued owner cancellation precedes recovery rebind and dispatch for a newer ready execution" {
    var table = core.Broker.init(issuer, owner);
    var seam: support.Fake = .{};
    const first = try table.offer(owner, 1, 17, 1, &seam);
    _ = try table.accept(owner, first.token, first.input, 1, &seam);
    const old_reply = support.answer(first);
    const old_rpc = first.rpc;
    _ = try table.workerFault(first.worker.endpoint, &seam);
    var status: abi.CellStatus = std.mem.zeroes(abi.CellStatus);
    status.instance = first.worker.instance;
    status.control = first.worker.control;
    status.slot = first.worker.slot;
    status.parent_endpoint = issuer;
    status.phase = 1;
    status.endpoint = first.worker.endpoint + 0x100;
    const sends_before = seam.send_calls;
    _ = try dispatcher.observe(&table, first.token, status, &seam);
    try testing.expectEqual(wire.State.recovering, first.state);
    try testing.expectEqual(old_rpc, first.rpc);
    try testing.expectEqual(@as(u8, 0), first.retries);
    try testing.expectEqual(@as(u64, 0), seam.rebind_calls);
    try testing.expectEqual(sends_before, seam.send_calls);
    const cancelled = try snapshot(call(&table, &seam, .{ .id = 2, .command = .cancel, .token = first.token }));
    try testing.expectEqual(wire.State.cancelled, cancelled.state);
    try testing.expectEqual(wire.Reason.cancelled, cancelled.reason);
    _ = try dispatcher.reconcile(&table, first.token, status, &seam);
    try testing.expectEqual(@as(u64, 0), seam.rebind_calls);
    try testing.expectEqual(sends_before, seam.send_calls);
    try testing.expectError(error.stale, table.deliver(&old_reply, &seam));
    try testing.expectEqual(@as(u32, 0), seam.domain().?.owned_pages);
    try testing.expectEqual(@as(u64, 1), seam.settle_calls);
}
test "result admission and post-stop settlement fence exact execution generation and fault restart counters" {
    const worker: abi.CreateResult = .{ .instance = 0x240, .control = 0x350, .endpoint = 0x506, .channel = 0x510, .creation = 0, .slot = 5, .identity = 1001 };
    var current: abi.CellStatus = std.mem.zeroes(abi.CellStatus);
    current.instance = worker.instance;
    current.control = worker.control;
    current.endpoint = worker.endpoint;
    current.generation = 5;
    current.slot = worker.slot;
    current.parent_endpoint = issuer;
    current.template_id = 4;
    current.depth = 2;
    current.phase = 1;
    current.own_pages = 2;
    current.faults = 1;
    current.restarts = 1;
    const fence = dispatcher.admissionFence(worker, current, issuer).?;
    try testing.expectEqual(@as(u64, 5), fence.generation);
    var saturated = current;
    saturated.faults = 0xffffffff;
    try testing.expect(dispatcher.admissionFence(worker, saturated, issuer) == null);
    for (0..10) |variation| {
        var changed = current;
        switch (variation) {
            0 => changed.phase = 2,
            1 => changed.instance ^= 1,
            2 => changed.control ^= 1,
            3 => changed.endpoint += 0x100,
            4 => changed.generation += 1,
            5 => changed.parent_endpoint += 0x100,
            6 => changed.template_id = 2,
            7 => changed.depth = 1,
            8 => changed.own_pages = 0,
            9 => changed.reserved_pages = 2,
            else => unreachable,
        }
        try testing.expect(dispatcher.admissionFence(worker, changed, issuer) == null);
    }
    var stopped = current;
    stopped.phase = 4;
    stopped.own_pages = 0;
    try testing.expect(dispatcher.fenceStable(worker, stopped, fence));
    stopped.phase = 3;
    try testing.expect(dispatcher.fenceStable(worker, stopped, fence));
    for (0..3) |variation| {
        var changed = stopped;
        switch (variation) {
            0 => changed.generation += 1,
            1 => changed.faults += 1,
            2 => changed.restarts += 1,
            else => unreachable,
        }
        try testing.expect(dispatcher.backingReleased(worker, changed));
        try testing.expect(!dispatcher.fenceStable(worker, changed, fence));
    }
}

test "production protocol dispatch rejects every command kind length and reserved header boundary without consuming offers" {
    var table = core.Broker.init(issuer, owner);
    var seam: support.Fake = .{};
    const packet: wire.Packet = .{ .id = 1, .command = .offer, .detail = 1, .data = 17 };
    for ([_]u32{ 0, 1, 31, 33, 0xffffffff }) |length| {
        var message = delivered(packet);
        message.length = length;
        try testing.expectEqual(std.meta.Tag(dispatcher.Dispatch).ignored, std.meta.activeTag(dispatcher.dispatch(&table, &message, &seam)));
    }
    // The envelope now recognizes the explicit byte-profile worker commands,
    // but none is an owner request to this broker. Preserve their denial as
    // an INVALID failure; genuinely unknown command bytes remain ignored.
    for (@intFromEnum(wire.Command.input)..@intFromEnum(wire.Command.authorize_input) + 1) |command| {
        var message = delivered(packet);
        message.payload[9] = @intCast(command);
        try fails(dispatcher.dispatch(&table, &message, &seam), error.invalid);
    }
    var stage_request = delivered(.{ .id = 2, .command = .stage, .detail = 2, .token = wire.token(1, 0, issuer).?, .data = 0x1a1 });
    try fails(dispatcher.dispatch(&table, &stage_request, &seam), error.invalid);
    for ([_]u8{0}) |command| {
        var message = delivered(packet);
        message.payload[9] = command;
        try testing.expectEqual(std.meta.Tag(dispatcher.Dispatch).ignored, std.meta.activeTag(dispatcher.dispatch(&table, &message, &seam)));
    }
    for (@intFromEnum(wire.Command.stage) + 1..256) |command| {
        var message = delivered(packet);
        message.payload[9] = @intCast(command);
        try testing.expectEqual(std.meta.Tag(dispatcher.Dispatch).ignored, std.meta.activeTag(dispatcher.dispatch(&table, &message, &seam)));
    }
    for (12..16) |offset| {
        var message = delivered(packet);
        message.payload[offset] = 1;
        try testing.expectEqual(std.meta.Tag(dispatcher.Dispatch).ignored, std.meta.activeTag(dispatcher.dispatch(&table, &message, &seam)));
    }
    for ([_]wire.Kind{ .response, .snapshot, .failure }) |kind| {
        var message = delivered(.{ .id = 1, .command = .offer, .kind = kind, .detail = 1, .data = 17 });
        try fails(dispatcher.dispatch(&table, &message, &seam), error.invalid);
    }
    var invalid_kind = delivered(packet);
    invalid_kind.payload[10] = 4;
    try testing.expectEqual(std.meta.Tag(dispatcher.Dispatch).ignored, std.meta.activeTag(dispatcher.dispatch(&table, &invalid_kind, &seam)));
    try testing.expectEqual(@as(u64, 0), table.offer_highwater);
    try testing.expectEqual(@as(u64, 1), table.next_serial);
    try testing.expectEqual(@as(u64, 0), seam.create_calls);
    try testing.expectEqual(@as(u64, 0), seam.send_calls);
}

test "actual eight-entry deferred inbox rejects pressure and preserves authenticated FIFO dispatch without extra backing" {
    var table = core.Broker.init(issuer, owner);
    var seam: support.Fake = .{};
    var inbox: transport.Inbox = .{};
    for (1..9) |id| {
        const message = delivered(.{ .id = id, .command = .offer, .detail = 1, .data = id * 17 });
        try testing.expect(inbox.push(message));
    }
    const ninth = delivered(.{ .id = 9, .command = .offer, .detail = 1, .data = 9 * 17 });
    try testing.expect(!inbox.push(ninth));
    try testing.expectEqual(@as(u64, 0), seam.create_calls);
    for (1..9) |id| {
        var message = inbox.pop().?;
        try testing.expectEqual(@as(u64, id), wire.decodeRequest(&message, owner).?.id);
        const result = dispatcher.dispatch(&table, &message, &seam);
        if (id <= 2) {
            const offered = try snapshot(result);
            try testing.expectEqual(wire.State.offered, offered.state);
        } else try fails(result, error.no_space);
    }
    try testing.expect(inbox.pop() == null);
    try testing.expect(inbox.push(ninth));
    var retried = inbox.pop().?;
    try fails(dispatcher.dispatch(&table, &retried, &seam), error.no_space);
    try testing.expectEqual(@as(u64, 2), seam.create_calls);
    try testing.expectEqual(@as(u64, 2), table.offer_highwater);
    try testing.expectEqual(@as(u32, 2), seam.domain().?.owned_slots);
    try testing.expectEqual(@as(u32, 4), seam.domain().?.owned_pages);
    try testing.expect(table.conserved(seam.domain().?));
}

test "production private reply stage fences forged binding collision and late cancellation while preserving unrelated reply" {
    var table = core.Broker.init(issuer, owner);
    var seam: support.Fake = .{};
    var replies: transport.Replies = .{};
    const first = try snapshot(call(&table, &seam, .{ .id = 1, .command = .offer, .detail = 1, .data = 17 }));
    const second = try snapshot(call(&table, &seam, .{ .id = 2, .command = .offer, .detail = 1, .data = 18 }));
    _ = call(&table, &seam, .{ .id = 3, .command = .accept, .detail = 1, .token = first.token, .data = first.input });
    _ = call(&table, &seam, .{ .id = 4, .command = .accept, .detail = 1, .token = second.token, .data = second.input });
    const first_reply = support.answer(&table.records[wire.tokenSlot(first.token).?]);
    const second_reply = support.answer(&table.records[wire.tokenSlot(second.token).?]);
    var forged = first_reply;
    wire.put64(&forged.payload, 0, wire.get64(&forged.payload, 0) + 1);
    try testing.expectEqual(transport.Hold.rejected, replies.hold(&table, forged));
    forged = first_reply;
    forged.sender += 0x100;
    try testing.expectEqual(transport.Hold.rejected, replies.hold(&table, forged));
    forged = first_reply;
    forged.payload[11] = 2;
    try testing.expectEqual(transport.Hold.rejected, replies.hold(&table, forged));
    try testing.expectEqual(transport.Hold.accepted, replies.hold(&table, first_reply));
    forged = first_reply;
    forged.payload[24] ^= 1;
    try testing.expectEqual(transport.Hold.full, replies.hold(&table, forged));
    try testing.expectEqual(transport.Hold.accepted, replies.hold(&table, second_reply));
    _ = call(&table, &seam, .{ .id = 5, .command = .cancel, .token = first.token });
    for (0..transport.delivery_windows) |_| {
        const ready = replies.advance();
        try testing.expect(ready[0] == null and ready[1] == null);
    }
    const ready = replies.advance();
    try testing.expectEqual(first_reply, ready[wire.tokenSlot(first.token).?].?);
    try testing.expectEqual(second_reply, ready[wire.tokenSlot(second.token).?].?);
    try testing.expectError(error.stale, table.deliver(&ready[wire.tokenSlot(first.token).?].?, &seam));
    _ = try table.deliver(&ready[wire.tokenSlot(second.token).?].?, &seam);
    try testing.expectEqual(wire.State.cancelled, (try table.status(owner, first.token)).state);
    try testing.expectEqual(wire.State.completed, (try table.status(owner, second.token)).state);
    try testing.expectEqual(@as(u64, 1), seam.validated_calls);
    try testing.expectEqual(@as(u32, 0), seam.domain().?.owned_slots);
    try testing.expect(table.conserved(seam.domain().?));
}

test "private record reap release cannot drain a successor token or occupy its valid reply slot" {
    var table = core.Broker.init(issuer, owner);
    var seam: support.Fake = .{};
    var replies: transport.Replies = .{};
    const first = try snapshot(call(&table, &seam, .{ .id = 1, .command = .offer, .detail = 1, .data = 17 }));
    _ = call(&table, &seam, .{ .id = 2, .command = .accept, .detail = 1, .token = first.token, .data = first.input });
    const old_reply = support.answer(&table.records[wire.tokenSlot(first.token).?]);
    try testing.expectEqual(transport.Hold.accepted, replies.hold(&table, old_reply));
    _ = call(&table, &seam, .{ .id = 3, .command = .cancel, .token = first.token });
    _ = call(&table, &seam, .{ .id = 4, .command = .reap, .token = first.token });
    try testing.expectEqual(old_reply, replies.release(first.token).?);
    const successor = try snapshot(call(&table, &seam, .{ .id = 5, .command = .offer, .detail = 1, .data = 18 }));
    _ = call(&table, &seam, .{ .id = 6, .command = .accept, .detail = 1, .token = successor.token, .data = successor.input });
    const new_reply = support.answer(&table.records[wire.tokenSlot(successor.token).?]);
    try testing.expectEqual(transport.Hold.rejected, replies.hold(&table, old_reply));
    try testing.expectEqual(transport.Hold.accepted, replies.hold(&table, new_reply));
    try testing.expect(replies.release(first.token) == null);
    try testing.expectEqual(new_reply, replies.release(successor.token).?);
    try testing.expect(replies.release(successor.token) == null);
    try testing.expectError(error.stale, table.deliver(&old_reply, &seam));
    _ = try table.deliver(&new_reply, &seam);
    try testing.expectEqual(wire.State.completed, (try table.status(owner, successor.token)).state);
}

test "partial lost snapshot remains unusable and fresh status reconstructs the same offered worker without execution" {
    var table = core.Broker.init(issuer, owner);
    var seam: support.Fake = .{};
    const first = try snapshot(call(&table, &seam, .{ .id = 1, .command = .offer, .detail = 1, .data = 17 }));
    var lost: wire.Collector = .{ .issuer = issuer, .requester = owner, .id = 1, .command = .offer };
    const lost_parts = first.messages(1, .offer);
    for (lost_parts[0..3]) |part| {
        var message = part;
        message.sender = issuer;
        try testing.expect(lost.push(&message));
    }
    try testing.expect(lost.take() == null);
    const resync = try snapshot(call(&table, &seam, .{ .id = 2, .command = .status, .data = 1 }));
    var current: wire.Collector = .{ .issuer = issuer, .requester = owner, .id = 2, .command = .status };
    var late = lost_parts[3];
    late.sender = issuer;
    try testing.expect(!current.push(&late));
    for (resync.messages(2, .status)) |part| {
        var message = part;
        message.sender = issuer;
        try testing.expect(current.push(&message));
    }
    try testing.expectEqual(first, current.take().?);
    try testing.expectEqual(@as(u64, 1), seam.create_calls);
    try testing.expectEqual(@as(u64, 0), seam.send_calls);
    try testing.expectEqual(@as(u32, 2), seam.domain().?.owned_pages);
}
