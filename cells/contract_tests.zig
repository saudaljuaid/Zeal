const std = @import("std");
const testing = std.testing;
const support = @import("contract_test_support.zig");
const core = support.core;
const wire = support.wire;
const abi = @import("abi.zig");
const issuer: u64 = 0x104;
const owner: u64 = 0x103;
fn delivered(packet: wire.Packet, sender: u64, operation: u32) abi.Message {
    var message = wire.encode(operation, packet); message.sender = sender; return message;
}
test "exact versioned wire authenticates operation endpoint length every reserved byte and command kind" {
    const packet: wire.Packet = .{ .id = 0x0102030405060708, .command = .offer, .detail = 1, .data = 0x1122334455667788 };
    var message = delivered(packet, owner, wire.request_operation);
    try testing.expectEqual(@as(u8, 8), message.payload[0]);
    try testing.expectEqual(@as(u8, 1), message.payload[7]);
    try testing.expectEqual(@as(u8, 0x88), message.payload[24]);
    try testing.expectEqual(packet, wire.decodeRequest(&message, owner).?);
    for ([_]u64{ 0, owner + 0x100, issuer }) |sender| try testing.expect(wire.decodeRequest(&message, sender) == null);
    for ([_]u32{ 0, 31, 33, 0xffffffff }) |length| { message.length = length; try testing.expect(wire.decodeRequest(&message, owner) == null); }
    message.length = 32;
    for (8..16) |index| {
        const original = message.payload[index];
        message.payload[index] = 0xff;
        try testing.expect(wire.decodeRequest(&message, owner) == null);
        message.payload[index] = original;
    }
    message.operation = wire.reply_operation;
    try testing.expect(wire.decodeRequest(&message, owner) == null);
}
test "typed serial and issuer encoding rejects kernel types generation overflow and bit mutation" {
    const token = wire.token(wire.serial_limit, 1, issuer).?;
    try testing.expectEqual(@as(usize, 1), wire.tokenSlot(token).?);
    try testing.expectEqual(wire.serial_limit, wire.tokenSerial(token));
    try testing.expectEqual(@as(u64, 1), wire.tokenGeneration(token));
    try testing.expectEqual(issuer, wire.tokenIssuer(token));
    for ([_]u64{ 0, 0x10, 0x30, 0x40, 0x50, 0x60, 0x70 }) |tag| try testing.expect(wire.tokenSlot((token & ~@as(u64, 255)) | tag) == null);
    try testing.expect(wire.token(0, 0, issuer) == null);
    try testing.expect(wire.token(wire.serial_limit + 1, 0, issuer) == null);
    try testing.expect(wire.token(1, 2, issuer) == null);
    try testing.expect(wire.token(1, 0, (wire.generation_limit + 1) << 8) == null);
    try testing.expect(wire.token(1, 0, 0) == null);
    try testing.expect(wire.token(1, 0, 0x100) == null);
    try testing.expect(wire.token(1, 0, 0x109) == null);
    const largest_issuer = (wire.generation_limit << 8) | 8;
    try testing.expectEqual(largest_issuer, wire.tokenIssuer(wire.token(wire.serial_limit, 1, largest_issuer).?));
    var broker = core.Broker.init(issuer, owner);
    var fake: support.Fake = .{};
    const record = try broker.offer(owner, 1, 0, 1, &fake);
    for (0..64) |bit| {
        const altered = record.token ^ (@as(u64, 1) << @intCast(bit));
        try testing.expectError(if (wire.tokenSlot(altered) == null) core.Error.invalid else core.Error.stale, broker.status(owner, altered));
    }
}
test "two real seam allocations back two offered records no work and third record pressure" {
    var broker = core.Broker.init(issuer, owner);
    var fake: support.Fake = .{};
    const first = try broker.offer(owner, 1, 17, 1, &fake);
    const first_token = first.token;
    const second = try broker.offer(owner, 2, 31, 1, &fake);
    try testing.expect(first.worker.instance != second.worker.instance);
    try testing.expect(first.worker.control != second.worker.control);
    try testing.expectEqual(@as(u64, 0), fake.send_calls);
    try testing.expect(broker.conserved(fake.domain().?));
    try testing.expectError(core.Error.no_space, broker.offer(owner, 3, 99, 1, &fake));
    try testing.expectEqual(@as(u64, 2), fake.create_calls);
    try testing.expectEqual(@as(u64, 2), broker.offer_highwater);
    try testing.expectEqual(first_token, (try broker.offer(owner, 1, 17, 1, &fake)).token);
    try testing.expectError(core.Error.invalid, broker.offer(owner, 1, 18, 1, &fake));
    try testing.expectError(core.Error.denied, broker.offer(owner + 256, 3, 99, 1, &fake));
    try testing.expectError(core.Error.invalid, broker.offer(owner, 3, 99, 2, &fake));
}
test "exact duplicate accept executes once interleaved authenticated results settle before receipts" {
    var broker = core.Broker.init(issuer, owner);
    var fake: support.Fake = .{};
    const first = try broker.offer(owner, 1, 17, 1, &fake);
    const second = try broker.offer(owner, 2, 31, 1, &fake);
    try testing.expectError(core.Error.denied, broker.accept(issuer, first.token, 17, 1, &fake));
    try testing.expectError(core.Error.invalid, broker.accept(owner, first.token, 18, 1, &fake));
    _ = try broker.accept(owner, first.token, 17, 1, &fake);
    _ = try broker.accept(owner, second.token, 31, 1, &fake);
    _ = try broker.accept(owner, first.token, 17, 1, &fake);
    try testing.expectEqual(@as(u64, 2), fake.send_calls);
    const second_answer = support.answer(second);
    const first_answer = support.answer(first);
    _ = try broker.deliver(&second_answer, &fake);
    try testing.expectEqual(core.State.running, first.state);
    try testing.expectEqual(core.State.completed, second.state);
    try testing.expectEqual(@as(u8, 0), second.backing_pages);
    try testing.expectEqual(@as(u8, 0), second.backing_slots);
    try testing.expect(broker.snapshot(second).valid());
    _ = try broker.deliver(&first_answer, &fake);
    try testing.expectError(core.Error.stale, broker.deliver(&first_answer, &fake));
    _ = try broker.accept(owner, first.token, 17, 1, &fake);
    try testing.expectEqual(@as(u64, 2), fake.send_calls);
    try testing.expectEqual(@as(u64, 2), fake.settle_calls);
    try testing.expectEqual(@as(u64, 2), fake.validated_calls);
    try testing.expect(broker.conserved(fake.domain().?));
    try testing.expectError(core.Error.no_space, broker.offer(owner, 3, 99, 1, &fake));
}
test "offer and completion reply loss query exact authoritative retained records without reexecution" {
    var broker = core.Broker.init(issuer, owner);
    var fake: support.Fake = .{};
    const record = try broker.offer(owner, 7, 0x73ab9c52de410689, 1, &fake);
    const token = record.token;
    try testing.expectEqual(token, (try broker.findOffer(owner, 7)).token);
    try testing.expectEqual(token, (try broker.offer(owner, 7, record.input, 1, &fake)).token);
    _ = try broker.accept(owner, token, record.input, 1, &fake);
    const reply = support.answer(record);
    _ = try broker.deliver(&reply, &fake);
    for (0..10) |_| try testing.expect(broker.snapshot(try broker.status(owner, token)).valid());
    try testing.expectEqual(@as(u64, 1), fake.create_calls);
    try testing.expectEqual(@as(u64, 1), fake.send_calls);
    try testing.expectEqual(@as(u64, 1), fake.settle_calls);
    try broker.reap(owner, token);
    try testing.expectError(core.Error.stale, broker.findOffer(owner, 7));
    try testing.expectError(core.Error.stale, broker.offer(owner, 7, 0x73ab9c52de410689, 1, &fake));
}
test "cancel offered running recovering and terminal fences privately held old replies and preserves sibling" {
    for ([_]core.State{ .offered, .running, .recovering }) |phase| {
        var broker = core.Broker.init(issuer, owner);
        var fake: support.Fake = .{};
        const first = try broker.offer(owner, 1, 17, 1, &fake);
        const second = try broker.offer(owner, 2, 31, 1, &fake);
        _ = try broker.accept(owner, second.token, 31, 1, &fake);
        const sibling = second.*;
        var late: abi.Message = undefined;
        if (phase != .offered) {
            _ = try broker.accept(owner, first.token, 17, 1, &fake);
            late = support.answer(first);
            if (phase == .recovering) _ = try broker.workerFault(first.worker.endpoint, &fake);
        }
        _ = try broker.cancel(owner, first.token, &fake);
        _ = try broker.cancel(owner, first.token, &fake);
        try testing.expectEqual(core.State.cancelled, first.state);
        try testing.expectEqual(@as(u64, 1), fake.settle_calls);
        try testing.expectEqual(sibling, second.*);
        if (phase != .offered) try testing.expectError(core.Error.stale, broker.deliver(&late, &fake));
        try testing.expectError(core.Error.not_ready, broker.retry(first.token, &fake));
        const sibling_answer = support.answer(second);
        _ = try broker.deliver(&sibling_answer, &fake);
        _ = try broker.cancel(owner, second.token, &fake);
        try testing.expectEqual(core.State.completed, second.state);
        try testing.expect(second.verified);
        try testing.expect(broker.conserved(fake.domain().?));
    }
}
test "restart explicit fresh rebind changes only execution RPC attempt and permits one retry" {
    var broker = core.Broker.init(issuer, owner);
    var fake: support.Fake = .{};
    const record = try broker.offer(owner, 1, 17, 1, &fake);
    _ = try broker.accept(owner, record.token, 17, 1, &fake);
    const old = record.*;
    const old_answer = support.answer(record);
    _ = try broker.workerFault(record.worker.endpoint, &fake);
    try testing.expectEqual(core.State.recovering, record.state);
    try testing.expectEqual(@as(u8, 2), record.backing_pages);
    try testing.expectError(core.Error.stale, broker.deliver(&old_answer, &fake));
    _ = try broker.retry(record.token, &fake);
    try testing.expectEqual(old.token, record.token);
    try testing.expectEqual(old.worker.instance, record.worker.instance);
    try testing.expectEqual(old.worker.control, record.worker.control);
    try testing.expect(record.worker.endpoint > old.worker.endpoint);
    try testing.expect(record.worker.channel != old.worker.channel);
    try testing.expect(record.rpc != old.rpc);
    try testing.expectEqual(@as(u8, 2), record.attempt);
    try testing.expectEqual(@as(u8, 1), record.retries);
    try testing.expectError(core.Error.stale, broker.deliver(&old_answer, &fake));
    const current = support.answer(record);
    _ = try broker.deliver(&current, &fake);
    try testing.expectEqual(core.State.completed, record.state);
    try testing.expect(broker.snapshot(record).valid());
}
test "second failure cleanup no additional attempt and rebind failure becomes finite failure" {
    for ([_]bool{ false, true }) |rebind_failure| {
        var broker = core.Broker.init(issuer, owner);
        var fake: support.Fake = .{};
        const record = try broker.offer(owner, 1, 17, 1, &fake);
        _ = try broker.accept(owner, record.token, 17, 1, &fake);
        _ = try broker.workerFault(record.worker.endpoint, &fake);
        if (rebind_failure) {
            fake.fail_rebind = true;
            try testing.expectError(core.Error.resource, broker.retry(record.token, &fake));
            try testing.expectEqual(core.Reason.rebind, record.reason);
        } else {
            _ = try broker.retry(record.token, &fake);
            _ = try broker.workerFault(record.worker.endpoint, &fake);
            try testing.expectEqual(core.Reason.second_fault, record.reason);
            try testing.expectEqual(@as(u64, 2), fake.send_calls);
        }
        try testing.expectEqual(core.State.failed, record.state);
        try testing.expectEqual(@as(u8, 0), record.backing_slots);
        try testing.expect(broker.snapshot(record).valid());
    }
}
test "forged exact results malformed unsolicited old generation and altered attempt cannot succeed" {
    var broker = core.Broker.init(issuer, owner);
    var fake: support.Fake = .{};
    const record = try broker.offer(owner, 1, 17, 1, &fake);
    _ = try broker.accept(owner, record.token, 17, 1, &fake);
    var reply = support.answer(record);
    reply.sender += 0x100;
    try testing.expectError(core.Error.stale, broker.deliver(&reply, &fake));
    reply = support.answer(record); reply.payload[11] = 2;
    try testing.expectError(core.Error.stale, broker.deliver(&reply, &fake));
    reply = support.answer(record); wire.put64(&reply.payload, 0, record.rpc + 1);
    try testing.expectError(core.Error.stale, broker.deliver(&reply, &fake));
    reply = support.answer(record); reply.payload[12] = 1;
    try testing.expectError(core.Error.invalid, broker.deliver(&reply, &fake));
    try testing.expectEqual(core.State.running, record.state);
    reply = support.answer(record); reply.payload[24] ^= 1;
    try testing.expectError(core.Error.invalid, broker.deliver(&reply, &fake));
    try testing.expectEqual(core.State.failed, record.state);
    try testing.expectEqual(core.Reason.invalid_result, record.reason);
    try testing.expect(!record.verified);
    try testing.expectEqual(@as(u64, 0), fake.validated_calls);
}
test "same requester transactions in separate exact broker scopes cannot cross contract authority" {
    var first_broker = core.Broker.init(0x104, owner);
    var second_broker = core.Broker.init(0x105, owner);
    var first_fake: support.Fake = .{};
    var second_fake: support.Fake = .{};
    const first = try first_broker.offer(owner, 1, 17, 1, &first_fake);
    const second = try second_broker.offer(owner, 1, 17, 1, &second_fake);
    try testing.expect(first.token != second.token);
    try testing.expectError(core.Error.stale, first_broker.accept(owner, second.token, 17, 1, &first_fake));
    try testing.expectError(core.Error.stale, second_broker.cancel(owner, first.token, &second_fake));
    try testing.expectEqual(@as(u64, 0), first_fake.send_calls);
    try testing.expectEqual(@as(u64, 0), second_fake.settle_calls);
    try testing.expect(first_broker.conserved(first_fake.domain().?));
    try testing.expect(second_broker.conserved(second_fake.domain().?));
}
test "cross contract token reply cannot consume another genuine interleaved computation" {
    var broker = core.Broker.init(issuer, owner);
    var fake: support.Fake = .{};
    const first = try broker.offer(owner, 1, 17, 1, &fake);
    const second = try broker.offer(owner, 2, 31, 1, &fake);
    _ = try broker.accept(owner, first.token, 17, 1, &fake);
    _ = try broker.accept(owner, second.token, 31, 1, &fake);
    const first_saved = first.*;
    const second_saved = second.*;
    var reply = support.answer(first);
    wire.put64(&reply.payload, 16, second.token);
    try testing.expectError(core.Error.stale, broker.deliver(&reply, &fake));
    try testing.expectEqual(first_saved, first.*);
    try testing.expectEqual(second_saved, second.*);
    try testing.expectEqual(@as(u64, 0), fake.settle_calls);
    reply = support.answer(second);
    _ = try broker.deliver(&reply, &fake);
    reply = support.answer(first);
    _ = try broker.deliver(&reply, &fake);
    try testing.expectEqual(@as(u64, 2), fake.validated_calls);
}
test "all response kinds unknown command bytes and invalid profiles reject before worker mutation" {
    const base: wire.Packet = .{ .id = 1, .command = .offer, .detail = 1, .data = 17 };
    for ([_]wire.Kind{ .response, .snapshot, .failure }) |kind| {
        var packet = base; packet.kind = kind;
        const message = delivered(packet, owner, wire.request_operation);
        try testing.expect(wire.decodeRequest(&message, owner) == null);
    }
    for ([_]u8{ 0, 10, 127, 255 }) |command| {
        var message = delivered(base, owner, wire.request_operation);
        message.payload[9] = command;
        try testing.expect(wire.decodeRequest(&message, owner) == null);
    }
    for ([_]u8{ 0, 2, 255 }) |profile| {
        var packet = base; packet.detail = profile;
        const message = delivered(packet, owner, wire.request_operation);
        try testing.expect(wire.decodeRequest(&message, owner) == null);
    }
}
test "failed prevalidation consumes no identity creation failure consumes identity and no backing" {
    var broker = core.Broker.init(issuer, owner);
    var fake: support.Fake = .{};
    try testing.expectError(core.Error.invalid, broker.offer(owner, 0, 17, 1, &fake));
    try testing.expectError(core.Error.invalid, broker.offer(owner, 1, 17, 0, &fake));
    fake.bad_domain = true;
    try testing.expectError(core.Error.resource, broker.offer(owner, 1, 17, 1, &fake));
    try testing.expectEqual(@as(u64, 0), broker.offer_highwater);
    fake.bad_domain = false; fake.fail_create = true;
    try testing.expectError(core.Error.resource, broker.offer(owner, 1, 17, 1, &fake));
    try testing.expectEqual(@as(u64, 1), broker.offer_highwater);
    try testing.expectEqual(@as(u64, 2), broker.next_serial);
    try testing.expectError(core.Error.stale, broker.offer(owner, 1, 17, 1, &fake));
    fake.fail_create = false;
    const record = try broker.offer(owner, 2, 17, 1, &fake);
    try testing.expectEqual(@as(u64, 2), wire.tokenSerial(record.token));
}
test "failed send cleans actual allocation and settlement failure exposes retained slot without receipt" {
    var broker = core.Broker.init(issuer, owner);
    var fake: support.Fake = .{};
    var record = try broker.offer(owner, 1, 17, 1, &fake);
    fake.fail_send = true;
    try testing.expectError(core.Error.transport, broker.accept(owner, record.token, 17, 1, &fake));
    try testing.expectEqual(core.State.failed, record.state);
    try testing.expectEqual(core.Reason.transport, record.reason);
    try testing.expectEqual(@as(u8, 0), record.backing_slots);
    try broker.reap(owner, record.token);
    fake.fail_send = false;
    record = try broker.offer(owner, 2, 17, 1, &fake);
    _ = try broker.accept(owner, record.token, 17, 1, &fake);
    const reply = support.answer(record);
    fake.partial_settle = true;
    try testing.expectError(core.Error.cleanup, broker.deliver(&reply, &fake));
    try testing.expectEqual(core.State.failed, record.state);
    try testing.expectEqual(core.Reason.lifecycle, record.reason);
    try testing.expectEqual(@as(u8, 1), record.backing_slots);
    try testing.expectEqual(@as(u8, 0), record.backing_pages);
    try testing.expect(!record.verified);
    try testing.expect(broker.conserved(fake.domain().?));
    try testing.expectError(core.Error.not_terminal, broker.reap(owner, record.token));
    fake.partial_settle = false;
    _ = try broker.cancel(owner, record.token, &fake);
    try testing.expectEqual(core.State.failed, record.state);
    try testing.expectEqual(@as(u8, 0), record.backing_slots);
    try testing.expectEqual(@as(u8, 2), record.cleanup_attempts);
    try broker.reap(owner, record.token);
}
test "duplicate backing seam cannot destroy or double back a different obligation" {
    var broker = core.Broker.init(issuer, owner);
    var fake: support.Fake = .{};
    const first = try broker.offer(owner, 1, 17, 1, &fake);
    const saved = first.*;
    fake.alias_create = true;
    try testing.expectError(core.Error.resource, broker.offer(owner, 2, 31, 1, &fake));
    try testing.expectEqual(saved, first.*);
    try testing.expectEqual(@as(u64, 0), fake.settle_calls);
    try testing.expectEqual(core.State.free, broker.records[1].state);
    try testing.expect(broker.conserved(fake.domain().?));
}
test "finite lost worker reply expiry settles failed and fences all later deliveries" {
    var broker = core.Broker.init(issuer, owner);
    var fake: support.Fake = .{};
    const record = try broker.offer(owner, 1, 17, 1, &fake);
    _ = try broker.accept(owner, record.token, 17, 1, &fake);
    const delayed = support.answer(record);
    _ = try broker.expire(record.token, &fake);
    try testing.expectEqual(core.State.failed, record.state);
    try testing.expectEqual(core.Reason.transport, record.reason);
    try testing.expectError(core.Error.stale, broker.deliver(&delayed, &fake));
    try testing.expect(broker.conserved(fake.domain().?));
    try testing.expectEqual(@as(u64, 1), fake.send_calls);
}
test "unavailable offered running recovering worker fails without cancellation and preserves sibling" {
    for ([_]core.State{ .offered, .running, .recovering }) |phase| {
        var broker = core.Broker.init(issuer, owner);
        var fake: support.Fake = .{};
        const affected = try broker.offer(owner, 1, 17, 1, &fake);
        const sibling = try broker.offer(owner, 2, 31, 1, &fake);
        _ = try broker.accept(owner, sibling.token, 31, 1, &fake);
        const preserved = sibling.*;
        var late: abi.Message = undefined;
        if (phase != .offered) {
            _ = try broker.accept(owner, affected.token, 17, 1, &fake);
            late = support.answer(affected);
            if (phase == .recovering) _ = try broker.workerFault(affected.worker.endpoint, &fake);
        }
        _ = try broker.workerUnavailable(affected.token, &fake);
        try testing.expectEqual(core.State.failed, affected.state);
        try testing.expectEqual(core.Reason.lifecycle, affected.reason);
        try testing.expectEqual(@as(u8, 0), affected.backing_slots);
        try testing.expectEqual(@as(u8, 0), affected.backing_pages);
        try testing.expect(!affected.verified and affected.result == 0);
        try testing.expectEqual(preserved, sibling.*);
        if (phase != .offered) try testing.expectError(core.Error.stale, broker.deliver(&late, &fake));
        const settled = affected.*;
        _ = try broker.workerUnavailable(affected.token, &fake);
        _ = try broker.cancel(owner, affected.token, &fake);
        try testing.expectEqual(settled, affected.*);
        try testing.expectEqual(@as(u64, 1), fake.settle_calls);
        const reply = support.answer(sibling);
        _ = try broker.deliver(&reply, &fake);
        const completed = sibling.*;
        _ = try broker.workerUnavailable(sibling.token, &fake);
        try testing.expectEqual(completed, sibling.*);
        try testing.expectEqual(@as(u64, 2), fake.settle_calls);
        try testing.expect(broker.conserved(fake.domain().?));
        try broker.reap(owner, affected.token);
        try testing.expectError(core.Error.stale, broker.workerUnavailable(settled.token, &fake));
    }
}
test "production lifecycle reconciliation fences an already dequeued result before private consumption" {
    const dispatch = @import("contract_dispatch.zig");
    const transport = @import("contract_transport.zig");
    for ([_]u32{ 2, 1 }) |observed_phase| {
        var broker = core.Broker.init(issuer, owner);
        var fake: support.Fake = .{};
        var staged: transport.Replies = .{};
        const affected = try broker.offer(owner, 1, 17, 1, &fake);
        const sibling = try broker.offer(owner, 2, 31, 1, &fake);
        _ = try broker.accept(owner, affected.token, 17, 1, &fake);
        _ = try broker.accept(owner, sibling.token, 31, 1, &fake);
        const old_reply = support.answer(affected);
        const sibling_reply = support.answer(sibling);
        try testing.expectEqual(transport.Hold.accepted, staged.hold(&broker, old_reply));
        try testing.expectEqual(transport.Hold.accepted, staged.hold(&broker, sibling_reply));
        const original = affected.*;
        const sibling_before = sibling.*;
        var status: abi.CellStatus = std.mem.zeroes(abi.CellStatus);
        status.instance = original.worker.instance;
        status.control = original.worker.control;
        status.slot = original.worker.slot;
        status.parent_endpoint = broker.issuer;
        status.template_id = 4;
        status.depth = 2;
        status.own_pages = 2;
        status.phase = observed_phase;
        status.endpoint = if (observed_phase == 2) 0 else original.worker.endpoint + 0x100;
        status.generation = if (observed_phase == 2) original.worker.endpoint >> 8 else status.endpoint >> 8;
        _ = try dispatch.reconcile(&broker, affected.token, status, &fake);
        try testing.expectEqual(core.State.recovering, affected.state);
        try testing.expectEqual(sibling_before, sibling.*);
        try testing.expectEqual(@as(u64, 0), fake.settle_calls);
        var ready: [2]?abi.Message = .{ null, null };
        for (0..transport.delivery_windows + 1) |_| ready = staged.advance();
        const stale = ready[wire.tokenSlot(affected.token).?].?;
        try testing.expectError(core.Error.stale, broker.deliver(&stale, &fake));
        try testing.expectEqual(core.State.recovering, affected.state);
        try testing.expect(!affected.verified and affected.result == 0);
        try testing.expectEqual(@as(u64, 0), fake.validated_calls);
        try testing.expectEqual(@as(u64, 0), fake.settle_calls);
        try testing.expectEqual(sibling_before, sibling.*);
        const preserved = ready[wire.tokenSlot(sibling.token).?].?;
        _ = try broker.deliver(&preserved, &fake);
        try testing.expectEqual(core.State.completed, sibling.state);
        status.phase = 1;
        status.endpoint = original.worker.endpoint + 0x100;
        status.generation = status.endpoint >> 8;
        _ = try dispatch.reconcile(&broker, affected.token, status, &fake);
        try testing.expectEqual(core.State.running, affected.state);
        try testing.expectEqual(@as(u8, 2), affected.attempt);
        try testing.expect(affected.rpc != original.rpc and affected.execution != original.execution);
        try testing.expectError(core.Error.stale, broker.deliver(&old_reply, &fake));
        const fresh = support.answer(affected);
        _ = try broker.deliver(&fresh, &fake);
        try testing.expectEqual(core.State.completed, affected.state);
        try testing.expectEqual(@as(u64, 2), fake.validated_calls);
        try testing.expectEqual(@as(u64, 2), fake.settle_calls);
        try testing.expect(broker.conserved(fake.domain().?));
    }
}
test "retirement after candidate admission cannot publish a settled receipt and preserves sibling" {
    for ([_]bool{ false, true }) |restart| {
        var broker = core.Broker.init(issuer, owner);
        var fake: support.Fake = .{};
        const affected = try broker.offer(owner, 1, 17, 1, &fake);
        const sibling = try broker.offer(owner, 2, 31, 1, &fake);
        _ = try broker.accept(owner, affected.token, 17, 1, &fake);
        _ = try broker.accept(owner, sibling.token, 31, 1, &fake);
        const admitted_attempt = affected.*;
        const sibling_before = sibling.*;
        const candidate = support.answer(affected);
        if (restart) fake.restart_during_settle = true else fake.fault_during_settle = true;
        try testing.expectError(core.Error.stale, broker.deliver(&candidate, &fake));
        try testing.expectEqual(core.State.failed, affected.state);
        try testing.expectEqual(core.Reason.lifecycle, affected.reason);
        try testing.expect(!affected.verified and affected.result == 0);
        try testing.expectEqual(@as(u8, 0), affected.backing_slots);
        try testing.expectEqual(@as(u8, 0), affected.backing_pages);
        try testing.expectEqual(admitted_attempt.token, affected.token);
        try testing.expectEqual(admitted_attempt.rpc, affected.rpc);
        try testing.expectEqual(admitted_attempt.attempt, affected.attempt);
        try testing.expectEqual(admitted_attempt.execution, broker.snapshot(affected).endpoint);
        try testing.expectEqual(sibling_before, sibling.*);
        try testing.expectEqual(@as(u64, 1), fake.validated_calls);
        try testing.expectEqual(@as(u64, 1), fake.settle_calls);
        fake.restart_during_settle = false;
        fake.fault_during_settle = false;
        try testing.expectError(core.Error.stale, broker.deliver(&candidate, &fake));
        const sibling_reply = support.answer(sibling);
        _ = try broker.deliver(&sibling_reply, &fake);
        try testing.expectEqual(core.State.completed, sibling.state);
        try testing.expect(sibling.verified and broker.snapshot(sibling).valid());
        try testing.expect(broker.conserved(fake.domain().?));
        try testing.expectEqual(@as(u64, 2), fake.settle_calls);
    }
}
test "candidate admission failure and saturated fault count fail closed before receipt publication" {
    for ([_]bool{ false, true }) |saturated| {
        var broker = core.Broker.init(issuer, owner);
        var fake: support.Fake = .{};
        const record = try broker.offer(owner, 1, 17, 1, &fake);
        _ = try broker.accept(owner, record.token, 17, 1, &fake);
        const before = record.*;
        const candidate = support.answer(record);
        if (saturated) fake.saturated_faults = true else fake.admission_failure = true;
        try testing.expectError(core.Error.stale, broker.deliver(&candidate, &fake));
        try testing.expectEqual(core.State.failed, record.state);
        try testing.expectEqual(core.Reason.lifecycle, record.reason);
        try testing.expect(!record.verified and record.result == 0);
        try testing.expectEqual(before.execution, broker.snapshot(record).endpoint);
        try testing.expectEqual(@as(u64, 0), fake.validated_calls);
        try testing.expectEqual(@as(u64, 1), fake.settle_calls);
        try testing.expect(broker.conserved(fake.domain().?));
    }
}
test "cleanup attempts bounded failure retains honest resources after two failed checks" {
    var broker = core.Broker.init(issuer, owner);
    var fake: support.Fake = .{};
    const record = try broker.offer(owner, 1, 17, 1, &fake);
    fake.partial_settle = true;
    try testing.expectError(core.Error.cleanup, broker.cancel(owner, record.token, &fake));
    try testing.expectError(core.Error.cleanup, broker.cancel(owner, record.token, &fake));
    try testing.expectError(core.Error.cleanup, broker.cancel(owner, record.token, &fake));
    try testing.expectEqual(@as(u64, 2), fake.settle_calls);
    try testing.expectEqual(@as(u8, 1), record.backing_slots);
    try testing.expectEqual(@as(u8, 0), record.backing_pages);
    try testing.expect(!record.verified);
    try testing.expect(broker.conserved(fake.domain().?));
}
test "a seam claiming cleanup without actual refund cannot publish completed status" {
    var broker = core.Broker.init(issuer, owner);
    var fake: support.Fake = .{};
    const record = try broker.offer(owner, 1, 17, 1, &fake);
    _ = try broker.accept(owner, record.token, 17, 1, &fake);
    const reply = support.answer(record);
    fake.false_refund = true;
    try testing.expectError(core.Error.cleanup, broker.deliver(&reply, &fake));
    try testing.expectEqual(core.State.failed, record.state);
    try testing.expectEqual(@as(u8, 2), record.backing_pages);
    try testing.expect(!record.verified);
}
test "terminal retention explicit reap serial reuse requester and broker cold retirement" {
    var broker = core.Broker.init(issuer, owner);
    var fake: support.Fake = .{};
    const record = try broker.offer(owner, 1, 17, 1, &fake);
    const old = record.*;
    try testing.expectError(core.Error.not_terminal, broker.reap(owner, old.token));
    _ = try broker.cancel(owner, old.token, &fake);
    try testing.expectError(core.Error.denied, broker.reap(owner + 0x100, old.token));
    try broker.reap(owner, old.token);
    try testing.expectError(core.Error.stale, broker.reap(owner, old.token));
    const fresh = try broker.offer(owner, 2, 17, 1, &fake);
    try testing.expect(fresh.token != old.token);
    try testing.expectError(core.Error.stale, broker.status(owner, old.token));
    _ = try broker.cancel(owner, fresh.token, &fake);
    broker = core.Broker.init(issuer + 0x100, owner);
    const cold = try broker.offer(owner, 1, 17, 1, &fake);
    try testing.expect(cold.token != old.token);
    try testing.expectError(core.Error.stale, broker.status(owner, old.token));
    try testing.expectError(core.Error.denied, broker.status(owner + 0x100, cold.token));
    var different_broker = core.Broker.init(issuer + 1, owner);
    var unrelated_fake: support.Fake = .{};
    const different = try different_broker.offer(owner, 1, 17, 1, &unrelated_fake);
    try testing.expect(different.token != old.token);
    try testing.expectError(core.Error.stale, different_broker.status(owner, old.token));
}
test "all serial generation RPC and attempt boundaries fail closed without wrap" {
    var broker = core.Broker.init(issuer, owner);
    var fake: support.Fake = .{};
    broker.next_serial = wire.serial_limit;
    const record = try broker.offer(owner, 1, 17, 1, &fake);
    try testing.expectEqual(wire.serial_limit, wire.tokenSerial(record.token));
    try testing.expectError(core.Error.exhausted, broker.offer(owner, 2, 31, 1, &fake));
    broker.rpc_sequence.next = std.math.maxInt(u64);
    _ = try broker.accept(owner, record.token, 17, 1, &fake);
    try testing.expectEqual(std.math.maxInt(u64), record.rpc);
    const dispatched_endpoint = record.worker.endpoint;
    _ = try broker.workerFault(record.worker.endpoint, &fake);
    try testing.expectError(core.Error.exhausted, broker.retry(record.token, &fake));
    try testing.expectEqual(core.State.failed, record.state);
    try testing.expectEqual(core.Reason.counter_exhausted, record.reason);
    try testing.expect(record.worker.endpoint != dispatched_endpoint);
    try testing.expectEqual(dispatched_endpoint, broker.snapshot(record).endpoint);
    try testing.expectEqual(dispatched_endpoint, record.execution);
    try testing.expectEqual(@as(u64, 0), broker.rpc_sequence.next);
    var overflow = core.Broker.init((wire.generation_limit + 1) << 8 | 4, owner);
    try testing.expectError(core.Error.exhausted, overflow.offer(owner, 1, 17, 1, &fake));
    for ([_]u64{ 0x100, 0x109, 0x1ff }) |bad_issuer| {
        var bad = core.Broker.init(bad_issuer, owner);
        try testing.expectError(core.Error.invalid, bad.offer(owner, 1, 17, 1, &fake));
        try testing.expectEqual(@as(u64, 0), bad.offer_highwater);
        try testing.expectEqual(@as(u64, 1), bad.next_serial);
    }
}
test "snapshot collector checks completeness order full scopes contradictory claims and exact receipt" {
    var broker = core.Broker.init(issuer, owner);
    var fake: support.Fake = .{};
    const record = try broker.offer(owner, 1, 17, 1, &fake);
    _ = try broker.accept(owner, record.token, 17, 1, &fake);
    const reply = support.answer(record);
    _ = try broker.deliver(&reply, &fake);
    var messages = broker.snapshot(record).messages(19, .receipt);
    for (&messages) |*message| message.sender = issuer;
    var collector: wire.Collector = .{ .issuer = issuer, .requester = owner, .id = 19, .command = .receipt, .token = record.token };
    try testing.expect(!collector.push(&messages[1]));
    for (messages, 0..) |message, index| {
        try testing.expect(collector.push(&message));
        if (index < 7) try testing.expect(collector.take() == null);
    }
    try testing.expect(collector.take().?.verified);
    try testing.expect(!collector.push(&messages[0]));
    for (0..8) |part| {
        var altered = messages;
        altered[part].payload[24] ^= if (part == 0) 0x40 else 1;
        var contradiction: wire.Collector = .{ .issuer = issuer, .requester = owner, .id = 19, .command = .receipt, .token = record.token };
        for (altered) |message| try testing.expect(contradiction.push(&message));
        if (part == 0 or part == 1 or part == 2 or part == 3 or part == 7) try testing.expect(contradiction.take() == null);
    }
    for (57..64) |bit| {
        var altered = messages;
        wire.put64(&altered[0].payload, 24, wire.get64(&altered[0].payload, 24) | (@as(u64, 1) << @intCast(bit)));
        var contradiction: wire.Collector = .{ .issuer = issuer, .requester = owner, .id = 19, .command = .receipt, .token = record.token };
        for (altered) |message| try testing.expect(contradiction.push(&message));
        try testing.expect(contradiction.take() == null);
    }
}
test "many offer accept cancel fault settle and reap cycles conserve finite domain and monotone serial" {
    var broker = core.Broker.init(issuer, owner);
    var fake: support.Fake = .{};
    var previous: u64 = 0;
    for (1..1001) |id| {
        const record = try broker.offer(owner, id, @as(u64, @intCast(id)) *% 0x9e3779b97f4a7c15, 1, &fake);
        const token = record.token;
        try testing.expect(wire.tokenSerial(token) > previous);
        previous = wire.tokenSerial(token);
        if (id % 3 == 0) _ = try broker.cancel(owner, token, &fake) else {
            _ = try broker.accept(owner, token, record.input, 1, &fake);
            if (id % 3 == 1) {
                _ = try broker.workerFault(record.worker.endpoint, &fake);
                _ = try broker.retry(token, &fake);
            }
            const reply = support.answer(record);
            _ = try broker.deliver(&reply, &fake);
        }
        try testing.expect(broker.conserved(fake.domain().?));
        try testing.expectEqual(@as(u32, 0), fake.domain().?.owned_pages);
        try broker.reap(owner, token);
        try testing.expectError(core.Error.stale, broker.status(owner, token));
    }
}
test "worker accepts current authenticated bounded attempt only once and bootstrap is exact" {
    var worker: wire.Worker = .{ .parent = issuer };
    const token = wire.token(1, 0, issuer).?;
    var message = delivered(.{ .id = 1, .command = .work, .detail = 1, .token = token, .data = 17 }, issuer, wire.request_operation);
    try testing.expect(worker.accept(&message) != null);
    try testing.expect(worker.accept(&message) == null);
    message.sender += 0x100;
    try testing.expect(worker.accept(&message) == null);
    message.sender = issuer;
    wire.put64(&message.payload, 0, 2);
    wire.put64(&message.payload, 16, wire.token(1, 0, issuer + 1).?);
    try testing.expect(worker.accept(&message) == null);
    try testing.expectEqual(@as(u64, 1), worker.last_rpc);
    wire.put64(&message.payload, 16, token);
    wire.put64(&message.payload, 0, std.math.maxInt(u64));
    try testing.expect(worker.accept(&message) != null);
    try testing.expect(worker.accept(&message) == null);
    var bootstrap = delivered(.{ .id = 1, .command = .bootstrap, .kind = .response, .data = 0x140 }, 0x105, wire.reply_operation);
    try testing.expect(wire.decodeBootstrap(&bootstrap, 0x105, 0x140));
    try testing.expect(!wire.decodeBootstrap(&bootstrap, 0x205, 0x140));
    try testing.expect(wire.decodeRequest(&bootstrap, 0x105) == null);
    bootstrap.payload[11] = 1;
    try testing.expect(!wire.decodeBootstrap(&bootstrap, 0x105, 0x140));
}
