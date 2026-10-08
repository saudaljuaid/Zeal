// Host sequence driver: invokes the production Broker after every action.
const std = @import("std");
const support = @import("contract_test_support.zig");
const core = support.core;
const wire = support.wire;
extern "c" fn printf(format: [*:0]const u8, ...) c_int;
const owner: u64 = 0x103;
fn report(broker: *const core.Broker, fake: *support.Fake, outcome: []const u8) void {
    const d = fake.domain().?;
    _ = printf("%.*s;%llu;%llu;%llu;%llu;%llu;%llu;%llu;%llu;%u;%u;%llu;%llu", @as(c_int, @intCast(outcome.len)), outcome.ptr,
        broker.next_serial, broker.offer_highwater, broker.rpc_sequence.next, fake.create_calls, fake.send_calls,
        fake.settle_calls, fake.rebind_calls, fake.validated_calls, d.owned_slots, d.owned_pages, broker.issuer, broker.requester);
    for (broker.records) |r| {
        if (r.state == .free) continue;
        _ = printf("|%llu,%llu,%llu,%u,%u,%u,%llu,%llu,%llu,%llu,%llu,%u,%u,%u,%u,%u,%llu,%u,%llu", r.token, r.offer_id, r.input,
            @as(c_uint, @intFromEnum(r.state)), @as(c_uint, r.retries), @as(c_uint, r.attempt), r.rpc,
            r.worker.instance, r.worker.control, r.worker.endpoint, r.worker.channel, r.worker.slot,
            @as(c_uint, r.backing_slots), @as(c_uint, r.backing_pages), @as(c_uint, @intFromEnum(r.reason)),
            @as(c_uint, @intFromBool(r.verified)), r.result, @as(c_uint, r.cleanup_attempts), broker.snapshot(&r).endpoint);
    }
    _ = printf("\n");
}
pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const arguments = try std.process.argsAlloc(allocator);
    if (arguments.len != 2) return error.Arguments;
    const source = try std.fs.cwd().readFileAlloc(allocator, arguments[1], 4 * 1024 * 1024);
    var requester: u64 = owner;
    var broker = core.Broker.init(0x104, requester);
    var fake: support.Fake = .{};
    var lines = std.mem.tokenizeScalar(u8, source, '\n');
    while (lines.next()) |line| {
        var parts = std.mem.tokenizeScalar(u8, line, ' ');
        const operation = parts.next().?[0];
        const a = try std.fmt.parseInt(u64, parts.next().?, 10);
        const b = try std.fmt.parseInt(u64, parts.next().?, 10);
        const c = try std.fmt.parseInt(u64, parts.next().?, 10);
        var outcome: []const u8 = "ok";
        switch (operation) {
            'O' => {
                fake.fail_create = c & 1 != 0;
                _ = broker.offer(if (c & 4 != 0) requester + 0x100 else requester, a, b, if (c & 2 != 0) 2 else 1, &fake) catch |err| { outcome = @errorName(err); };
                fake.fail_create = false;
            },
            'A' => {
                const input = if (broker.status(requester, a)) |record| record.input ^ b else |_| b;
                fake.fail_send = c & 2 != 0;
                _ = broker.accept(if (c & 1 != 0) requester + 0x100 else requester, a, input, 1, &fake) catch |err| { outcome = @errorName(err); };
                fake.fail_send = false;
            },
            'C' => { _ = broker.cancel(if (b != 0) requester + 0x100 else requester, a, &fake) catch |err| { outcome = @errorName(err); }; },
            'R' => { broker.reap(if (b != 0) requester + 0x100 else requester, a) catch |err| { outcome = @errorName(err); }; },
            'Q' => { _ = broker.status(if (b != 0) requester + 0x100 else requester, a) catch |err| { outcome = @errorName(err); }; },
            'L' => { _ = broker.findOffer(if (b != 0) requester + 0x100 else requester, a) catch |err| { outcome = @errorName(err); }; },
            'D' => {
                const record = broker.status(requester, a) catch |err| { outcome = @errorName(err); report(&broker, &fake, outcome); continue; };
                if (b == 5) outcome = "lost" else {
                    var reply = support.answer(record);
                    if (b == 1) reply.payload[24] ^= 1;
                    if (b == 2) reply.sender -= 0x100;
                    if (b == 3) reply.payload[11] = if (record.attempt == 1) 2 else 1;
                    if (b == 4) reply.payload[12] = 1;
                    _ = broker.deliver(&reply, &fake) catch |err| { outcome = @errorName(err); };
                }
            },
            'F' => {
                const record = broker.status(requester, a) catch |err| { outcome = @errorName(err); report(&broker, &fake, outcome); continue; };
                _ = broker.workerFault(record.worker.endpoint, &fake) catch |err| { outcome = @errorName(err); };
            },
            'T' => {
                fake.fail_rebind = b != 0;
                _ = broker.retry(a, &fake) catch |err| { outcome = @errorName(err); };
                fake.fail_rebind = false;
            },
            'E' => { _ = broker.expire(a, &fake) catch |err| { outcome = @errorName(err); }; },
            'U' => { _ = broker.workerUnavailable(a, &fake) catch |err| { outcome = @errorName(err); }; },
            'X' => { broker.next_serial = a; broker.rpc_sequence.next = b; },
            'Y' => { fake.partial_settle = a == 1; fake.false_refund = a == 2; },
            'V' => {
                fake.fault_during_settle = a == 1;
                fake.restart_during_settle = a == 2;
                fake.admission_failure = a == 3;
                fake.saturated_faults = a == 4;
            },
            'B' => {
                fake.partial_settle = false;
                fake.false_refund = false;
                fake.fault_during_settle = false;
                fake.restart_during_settle = false;
                fake.admission_failure = false;
                fake.saturated_faults = false;
                for (fake.objects) |object| if (object) |worker| {
                    if (!fake.settle(worker)) return error.RetirementCleanup;
                };
                if (b != 0) requester = b;
                broker = core.Broker.init(a, requester);
            },
            'G' => { _ = broker.accept(b, a, c, 1, &fake) catch |err| { outcome = @errorName(err); }; },
            else => return error.Operation,
        }
        if (!broker.conserved(fake.domain().?)) return error.Conservation;
        report(&broker, &fake, outcome);
    }
}
