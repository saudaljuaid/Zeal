// Exact bounded service dispatch shared by the isolated broker and host cases.
// Lifecycle/transport callbacks are the same small seam used by Broker.
const abi = @import("abi.zig");
const core = @import("contract_core.zig");
const wire = core.wire;
pub const Dispatch = union(enum) {
    ignored: void,
    snapshot: struct { request: wire.Packet, value: wire.Snapshot, new_offer: bool = false },
    reaped: wire.Packet,
    failure: struct { request: wire.Packet, reason: core.Error },
};
fn rejected(packet: wire.Packet, reason: core.Error) Dispatch {
    return .{ .failure = .{ .request = packet, .reason = reason } };
}
pub fn failureCode(reason: core.Error) u64 {
    return switch (reason) {
        error.denied => 1,
        error.invalid => 2,
        error.stale => 3,
        error.no_space => 4,
        error.exhausted => 5,
        error.resource => 6,
        error.transport => 7,
        error.cleanup => 8,
        error.not_terminal => 9,
        error.not_ready => 10,
    };
}
pub fn attemptRetired(endpoint: u64, status: abi.CellStatus) bool {
    // An owner busy publishing a bounded snapshot may observe the restarted
    // execution after its brief BACKOFF interval has already elapsed.
    return status.phase == 2 or (status.phase == 1 and status.endpoint != endpoint);
}
pub fn backingReleased(worker: abi.CreateResult, status: abi.CellStatus) bool {
    // Kernel stop can retain an already quarantined terminal phase. Both
    // terminal forms are nonrunnable and reapable once their pages are gone.
    return (status.phase == 3 or status.phase == 4) and status.instance == worker.instance and
        status.control == worker.control and status.own_pages == 0 and
        status.reserved_slots == 0 and status.reserved_pages == 0;
}
pub fn admissionFence(worker: abi.CreateResult, status: abi.CellStatus, parent: u64) ?core.Fence {
    if (status.phase != 1 or status.instance != worker.instance or status.control != worker.control or
        status.endpoint != worker.endpoint or status.generation != worker.endpoint >> 8 or status.slot != worker.slot or
        status.parent_endpoint != parent or status.template_id != 4 or status.depth != 2 or status.own_pages != 2 or
        status.reserved_slots != 0 or status.reserved_pages != 0 or status.faults == 0xffffffff) return null;
    return .{ .generation = status.generation, .faults = status.faults, .restarts = status.restarts };
}
pub fn fenceStable(worker: abi.CreateResult, status: abi.CellStatus, fence: core.Fence) bool {
    return fence.faults != 0xffffffff and backingReleased(worker, status) and status.generation == fence.generation and
        status.faults == fence.faults and status.restarts == fence.restarts;
}
pub fn reconcile(table: *core.Broker, token: u64, status: abi.CellStatus, seam: anytype) core.Error!*const core.Record {
    return reconcileWorker(table, token, status, true, seam);
}
pub fn observe(table: *core.Broker, token: u64, status: abi.CellStatus, seam: anytype) core.Error!*const core.Record {
    // A dequeued owner command takes precedence over launching a fresh retry.
    return reconcileWorker(table, token, status, false, seam);
}
fn reconcileWorker(table: *core.Broker, token: u64, status: abi.CellStatus, allow_retry: bool, seam: anytype) core.Error!*const core.Record {
    const record = try table.status(table.requester, token);
    if (record.terminal()) return record;
    if (status.instance != record.worker.instance or status.control != record.worker.control or
        status.slot != record.worker.slot or status.parent_endpoint != table.issuer) return error.invalid;
    if (status.phase == 3 or status.phase == 4) return try table.workerUnavailable(token, seam);
    if (record.state == .running and attemptRetired(record.worker.endpoint, status))
        return try table.workerFault(record.worker.endpoint, seam);
    if (allow_retry and record.state == .recovering and status.phase == 1 and status.endpoint != record.worker.endpoint)
        return try table.retry(token, seam);
    return record;
}
pub fn dispatch(table: *core.Broker, message: *const abi.Message, seam: anytype) Dispatch {
    const envelope = wire.decode(message, table.requester, wire.request_operation) orelse return .{ .ignored = {} };
    const packet = wire.decodeRequest(message, table.requester) orelse return rejected(envelope, error.invalid);
    const sender = message.sender;
    if (packet.command == .reap) {
        table.reap(sender, packet.token) catch |reason| return rejected(packet, reason);
        return .{ .reaped = packet };
    }
    var new_offer = false;
    const record: *const core.Record = switch (packet.command) {
        .offer => blk: {
            const previous = table.next_serial;
            const offered = table.offer(sender, packet.id, packet.data, packet.detail, seam) catch |reason| return rejected(packet, reason);
            new_offer = table.next_serial != previous;
            break :blk offered;
        },
        .accept => table.accept(sender, packet.token, packet.data, packet.detail, seam) catch |reason| return rejected(packet, reason),
        .status => if (packet.token == 0)
            table.findOffer(sender, packet.data) catch |reason| return rejected(packet, reason)
        else
            table.status(sender, packet.token) catch |reason| return rejected(packet, reason),
        .receipt => blk: {
            const found = table.status(sender, packet.token) catch |reason| return rejected(packet, reason);
            if (!found.terminal()) return rejected(packet, error.not_terminal);
            break :blk found;
        },
        .cancel => table.cancel(sender, packet.token, seam) catch |reason| return rejected(packet, reason),
        .reap, .work, .fault, .bootstrap => unreachable,
    };
    return .{ .snapshot = .{ .request = packet, .value = table.snapshot(record), .new_offer = new_offer } };
}
