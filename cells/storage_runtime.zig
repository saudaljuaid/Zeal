const abi = @import("abi.zig");
const wire = @import("storage_wire.zig");
const storage = @import("storage.zig");
const syscall = @import("syscall.zig");
const snapshot = @import("snapshot.zig");
const snapshot_wire = @import("snapshot_wire.zig");

const transport = @import("storage_transport.zig");
pub const Inbox = transport.Inbox;

fn outcome(code: u64, id: u64, operation: u32, result: i32) void {
    syscall.reportValues(code, id, (@as(u64, operation) << 32) | @as(u32, @bitCast(result)));
}

// Bounded retries apply only before enqueue. An enqueued write is never retransmitted here.
pub fn sendBounded(endpoint: u64, message: *const abi.Message, operation: abi.Operation) i32 {
    for (0..4) |_| {
        const result = syscall.sendGranted(endpoint, message, operation);
        if (result != @intFromEnum(abi.Error.again)) return @intCast(result);
        _ = syscall.sleep(1);
    }
    return @intFromEnum(abi.Error.timeout);
}

pub fn block() noreturn {
    const backing: *storage.Block = @ptrFromInt(abi.memory_base + 4096);
    backing.* = storage.Block.init();
    while (true) {
        var request: abi.Message = undefined;
        if (syscall.receiveWait(&request, 10) != 0) continue;
        const filesystem = syscall.lookup(.filesystem);
        if (filesystem == 0 or request.sender != filesystem) continue;
        if (@import("protocol.zig").validBlockRequest(&request, filesystem)) {
            var reply = abi.Message.empty(.read_reply);
            reply.length = storage.hello.len;
            @memcpy(reply.payload[0..storage.hello.len], backing.bytes[0..storage.hello.len]);
            _ = sendBounded(filesystem, &reply, .read_reply);
            continue;
        }
        const parsed = wire.decodeRequest(&request) orelse continue;
        var data = [_]u8{0} ** 8;
        const result = switch (request.operation) {
            @intFromEnum(abi.Operation.block_read) => backing.read(parsed.offset, @intCast(parsed.value), &data),
            @intFromEnum(abi.Operation.block_write) => backing.write(parsed.offset, parsed.data[0..@intCast(parsed.value)]),
            else => continue,
        };
        outcome(30, parsed.id, request.operation, result);
        var reply = wire.reply(.block_reply, parsed.id, 0, parsed.offset, result, if (request.operation == @intFromEnum(abi.Operation.block_read) and result > 0) data[0..@intCast(result)] else &.{});
        _ = sendBounded(filesystem, &reply, .block_reply);
    }
}

pub const Server = struct {
    fs: storage.Fs,
    snapshots: snapshot.Table,
    owner_endpoint: u64 = 0,
    // Trace proof cache only: cache full nonwrapping capability handles. A new
    // generation or same-endpoint route replacement needs a fresh query.
    queried_replies: [8]u64 = [_]u64{0} ** 8,
    sequence: wire.Sequence = .{},
    inbox: Inbox = .{},

    pub fn init(generation: u64) Server {
        // Compatibility constructor disables snapshot issuance until an exact
        // endpoint is supplied; runtime uses initAt with BootInfo.endpoint.
        return initAt(generation, 0);
    }
    pub fn initAt(generation: u64, endpoint: u64) Server {
        return .{ .fs = storage.Fs.init(generation), .snapshots = snapshot.Table.init(endpoint) };
    }
    pub fn rebind(self: *Server) void {
        _ = self.fs.rebindBlock(syscall.lookup(.block));
        self.snapshots.invalidateBlock(self.fs.block);
        self.rebindOwner(syscall.lookup(.probe));
    }
    pub fn rebindOwner(self: *Server, endpoint: u64) void {
        if (self.owner_endpoint == endpoint) return;
        _ = self.snapshots.retireOwner(self.owner_endpoint);
        self.owner_endpoint = endpoint;
    }

    fn transfer(self: *Server, app_id: u64, operation: abi.Operation, address: u32, count: u32, data: []const u8) ?wire.Header {
        var pending = transport.Request.init(&self.sequence, self.fs.block, .block_reply, 0, address, count, true) orelse return null;
        var request = wire.request(operation, pending.id, 0, address, count, data);
        syscall.reportValues(37, app_id, pending.id);
        while (pending.canSend()) {
            const result: i32 = @intCast(syscall.sendGranted(pending.endpoint, &request, operation));
            pending.sent(result);
            if (pending.canSend()) _ = syscall.sleep(1);
        }
        while (pending.canReceive()) {
            if (self.inbox.count == self.inbox.messages.len) {
                pending.cancel();
                break;
            }
            var message: abi.Message = undefined;
            const result: i32 = @intCast(syscall.receiveWait(&message, transport.receive_ticks));
            self.rebind();
            if (pending.received(self.fs.block, result, if (result == 0) &message else null)) |reply| return reply;
            // Late block replies cannot become client requests. Other dequeued traffic retains FIFO order.
            if (result == 0 and message.operation != @intFromEnum(abi.Operation.block_reply)) _ = self.inbox.push(message);
        }
        return null;
    }

    pub fn accepts(operation: u32) bool {
        return (operation >= @intFromEnum(abi.Operation.file_open) and operation <= @intFromEnum(abi.Operation.file_close)) or
            operation == @intFromEnum(abi.Operation.snapshot_control) or
            operation == @intFromEnum(abi.Operation.snapshot_read) or operation == @intFromEnum(abi.Operation.snapshot_release);
    }

    pub fn process(self: *Server, request: *const abi.Message) void {
        var io: KernelIo = .{};
        const reply_value = self.processWith(request, &io) orelse return;
        var reply = reply_value;
        if (reply.operation == @intFromEnum(abi.Operation.snapshot_reply) and !self.proveReplyRoute(request.sender)) return;
        _ = sendBounded(request.sender, &reply, if (reply.operation == @intFromEnum(abi.Operation.snapshot_reply)) .snapshot_reply else .file_result);
    }

    fn proveReplyRoute(self: *Server, endpoint: u64) bool {
        if (!snapshot.validEndpoint(endpoint)) return false;
        const slot: usize = @intCast((endpoint & 255) - 1);
        const found = syscall.find(endpoint, abi.right(.snapshot_reply));
        if (found <= 0) return false;
        const handle: u64 = @intCast(found);
        if (self.queried_replies[slot] == handle) return true;
        var information: abi.CapabilityInfo = undefined;
        if (syscall.query(@intCast(found), &information) != 0 or information.holder != self.snapshots.issuer or
            information.target != endpoint or information.parent != 0 or information.reserved != 0) return false;
        const expected = abi.right(.snapshot_reply) | (if (endpoint == self.owner_endpoint) abi.right(.file_result) else @as(u32, 0));
        if (information.rights != expected) return false;
        self.queried_replies[slot] = handle;
        return true;
    }

    // The same dispatcher runs in ring three and host tests. IO supplies only
    // dependency refresh, actual block transfers and tracing; it never supplies
    // captured fixture bytes. processWith is synchronous: queued client writes
    // remain in the bounded deferred inbox until the entire capture returns.
    pub fn processWith(self: *Server, request: *const abi.Message, io: anytype) ?abi.Message {
        io.refresh(self);
        if (request.operation == @intFromEnum(abi.Operation.snapshot_control)) return self.controlWith(request, io);
        if (request.operation == @intFromEnum(abi.Operation.snapshot_release)) {
            const parsed = snapshot_wire.decodeRelease(request) orelse return null;
            const result = self.snapshots.releaseBound(request.sender, parsed.reference, parsed.reader);
            io.report(31, parsed.transaction, request.operation, @intFromEnum(result));
            return snapshot_wire.readReply(parsed.transaction, parsed.reference, 0, @intFromEnum(result), &.{});
        }
        if (request.operation == @intFromEnum(abi.Operation.snapshot_read)) {
            const parsed = snapshot_wire.decodeRead(request) orelse return null;
            var bytes = [_]u8{0} ** 8;
            const result = self.snapshots.read(request.sender, parsed.reference, parsed.offset, parsed.count, &bytes);
            io.report(31, parsed.transaction, request.operation, result);
            return snapshot_wire.readReply(parsed.transaction, parsed.reference, parsed.offset, result, if (result > 0) bytes[0..@intCast(result)] else &.{});
        }
        var id: u64 = 0;
        var token: u64 = 0;
        var offset: u32 = 0;
        var result: i32 = @intFromEnum(storage.Status.invalid);
        var bytes = [_]u8{0} ** 8;
        var read_data = false;
        if (request.operation == @intFromEnum(abi.Operation.file_open)) {
            const open = wire.decodeOpen(request) orelse return null;
            id = open.id;
            const plan = self.fs.prepareOpen(request.sender, open.name);
            result = @intFromEnum(plan.status);
            if (plan.status == .ok) {
                var cleared = true;
                if (plan.needs_zero) {
                    var at: u32 = 0;
                    while (at < storage.file_size) : (at += storage.chunk_size) {
                        const answer = io.transfer(self, id, .block_write, plan.address + at, storage.chunk_size, &bytes);
                        if (answer == null or answer.?.value != storage.chunk_size) {
                            cleared = false;
                            break;
                        }
                    }
                }
                result = if (cleared) @intFromEnum(self.fs.commitOpen(plan)) else @intFromEnum(storage.Status.timeout);
                if (result == 0) token = plan.token;
            }
        } else {
            const parsed = wire.decodeRequest(request) orelse return null;
            id = parsed.id;
            token = parsed.handle;
            offset = parsed.offset;
            if (request.operation == @intFromEnum(abi.Operation.file_close)) {
                result = @intFromEnum(self.fs.close(request.sender, token));
            } else {
                const write = request.operation == @intFromEnum(abi.Operation.file_write);
                const plan = if (write) self.fs.prepareWrite(request.sender, token, offset, @intCast(parsed.value)) else self.fs.prepareRead(request.sender, token, offset, @intCast(parsed.value));
                result = @intFromEnum(plan.status);
                if (plan.status == .ok) {
                    const answer = io.transfer(self, id, if (write) .block_write else .block_read, plan.address, plan.count, if (write) parsed.data[0..plan.count] else &.{});
                    if (answer) |value| {
                        result = value.value;
                        if (result >= 0) {
                            if (write) {
                                const committed = self.fs.commitWrite(plan);
                                if (committed != .ok) result = @intFromEnum(committed);
                            } else {
                                bytes = value.data;
                                read_data = true;
                            }
                        }
                    } else result = @intFromEnum(storage.Status.timeout);
                }
            }
        }
        io.report(31, id, request.operation, result);
        return wire.reply(.file_result, id, token, offset, result, if (read_data and result > 0) bytes[0..@intCast(result)] else &.{});
    }

    fn controlWith(self: *Server, request: *const abi.Message, io: anytype) ?abi.Message {
        const parsed = snapshot_wire.decodeControl(request) orelse return null;
        // The approved owner is an exact current endpoint, located by the
        // configured root role. That location grants no IPC operation rights.
        // Deferred predecessor work cannot repopulate a retired owner table.
        if (self.owner_endpoint == 0 or request.sender != self.owner_endpoint)
            return snapshot_wire.controlReply(parsed.transaction, .{}, 0, 0, .denied, parsed.action, .empty);
        if (parsed.action == .inventory) {
            const summary: u64 = @as(u64, @intCast(self.snapshots.retained())) |
                (@as(u64, @intCast(self.snapshots.backing())) << 8) |
                (@as(u64, @intCast(self.snapshots.readerCount())) << 24);
            io.report(103, summary, 0, @intCast(self.snapshots.liveCount()));
            return snapshot_wire.controlReply(parsed.transaction, .{ .issuer = self.snapshots.issuer, .token = summary }, self.fs.block, @intCast(self.snapshots.liveCount()), .ok, .inventory, .empty);
        }
        if (parsed.action == .bind or parsed.action == .bind_check) {
            const ready = if (comptime @hasDecl(@typeInfo(@TypeOf(io)).pointer.child, "readerValid"))
                io.readerValid(self, parsed.peer)
            else
                @import("builtin").is_test and snapshot.validEndpoint(parsed.peer);
            if (!ready) return snapshot_wire.controlReply(parsed.transaction, .{}, 0, 0, .denied, parsed.action, .empty);
        }
        const reference: snapshot.Ref = .{ .issuer = self.snapshots.issuer, .token = parsed.subject };
        var result: storage.Status = .stale;
        var record: snapshot.Record = .{};
        if (parsed.action == .create) {
            const capture = self.snapshots.begin(&self.fs, request.sender, parsed.transaction, parsed.subject);
            result = capture.status;
            if (capture.fresh) {
                io.report(100, request.sender, @truncate(parsed.transaction >> 32), @bitCast(@as(u32, @truncate(parsed.transaction))));
                var offset: u32 = 0;
                while (offset < capture.length) {
                    const amount = @min(storage.chunk_size, @as(u32, capture.length) - offset);
                    const plan = self.fs.prepareRead(request.sender, parsed.subject, offset, amount);
                    if (plan.status != .ok or plan.count != amount) {
                        result = self.snapshots.fail(request.sender, capture.reference, .stale);
                        break;
                    }
                    const answer = io.transfer(self, parsed.transaction, .block_read, plan.address, amount, &.{});
                    io.refresh(self);
                    if (answer == null or answer.?.value != amount) {
                        const reason: storage.Status = if (self.fs.block != capture.block) .stale else .timeout;
                        // A dependency refresh may already mark it failed.
                        _ = self.snapshots.fail(request.sender, capture.reference, reason);
                        result = reason;
                        break;
                    }
                    result = self.snapshots.append(&self.fs, request.sender, capture.reference, offset, answer.?.data[0..amount]);
                    if (result != .ok) {
                        _ = self.snapshots.fail(request.sender, capture.reference, result);
                        break;
                    }
                    offset += amount;
                }
                if (result == .ok) result = self.snapshots.publish(&self.fs, request.sender, capture.reference);
                if (result == .ok) io.report(101, capture.reference.token, 0, capture.length);
            }
            if (self.snapshots.status(request.sender, parsed.transaction)) |found| record = found;
        } else if (parsed.action == .status) {
            if (self.snapshots.status(request.sender, parsed.subject)) |found| {
                record = found;
                result = if (found.state == .capturing) .again else found.last_status;
            }
        } else {
            result = switch (parsed.action) {
                .bind => self.snapshots.bind(request.sender, reference, parsed.peer),
                .bind_check => self.snapshots.bindChecker(request.sender, reference, parsed.peer),
                .revoke => self.snapshots.revoke(request.sender, reference, parsed.peer),
                .close => self.snapshots.close(request.sender, reference),
                .reap => self.snapshots.reap(request.sender, reference),
                else => unreachable,
            };
            if (self.snapshots.index(reference)) |slot| {
                if (self.snapshots.records[slot].owner == request.sender) record = self.snapshots.records[slot];
            }
        }
        io.report(31, parsed.transaction, request.operation, @intFromEnum(result));
        return snapshot_wire.controlReply(parsed.transaction, .{ .issuer = self.snapshots.issuer, .token = record.token }, record.block, record.length, result, parsed.action, record.state);
    }
};

const KernelIo = struct {
    pub fn refresh(_: *KernelIo, server: *Server) void {
        server.rebind();
    }
    pub fn transfer(_: *KernelIo, server: *Server, app_id: u64, operation: abi.Operation, address: u32, count: u32, data: []const u8) ?wire.Header {
        return server.transfer(app_id, operation, address, count, data);
    }
    pub fn report(_: *KernelIo, code: u64, id: u64, operation: u32, result: i32) void {
        outcome(code, id, operation, result);
    }
    pub fn readerValid(_: *KernelIo, server: *Server, endpoint: u64) bool {
        return server.proveReplyRoute(endpoint);
    }
};
