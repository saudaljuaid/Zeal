const abi = @import("abi.zig");

pub fn raw(number: u64, arg0: u64, arg1: u64, arg2: u64) i64 {
    return asm volatile ("int $0x80"
        : [result] "={rax}" (-> i64),
        : [number] "{rax}" (number),
          [arg0] "{rdi}" (arg0),
          [arg1] "{rsi}" (arg1),
          [arg2] "{rdx}" (arg2),
        : .{ .memory = true });
}

pub fn yield() void {
    _ = raw(@intFromEnum(abi.Call.yield), 0, 0, 0);
}

pub fn send(endpoint: u64, message: *const abi.Message, capability: u64) i64 {
    return raw(@intFromEnum(abi.Call.send), endpoint, @intFromPtr(message), capability);
}

pub fn sendGranted(endpoint: u64, message: *const abi.Message, operation: abi.Operation) i64 {
    const capability = find(endpoint, abi.right(operation));
    if (capability <= 0) return capability;
    return send(endpoint, message, @intCast(capability));
}

pub fn receive(message: *abi.Message) i64 {
    return raw(@intFromEnum(abi.Call.recv), @intFromPtr(message), 0, 0);
}

pub fn sleep(duration: u64) i64 {
    return raw(@intFromEnum(abi.Call.sleep), duration, 0, 0);
}

pub fn receiveWait(message: *abi.Message, timeout: u64) i64 {
    return raw(@intFromEnum(abi.Call.recv_wait), @intFromPtr(message), timeout, 0);
}

pub fn lookup(role: abi.Role) u64 {
    // Only manifest roots have stable role-to-diagnostic routing. Runtime
    // endpoints come from creation/status results, even for identical images.
    if (@intFromEnum(role) >= 4) return 0;
    const result = raw(@intFromEnum(abi.Call.lookup), (@as(u64, @intFromEnum(role)) + 1) * 100, 0, 0);
    return if (result > 0) @intCast(result) else 0;
}

pub fn find(endpoint: u64, rights: u32) i64 {
    return raw(@intFromEnum(abi.Call.find), endpoint, rights, 0);
}

pub fn delegate(request: *const abi.DelegateRequest) i64 {
    return raw(@intFromEnum(abi.Call.delegate), @intFromPtr(request), 0, 0);
}

pub fn query(capability: u64, info: *abi.CapabilityInfo) i64 {
    return raw(@intFromEnum(abi.Call.query), capability, @intFromPtr(info), 0);
}

pub fn revoke(capability: u64) i64 {
    return raw(@intFromEnum(abi.Call.revoke), capability, 0, 0);
}

pub fn report(code: u64) void {
    reportValues(code, 0, 0);
}

pub fn reportValues(code: u64, value: u64, extra: u64) void {
    _ = raw(@intFromEnum(abi.Call.report), code, value, extra);
}

pub fn boot(info: *abi.BootInfo) i64 {
    return raw(@intFromEnum(abi.Call.boot), @intFromPtr(info), 0, 0);
}

pub fn consoleRead(bytes: []u8) i64 {
    return raw(@intFromEnum(abi.Call.console_read), @intFromPtr(bytes.ptr), bytes.len, 0);
}

pub fn consoleWrite(bytes: []const u8) i64 {
    return raw(@intFromEnum(abi.Call.console_write), @intFromPtr(bytes.ptr), bytes.len, 0);
}

pub fn systemInfo(info: *abi.SystemInfo) i64 {
    return raw(@intFromEnum(abi.Call.system_info), @intFromPtr(info), @sizeOf(abi.SystemInfo), 0);
}

pub fn create(request: *const abi.CreateRequest, result: *abi.CreateResult) i64 {
    return raw(@intFromEnum(abi.Call.create), @intFromPtr(request), @sizeOf(abi.CreateRequest), @intFromPtr(result));
}
pub fn status(control: u64, result: *abi.CellStatus) i64 {
    return raw(@intFromEnum(abi.Call.status), control, @intFromPtr(result), @sizeOf(abi.CellStatus));
}
pub fn stop(control: u64) i64 {
    return raw(@intFromEnum(abi.Call.stop), control, 0, 0);
}
pub fn reap(control: u64) i64 {
    return raw(@intFromEnum(abi.Call.reap), control, 0, 0);
}
pub fn rebind(request: *const abi.RebindRequest, result: *abi.CreateResult) i64 {
    return raw(@intFromEnum(abi.Call.rebind), @intFromPtr(request), @sizeOf(abi.RebindRequest), @intFromPtr(result));
}
pub fn creationRevoke(domain: u64) i64 {
    return raw(@intFromEnum(abi.Call.creation_revoke), domain, 0, 0);
}
pub fn domainStatus(domain: u64, result: *abi.DomainStatus) i64 {
    return raw(@intFromEnum(abi.Call.domain_status), domain, @intFromPtr(result), @sizeOf(abi.DomainStatus));
}

pub fn exit() noreturn {
    _ = raw(@intFromEnum(abi.Call.exit), 0, 0, 0);
    while (true) yield();
}
