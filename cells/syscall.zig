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

pub fn exit() noreturn {
    _ = raw(@intFromEnum(abi.Call.exit), 0, 0, 0);
    while (true) yield();
}
