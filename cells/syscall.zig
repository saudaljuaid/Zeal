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

pub fn send(handle: u64, message: *const abi.Message) i64 {
    return raw(@intFromEnum(abi.Call.send), handle, @intFromPtr(message), 0);
}

pub fn receive(message: *abi.Message) i64 {
    return raw(@intFromEnum(abi.Call.recv), @intFromPtr(message), 0, 0);
}

pub fn lookup(role: abi.Role) u64 {
    const result = raw(@intFromEnum(abi.Call.lookup), @intFromEnum(role), 0, 0);
    return if (result > 0) @intCast(result) else 0;
}

pub fn report(code: u64) void {
    _ = raw(@intFromEnum(abi.Call.report), code, 0, 0);
}

pub fn boot(info: *abi.BootInfo) i64 {
    return raw(@intFromEnum(abi.Call.boot), @intFromPtr(info), 0, 0);
}

pub fn exit() noreturn {
    _ = raw(@intFromEnum(abi.Call.exit), 0, 0, 0);
    while (true) yield();
}
