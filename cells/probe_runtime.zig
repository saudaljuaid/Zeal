const abi = @import("abi.zig");
const syscall = @import("syscall.zig");

fn expect(result: i64, expected: abi.Error) void {
    if (result != @intFromEnum(expected)) {
        syscall.report(255);
        syscall.exit();
    }
}

fn addressChecks() noreturn {
    const bad_reads = [_]u64{ 0, 0x10000, abi.image_base + abi.image_size - 47, abi.stack_base + abi.stack_size - 47, 0xfffffffffffffff0 };
    for (bad_reads) |address| {
        expect(syscall.raw(@intFromEnum(abi.Call.send), 0, address, 0), .bad_address);
    }
    const bad_writes = [_]u64{ 0, 0x10000, abi.image_base, abi.stack_base - 1, abi.stack_base + abi.stack_size - 23, 0xfffffffffffffff0 };
    for (bad_writes) |address| {
        expect(syscall.raw(@intFromEnum(abi.Call.boot), address, 0, 0), .bad_address);
        expect(syscall.raw(@intFromEnum(abi.Call.recv), address, 0, 0), .bad_address);
    }
    expect(syscall.raw(99, 0, 0, 0), .invalid);
    expect(syscall.raw(@intFromEnum(abi.Call.lookup), 4, 0, 0), .invalid);
    syscall.report(2);
    syscall.exit();
}

fn capabilityChecks() noreturn {
    var message = abi.Message.empty(.file_read);
    message.sender = 0xffffffffffffffff;
    for (0..3) |slot| {
        const discovered = syscall.raw(@intFromEnum(abi.Call.lookup), (slot + 1) * 100, 0, 0);
        if (discovered <= 0) {
            syscall.report(255);
            syscall.exit();
        }
        expect(syscall.raw(@intFromEnum(abi.Call.find), @intCast(discovered),
            (@as(u64, 1) << 32) | abi.right(.file_read), 0), .invalid);
        const handle: u64 = (1 << 8) | (slot + 1);
        expect(syscall.find(handle, abi.right(.file_read)), .denied);
        expect(syscall.send(handle, &message, 0x101), .denied);
        expect(syscall.send(handle + (1 << 8), &message, 0x101), .stale);
    }
    expect(syscall.send(0, &message, 0), .invalid);
    expect(syscall.send(255, &message, 0), .invalid);
    syscall.report(2);
    syscall.exit();
}

fn waitChecks() noreturn {
    expect(syscall.sleep(0), .ok);
    expect(syscall.sleep(abi.wait_max_ticks + 1), .invalid);
    expect(syscall.sleep(0xffffffffffffffff), .invalid);
    var message = abi.Message.empty(.cap_offer);
    expect(syscall.receiveWait(&message, abi.wait_max_ticks + 1), .invalid);
    expect(syscall.raw(@intFromEnum(abi.Call.recv_wait), abi.image_base, 2, 0), .bad_address);
    expect(syscall.receiveWait(&message, 0), .again);
    const client = syscall.lookup(.client);
    if (client != 0) {
        expect(syscall.receiveWait(&message, 100), .ok);
        const value = @as(*align(1) const u64, @ptrCast(&message.payload)).*;
        if (message.sender != client or message.operation != @intFromEnum(abi.Operation.cap_offer) or
            message.length != 8 or value != 0x7a65616c77616b65) {
            syscall.report(255);
            syscall.exit();
        }
        syscall.reportValues(15, message.sender, value);
    }
    expect(syscall.receive(&message), .again);
    expect(syscall.receiveWait(&message, 0), .again);
    message.sender = 0x55aa55aa55aa55aa;
    expect(syscall.receiveWait(&message, 2), .timeout);
    if (message.sender != 0x55aa55aa55aa55aa) {
        syscall.report(255);
        syscall.exit();
    }
    expect(syscall.sleep(3), .ok);
    syscall.reportValues(16, 7, 3);
    syscall.exit();
}

pub fn run(scenario: u64) noreturn {
    switch (scenario) {
        0 => asm volatile ("ud2"),
        1 => {
            const pointer: *volatile u8 = @ptrFromInt(0x10000);
            pointer.* = 0x5a;
        },
        2 => {
            const pointer: *volatile u8 = @ptrFromInt(abi.image_base);
            pointer.* = 0x5a;
        },
        3 => {
            var code: [1]u8 = undefined;
            const pointer: *volatile u8 = &code[0];
            pointer.* = 0xc3;
            asm volatile ("call *%[target]"
                :
                : [target] "r" (@intFromPtr(&code)),
                : .{ .memory = true });
        },
        4 => asm volatile ("cli"),
        5 => asm volatile ("outb %%al, %%dx"
            :
            : [value] "{al}" (@as(u8, 0)),
              [port] "{dx}" (@as(u16, 0x80)),
        ),
        6 => while (true) asm volatile ("pause"),
        7 => addressChecks(),
        8 => capabilityChecks(),
        19 => waitChecks(),
        9 => {
            const pointer: *allowzero const volatile u8 = @ptrFromInt(0);
            _ = pointer.*;
        },
        10 => {
            const pointer: *volatile u64 = @ptrFromInt(abi.stack_base - 8);
            pointer.* = 0;
        },
        11 => {
            const pointer: *const volatile u8 = @ptrFromInt(abi.image_base + abi.image_size);
            _ = pointer.*;
        },
        12 => while (true) syscall.yield(),
        13 => asm volatile ("fninit"),
        14 => asm volatile ("pxor %xmm0, %xmm0"),
        15 => {
            var info: abi.BootInfo = undefined;
            asm volatile ("std" ::: .{ .memory = true });
            const result = syscall.boot(&info);
            const flags = asm volatile ("pushfq; popq %[flags]; cld"
                : [flags] "=r" (-> u64),
                :
                : .{ .memory = true });
            expect(result, .ok);
            if (flags & (1 << 10) == 0 or info.abi != abi.version or info.role != 3) {
                syscall.report(255);
                syscall.exit();
            }
            syscall.report(2);
            syscall.exit();
        },
        16 => {
            asm volatile ("movabs $0x0000800000000000, %rsp; int $0x80"
                :
                : [number] "{rax}" (@as(u64, 0)),
                : .{ .memory = true });
            unreachable;
        },
        17 => asm volatile ("syscall" ::: .{ .rcx = true, .r11 = true, .memory = true }),
        18 => asm volatile ("sysenter" ::: .{ .memory = true }),
        else => {},
    }
    syscall.report(255);
    syscall.exit();
}
