pub const image_base: usize = 0x40000000;
pub const image_size: usize = 0x10000;
pub const stack_base: usize = 0x40020000;
pub const stack_size: usize = 0x4000;
pub const payload_size = 32;
pub const version = 1;

pub const Role = enum(u32) { block, filesystem, client, probe };
pub const Call = enum(u64) { yield, send, recv, lookup, report, boot, exit };
pub const Error = enum(i64) {
    ok = 0,
    invalid = -1,
    denied = -2,
    stale = -3,
    again = -4,
    bad_address = -5,
    too_large = -6,
};
pub const Operation = enum(u32) { read = 1, read_reply, file_read, file_reply };

pub const Message = extern struct {
    sender: u64,
    operation: u32,
    length: u32,
    payload: [payload_size]u8,

    pub fn empty(operation: Operation) Message {
        return .{
            .sender = 0,
            .operation = @intFromEnum(operation),
            .length = 0,
            .payload = [_]u8{0} ** payload_size,
        };
    }
};

pub const BootInfo = extern struct {
    abi: u32,
    role: u32,
    generation: u64,
    scenario: u64,
};

comptime {
    if (@sizeOf(Message) != 48 or @offsetOf(Message, "payload") != 16)
        @compileError("message layout differs from include/zeal/abi.h");
    if (@sizeOf(BootInfo) != 24 or @offsetOf(BootInfo, "generation") != 8)
        @compileError("boot layout differs from include/zeal/abi.h");
}
