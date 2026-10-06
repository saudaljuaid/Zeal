pub const image_base: usize = 0x40000000;
pub const image_size: usize = 0x10000;
pub const stack_base: usize = 0x40020000;
pub const stack_size: usize = 0x4000;
pub const memory_base: usize = 0x40030000;
pub const payload_size = 32;
pub const version = 3;
pub const operation_rights: u32 = 0x3fff;
pub const wait_max_ticks: u64 = 1000;
pub const delegate_right: u32 = 1 << 31;

pub const Role = enum(u32) { block, filesystem, client, probe };
pub const Call = enum(u64) { yield, send, recv, lookup, report, boot, exit, find, delegate, query, revoke, sleep, recv_wait };
pub const Error = enum(i64) {
    ok = 0,
    invalid = -1,
    denied = -2,
    stale = -3,
    again = -4,
    bad_address = -5,
    too_large = -6,
    no_space = -7,
    timeout = -8,
};
pub const Operation = enum(u32) {
    read = 1, read_reply, file_read, file_reply, cap_offer, cap_ack,
    block_read, block_write, block_reply, file_open,
    file_chunk_read, file_write, file_close, file_result,
};

pub fn right(operation: Operation) u32 {
    return @as(u32, 1) << @intCast(@intFromEnum(operation) - 1);
}

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

pub const DelegateRequest = extern struct {
    parent: u64,
    holder_endpoint: u64,
    rights: u32,
    reserved: u32 = 0,
};

pub const CapabilityInfo = extern struct {
    holder: u64,
    target: u64,
    rights: u32,
    reserved: u32,
    parent: u64,
};

comptime {
    if (version != 3 or @intFromEnum(Operation.file_result) != 14 or
        operation_rights != (right(.file_result) << 1) - 1)
        @compileError("storage operation ABI differs from include/zeal/abi.h");
    if (@intFromEnum(Call.sleep) != 11 or @intFromEnum(Call.recv_wait) != 12 or
        @intFromEnum(Error.timeout) != -8 or wait_max_ticks != 1000)
        @compileError("wait ABI differs from include/zeal/abi.h");
    if (@sizeOf(Message) != 48 or @offsetOf(Message, "payload") != 16)
        @compileError("message layout differs from include/zeal/abi.h");
    if (@sizeOf(BootInfo) != 24 or @offsetOf(BootInfo, "generation") != 8)
        @compileError("boot layout differs from include/zeal/abi.h");
    if (@sizeOf(DelegateRequest) != 24 or @offsetOf(DelegateRequest, "rights") != 16)
        @compileError("delegation layout differs from include/zeal/abi.h");
    if (@sizeOf(CapabilityInfo) != 32 or @offsetOf(CapabilityInfo, "parent") != 24)
        @compileError("capability layout differs from include/zeal/abi.h");
}
