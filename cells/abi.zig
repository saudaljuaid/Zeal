pub const image_base: usize = 0x40000000;
pub const image_size: usize = 0x10000;
pub const stack_base: usize = 0x40020000;
pub const stack_size: usize = 0x4000;
pub const memory_base: usize = 0x40030000;
pub const payload_size = 32;
pub const version = 4;
pub const operation_rights: u32 = 0xfffff;
pub const wait_max_ticks: u64 = 1000;
pub const delegate_right: u32 = 1 << 31;
pub const console_limit: usize = 64;
pub const build_id_size: usize = 48;

pub const Role = enum(u32) { block, filesystem, client, probe, supervisor, worker };
pub const Call = enum(u64) { yield, send, recv, lookup, report, boot, exit, find, delegate, query, revoke, sleep, recv_wait, create, status, stop, reap, rebind, creation_revoke, domain_status, console_read, console_write, system_info };
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
    not_found = -9,
};
pub const Operation = enum(u32) {
    read = 1,
    read_reply,
    file_read,
    file_reply,
    cap_offer,
    cap_ack,
    block_read,
    block_write,
    block_reply,
    file_open,
    file_chunk_read,
    file_write,
    file_close,
    file_result,
    hosting_request,
    hosting_reply,
    snapshot_control,
    snapshot_read,
    snapshot_reply,
    snapshot_release,
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
    endpoint: u64,
    parent_endpoint: u64,
    instance: u64,
    creation: u64,
    parent_channel: u64,
    template_id: u32,
    depth: u32,
    identity: u32,
    reserved: u32,
};

pub const SystemInfo = extern struct {
    abi: u32,
    console_limit: u32,
    image_budget: u32,
    stack_budget: u32,
    writable_budget: u32,
    console_entitled: u32,
    ticks: u64,
    build_id: [build_id_size]u8,
};

pub const instance_tag: u32 = 0x40;
pub const control_tag: u32 = 0x50;
pub const domain_tag: u32 = 0x60;
pub const host_query_right: u32 = 1;
pub const host_stop_right: u32 = 2;
pub const host_reap_right: u32 = 4;
pub const supervisor_template: u32 = 1;
pub const worker_template: u32 = 2;
pub const analysis_broker_template: u32 = 5;
pub const analysis_worker_template: u32 = 6;

pub const CreateRequest = extern struct {
    authority: u64,
    request: u64,
    template_id: u32,
    descendant_slots: u32 = 0,
    descendant_pages: u32 = 0,
    reserved: u32 = 0,
};
pub const CreateResult = extern struct {
    instance: u64,
    control: u64,
    endpoint: u64,
    channel: u64,
    creation: u64,
    slot: u32,
    identity: u32,
};
pub const RebindRequest = extern struct {
    authority: u64,
    control: u64,
    request: u64,
    reserved: u64 = 0,
};
pub const CellStatus = extern struct {
    instance: u64,
    control: u64,
    endpoint: u64,
    domain: u64,
    parent_instance: u64,
    parent_endpoint: u64,
    generation: u64,
    slot: u32,
    template_id: u32,
    depth: u32,
    phase: u32,
    faults: u32,
    restarts: u32,
    reason: u32,
    own_pages: u32,
    reserved_slots: u32,
    reserved_pages: u32,
    available_slots: u32,
    available_pages: u32,
};
pub const DomainStatus = extern struct {
    domain: u64,
    holder: u64,
    instance: u64,
    slot_limit: u32,
    page_limit: u32,
    owned_slots: u32,
    owned_pages: u32,
    reserved_slots: u32,
    reserved_pages: u32,
    available_slots: u32,
    available_pages: u32,
    max_depth: u32,
    template_mask: u32,
    recipe: u32,
    revoked: u32,
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
    if (@intFromEnum(Call.console_read) != 20 or @intFromEnum(Call.console_write) != 21 or
        @intFromEnum(Call.system_info) != 22 or @sizeOf(SystemInfo) != 80 or
        @alignOf(SystemInfo) != 8 or @offsetOf(SystemInfo, "ticks") != 24 or
        @offsetOf(SystemInfo, "build_id") != 32)
        @compileError("console additive ABI differs from include/zeal/abi.h");
    if (version != 4 or @intFromEnum(Operation.file_result) != 14 or
        @intFromEnum(Operation.hosting_reply) != 16 or
        @intFromEnum(Operation.snapshot_control) != 17 or
        @intFromEnum(Operation.snapshot_read) != 18 or
        @intFromEnum(Operation.snapshot_reply) != 19 or
        @intFromEnum(Operation.snapshot_release) != 20 or
        operation_rights != (right(.snapshot_release) << 1) - 1)
        @compileError("storage operation ABI differs from include/zeal/abi.h");
    if (@intFromEnum(Call.sleep) != 11 or @intFromEnum(Call.recv_wait) != 12 or
        @intFromEnum(Error.timeout) != -8 or wait_max_ticks != 1000)
        @compileError("wait ABI differs from include/zeal/abi.h");
    if (@sizeOf(Message) != 48 or @offsetOf(Message, "payload") != 16)
        @compileError("message layout differs from include/zeal/abi.h");
    if (@sizeOf(BootInfo) != 80 or @offsetOf(BootInfo, "generation") != 8 or @offsetOf(BootInfo, "template_id") != 64)
        @compileError("boot layout differs from include/zeal/abi.h");
    if (@sizeOf(CreateRequest) != 32 or @offsetOf(CreateRequest, "template_id") != 16 or
        @sizeOf(CreateResult) != 48 or @offsetOf(CreateResult, "slot") != 40 or
        @sizeOf(RebindRequest) != 32 or @offsetOf(RebindRequest, "request") != 16 or
        @sizeOf(CellStatus) != 104 or @offsetOf(CellStatus, "slot") != 56 or
        @sizeOf(DomainStatus) != 72 or @offsetOf(DomainStatus, "slot_limit") != 24 or
        @intFromEnum(Call.create) != 13 or @intFromEnum(Call.domain_status) != 19)
        @compileError("hosting layout differs from include/zeal/abi.h");
    if (@sizeOf(DelegateRequest) != 24 or @offsetOf(DelegateRequest, "rights") != 16)
        @compileError("delegation layout differs from include/zeal/abi.h");
    if (@sizeOf(CapabilityInfo) != 32 or @offsetOf(CapabilityInfo, "parent") != 24)
        @compileError("capability layout differs from include/zeal/abi.h");
}
