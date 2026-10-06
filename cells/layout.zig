const std = @import("std");
const abi = @import("abi.zig");

pub fn main() !void {
    var buffer: [2048]u8 = undefined;
    const output = try std.fmt.bufPrint(&buffer,
        "{{\"version\":{d},\"message_size\":{d},\"message_align\":{d},\"message_payload\":{d}," ++
        "\"boot_size\":{d},\"boot_generation\":{d},\"request_size\":{d},\"request_rights\":{d}," ++
        "\"info_size\":{d},\"info_parent\":{d},\"find\":{d},\"delegate\":{d},\"query\":{d},\"revoke\":{d}," ++
        "\"no_space\":{d},\"file_read_right\":{d},\"cap_ack_right\":{d},\"delegate_right\":{d}," ++
        "\"sleep\":{d},\"recv_wait\":{d},\"timeout\":{d},\"wait_max_ticks\":{d}," ++
        "\"operation_max\":{d},\"operation_rights\":{d},\"block_read_right\":{d},\"block_write_right\":{d}," ++
        "\"block_reply_right\":{d},\"file_open_right\":{d},\"file_chunk_read_right\":{d}," ++
        "\"file_write_right\":{d},\"file_close_right\":{d},\"file_result_right\":{d}}}\n",
        .{
            abi.version, @sizeOf(abi.Message), @alignOf(abi.Message), @offsetOf(abi.Message, "payload"),
            @sizeOf(abi.BootInfo), @offsetOf(abi.BootInfo, "generation"),
            @sizeOf(abi.DelegateRequest), @offsetOf(abi.DelegateRequest, "rights"),
            @sizeOf(abi.CapabilityInfo), @offsetOf(abi.CapabilityInfo, "parent"),
            @intFromEnum(abi.Call.find), @intFromEnum(abi.Call.delegate),
            @intFromEnum(abi.Call.query), @intFromEnum(abi.Call.revoke),
            @intFromEnum(abi.Error.no_space), abi.right(.file_read), abi.right(.cap_ack), abi.delegate_right,
            @intFromEnum(abi.Call.sleep), @intFromEnum(abi.Call.recv_wait),
            @intFromEnum(abi.Error.timeout), abi.wait_max_ticks,
            @intFromEnum(abi.Operation.file_result), abi.operation_rights,
            abi.right(.block_read), abi.right(.block_write), abi.right(.block_reply),
            abi.right(.file_open), abi.right(.file_chunk_read), abi.right(.file_write),
            abi.right(.file_close), abi.right(.file_result),
        });
    var offset: usize = 0;
    while (offset < output.len) offset += try std.posix.write(1, output[offset..]);
}
