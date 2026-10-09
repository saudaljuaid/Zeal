const std = @import("std");
const abi = @import("abi.zig");

pub fn main() !void {
    var buffer: [1024]u8 = undefined;
    const output = try std.fmt.bufPrint(&buffer,
        "{{\"read\":{d},\"write\":{d},\"system_info\":{d},\"limit\":{d},\"not_found\":{d},\"size\":{d},\"align\":{d},\"abi\":{d},\"console_limit\":{d},\"image_budget\":{d},\"stack_budget\":{d},\"writable_budget\":{d},\"console_entitled\":{d},\"ticks\":{d},\"build_id\":{d},\"build_id_size\":{d}}}\n",
        .{ @intFromEnum(abi.Call.console_read), @intFromEnum(abi.Call.console_write), @intFromEnum(abi.Call.system_info),
            abi.console_limit, @intFromEnum(abi.Error.not_found), @sizeOf(abi.SystemInfo), @alignOf(abi.SystemInfo),
            @offsetOf(abi.SystemInfo, "abi"), @offsetOf(abi.SystemInfo, "console_limit"),
            @offsetOf(abi.SystemInfo, "image_budget"), @offsetOf(abi.SystemInfo, "stack_budget"),
            @offsetOf(abi.SystemInfo, "writable_budget"), @offsetOf(abi.SystemInfo, "console_entitled"),
            @offsetOf(abi.SystemInfo, "ticks"), @offsetOf(abi.SystemInfo, "build_id"), abi.build_id_size });
    var at: usize = 0;
    while (at < output.len) at += try std.posix.write(1, output[at..]);
}
