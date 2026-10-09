const std = @import("std");
const abi = @import("abi.zig");

pub fn main() !void {
    var buffer: [1024]u8 = undefined;
    const output = try std.fmt.bufPrint(&buffer,
        "{{\"list\":{d},\"truncate\":{d},\"list_right\":{d},\"truncate_right\":{d},\"size\":{d},\"align\":{d},\"request\":{d},\"index\":{d},\"metadata\":{d},\"name\":{d}}}\n",
        .{ @intFromEnum(abi.Operation.file_list), @intFromEnum(abi.Operation.file_truncate),
            abi.right(.file_list), abi.right(.file_truncate), @sizeOf(abi.FileEntryReply),
            @alignOf(abi.FileEntryReply), @offsetOf(abi.FileEntryReply, "request"),
            @offsetOf(abi.FileEntryReply, "index"), @offsetOf(abi.FileEntryReply, "metadata"),
            @offsetOf(abi.FileEntryReply, "name") });
    var offset: usize = 0;
    while (offset < output.len) offset += try std.posix.write(1, output[offset..]);
}
