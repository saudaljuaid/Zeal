const abi = @import("abi.zig");

// Each successful partial write consumes at least one of the at most64 bytes.
// Eight total zero-progress attempts are allowed, with finite sleeps. Neither
// slow partial progress nor a permanently unavailable UART can spin forever.
pub fn writeBounded(bytes: []const u8, io: anytype) i32 {
    if (bytes.len > abi.console_limit) return @intFromEnum(abi.Error.too_large);
    var offset: usize = 0;
    var idle_attempts: usize = 0;
    for (0..abi.console_limit + 8) |_| {
        if (offset == bytes.len) return 0;
        const sent = io.send(bytes[offset..]);
        if (sent < 0) return @intCast(sent);
        if (sent > bytes.len - offset) return @intFromEnum(abi.Error.invalid);
        if (sent == 0) {
            idle_attempts += 1;
            if (idle_attempts == 8) return @intFromEnum(abi.Error.timeout);
            io.idle();
        } else offset += @intCast(sent);
    }
    return if (offset == bytes.len) 0 else @intFromEnum(abi.Error.timeout);
}
