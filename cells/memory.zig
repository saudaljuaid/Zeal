// Freestanding compiler support for copies within a cell's private address space.
export fn memcpy(destination: [*]u8, source: [*]const u8, length: usize) callconv(.c) [*]u8 {
    const out: [*]volatile u8 = destination;
    const input: [*]const volatile u8 = source;
    for (0..length) |index| out[index] = input[index];
    return destination;
}
export fn memset(destination: [*]u8, value: c_int, length: usize) callconv(.c) [*]u8 {
    const out: [*]volatile u8 = destination;
    for (0..length) |index| out[index] = @truncate(@as(c_uint, @bitCast(value)));
    return destination;
}
