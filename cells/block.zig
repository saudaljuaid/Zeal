export fn _start() linksection(".text.entry") callconv(.c) noreturn {
    @import("runtime.zig").run(.block);
}
