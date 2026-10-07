export fn _start() linksection(".text.entry") callconv(.c) noreturn {
    @import("hosting_runtime.zig").supervisor();
}
