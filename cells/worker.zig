export fn _start() linksection(".text.entry") callconv(.c) noreturn {
    var info: @import("abi.zig").BootInfo = undefined;
    if (@import("syscall.zig").boot(&info) != 0) @import("syscall.zig").exit();
    if (info.template_id == @import("contract_runtime.zig").worker_template)
        @import("contract_runtime.zig").worker();
    @import("hosting_runtime.zig").worker();
}
