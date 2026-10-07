// Compile production application modules into one host-test artifact.
comptime {
    _ = @import("hosting_wire.zig");
    _ = @import("hosting_transport.zig");
    _ = @import("hosting_app.zig");
    _ = @import("hosting_storage.zig");
}
