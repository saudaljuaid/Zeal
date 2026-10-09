const abi = @import("abi.zig");
const syscall = @import("syscall.zig");
const core = @import("console_core.zig");
const storage = @import("storage.zig");
const client = @import("console_storage.zig");
comptime {
    _ = @import("memory.zig");
}

const Io = struct {
    files: client.Client = .{},
    failed: bool = false,

    pub fn write(self: *Io, bytes: []const u8) void {
        // A local CRLF expansion buffer keeps every checked device call <=64.
        var buffer: [64]u8 = undefined;
        var used: usize = 0;
        for (bytes) |byte| {
            const need: usize = if (byte == '\n') 2 else 1;
            if (used + need > buffer.len) {
                self.flush(buffer[0..used]);
                used = 0;
            }
            if (byte == '\n') {
                buffer[used] = '\r';
                used += 1;
            }
            buffer[used] = byte;
            used += 1;
        }
        self.flush(buffer[0..used]);
    }
    fn flush(self: *Io, bytes: []const u8) void {
        if (self.failed) return;
        var output: OutputIo = .{};
        if (@import("console_output.zig").writeBounded(bytes, &output) != 0) self.failed = true;
    }
    fn number(self: *Io, value: u64, hexadecimal: bool) void {
        var buffer: [20]u8 = undefined;
        var at: usize = buffer.len;
        var remaining = value;
        const base: u64 = if (hexadecimal) 16 else 10;
        const digits = "0123456789abcdef";
        while (true) {
            at -= 1;
            buffer[at] = digits[@intCast(remaining % base)];
            remaining /= base;
            if (remaining == 0) break;
        }
        if (hexadecimal) self.write("0x");
        self.write(buffer[at..]);
    }
    fn field(self: *Io, label: []const u8, value: u64, hexadecimal: bool) void {
        self.write(label);
        self.number(value, hexadecimal);
    }
    fn system(information: *abi.SystemInfo) bool {
        return syscall.raw(@intFromEnum(abi.Call.system_info), @intFromPtr(information), @sizeOf(abi.SystemInfo), 0) == 0;
    }
    pub fn version(self: *Io) void {
        var information: abi.SystemInfo = undefined;
        if (!system(&information)) {
            self.write("version: system information unavailable\n");
            return;
        }
        var length: usize = 0;
        while (length < information.build_id.len and information.build_id[length] != 0) length += 1;
        self.write("Zeal build=");
        self.write(information.build_id[0..length]);
        self.field(" abi=", information.abi, false);
        self.write("\n");
    }
    pub fn info(self: *Io) void {
        var boot: abi.BootInfo = undefined;
        var information: abi.SystemInfo = undefined;
        if (syscall.boot(&boot) != 0 or !system(&information)) {
            self.write("info: system information unavailable\n");
            return;
        }
        self.field("identity=", boot.identity, false);
        self.field(" role=", boot.role, false);
        self.field(" generation=", boot.generation, false);
        self.field(" endpoint=", boot.endpoint, true);
        self.write("\n");
        self.field("live ticks=", information.ticks, false);
        self.field(" filesystem=", syscall.lookup(.filesystem), true);
        self.field(" block=", syscall.lookup(.block), true);
        self.write("\n");
        self.field("configured image=", information.image_budget, false);
        self.field(" stack=", information.stack_budget, false);
        self.field(" writable=", information.writable_budget, false);
        self.field(" console_io=", information.console_limit, false);
        self.field(" line=", core.line_limit, false);
        self.write("\n");
        self.field("boot parent=", boot.parent_endpoint, true);
        self.field(" depth=", boot.depth, false);
        self.field(" console=", information.console_entitled, false);
        self.field(" scenario=", boot.scenario, false);
        self.write("\n");
        self.field("boot instance=", boot.instance, true);
        self.field(" creation=", boot.creation, true);
        self.field(" parent_channel=", boot.parent_channel, true);
        self.field(" template=", boot.template_id, false);
        self.write("\n");
        self.write("global statistics: unavailable\n");
    }
    pub fn cat(self: *Io, name: []const u8) void {
        var bytes: [storage.file_size]u8 = undefined;
        var transport: FileIo = .{};
        const result = self.files.read(name, &bytes, &transport);
        if (result.status == 0) {
            core.renderFile(bytes[0..result.length], self);
            if (result.length == 0 or bytes[result.length - 1] != '\n') self.write("\n");
        } else {
            self.write("cat: ");
            self.write(name);
            self.write(": ");
            self.write(core.errorText(result.status));
            self.write("\n");
        }
        if (result.open_unknown) core.unknownOpen("cat", self);
        core.closeFailure("cat", result.close_status, self);
    }
    pub fn replace(self: *Io, name: []const u8, text: []const u8) void {
        var transport: FileIo = .{};
        const result = self.files.replace(name, text, &transport);
        core.mutationResult("write", name, result, self);
    }
    pub fn append(self: *Io, name: []const u8, text: []const u8) void {
        var transport: FileIo = .{};
        const result = self.files.append(name, text, &transport);
        core.mutationResult("append", name, result, self);
    }
    pub fn list(self: *Io) void {
        var transport: FileIo = .{};
        const result = self.files.list(&transport);
        if (result.status != 0) {
            self.write("ls: ");
            self.write(core.errorText(result.status));
            self.write("\n");
            return;
        }
        for (result.entries[0..result.length]) |entry|
            core.renderEntry(entry.name[0..entry.name_length], entry.length, entry.readonly, self);
    }
};

const OutputIo = struct {
    pub fn send(_: *OutputIo, bytes: []const u8) i64 {
        return syscall.raw(@intFromEnum(abi.Call.console_write), @intFromPtr(bytes.ptr), bytes.len, 0);
    }
    pub fn idle(_: *OutputIo) void {
        _ = syscall.sleep(1);
    }
};

const FileIo = struct {
    pub fn endpoint(_: *FileIo) u64 {
        return syscall.lookup(.filesystem);
    }
    pub fn send(_: *FileIo, endpoint_value: u64, message: *const abi.Message, operation: abi.Operation) i32 {
        return @intCast(syscall.sendGranted(endpoint_value, message, operation));
    }
    pub fn receive(_: *FileIo, message: *abi.Message, ticks: u64) i32 {
        return @intCast(syscall.receiveWait(message, ticks));
    }
    pub fn idle(_: *FileIo) void {
        _ = syscall.sleep(1);
    }
    pub fn chunk(_: *FileIo, id: u64, bytes: *const [8]u8) void {
        var word: u64 = 0;
        for (bytes, 0..) |byte, index| word |= @as(u64, byte) << @intCast(index * 8);
        syscall.reportValues(32, id, word);
    }
};

pub fn run() noreturn {
    var application: core.App = .{};
    var io: Io = .{};
    var boot: abi.BootInfo = undefined;
    if (syscall.boot(&boot) != 0) syscall.exit();
    if (boot.scenario == 27) {
        var boundary_buffer: [64]u8 = [_]u8{0} ** 64;
        for ([_]abi.Call{ .console_read, .console_write }) |call| {
            const address = @intFromPtr(&boundary_buffer);
            if (syscall.raw(@intFromEnum(call), 0, 1, 0) != @intFromEnum(abi.Error.bad_address) or
                syscall.raw(@intFromEnum(call), address, 65, 0) != @intFromEnum(abi.Error.too_large) or
                syscall.raw(@intFromEnum(call), address, 1, 1) != @intFromEnum(abi.Error.invalid))
            {
                syscall.report(255);
                syscall.exit();
            }
        }
    }
    application.start(&io);
    while (!io.failed) {
        var input: [64]u8 = undefined;
        const got = syscall.raw(@intFromEnum(abi.Call.console_read), @intFromPtr(&input), input.len, 0);
        if (got < 0 or got > input.len) {
            io.write("console: serial input failed\n");
            break;
        }
        for (input[0..@intCast(got)]) |byte| _ = application.consume(byte, &io);
        // Also sleep after continuous input: each turn consumes at most64 bytes.
        _ = syscall.sleep(1);
    }
    syscall.exit();
}

pub fn probe(scenario: u64) noreturn {
    var scratch: [1]u8 = .{0};
    const read_denied = syscall.raw(@intFromEnum(abi.Call.console_read), @intFromPtr(&scratch), 1, 0);
    const write_denied = syscall.raw(@intFromEnum(abi.Call.console_write), @intFromPtr(&scratch), 1, 0);
    if (read_denied != @intFromEnum(abi.Error.denied) or write_denied != @intFromEnum(abi.Error.denied)) {
        syscall.report(255);
        syscall.exit();
    }
    syscall.reportValues(111, 2, 0);
    var progress: u64 = 0;
    while (true) {
        _ = syscall.sleep(10);
        if (scenario == 27) syscall.reportValues(110, progress, 0);
        if (progress == 0xffffffffffffffff) syscall.exit();
        progress += 1;
    }
}
