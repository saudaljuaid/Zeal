const std = @import("std");
const testing = std.testing;
const core = @import("console_core.zig");
const output = @import("console_output.zig");

fn expectEvent(expected: std.meta.Tag(core.Event), actual: core.Event) !void {
    try testing.expectEqual(expected, std.meta.activeTag(actual));
}

fn typeLine(editor: *core.LineEditor, bytes: []const u8) void {
    for (bytes) |byte| _ = editor.push(byte);
}

fn expectProblem(line: []const u8, expected: core.Problem) !void {
    const command = core.parse(line);
    try testing.expect(command == .problem);
    try testing.expectEqual(expected, command.problem);
}

test "line editing covers printable ASCII both erase keys empty lines and exact limit" {
    var editor: core.LineEditor = .{};
    try expectEvent(.none, editor.push(8));
    try expectEvent(.none, editor.push(127));
    try expectEvent(.empty, editor.push('\n'));
    for (32..127) |byte| {
        const event = editor.push(@intCast(byte));
        try expectEvent(.echo, event);
        try testing.expectEqual(@as(u8, @intCast(byte)), event.echo);
    }
    try testing.expectEqual(@as(usize, 95), editor.length);
    try expectEvent(.erase, editor.push(8));
    try expectEvent(.erase, editor.push(127));
    try testing.expectEqual(@as(usize, 93), editor.length);
    try expectEvent(.echo, editor.push('x'));
    try expectEvent(.echo, editor.push('y'));
    try expectEvent(.echo, editor.push('z'));
    const event = editor.push('\n');
    try expectEvent(.ready, event);
    try testing.expectEqual(core.line_limit, event.ready.len);
    try testing.expectEqualStrings("xyz", event.ready[93..]);
    try testing.expectEqual(@as(usize, 0), editor.length);
    typeLine(&editor, "cat /hellp");
    try expectEvent(.erase, editor.push(8));
    _ = editor.push('o');
    try testing.expectEqualStrings("cat /hello", editor.push('\n').ready);
}

test "CRLF produces one completion while bare LF and CR independently complete" {
    var editor: core.LineEditor = .{};
    typeLine(&editor, "help");
    try testing.expectEqualStrings("help", editor.push('\r').ready);
    try expectEvent(.none, editor.push('\n'));
    try expectEvent(.empty, editor.push('\n'));
    typeLine(&editor, "version");
    try testing.expectEqualStrings("version", editor.push('\r').ready);
    // A non-LF after CR belongs to the next line and must not be swallowed.
    try expectEvent(.echo, editor.push('i'));
    typeLine(&editor, "nfo");
    try testing.expectEqualStrings("info", editor.push('\n').ready);
    try expectEvent(.empty, editor.push('\r'));
    try expectEvent(.empty, editor.push('\r'));
    try expectEvent(.none, editor.push('\n'));
}

test "overflow discards whole command after erase and recovers at next line" {
    var editor: core.LineEditor = .{};
    typeLine(&editor, "help");
    for (4..core.line_limit) |_| _ = editor.push(' ');
    try testing.expectEqual(core.line_limit, editor.length);
    try expectEvent(.none, editor.push('x'));
    for (0..core.line_limit + 4) |_| try expectEvent(.none, editor.push(8));
    typeLine(&editor, "cat /hello");
    try expectEvent(.overflow, editor.push('\r'));
    try expectEvent(.none, editor.push('\n'));
    typeLine(&editor, "info");
    try testing.expectEqualStrings("info", editor.push('\n').ready);
}

test "every unsupported byte rejects complete line until enter then recovers" {
    for (0..256) |value| {
        const byte: u8 = @intCast(value);
        if (byte == 8 or byte == 127 or byte == '\r' or byte == '\n' or (byte >= 32 and byte <= 126)) continue;
        var editor: core.LineEditor = .{};
        typeLine(&editor, "help");
        try expectEvent(.none, editor.push(byte));
        _ = editor.push(8);
        _ = editor.push(127);
        typeLine(&editor, "version");
        try expectEvent(.invalid, editor.push('\n'));
        typeLine(&editor, "cat /hello");
        try testing.expectEqualStrings("cat /hello", editor.push('\n').ready);
    }
}

test "parser accepts exactly implemented verbs and flat path contract" {
    try testing.expect(core.parse("") == .empty);
    try testing.expect(core.parse("   ") == .empty);
    try testing.expect(core.parse("help") == .help);
    try testing.expect(core.parse("  version  ") == .version);
    try testing.expect(core.parse(" info ") == .info);
    try testing.expect(core.parse("  ls  ") == .ls);
    const command = core.parse("  cat  /hello  ");
    try testing.expect(command == .cat);
    try testing.expectEqualStrings("/hello", command.cat);
    for ([_][]const u8{ "/x", "/A_a-z.09", "/123456789012345" }) |path| {
        var line: [32]u8 = undefined;
        @memcpy(line[0..4], "cat ");
        @memcpy(line[4..][0..path.len], path);
        try testing.expect(core.parse(line[0 .. 4 + path.len]) == .cat);
    }
}

test "malformed commands controls excessive arguments and invalid paths never dispatch" {
    for ([_][]const u8{ "help x", "version x", "info x", "ls /hello", "cat /hello x", "cat /hello x y" }) |line| try expectProblem(line, .excessive_arguments);
    for ([_][]const u8{ "cat", "cat  " }) |line| try expectProblem(line, .missing_path);
    for ([_][]const u8{ "cat hello", "cat /", "cat /a/b", "cat /1234567890123456", "cat '/hello'", "cat /he;lo", "cat /he\\lo" }) |line| try expectProblem(line, .malformed_path);
    for ([_][]const u8{ "Help", "unknown", "help;version" }) |line| try expectProblem(line, .unknown_command);
    for ([_][]const u8{ "help\t", "help\x00", "cat /hello\x1b", "help\xff" }) |line| try expectProblem(line, .invalid_input);
    const too_long = [_]u8{' '} ** (core.line_limit + 1);
    try expectProblem(&too_long, .line_overflow);
}

const Seam = struct {
    output: [8192]u8 = [_]u8{0} ** 8192,
    length: usize = 0,
    version_calls: usize = 0,
    info_calls: usize = 0,
    cat_calls: usize = 0,
    list_calls: usize = 0,
    replace_calls: usize = 0,
    append_calls: usize = 0,
    path: [16]u8 = [_]u8{0} ** 16,
    path_length: usize = 0,
    payload: [core.line_limit]u8 = [_]u8{0} ** core.line_limit,
    payload_length: usize = 0,

    pub fn write(self: *Seam, bytes: []const u8) void {
        std.debug.assert(self.length + bytes.len <= self.output.len);
        @memcpy(self.output[self.length..][0..bytes.len], bytes);
        self.length += bytes.len;
    }
    pub fn version(self: *Seam) void {
        self.version_calls += 1;
        self.write("actual version seam\n");
    }
    pub fn info(self: *Seam) void {
        self.info_calls += 1;
        self.write("actual info seam\n");
    }
    pub fn cat(self: *Seam, path: []const u8) void {
        self.cat_calls += 1;
        @memcpy(self.path[0..path.len], path);
        self.path_length = path.len;
        self.write("file service seam\n");
    }
    pub fn list(self: *Seam) void {
        self.list_calls += 1;
        self.write("actual file metadata seam\n");
    }
    fn capture(self: *Seam, path: []const u8, payload: []const u8) void {
        @memcpy(self.path[0..path.len], path);
        self.path_length = path.len;
        @memcpy(self.payload[0..payload.len], payload);
        self.payload_length = payload.len;
    }
    pub fn replace(self: *Seam, path: []const u8, payload: []const u8) void {
        self.replace_calls += 1;
        self.capture(path, payload);
        self.write("replacement service seam\n");
    }
    pub fn append(self: *Seam, path: []const u8, payload: []const u8) void {
        self.append_calls += 1;
        self.capture(path, payload);
        self.write("append service seam\n");
    }
    fn text(self: *const Seam) []const u8 {
        return self.output[0..self.length];
    }
};

fn feed(app: *core.App, seam: *Seam, bytes: []const u8) usize {
    var completed: usize = 0;
    for (bytes) |byte| if (app.consume(byte, seam)) {
        completed += 1;
    };
    return completed;
}

test "production dispatcher invokes exact service seam and invalid commands invoke none" {
    var seam: Seam = .{};
    core.execute("help", &seam);
    try testing.expectEqualStrings(core.help_text, seam.text());
    core.execute("version", &seam);
    core.execute("info", &seam);
    core.execute("cat /hello", &seam);
    try testing.expectEqual(@as(usize, 1), seam.version_calls);
    try testing.expectEqual(@as(usize, 1), seam.info_calls);
    try testing.expectEqual(@as(usize, 1), seam.cat_calls);
    try testing.expectEqualStrings("/hello", seam.path[0..seam.path_length]);
    for ([_][]const u8{ "", " ", "help x", "version extra", "info x", "cat", "cat /a/b", "cat /hello other", "unknown", "cat /hello\xff" }) |line| core.execute(line, &seam);
    try testing.expectEqual(@as(usize, 1), seam.version_calls);
    try testing.expectEqual(@as(usize, 1), seam.info_calls);
    try testing.expectEqual(@as(usize, 1), seam.cat_calls);
}

test "production app plain prompt editing CRLF multi-command dispatch and recovery" {
    var app: core.App = .{};
    var seam: Seam = .{};
    app.start(&seam);
    try testing.expectEqualStrings("zeal> ", seam.text());
    try testing.expectEqual(@as(usize, 1), feed(&app, &seam, "cat /hellp\x08o\r\n"));
    try testing.expectEqualStrings("zeal> cat /hellp\x08 \x08o\nfile service seam\nzeal> ", seam.text());
    try testing.expectEqualStrings("/hello", seam.path[0..seam.path_length]);
    try testing.expectEqual(@as(usize, 4), feed(&app, &seam, "version\ninfo\rhelp\r\n\n"));
    try testing.expectEqual(@as(usize, 1), seam.version_calls);
    try testing.expectEqual(@as(usize, 1), seam.info_calls);
    try testing.expectEqual(@as(usize, 1), seam.cat_calls);
    try testing.expect(std.mem.endsWith(u8, seam.text(), "zeal> \nzeal> "));
    try testing.expectEqual(@as(usize, 2), feed(&app, &seam, "cat /hello\x1b[31m\x7f\nversion\n"));
    try testing.expectEqual(@as(usize, 1), seam.cat_calls);
    try testing.expectEqual(@as(usize, 2), seam.version_calls);
    try testing.expect(std.mem.indexOf(u8, seam.text(), core.problemText(.invalid_input)) != null);
    _ = feed(&app, &seam, "help");
    for (4..core.line_limit + 1) |_| _ = feed(&app, &seam, " ");
    _ = feed(&app, &seam, "\x08\x7fcat /hello\ninfo\n");
    try testing.expectEqual(@as(usize, 1), seam.cat_calls);
    try testing.expectEqual(@as(usize, 2), seam.info_calls);
    try testing.expect(std.mem.indexOf(u8, seam.text(), core.problemText(.line_overflow)) != null);
    try testing.expect(std.mem.endsWith(u8, seam.text(), "actual info seam\nzeal> "));
}

test "file rendering covers all bytes without emitting unsafe controls and preserves source" {
    var source: [256]u8 = undefined;
    for (&source, 0..) |*byte, value| byte.* = @intCast(value);
    const before = source;
    var seam: Seam = .{};
    core.renderFile(&source, &seam);
    try testing.expectEqualSlices(u8, &before, &source);
    for (seam.text()) |byte| try testing.expect(byte == '\n' or (byte >= 32 and byte <= 126));
    try testing.expect(std.mem.indexOf(u8, seam.text(), "\\x00") != null);
    try testing.expect(std.mem.indexOf(u8, seam.text(), "\\x1B") != null);
    try testing.expect(std.mem.indexOf(u8, seam.text(), "\\xFF") != null);
    var scratch: [4]u8 = undefined;
    try testing.expectEqualStrings("\\x09", core.renderByte('\t', &scratch));
    try testing.expectEqualStrings("\\x0D", core.renderByte('\r', &scratch));
    try testing.expectEqualStrings("\n", core.renderByte('\n', &scratch));
    try testing.expectEqualStrings("\\\\", core.renderByte('\\', &scratch));
    try testing.expectEqualStrings("A", core.renderByte('A', &scratch));
    var exact: Seam = .{};
    core.renderFile("a\\x1B\x1b\n\x00\xff", &exact);
    try testing.expectEqualStrings("a\\\\x1B\\x1B\n\\x00\\xFF", exact.text());
}

test "write and append preserve every byte after one payload separator including spaces" {
    for ([_]struct { line: []const u8, expected: []const u8 }{
        .{ .line = "write /note", .expected = "" },
        .{ .line = "write /note ", .expected = "" },
        .{ .line = "write /note  ", .expected = " " },
        .{ .line = "  write   /note   Hello  Zeal  ", .expected = "  Hello  Zeal  " },
        .{ .line = "write /note \\\"$x *\\\\", .expected = "\\\"$x *\\\\" },
    }) |case| {
        const parsed = core.parse(case.line);
        try testing.expect(parsed == .write);
        try testing.expectEqualStrings("/note", parsed.write.path);
        try testing.expectEqualStrings(case.expected, parsed.write.text);
    }
    for ([_]struct { line: []const u8, expected: []const u8 }{
        .{ .line = "append /note ", .expected = "" },
        .{ .line = "append /note   ! ", .expected = "  ! " },
    }) |case| {
        const parsed = core.parse(case.line);
        try testing.expect(parsed == .append);
        try testing.expectEqualStrings("/note", parsed.append.path);
        try testing.expectEqualStrings(case.expected, parsed.append.text);
    }
    for ([_][]const u8{ "write", "  write  " }) |line| try expectProblem(line, .write_usage);
    for ([_][]const u8{ "append", "append ", "append /note" }) |line| try expectProblem(line, .append_usage);
    for ([_][]const u8{ "write missing text", "append /a/b text", "write /1234567890123456 data" }) |line| try expectProblem(line, .malformed_path);
}

test "actual dispatcher and editor invoke new operations while rejecting overflow prefixes" {
    var app: core.App = .{};
    var seam: Seam = .{};
    app.start(&seam);
    try testing.expectEqual(@as(usize, 4), feed(&app, &seam, "ls\nwrite /note Hello  Zeal \r\nappend /note !\nwrite /note\n"));
    try testing.expectEqual(@as(usize, 1), seam.list_calls);
    try testing.expectEqual(@as(usize, 2), seam.replace_calls);
    try testing.expectEqual(@as(usize, 1), seam.append_calls);
    try testing.expectEqual(@as(usize, 0), seam.payload_length);
    core.execute("write /note   preserved  ", &seam);
    try testing.expectEqualStrings("  preserved  ", seam.payload[0..seam.payload_length]);
    _ = feed(&app, &seam, "write /note ");
    for (12..core.line_limit + 1) |_| _ = feed(&app, &seam, "x");
    _ = feed(&app, &seam, "\x08\x7f\nappend /note\nls\n");
    try testing.expectEqual(@as(usize, 3), seam.replace_calls);
    try testing.expectEqual(@as(usize, 1), seam.append_calls);
    try testing.expectEqual(@as(usize, 2), seam.list_calls);
    try testing.expect(std.mem.indexOf(u8, seam.text(), core.problemText(.line_overflow)) != null);
    try testing.expect(std.mem.endsWith(u8, seam.text(), "actual file metadata seam\nzeal> "));
}

test "production outcome formatting distinguishes acknowledged prefix unknown open and close failure" {
    const Mutation = @import("console_storage.zig").MutationResult;
    var seam: Seam = .{};
    core.mutationResult("write", "/note", Mutation{ .length = 10 }, &seam);
    core.mutationResult("append", "/note", Mutation{ .status = -6 }, &seam);
    core.mutationResult("write", "/note", Mutation{ .status = -8, .length = 8, .changed = true, .unknown = true, .close_status = -3 }, &seam);
    core.mutationResult("write", "/new", Mutation{ .status = -8, .changed = true, .unknown = true, .open_unknown = true }, &seam);
    core.renderEntry("/hello", 14, true, &seam);
    core.renderEntry("/note", 128, false, &seam);
    try testing.expectEqualStrings(
        "write: /note: 10 bytes acknowledged\n" ++
            "append: /note: file or transfer exceeds its limit (0 bytes acknowledged; incomplete)\n" ++
            "write: /note: filesystem service timeout (8 bytes acknowledged; incomplete; file may have changed; outcome unknown)\n" ++
            "write: close: stale handle or service generation changed (handle may remain open)\n" ++
            "write: /new: filesystem service timeout (0 bytes acknowledged; incomplete; file may have changed; outcome unknown)\n" ++
            "write: open result unknown; handle may remain open\n" ++
            "/hello 14 bytes read-only\n/note 128 bytes writable\n",
        seam.text(),
    );
}

const OutputSeam = struct {
    bytes: [64]u8 = [_]u8{0} ** 64,
    length: usize = 0,
    calls: usize = 0,
    idles: usize = 0,
    plan: []const i64 = &.{},
    each: usize = 1,
    overcount: bool = false,

    pub fn send(self: *OutputSeam, bytes: []const u8) i64 {
        const index = self.calls;
        self.calls += 1;
        std.debug.assert(self.calls <= 72 and bytes.len > 0 and bytes.len <= 64);
        if (self.overcount) return @intCast(bytes.len + 1);
        const amount = if (index < self.plan.len) self.plan[index] else @as(i64, @intCast(@min(bytes.len, self.each)));
        if (amount > 0) {
            const count: usize = @intCast(amount);
            std.debug.assert(count <= bytes.len and self.length + count <= self.bytes.len);
            @memcpy(self.bytes[self.length..][0..count], bytes[0..count]);
            self.length += count;
        }
        return amount;
    }
    pub fn idle(self: *OutputSeam) void {
        self.idles += 1;
    }
};

test "production output accepts every one-byte partial write through full 64-byte checked slice" {
    var bytes: [64]u8 = undefined;
    for (&bytes, 0..) |*byte, index| byte.* = @intCast(index);
    const before = bytes;
    var io: OutputSeam = .{};
    try testing.expectEqual(@as(i32, 0), output.writeBounded(&bytes, &io));
    try testing.expectEqual(@as(usize, 64), io.calls);
    try testing.expectEqual(@as(usize, 0), io.idles);
    try testing.expectEqualSlices(u8, &bytes, &io.bytes);
    try testing.expectEqualSlices(u8, &before, &bytes);
}

test "production output keeps order across partial writes and seven total stalls with bounded sleeps" {
    var bytes: [64]u8 = undefined;
    for (&bytes, 0..) |*byte, index| byte.* = @intCast(255 - index);
    var io: OutputSeam = .{ .plan = &.{ 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1 } };
    try testing.expectEqual(@as(i32, 0), output.writeBounded(&bytes, &io));
    try testing.expectEqual(@as(usize, 71), io.calls);
    try testing.expectEqual(@as(usize, 7), io.idles);
    try testing.expectEqualSlices(u8, &bytes, &io.bytes);
    var wider: OutputSeam = .{ .each = 8, .plan = &.{ 3, 0, 2, 0, 5 } };
    try testing.expectEqual(@as(i32, 0), output.writeBounded(&bytes, &wider));
    try testing.expect(wider.calls <= 16 and wider.idles == 2);
    try testing.expectEqualSlices(u8, &bytes, &wider.bytes);
}

test "eight total output stalls timeout even when intervening writes make progress" {
    const bytes = [_]u8{'x'} ** 64;
    var busy: OutputSeam = .{ .plan = &.{ 0, 0, 0, 0, 0, 0, 0, 0 } };
    try testing.expectEqual(@as(i32, -8), output.writeBounded(&bytes, &busy));
    try testing.expectEqual(@as(usize, 8), busy.calls);
    try testing.expectEqual(@as(usize, 7), busy.idles);
    try testing.expectEqual(@as(usize, 0), busy.length);
    var progress: OutputSeam = .{ .plan = &.{ 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0 } };
    try testing.expectEqual(@as(i32, -8), output.writeBounded(&bytes, &progress));
    try testing.expectEqual(@as(usize, 15), progress.calls);
    try testing.expectEqual(@as(usize, 7), progress.idles);
    try testing.expectEqual(@as(usize, 7), progress.length);
}

test "output propagates negative errors rejects forged counts and guards empty oversized slices" {
    const bytes = [_]u8{'x'} ** 64;
    for ([_]i64{ -1, -2, -3, -4, -5, -6, -7, -8 }) |failure| {
        var io: OutputSeam = .{ .plan = &.{ 1, 1, failure } };
        try testing.expectEqual(@as(i32, @intCast(failure)), output.writeBounded(&bytes, &io));
        try testing.expectEqual(@as(usize, 3), io.calls);
        try testing.expectEqual(@as(usize, 2), io.length);
        try testing.expectEqual(@as(usize, 0), io.idles);
    }
    var forged: OutputSeam = .{ .overcount = true };
    try testing.expectEqual(@as(i32, -1), output.writeBounded(&bytes, &forged));
    try testing.expectEqual(@as(usize, 1), forged.calls);
    try testing.expectEqual(@as(usize, 0), forged.length);
    const oversized = [_]u8{'x'} ** 65;
    var guarded: OutputSeam = .{};
    try testing.expectEqual(@as(i32, -6), output.writeBounded(&oversized, &guarded));
    try testing.expectEqual(@as(usize, 0), guarded.calls);
    try testing.expectEqual(@as(i32, 0), output.writeBounded("", &guarded));
    try testing.expectEqual(@as(usize, 0), guarded.calls);
}
