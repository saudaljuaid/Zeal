// Ring-3 console input, parsing, rendering and dispatch. No device access here.
const storage = @import("storage.zig");

pub const line_limit: usize = 96;
pub const prompt = "zeal> ";
pub const help_text =
    "help                 Show supported commands\n" ++
    "version              Show build and ABI identification\n" ++
    "info                 Show this cell and its boot resources\n" ++
    "ls                   List flat files, byte lengths and access\n" ++
    "write <path> [text]  Replace or create a writable file\n" ++
    "append <path> <text> Append to an existing writable file\n" ++
    "cat <path>           Read a flat absolute file path (2-16 bytes)\n";

pub const Event = union(enum) {
    none,
    echo: u8,
    erase,
    // The slice remains valid until the next push. Consume it synchronously.
    ready: []const u8,
    empty,
    overflow,
    invalid,
};

pub const LineEditor = struct {
    bytes: [line_limit]u8 = [_]u8{0} ** line_limit,
    length: usize = 0,
    fault: enum { none, overflow, invalid } = .none,
    skip_lf: bool = false,

    pub fn push(self: *LineEditor, byte: u8) Event {
        if (self.skip_lf) {
            self.skip_lf = false;
            if (byte == '\n') return .none;
        }
        if (byte == '\r' or byte == '\n') {
            self.skip_lf = byte == '\r';
            const length = self.length;
            const fault = self.fault;
            self.length = 0;
            self.fault = .none;
            return switch (fault) {
                .overflow => .overflow,
                .invalid => .invalid,
                .none => if (length == 0) .empty else .{ .ready = self.bytes[0..length] },
            };
        }
        // Once rejected, the whole line stays rejected even after backspace.
        if (self.fault != .none) return .none;
        if (byte == 8 or byte == 127) {
            if (self.length == 0) return .none;
            self.length -= 1;
            return .erase;
        }
        if (byte < 32 or byte > 126) {
            self.fault = .invalid;
            return .none;
        }
        if (self.length == line_limit) {
            self.fault = .overflow;
            return .none;
        }
        self.bytes[self.length] = byte;
        self.length += 1;
        return .{ .echo = byte };
    }
};

pub const Problem = enum {
    unknown_command,
    excessive_arguments,
    missing_path,
    write_usage,
    append_usage,
    malformed_path,
    invalid_input,
    line_overflow,
};

pub const Command = union(enum) {
    empty,
    help,
    version,
    info,
    ls,
    cat: []const u8,
    write: Payload,
    append: Payload,
    problem: Problem,
};

pub const Payload = struct { path: []const u8, text: []const u8 };

fn equal(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| if (left != right) return false;
    return true;
}

// The parser accepts spaces as separators, without quoting or expansion.
// The production editor excludes tabs and other controls before this seam.
pub fn parse(line: []const u8) Command {
    if (line.len > line_limit) return .{ .problem = .line_overflow };
    for (line) |byte| if (byte < 32 or byte > 126) return .{ .problem = .invalid_input };
    var at: usize = 0;
    while (at < line.len and line[at] == ' ') : (at += 1) {}
    if (at == line.len) return .empty;
    const start = at;
    while (at < line.len and line[at] != ' ') : (at += 1) {}
    const verb = line[start..at];
    while (at < line.len and line[at] == ' ') : (at += 1) {}
    const replacing = equal(verb, "write");
    const appending = equal(verb, "append");
    if (equal(verb, "cat") or replacing or appending) {
        if (at == line.len) return .{ .problem = if (replacing) .write_usage else if (appending) .append_usage else .missing_path };
        const path_start = at;
        while (at < line.len and line[at] != ' ') : (at += 1) {}
        const path = line[path_start..at];
        if (!storage.validName(path)) return .{ .problem = .malformed_path };
        if (replacing or appending) {
            if (appending and at == line.len) return .{ .problem = .append_usage };
            // Exactly one space separates path and payload. All remaining
            // spaces are bytes, including leading and trailing payload spaces.
            const payload: Payload = .{ .path = path, .text = if (at == line.len) "" else line[at + 1 ..] };
            return if (replacing) .{ .write = payload } else .{ .append = payload };
        }
        while (at < line.len and line[at] == ' ') : (at += 1) {}
        if (at != line.len) return .{ .problem = .excessive_arguments };
        return .{ .cat = path };
    }
    const command: Command = if (equal(verb, "help")) .help else if (equal(verb, "version")) .version else if (equal(verb, "info")) .info else if (equal(verb, "ls")) .ls else return .{ .problem = .unknown_command };
    if (at != line.len) return .{ .problem = .excessive_arguments };
    return command;
}

pub fn problemText(problem: Problem) []const u8 {
    return switch (problem) {
        .unknown_command => "error: unknown command; type help\n",
        .excessive_arguments => "error: too many arguments; type help for syntax\n",
        .missing_path => "error: usage: cat <path>\n",
        .write_usage => "error: usage: write <path> [text]\n",
        .append_usage => "error: usage: append <path> <text>\n",
        .malformed_path => "error: path must be / plus 1-15 ASCII letters, digits, _, - or .\n",
        .invalid_input => "error: unsupported input byte; command discarded\n",
        .line_overflow => "error: line too long (maximum 96 bytes); command discarded\n",
    };
}

// The real runtime and host tests supply the same bounded output/service seam.
// write performs terminal newline conversion; command services live in ring 3.
pub fn execute(line: []const u8, io: anytype) void {
    switch (parse(line)) {
        .empty => {},
        .help => io.write(help_text),
        .version => io.version(),
        .info => io.info(),
        .ls => io.list(),
        .cat => |path| io.cat(path),
        .write => |payload| io.replace(payload.path, payload.text),
        .append => |payload| io.append(payload.path, payload.text),
        .problem => |problem| io.write(problemText(problem)),
    }
}

pub const App = struct {
    editor: LineEditor = .{},

    pub fn start(_: *App, io: anytype) void {
        io.write(prompt);
    }

    // True means one line completed, including an empty or rejected line.
    pub fn consume(self: *App, byte: u8, io: anytype) bool {
        switch (self.editor.push(byte)) {
            .none => return false,
            .echo => |printable| {
                const output = [_]u8{printable};
                io.write(&output);
                return false;
            },
            .erase => {
                io.write("\x08 \x08");
                return false;
            },
            .ready => |line| {
                io.write("\n");
                execute(line, io);
            },
            .empty => io.write("\n"),
            .overflow => {
                io.write("\n");
                io.write(problemText(.line_overflow));
            },
            .invalid => {
                io.write("\n");
                io.write(problemText(.invalid_input));
            },
        }
        io.write(prompt);
        return true;
    }
};

// File bytes remain unchanged. LF is a terminal newline; backslash is doubled
// so escaped bytes are distinguishable from literal text. Every other control
// or non-ASCII byte is shown as \xHH, preventing terminal escape injection.
pub fn renderByte(byte: u8, scratch: *[4]u8) []const u8 {
    if (byte == '\n') return "\n";
    if (byte == '\\') return "\\\\";
    if (byte >= 32 and byte <= 126) {
        scratch[0] = byte;
        return scratch[0..1];
    }
    const hex = "0123456789ABCDEF";
    scratch.* = .{ '\\', 'x', hex[byte >> 4], hex[byte & 15] };
    return scratch;
}

pub fn renderFile(bytes: []const u8, io: anytype) void {
    var scratch: [4]u8 = undefined;
    for (bytes) |byte| io.write(renderByte(byte, &scratch));
}

pub fn errorText(status: i32) []const u8 {
    return switch (status) {
        -1 => "invalid request or path",
        -2 => "access denied",
        -3 => "stale handle or service generation changed",
        -4 => "filesystem service unavailable",
        -5 => "invalid user address",
        -6 => "file or transfer exceeds its limit",
        -7 => "filesystem files, handles or request identities exhausted",
        -8 => "filesystem service timeout",
        -9 => "file not found",
        else => "filesystem service failed",
    };
}

fn decimal(value: u32, io: anytype) void {
    var buffer: [10]u8 = undefined;
    var at = buffer.len;
    var remaining = value;
    while (true) {
        at -= 1;
        buffer[at] = @intCast('0' + remaining % 10);
        remaining /= 10;
        if (remaining == 0) break;
    }
    io.write(buffer[at..]);
}

pub fn renderEntry(name: []const u8, length: u32, readonly: bool, io: anytype) void {
    io.write(name);
    io.write(" ");
    decimal(length, io);
    io.write(if (readonly) " bytes read-only\n" else " bytes writable\n");
}

pub fn closeFailure(verb: []const u8, status: i32, io: anytype) void {
    if (status == 0) return;
    io.write(verb);
    io.write(": close: ");
    io.write(errorText(status));
    io.write(" (handle may remain open)\n");
}

pub fn unknownOpen(verb: []const u8, io: anytype) void {
    io.write(verb);
    io.write(": open result unknown; handle may remain open\n");
}

// The actual runtime and direct tests share these outcome words. A positive
// acknowledged prefix is not represented as a completed failed command.
pub fn mutationResult(verb: []const u8, name: []const u8, result: anytype, io: anytype) void {
    io.write(verb);
    io.write(": ");
    io.write(name);
    io.write(": ");
    if (result.status != 0) {
        io.write(errorText(result.status));
        io.write(" (");
    }
    decimal(result.length, io);
    io.write(" bytes acknowledged");
    if (result.status != 0) {
        io.write("; incomplete");
        if (result.changed) io.write("; file may have changed");
        if (result.unknown) io.write("; outcome unknown");
        io.write(")");
    }
    io.write("\n");
    if (result.open_unknown) unknownOpen(verb, io);
    closeFailure(verb, result.close_status, io);
}
