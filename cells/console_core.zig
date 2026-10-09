// Ring-3 console input, parsing, rendering and dispatch. No device access here.
const storage = @import("storage.zig");

pub const line_limit: usize = 96;
pub const prompt = "zeal> ";
pub const help_text =
    "help                 Show supported commands\n" ++
    "version              Show build and ABI identification\n" ++
    "info                 Show this cell and its boot resources\n" ++
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
    malformed_path,
    invalid_input,
    line_overflow,
};

pub const Command = union(enum) {
    empty,
    help,
    version,
    info,
    cat: []const u8,
    problem: Problem,
};

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
    if (equal(verb, "cat")) {
        if (at == line.len) return .{ .problem = .missing_path };
        const path_start = at;
        while (at < line.len and line[at] != ' ') : (at += 1) {}
        const path = line[path_start..at];
        while (at < line.len and line[at] == ' ') : (at += 1) {}
        if (at != line.len) return .{ .problem = .excessive_arguments };
        if (!storage.validName(path)) return .{ .problem = .malformed_path };
        return .{ .cat = path };
    }
    const command: Command = if (equal(verb, "help")) .help else if (equal(verb, "version")) .version else if (equal(verb, "info")) .info else return .{ .problem = .unknown_command };
    if (at != line.len) return .{ .problem = .excessive_arguments };
    return command;
}

pub fn problemText(problem: Problem) []const u8 {
    return switch (problem) {
        .unknown_command => "error: unknown command; type help\n",
        .excessive_arguments => "error: too many arguments; type help for syntax\n",
        .missing_path => "error: usage: cat <path>\n",
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
        .cat => |path| io.cat(path),
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
