//! CLI parsing, validation dispatch, and output selection.
//!
//! Regular-file validation uses bounded stream input.

const std = @import("std");
const builtin = @import("builtin");
const diagnostic = @import("diagnostic.zig");
const output = @import("output.zig");
const validate = @import("validate.zig");
const version = @import("version.zig");

const DiagnosticSink = diagnostic.DiagnosticSink;

const Presentation = struct {
    is_tty: bool = false,
    auto_color: bool = false,
};

pub const ColorMode = enum {
    auto,
    always,
    never,
};

/// Parsed `check` subcommand flags and borrowed input path.
pub const CheckCommand = struct {
    output_mode: output.OutputMode = .text,
    skip_binary: bool = false,
    skip_index: bool = false,
    skip_semantic: bool = false,
    max_binary_size: ?usize = null,
    obo_path: ?[]const u8 = null,
    color_mode: ColorMode = .auto,
    input: []const u8,
};

/// Top-level CLI command after parsing.
pub const Command = union(enum) {
    check: CheckCommand,
};

const ParseError = error{
    MissingCommand,
    MissingInputPath,
    MultipleInputPaths,
    UnsupportedCommand,
    UnexpectedFlag,
    ConflictingOutputMode,
    MissingBinarySize,
    MissingOboPath,
    InvalidValue,
    MissingColorMode,
    InvalidColorMode,
    Overflow,
};

/// Parses process arguments, runs validation, flushes output, and returns the exit code.
pub fn run(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(gpa);
    defer gpa.free(args);

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_file_writer: std.Io.File.Writer = .init(.stdout(), init.io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;
    var stderr_buffer: [1024]u8 = undefined;
    var stderr_file_writer: std.Io.File.Writer = .init(.stderr(), init.io, &stderr_buffer);
    const stderr = &stderr_file_writer.interface;

    const stdout_file = std.Io.File.stdout();
    const is_tty = try fileIsTty(init.io, stdout_file);
    const no_color = if (init.environ_map.get("NO_COLOR")) |value| value.len > 0 else false;
    const force_color = if (init.environ_map.get("CLICOLOR_FORCE")) |value| value.len > 0 else false;
    const presentation = Presentation{
        .is_tty = is_tty,
        .auto_color = try autoColorEnabled(init.io, stdout_file, init.environ_map, is_tty, no_color, force_color),
    };
    const exit_code = runArgsWithPresentation(gpa, init.io, stdout, stderr, args, presentation) catch |err| {
        // Preserve the original failure; output after a failed run is best effort.
        flushWriters(stdout, stderr) catch {};
        return err;
    };
    try flushWriters(stdout, stderr);
    return exit_code;
}

fn flushWriters(stdout: *std.Io.Writer, stderr: *std.Io.Writer) std.Io.Writer.Error!void {
    var first_error: ?std.Io.Writer.Error = null;
    stdout.flush() catch |err| {
        first_error = err;
    };
    stderr.flush() catch |err| {
        if (first_error == null) first_error = err;
    };
    if (first_error) |err| return err;
}

fn fileIsTty(io: std.Io, file: std.Io.File) std.Io.Cancelable!bool {
    if (builtin.os.tag == .linux) {
        while (true) {
            var window_size: std.posix.winsize = undefined;
            const fd: usize = @bitCast(@as(isize, file.handle));
            const rc = std.os.linux.syscall3(
                .ioctl,
                fd,
                std.os.linux.T.IOCGWINSZ,
                @intFromPtr(&window_size),
            );
            switch (std.os.linux.errno(rc)) {
                .SUCCESS => return true,
                .INTR => continue,
                else => return false,
            }
        }
    }
    if (builtin.link_libc and builtin.os.tag != .windows) {
        return std.c.isatty(file.handle) == 1;
    }
    return file.isTty(io);
}

fn autoColorEnabled(
    io: std.Io,
    file: std.Io.File,
    environ: *const std.process.Environ.Map,
    is_tty: bool,
    no_color: bool,
    force_color: bool,
) std.Io.Cancelable!bool {
    if (no_color) return false;
    if (force_color) return true;
    if (!is_tty) return false;
    if (builtin.os.tag == .windows) {
        return switch (try std.Io.Terminal.Mode.detect(io, file, false, false)) {
            .escape_codes => true,
            .no_color, .windows_api => false,
        };
    }
    if (environ.get("TERM")) |term| return !std.mem.eql(u8, term, "dumb");
    return true;
}

/// Runs borrowed argv through caller-provided writers, returning a CLI exit code.
pub fn runArgs(
    allocator: std.mem.Allocator,
    io: std.Io,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
    args: []const []const u8,
) !u8 {
    return runArgsWithPresentation(allocator, io, stdout, stderr, args, .{});
}

fn runArgsWithPresentation(
    allocator: std.mem.Allocator,
    io: std.Io,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
    args: []const []const u8,
    presentation: Presentation,
) !u8 {
    if (wantsHelp(args)) {
        try writeUsage(stdout);
        return 0;
    }

    if (wantsVersion(args)) {
        try stdout.print("mzValidate v{s} mapping={s}@{s}\n", .{
            version.semantic,
            version.mapping_model,
            version.mapping_model_version,
        });
        return 0;
    }

    const command = parseArgs(args) catch |err| switch (err) {
        error.MissingCommand,
        error.MissingInputPath,
        error.MultipleInputPaths,
        error.UnsupportedCommand,
        error.UnexpectedFlag,
        error.ConflictingOutputMode,
        error.MissingBinarySize,
        error.MissingOboPath,
        error.InvalidValue,
        error.MissingColorMode,
        error.InvalidColorMode,
        error.Overflow,
        => {
            const parse_err: ParseError = @errorCast(err);
            try writeParseError(stderr, parse_err, args);
            try stderr.writeAll("\n");
            try writeUsageHint(stderr);
            return 2;
        },
    };

    return switch (command) {
        .check => |check| try runCheck(allocator, io, stdout, check, presentation),
    };
}

/// Parses argv into a command that borrows its input path from `args`.
pub fn parseArgs(args: []const []const u8) ParseError!Command {
    if (args.len < 2) return error.MissingCommand;
    if (!std.mem.eql(u8, args[1], "check")) return error.UnsupportedCommand;

    var input_path: ?[]const u8 = null;
    var output_mode: output.OutputMode = .text;
    var output_mode_set = false;
    var skip_binary = false;
    var skip_index = false;
    var skip_semantic = false;
    var max_binary_size: ?usize = null;
    var obo_path: ?[]const u8 = null;
    var color_mode: ColorMode = .auto;

    var i: usize = 2;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--max-binary-size")) {
            i += 1;
            if (i >= args.len) return error.MissingBinarySize;
            max_binary_size = try parseSize(args[i]);
            continue;
        }
        if (std.mem.eql(u8, arg, "--skip-binary")) {
            skip_binary = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--skip-index")) {
            skip_index = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--skip-semantic")) {
            skip_semantic = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--obo")) {
            i += 1;
            if (i >= args.len) return error.MissingOboPath;
            obo_path = args[i];
            continue;
        }
        if (std.mem.eql(u8, arg, "--color")) {
            i += 1;
            if (i >= args.len) return error.MissingColorMode;
            color_mode = parseColorMode(args[i]) orelse return error.InvalidColorMode;
            continue;
        }
        if (std.mem.eql(u8, arg, "--json")) {
            if (output_mode_set and output_mode != .json) return error.ConflictingOutputMode;
            output_mode = .json;
            output_mode_set = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--summary")) {
            if (output_mode_set and output_mode != .summary) return error.ConflictingOutputMode;
            output_mode = .summary;
            output_mode_set = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--brief")) {
            if (output_mode_set and output_mode != .brief) return error.ConflictingOutputMode;
            output_mode = .brief;
            output_mode_set = true;
            continue;
        }
        if (std.mem.startsWith(u8, arg, "-")) return error.UnexpectedFlag;

        if (input_path != null) return error.MultipleInputPaths;
        input_path = arg;
    }

    return .{ .check = .{
        .output_mode = output_mode,
        .skip_binary = skip_binary,
        .skip_index = skip_index,
        .skip_semantic = skip_semantic,
        .max_binary_size = max_binary_size,
        .obo_path = obo_path,
        .color_mode = color_mode,
        .input = input_path orelse return error.MissingInputPath,
    } };
}

fn wantsHelp(args: []const []const u8) bool {
    if (args.len == 1) return true;
    if (args.len == 2 and isHelpFlag(args[1])) return true;
    if (args.len == 3 and std.mem.eql(u8, args[1], "check") and isHelpFlag(args[2])) return true;
    return false;
}

fn wantsVersion(args: []const []const u8) bool {
    if (args.len == 2 and isVersionFlag(args[1])) return true;
    if (args.len == 3 and std.mem.eql(u8, args[1], "check") and isVersionFlag(args[2])) return true;
    return false;
}

fn isHelpFlag(arg: []const u8) bool {
    return std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help");
}

fn isVersionFlag(arg: []const u8) bool {
    return std.mem.eql(u8, arg, "--version");
}

fn runCheck(
    allocator: std.mem.Allocator,
    io: std.Io,
    writer: *std.Io.Writer,
    check: CheckCommand,
    presentation: Presentation,
) !u8 {
    // Keep each mode's fixed output state out of the other modes' stack frames.
    // Combining them regresses payload-heavy parsing under ReleaseFast.
    return switch (check.output_mode) {
        .text => @call(.never_inline, runCheckMode, .{ .text, allocator, io, writer, check, presentation }),
        .json => @call(.never_inline, runCheckMode, .{ .json, allocator, io, writer, check, {} }),
        .summary => @call(.never_inline, runCheckMode, .{ .summary, allocator, io, writer, check, {} }),
        .brief => @call(.never_inline, runCheckMode, .{ .brief, allocator, io, writer, check, {} }),
    };
}

fn runCheckMode(
    comptime mode: output.OutputMode,
    allocator: std.mem.Allocator,
    io: std.Io,
    writer: *std.Io.Writer,
    check: CheckCommand,
    presentation: if (mode == .text) Presentation else void,
) !u8 {
    const diagnostic_defaults = diagnostic.ResourceLimits{};
    const options = validate.CheckOptions{
        .skip_binary = check.skip_binary,
        .skip_index = check.skip_index,
        .skip_semantic = check.skip_semantic,
        .max_binary_size = check.max_binary_size,
        .obo_path = check.obo_path,
    };
    var context = validate.InvocationContext.init(allocator, io, options);
    defer context.deinit();

    const started: ?std.Io.Clock.Timestamp = if (comptime mode == .text)
        if (presentation.is_tty) .now(io, .awake) else null
    else
        null;
    var diagnostics = DiagnosticSink.init(.{
        .max_diagnostics = if (mode == .summary) 0 else diagnostic_defaults.max_diagnostics,
        .max_rendered_bytes = if (mode == .summary) 0 else diagnostic_defaults.max_rendered_bytes,
        .retain_details = mode != .summary,
        .aggregate_occurrences = mode == .text or mode == .json or mode == .brief,
    });
    defer diagnostics.deinit(allocator);

    const result = context.validateOne(&diagnostics, check.input);
    if (mode == .text or mode == .json) diagnostics.sortGroups();
    switch (mode) {
        .text => try output.renderTextFile(writer, diagnostics.items, &result, check.input, .{
            .elapsed_ns = if (started) |timestamp| timestamp.untilNow(io).raw.nanoseconds else null,
            .color = switch (check.color_mode) {
                .auto => presentation.auto_color,
                .always => true,
                .never => false,
            },
        }),
        .json => try output.renderJsonResult(writer, diagnostics.items, &result, check.input),
        .summary => try output.renderSummaryResult(writer, diagnostic.summarizeResults(&.{result})),
        .brief => try output.renderBriefFile(writer, diagnostics.items, &result, check.input),
    }
    return diagnostic.exitCodeForResults(&.{result});
}

// --- Private Helpers ---

fn writeUsage(writer: *std.Io.Writer) std.Io.Writer.Error!void {
    try writer.writeAll(
        "mzValidate validates one mzML input in a primary forward pass without building an XML tree.\n\n" ++
            "Usage\n" ++
            "  mzValidate check <input.mzML> [options]\n" ++
            "  mzValidate --help\n\n" ++
            "Commands\n" ++
            "  check        Validate one mzML input.\n\n" ++
            "Options\n" ++
            "  --brief      Emit a compact grouped table.\n" ++
            "  --summary    Emit only aggregate status and severity counts.\n" ++
            "  --json       Emit grouped JSON schema 1 for CI and pipelines.\n" ++
            "  --color MODE Colorize default output: auto, always, or never.\n" ++
            "  --skip-binary\n" ++
            "               Skip binary payload checks.\n" ++
            "  --skip-index Skip index offset and checksum checks.\n" ++
            "  --skip-semantic\n" ++
            "               Skip CV term and semantic validation.\n" ++
            "  --max-binary-size N\n" ++
            "               Reject any binary array whose encodedLength exceeds N.\n" ++
            "               Suffix: K/M/G/T for KiB/MiB/GiB/TiB (binary).\n" ++
            "  --obo <path> Replace the embedded OBO catalog with a custom file.\n" ++
            "               Mapping policy remains the embedded mzML.xsd contract; see --version for its version.\n" ++
            "  --version    Print the mzValidate version number and exit.\n" ++
            "  --help, -h   Show this help text.\n" ++
            "Behavior\n" ++
            "  One input is validated per invocation.\n" ++
            "  Human result lines show completion, status, and severity counts.\n" ++
            "  Default output groups identical findings per input and keeps three example locations.\n" ++
            "  JSON records the same groups, exact occurrence counts, and one summary.\n" ++
            "  Summary mode reports the result for the input.\n" ++
            "  Brief mode groups repeated findings for the input.\n\n" ++
            "Exit Codes\n" ++
            "  0  clean\n" ++
            "  1  warnings only\n" ++
            "  2  errors present or CLI usage failure\n\n" ++
            "Examples\n" ++
            "  mzValidate check sample.mzML\n" ++
            "  mzValidate check sample.mzML --summary\n" ++
            "  mzValidate check sample.mzML --json --skip-binary\n" ++
            "  mzValidate check sample.mzML --json > report.json\n",
    );
}

fn writeUsageHint(writer: *std.Io.Writer) std.Io.Writer.Error!void {
    try writer.writeAll("usage: mzValidate check <input.mzML> [options]\n");
}

fn writeParseError(writer: *std.Io.Writer, err: ParseError, args: []const []const u8) std.Io.Writer.Error!void {
    switch (err) {
        error.MissingCommand => try writer.writeAll("error: missing command"),
        error.MissingInputPath => try writer.writeAll("error: missing input path after `check`"),
        error.MultipleInputPaths => try writer.writeAll("error: check accepts exactly one input path"),
        error.UnsupportedCommand => {
            if (args.len >= 2) {
                try writer.print("error: unsupported command: {s}", .{args[1]});
            } else {
                try writer.writeAll("error: unsupported command");
            }
        },
        error.UnexpectedFlag => {
            if (findUnexpectedFlag(args[2..])) |flag| {
                try writer.print("error: unexpected flag: {s}", .{flag});
            } else {
                try writer.writeAll("error: unexpected flag");
            }
        },
        error.ConflictingOutputMode => try writer.writeAll("error: choose one of --brief, --summary, or --json"),
        error.MissingBinarySize => try writer.writeAll("error: --max-binary-size requires a value"),
        error.MissingOboPath => try writer.writeAll("error: --obo requires a path"),
        error.InvalidValue => try writer.writeAll("error: invalid --max-binary-size value"),
        error.MissingColorMode => try writer.writeAll("error: --color requires auto, always, or never"),
        error.InvalidColorMode => try writer.writeAll("error: invalid --color mode (expected auto, always, or never)"),
        error.Overflow => try writer.writeAll("error: --max-binary-size value overflow (too large)"),
    }
}

fn findUnexpectedFlag(args: []const []const u8) ?[]const u8 {
    for (args) |arg| {
        if (std.mem.startsWith(u8, arg, "-") and !isKnownFlag(arg)) return arg;
    }
    return null;
}

fn isKnownFlag(arg: []const u8) bool {
    return isHelpFlag(arg) or
        isVersionFlag(arg) or
        std.mem.eql(u8, arg, "--skip-binary") or
        std.mem.eql(u8, arg, "--skip-index") or
        std.mem.eql(u8, arg, "--skip-semantic") or
        std.mem.eql(u8, arg, "--max-binary-size") or
        std.mem.eql(u8, arg, "--obo") or
        std.mem.eql(u8, arg, "--color") or
        std.mem.eql(u8, arg, "--json") or
        std.mem.eql(u8, arg, "--summary") or
        std.mem.eql(u8, arg, "--brief");
}

fn parseColorMode(value: []const u8) ?ColorMode {
    if (std.mem.eql(u8, value, "auto")) return .auto;
    if (std.mem.eql(u8, value, "always")) return .always;
    if (std.mem.eql(u8, value, "never")) return .never;
    return null;
}

// Bare K/M/G/T suffixes use binary units; KB/MB/GB use decimal units.
fn parseSize(value: []const u8) error{ Overflow, InvalidValue }!usize {
    if (value.len == 0) return error.InvalidValue;

    var digits_len: usize = 0;
    while (digits_len < value.len and std.ascii.isDigit(value[digits_len])) : (digits_len += 1) {}

    if (digits_len == 0) return error.InvalidValue;

    const number = std.fmt.parseUnsigned(usize, value[0..digits_len], 10) catch |err| switch (err) {
        error.Overflow => return error.Overflow,
        error.InvalidCharacter => return error.InvalidValue,
    };
    if (digits_len == value.len) return number;

    const suffix = value[digits_len..];
    const multiplier = if (std.ascii.eqlIgnoreCase(suffix, "K") or std.ascii.eqlIgnoreCase(suffix, "Ki"))
        @as(usize, 1024)
    else if (std.ascii.eqlIgnoreCase(suffix, "M") or std.ascii.eqlIgnoreCase(suffix, "Mi"))
        @as(usize, 1024 * 1024)
    else if (std.ascii.eqlIgnoreCase(suffix, "G") or std.ascii.eqlIgnoreCase(suffix, "Gi"))
        @as(usize, 1024 * 1024 * 1024)
    else if (std.ascii.eqlIgnoreCase(suffix, "T") or std.ascii.eqlIgnoreCase(suffix, "Ti"))
        @as(usize, 1024 * 1024 * 1024 * 1024)
    else if (std.ascii.eqlIgnoreCase(suffix, "KB"))
        @as(usize, 1000)
    else if (std.ascii.eqlIgnoreCase(suffix, "MB"))
        @as(usize, 1000 * 1000)
    else if (std.ascii.eqlIgnoreCase(suffix, "GB"))
        @as(usize, 1000 * 1000 * 1000)
    else
        return error.InvalidValue;

    return std.math.mul(usize, number, multiplier) catch error.Overflow;
}

fn expectJsonGolden(args: []const []const u8, expected_exit_code: u8, golden_path: []const u8) !void {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, args);
    const expected = try std.Io.Dir.cwd().readFileAlloc(io, golden_path, allocator, .limited(128 * 1024));
    defer allocator.free(expected);

    try std.testing.expectEqual(expected_exit_code, exit_code);
    try std.testing.expectEqualStrings(expected, stdout_writer.written());
    try std.testing.expectEqualStrings("", stderr_writer.written());
}

fn testFlushDrain(writer: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
    _ = data;
    _ = splat;
    if (writer.buffer[0] == 'F') return error.WriteFailed;
    writer.end = 0;
    return 0;
}

const test_flush_vtable: std.Io.Writer.VTable = .{ .drain = testFlushDrain };

// --- Unit Tests ---

test "output write failures propagate" {
    const argv = [_][]const u8{ "mzValidate", "--help" };
    var stdout: std.Io.Writer = .failing;
    var stderr_buffer: [64]u8 = undefined;
    var stderr = std.Io.Writer.fixed(&stderr_buffer);

    try std.testing.expectError(
        error.WriteFailed,
        runArgs(std.testing.allocator, std.testing.io, &stdout, &stderr, &argv),
    );
}

test "flush attempts stderr after stdout failure" {
    var stdout_buffer: [1]u8 = undefined;
    var stdout: std.Io.Writer = .{ .vtable = &test_flush_vtable, .buffer = &stdout_buffer };
    var stderr_buffer: [1]u8 = undefined;
    var stderr: std.Io.Writer = .{ .vtable = &test_flush_vtable, .buffer = &stderr_buffer };
    try stdout.writeByte('F');
    try stderr.writeByte('S');

    try std.testing.expectError(error.WriteFailed, flushWriters(&stdout, &stderr));
    try std.testing.expectEqual(@as(usize, 0), stderr.end);
}

test "[unit]: parser accepts one input path with options" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "sample-a.mzML",
        "--json",
        "--skip-binary",
    };

    const command = try parseArgs(&argv);

    switch (command) {
        .check => |check| {
            try std.testing.expectEqual(output.OutputMode.json, check.output_mode);
            try std.testing.expect(check.skip_binary);
            try std.testing.expectEqualStrings("sample-a.mzML", check.input);
        },
    }
}

test "[unit]: rejects a second input path even when separated by options" {
    const adjacent = [_][]const u8{ "mzValidate", "check", "one.mzML", "two.mzML" };
    const separated = [_][]const u8{ "mzValidate", "check", "one.mzML", "--skip-index", "two.mzML" };

    try std.testing.expectError(error.MultipleInputPaths, parseArgs(&adjacent));
    try std.testing.expectError(error.MultipleInputPaths, parseArgs(&separated));
}

test "rejects the removed memory limit flag" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "sample.mzML",
        "-memory-limit",
        "2M",
    };

    try std.testing.expectError(error.UnexpectedFlag, parseArgs(&argv));
}

test "rejects conflicting output modes" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "sample.mzML",
        "--json",
        "--summary",
    };

    try std.testing.expectError(error.ConflictingOutputMode, parseArgs(&argv));
}

test "requires an input path after check" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "--skip-binary",
        "--summary",
    };

    try std.testing.expectError(error.MissingInputPath, parseArgs(&argv));
}

test "rejects an unknown flag" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "-xml",
        "sample.mzML",
    };

    try std.testing.expectError(error.UnexpectedFlag, parseArgs(&argv));
}

test "parses a raw binary size limit" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "sample.mzML",
        "--max-binary-size",
        "1048576",
    };

    const command = try parseArgs(&argv);

    switch (command) {
        .check => |check| {
            try std.testing.expectEqual(@as(?usize, 1048576), check.max_binary_size);
        },
    }
}

test "parses a suffixed binary size limit" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "sample.mzML",
        "--max-binary-size",
        "1M",
    };

    const command = try parseArgs(&argv);

    switch (command) {
        .check => |check| {
            try std.testing.expectEqual(@as(?usize, 1024 * 1024), check.max_binary_size);
        },
    }
}

test "rejects a missing binary size limit" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "sample.mzML",
        "--max-binary-size",
    };

    try std.testing.expectError(error.MissingBinarySize, parseArgs(&argv));
}

test "rejects a missing OBO path" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "sample.mzML",
        "--obo",
    };

    try std.testing.expectError(error.MissingOboPath, parseArgs(&argv));
}

test "rejects an invalid binary size suffix" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "sample.mzML",
        "--max-binary-size",
        "1X",
    };

    try std.testing.expectError(error.InvalidValue, parseArgs(&argv));
}

test "parses raw byte sizes" {
    try std.testing.expectEqual(@as(usize, 0), try parseSize("0"));
    try std.testing.expectEqual(@as(usize, 1), try parseSize("1"));
    try std.testing.expectEqual(@as(usize, 999), try parseSize("999"));
}

test "rejects a size number overflow" {
    const too_large = comptime std.fmt.comptimePrint("{d}0", .{std.math.maxInt(usize)});
    try std.testing.expectError(error.Overflow, parseSize(too_large));
}

test "parses binary size suffixes" {
    try std.testing.expectEqual(@as(usize, 1 * 1024), try parseSize("1K"));
    try std.testing.expectEqual(@as(usize, 2 * 1024 * 1024), try parseSize("2M"));
    try std.testing.expectEqual(@as(usize, 3 * 1024 * 1024 * 1024), try parseSize("3G"));
}

test "parses decimal size suffixes" {
    try std.testing.expectEqual(@as(usize, 1 * 1000), try parseSize("1KB"));
    try std.testing.expectEqual(@as(usize, 2 * 1000 * 1000), try parseSize("2MB"));
    try std.testing.expectEqual(@as(usize, 3 * 1000 * 1000 * 1000), try parseSize("3GB"));
}

test "rejects an empty size" {
    try std.testing.expectError(error.InvalidValue, parseSize(""));
}

test "rejects a non-numeric size" {
    try std.testing.expectError(error.InvalidValue, parseSize("abc"));
}

test "rejects an unknown size suffix" {
    try std.testing.expectError(error.InvalidValue, parseSize("1X"));
}

test "parses size suffixes case-insensitively" {
    try std.testing.expectEqual(@as(usize, 1 * 1024), try parseSize("1k"));
    try std.testing.expectEqual(@as(usize, 1 * 1024), try parseSize("1K"));
    try std.testing.expectEqual(@as(usize, 1 * 1024), try parseSize("1ki"));
    try std.testing.expectEqual(@as(usize, 1 * 1024 * 1024), try parseSize("1m"));
    try std.testing.expectEqual(@as(usize, 1 * 1024 * 1024 * 1024), try parseSize("1g"));
}

test "help writes usage to stdout" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{ "mzValidate", "--help" };

    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    try std.testing.expectEqual(@as(u8, 0), exit_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "--max-binary-size N") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "-memory-limit") == null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "One input is validated per invocation.") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "[more files...]") == null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "Brief mode groups repeated findings for the input.") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "collapses groups across inputs") == null);
    try std.testing.expectEqualStrings("", stderr_writer.written());
}

test "version reports the mapping policy" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{ "mzValidate", "--version" };

    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    try std.testing.expectEqual(@as(u8, 0), exit_code);
    try std.testing.expectEqualStrings(
        "mzValidate v" ++ version.semantic ++ " mapping=" ++ version.mapping_model ++ "@" ++ version.mapping_model_version ++ "\n",
        stdout_writer.written(),
    );
    try std.testing.expectEqualStrings("", stderr_writer.written());
}

test "check help writes usage to stdout" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{ "mzValidate", "check", "-h" };

    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    try std.testing.expectEqual(@as(u8, 0), exit_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "--skip-semantic") != null);
    try std.testing.expectEqualStrings("", stderr_writer.written());
}

test "unsupported command reports a usage error" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{ "mzValidate", "scan" };

    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    try std.testing.expectEqual(@as(u8, 2), exit_code);
    try std.testing.expectEqualStrings("", stdout_writer.written());
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.written(), "unsupported command: scan") != null);
    try std.testing.expectEqualStrings(
        "error: unsupported command: scan\n" ++
            "usage: mzValidate check <input.mzML> [options]\n",
        stderr_writer.written(),
    );
}

test "unexpected flag reports a usage error" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{ "mzValidate", "check", "sample.mzML", "-wat" };

    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    try std.testing.expectEqual(@as(u8, 2), exit_code);
    try std.testing.expectEqualStrings("", stdout_writer.written());
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.written(), "unexpected flag: -wat") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.written(), "usage: mzValidate check") != null);
}

test "missing input path reports a usage error" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{ "mzValidate", "check", "--summary" };

    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    try std.testing.expectEqual(@as(u8, 2), exit_code);
    try std.testing.expectEqualStrings("", stdout_writer.written());
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.written(), "missing input path after `check`") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.written(), "usage: mzValidate check") != null);
}

test "[unit]: multiple input paths report a usage error" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{ "mzValidate", "check", "one.mzML", "--summary", "two.mzML" };

    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    try std.testing.expectEqual(@as(u8, 2), exit_code);
    try std.testing.expectEqualStrings("", stdout_writer.written());
    try std.testing.expectEqualStrings(
        "error: check accepts exactly one input path\n" ++
            "usage: mzValidate check <input.mzML> [options]\n",
        stderr_writer.written(),
    );
}

test "missing OBO path reports the correct flag" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{ "mzValidate", "check", "sample.mzML", "--obo" };

    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    try std.testing.expectEqual(@as(u8, 2), exit_code);
    try std.testing.expectEqualStrings("", stdout_writer.written());
    try std.testing.expectEqualStrings(
        "error: --obo requires a path\n" ++
            "usage: mzValidate check <input.mzML> [options]\n",
        stderr_writer.written(),
    );
}

test "conflicting output modes report a usage error" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{ "mzValidate", "check", "sample.mzML", "--json", "--summary" };

    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    try std.testing.expectEqual(@as(u8, 2), exit_code);
    try std.testing.expectEqualStrings("", stdout_writer.written());
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.written(), "choose one of --brief, --summary, or --json") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.written(), "usage: mzValidate check") != null);
}

test "[unit]: summary reports one corrupt input" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "fixtures/mzml/invalid/invalid-base64.mzML",
        "--skip-semantic",
        "--skip-index",
        "--summary",
    };

    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    try std.testing.expectEqual(@as(u8, 2), exit_code);
    try std.testing.expectEqualStrings(
        "complete: errors (info=0 warnings=0 errors=1)\n",
        stdout_writer.written(),
    );
    try std.testing.expectEqualStrings("", stderr_writer.written());
}

test "json contract: clean result matches golden" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "fixtures/examples/mzml/single-spectrum-missing-cv-terms.mzML",
        "--skip-semantic",
        "--skip-index",
        "--json",
    };

    try expectJsonGolden(&argv, 0, "fixtures/output/json-v1-clean.json");
}

test "json contract: findings result matches golden" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "fixtures/mzml/invalid/invalid-base64.mzML",
        "--skip-semantic",
        "--json",
    };

    try expectJsonGolden(&argv, 2, "fixtures/output/json-v1-findings.json");
}

test "json contract: incomplete result matches golden" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "missing-p51.mzML",
        "--json",
    };

    try expectJsonGolden(&argv, 2, "fixtures/output/json-v1-incomplete.json");
}

test "external entities report an XML contract diagnostic" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "fixtures/xml/invalid/external-entity.xml",
    };

    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    try std.testing.expectEqual(@as(u8, 2), exit_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "x001  DTD or unsupported XML construct [mzml.structure.xml]") != null);
    try std.testing.expectEqualStrings("", stderr_writer.written());
}

test "[unit]: text output groups one corrupt input" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "fixtures/mzml/invalid/invalid-base64.mzML",
        "--skip-semantic",
        "--skip-index",
    };

    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    try std.testing.expectEqual(@as(u8, 2), exit_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "input: fixtures/mzml/invalid/invalid-base64.mzML") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "x001  binary payload is not valid base64 [mzml.binary.base64]") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "examples:\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "byte ") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "spectrum ") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "complete: errors | info 0, warnings 0, errors 1 | 1 groups") != null);
    try std.testing.expectEqualStrings("", stderr_writer.written());
}

test "[unit]: default output ranks grouped findings" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "fixtures/mzml/valid/tiny.pwiz.1.1.mzML",
    };
    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);
    const rendered = stdout_writer.written();
    const error_ten = std.mem.indexOf(u8, rendered, "x010  default binary array must not declare dataProcessingRef [mzml.binary.default-array]");
    const error_three = std.mem.indexOf(u8, rendered, "x003  attribute must be an XML Schema anyURI [mzml.structure.attribute]");
    const warning_four = std.mem.indexOf(u8, rendered, "x004  CV term name does not match the catalog name or a synonym [mzml.cv.name-mismatch]");
    const info_nine = std.mem.indexOf(u8, rendered, "x009  unitName does not match the term's canonical name [mzml.cv.unit]");

    try std.testing.expectEqual(@as(u8, 2), exit_code);
    try std.testing.expect(error_ten != null);
    try std.testing.expect(error_three != null);
    try std.testing.expect(warning_four != null);
    try std.testing.expect(info_nine != null);
    try std.testing.expect(error_ten.? < error_three.?);
    try std.testing.expect(error_three.? < warning_four.?);
    try std.testing.expect(warning_four.? < info_nine.?);
    try std.testing.expectEqualStrings("", stderr_writer.written());
}

test "[unit]: brief output renders one input" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "fixtures/mzml/invalid/invalid-base64.mzML",
        "--skip-semantic",
        "--skip-index",
        "--brief",
    };

    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);
    try std.testing.expectEqual(@as(u8, 2), exit_code);
    try std.testing.expectEqualStrings(
        "input: fixtures/mzml/invalid/invalid-base64.mzML\n" ++
            "complete: errors (info=0 warnings=0 errors=1)\n" ++
            "\n" ++
            "1  error  mzml.binary.base64  binary payload is not valid base64\n",
        stdout_writer.written(),
    );
    try std.testing.expectEqualStrings("", stderr_writer.written());
}

test "[unit]: verbose flag is rejected" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "sample.mzML",
        "--verbose",
    };

    try std.testing.expectError(error.UnexpectedFlag, parseArgs(&argv));
}

test "[unit]: canonical color flag selects forced color" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "sample.mzML",
        "--color",
        "always",
    };
    const command = try parseArgs(&argv);

    switch (command) {
        .check => |check| try std.testing.expectEqual(ColorMode.always, check.color_mode),
    }
}

test "[unit]: color flag requires a mode" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "sample.mzML",
        "--color",
    };

    try std.testing.expectError(error.MissingColorMode, parseArgs(&argv));
}

test "[unit]: color flag rejects an unknown mode" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "sample.mzML",
        "--color",
        "sometimes",
    };

    try std.testing.expectError(error.InvalidColorMode, parseArgs(&argv));
}

test "skipping binary checks keeps valid structure clean" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "fixtures/mzml/invalid/invalid-base64.mzML",
        "--skip-binary",
        "--skip-semantic",
        "--skip-index",
        "--summary",
    };

    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    try std.testing.expectEqual(@as(u8, 0), exit_code);
    try std.testing.expectEqualStrings(
        "complete: clean (info=0 warnings=0 errors=0)\n",
        stdout_writer.written(),
    );
    try std.testing.expectEqualStrings("", stderr_writer.written());
}

test "[unit]: summary reports one missing input failure" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "missing-a.mzML",
        "--summary",
    };

    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    try std.testing.expectEqual(@as(u8, 2), exit_code);
    try std.testing.expectEqualStrings(
        "incomplete: errors (info=0 warnings=0 errors=1)\n" ++
            "failure: stage=input reason=input rule=runtime.file-open input=missing-a.mzML\n",
        stdout_writer.written(),
    );
    try std.testing.expectEqualStrings("", stderr_writer.written());
}
