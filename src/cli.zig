//! CLI parsing, validation dispatch, and output selection.
//!
//! Regular-file validation uses bounded stream input.

const std = @import("std");
const builtin = @import("builtin");
const diagnostic = @import("diagnostic.zig");
const output = @import("output.zig");
const progress = @import("progress.zig");
const terminal_text = @import("terminal_text.zig");
const validate = @import("validate.zig");
const version = @import("version.zig");

const DiagnosticSink = diagnostic.DiagnosticSink;

const Presentation = struct {
    is_tty: bool = false,
    auto_color: bool = false,
    terminal_columns: ?usize = null,
    stderr_progress: bool = false,
    progress_columns: ?usize = null,
    progress_delay_ns: i96 = 500_000_000,
    progress_refresh_ns: i96 = 150_000_000,
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
    var progress_buffer: [512]u8 = undefined;
    var progress_file_writer: std.Io.File.Writer = .init(.stderr(), init.io, &progress_buffer);
    const progress_stderr = &progress_file_writer.interface;

    const stdout_file = std.Io.File.stdout();
    const stderr_file = std.Io.File.stderr();
    const stdout_terminal = try detectTerminal(init.io, stdout_file);
    const stderr_terminal = try detectTerminal(init.io, stderr_file);
    const no_color = if (init.environ_map.get("NO_COLOR")) |value| value.len > 0 else false;
    const force_color = if (init.environ_map.get("CLICOLOR_FORCE")) |value| value.len > 0 else false;
    const presentation = Presentation{
        .is_tty = stdout_terminal.is_tty,
        .auto_color = try autoColorEnabled(init.io, stdout_file, init.environ_map, stdout_terminal.is_tty, no_color, force_color),
        .terminal_columns = stdout_terminal.columns,
        .stderr_progress = try terminalSupportsEscapeCodes(init.io, stderr_file, init.environ_map, stderr_terminal.is_tty),
        .progress_columns = stderr_terminal.columns,
    };
    const exit_code = runArgsWithProgressWriter(gpa, init.io, stdout, stderr, progress_stderr, args, presentation) catch |err| {
        if (isBrokenPipeFailure(err, stdout_file_writer.err, stderr_file_writer.err)) return 0;
        // Preserve the original failure; output after a failed run is best effort.
        flushWriters(stdout, stderr) catch {};
        return err;
    };
    flushWriters(stdout, stderr) catch |err| {
        if (isBrokenPipeFailure(err, stdout_file_writer.err, stderr_file_writer.err)) return 0;
        return err;
    };
    return exit_code;
}

fn isBrokenPipeFailure(
    write_error: anyerror,
    stdout_error: ?std.Io.File.Writer.Error,
    stderr_error: ?std.Io.File.Writer.Error,
) bool {
    if (write_error != error.WriteFailed) return false;

    var found = false;
    for ([_]?std.Io.File.Writer.Error{ stdout_error, stderr_error }) |optional_error| {
        const err = optional_error orelse continue;
        if (err != error.BrokenPipe) return false;
        found = true;
    }
    return found;
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

const Terminal = struct {
    is_tty: bool,
    columns: ?usize,
};

fn detectTerminal(io: std.Io, file: std.Io.File) std.Io.Cancelable!Terminal {
    if (builtin.os.tag == .windows) {
        if (!try file.isTty(io)) return .{ .is_tty = false, .columns = null };

        var console_info = std.os.windows.CONSOLE.USER_IO.GET_SCREEN_BUFFER_INFO;
        const columns: ?usize = switch (try console_info.operate(io, file)) {
            .SUCCESS => if (console_info.Data.dwWindowSize.X > 0) @intCast(console_info.Data.dwWindowSize.X) else null,
            else => null,
        };
        return .{ .is_tty = true, .columns = columns };
    }

    var window_size: std.posix.winsize = .{
        .row = 0,
        .col = 0,
        .xpixel = 0,
        .ypixel = 0,
    };
    const result = (try io.operate(.{ .device_io_control = .{
        .file = file,
        .code = std.posix.T.IOCGWINSZ,
        .arg = &window_size,
    } })).device_io_control;
    if (result < 0) return .{ .is_tty = false, .columns = null };
    return .{
        .is_tty = true,
        .columns = if (window_size.col > 0) @intCast(window_size.col) else null,
    };
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
    return terminalSupportsEscapeCodes(io, file, environ, is_tty);
}

fn terminalSupportsEscapeCodes(
    io: std.Io,
    file: std.Io.File,
    environ: *const std.process.Environ.Map,
    is_tty: bool,
) std.Io.Cancelable!bool {
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
    return runArgsWithProgressWriter(allocator, io, stdout, stderr, stderr, args, presentation);
}

fn runArgsWithProgressWriter(
    allocator: std.mem.Allocator,
    io: std.Io,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
    progress_writer: *std.Io.Writer,
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
        .check => |check| try runCheck(allocator, io, stdout, progress_writer, check, presentation),
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
    progress_writer: *std.Io.Writer,
    check: CheckCommand,
    presentation: Presentation,
) !u8 {
    // Keep each mode's fixed output state out of the other modes' stack frames.
    // Combining them regresses payload-heavy parsing under ReleaseFast.
    return switch (check.output_mode) {
        .text => @call(.never_inline, runCheckMode, .{ .text, allocator, io, writer, progress_writer, check, presentation }),
        .json => @call(.never_inline, runCheckMode, .{ .json, allocator, io, writer, {}, check, {} }),
        .summary => @call(.never_inline, runCheckMode, .{ .summary, allocator, io, writer, progress_writer, check, presentation }),
    };
}

fn runCheckMode(
    comptime mode: output.OutputMode,
    allocator: std.mem.Allocator,
    io: std.Io,
    writer: *std.Io.Writer,
    progress_writer: if (mode == .json) void else *std.Io.Writer,
    check: CheckCommand,
    presentation: if (mode == .json) void else Presentation,
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

    const started: ?std.Io.Clock.Timestamp = if (comptime mode != .json)
        if (presentation.is_tty or presentation.stderr_progress) .now(io, .awake) else null
    else
        null;
    var progress_renderer: if (mode == .json) void else ?ProgressRenderer = if (mode == .json) {} else if (presentation.stderr_progress)
        ProgressRenderer.init(
            io,
            progress_writer,
            check.input,
            started.?,
            presentation.progress_columns,
            presentation.progress_delay_ns,
            presentation.progress_refresh_ns,
        )
    else
        null;
    defer if (comptime mode != .json) {
        if (progress_renderer) |*renderer| renderer.clear();
    };
    var diagnostics = DiagnosticSink.init(.{
        .max_diagnostics = if (mode == .summary) 0 else diagnostic_defaults.max_diagnostics,
        .max_rendered_bytes = if (mode == .summary) 0 else diagnostic_defaults.max_rendered_bytes,
        .retain_details = mode != .summary,
        .aggregate_occurrences = mode == .text or mode == .json,
    });
    defer diagnostics.deinit(allocator);

    const result = if (comptime mode == .json)
        context.validateOne(&diagnostics, check.input)
    else if (progress_renderer) |*renderer|
        context.validateOneWithProgress(&diagnostics, check.input, renderer.observer())
    else
        context.validateOne(&diagnostics, check.input);
    if (comptime mode != .json) {
        if (progress_renderer) |*renderer| renderer.clear();
    }
    if (mode == .text or mode == .json) diagnostics.sortGroups();
    const human_options: if (mode == .json) void else output.HumanResultOptions = if (mode == .json) {} else .{
        .elapsed_ns = if (presentation.is_tty) started.?.untilNow(io).raw.nanoseconds else null,
        .color = switch (check.color_mode) {
            .auto => presentation.auto_color,
            .always => true,
            .never => false,
        },
        .terminal_columns = presentation.terminal_columns,
    };
    switch (mode) {
        .text => try output.renderTextFile(writer, diagnostics.items, &result, check.input, human_options),
        .json => try output.renderJsonResult(writer, diagnostics.items, &result, check.input),
        .summary => try output.renderSummaryResult(writer, diagnostic.summarizeResults(&.{result}), human_options),
    }
    return diagnostic.exitCodeForResults(&.{result});
}

const ProgressRenderer = struct {
    io: std.Io,
    writer: *std.Io.Writer,
    path: []const u8,
    started: std.Io.Clock.Timestamp,
    terminal_columns: ?usize,
    delay_ns: i96,
    refresh_ns: i96,
    last_render_ns: ?i96 = null,
    visible: bool = false,
    disabled: bool = false,

    fn init(
        io: std.Io,
        writer: *std.Io.Writer,
        path: []const u8,
        started: std.Io.Clock.Timestamp,
        terminal_columns: ?usize,
        delay_ns: i96,
        refresh_ns: i96,
    ) ProgressRenderer {
        return .{
            .io = io,
            .writer = writer,
            .path = path,
            .started = started,
            .terminal_columns = terminal_columns,
            .delay_ns = delay_ns,
            .refresh_ns = refresh_ns,
        };
    }

    fn observer(renderer: *ProgressRenderer) progress.Observer {
        return .{
            .context = renderer,
            .update_fn = observe,
        };
    }

    fn observe(context: *anyopaque, update: progress.Update) void {
        const renderer: *ProgressRenderer = @ptrCast(@alignCast(context));
        if (renderer.disabled) return;
        renderer.updateAt(update, renderer.started.untilNow(renderer.io).raw.nanoseconds);
    }

    fn updateAt(renderer: *ProgressRenderer, update: progress.Update, elapsed_ns: i96) void {
        if (renderer.disabled or elapsed_ns < renderer.delay_ns) return;
        if (renderer.last_render_ns) |last_render_ns| {
            if (elapsed_ns >= last_render_ns and
                elapsed_ns - last_render_ns < renderer.refresh_ns)
            {
                return;
            }
        }
        renderer.renderAt(update, elapsed_ns) catch {
            // Terminal progress is optional; reporting failures must not weaken validation.
            renderer.disabled = true;
            return;
        };
        renderer.last_render_ns = elapsed_ns;
        renderer.visible = true;
    }

    fn renderAt(
        renderer: *ProgressRenderer,
        update: progress.Update,
        elapsed_ns: i96,
    ) std.Io.Writer.Error!void {
        try renderer.writer.writeAll("\r\x1b[2K");
        try renderer.writer.writeAll(switch (update.phase) {
            .parse => "parse   ",
            .checksum => "checksum",
        });
        try renderer.writer.writeAll(" | ");
        const percent = progressPercent(update.completed_bytes, update.total_bytes);
        if (percent < 10) try renderer.writer.writeAll("  ") else if (percent < 100) try renderer.writer.writeByte(' ');
        try renderer.writer.print("{d}% | ", .{percent});
        try writeProgressBytes(renderer.writer, update.completed_bytes);
        try renderer.writer.writeAll(" / ");
        try writeProgressBytes(renderer.writer, update.total_bytes);
        try renderer.writer.writeAll(" | ");
        try writeProgressElapsed(renderer.writer, elapsed_ns);
        try renderer.writer.writeAll(" | ");
        try writeProgressPath(
            renderer.writer,
            renderer.path,
            renderer.terminal_columns,
            progressPrefixWidth(update, elapsed_ns),
        );
        try renderer.writer.flush();
    }

    fn clear(renderer: *ProgressRenderer) void {
        if (renderer.disabled or !renderer.visible) return;
        renderer.writer.writeAll("\r\x1b[2K") catch {
            renderer.disabled = true;
            return;
        };
        renderer.writer.flush() catch {
            renderer.disabled = true;
            return;
        };
        renderer.visible = false;
    }
};

fn progressPercent(completed_bytes: u64, total_bytes: u64) u8 {
    if (total_bytes == 0) return 100;
    const bounded = @min(completed_bytes, total_bytes);
    return @intCast((@as(u128, bounded) * 100) / total_bytes);
}

fn writeProgressBytes(writer: *std.Io.Writer, bytes: u64) std.Io.Writer.Error!void {
    const units = [_]struct { bytes: u64, label: []const u8 }{
        .{ .bytes = 1_000_000_000, .label = "GB" },
        .{ .bytes = 1_000_000, .label = "MB" },
        .{ .bytes = 1_000, .label = "KB" },
    };
    for (units) |unit| {
        if (bytes < unit.bytes) continue;
        const tenths: u64 = @intCast((@as(u128, bytes) * 10 + unit.bytes / 2) / unit.bytes);
        try writer.print("{d}.{d} {s}", .{ tenths / 10, tenths % 10, unit.label });
        return;
    }
    try writer.print("{d} B", .{bytes});
}

fn writeProgressElapsed(writer: *std.Io.Writer, elapsed_ns: i96) std.Io.Writer.Error!void {
    const nanoseconds: u96 = @intCast(@max(elapsed_ns, 0));
    const tenths = nanoseconds / 100_000_000;
    try writer.print("{d}.{d}s", .{ tenths / 10, tenths % 10 });
}

fn writeProgressPath(
    writer: *std.Io.Writer,
    path: []const u8,
    terminal_columns: ?usize,
    prefix_width: usize,
) std.Io.Writer.Error!void {
    const columns = terminal_columns orelse {
        try writer.writeAll(path);
        return;
    };
    const available = if (columns > prefix_width) columns - prefix_width else 1;
    if (terminal_text.displayWidth(path) <= available) {
        try writer.writeAll(path);
        return;
    }
    if (available <= 3) {
        try writer.writeAll(path[terminal_text.suffixStartForWidth(path, available)..]);
        return;
    }
    try writer.writeAll("...");
    try writer.writeAll(path[terminal_text.suffixStartForWidth(path, available - 3)..]);
}

fn progressPrefixWidth(update: progress.Update, elapsed_ns: i96) usize {
    return 27 + progressBytesWidth(update.completed_bytes) +
        progressBytesWidth(update.total_bytes) + progressElapsedWidth(elapsed_ns);
}

fn progressBytesWidth(bytes: u64) usize {
    const units = [_]struct { bytes: u64, label: []const u8 }{
        .{ .bytes = 1_000_000_000, .label = "GB" },
        .{ .bytes = 1_000_000, .label = "MB" },
        .{ .bytes = 1_000, .label = "KB" },
    };
    for (units) |unit| {
        if (bytes < unit.bytes) continue;
        const tenths: u64 = @intCast((@as(u128, bytes) * 10 + unit.bytes / 2) / unit.bytes);
        return decimalDigits(tenths / 10) + 3 + unit.label.len;
    }
    return decimalDigits(bytes) + 2;
}

fn progressElapsedWidth(elapsed_ns: i96) usize {
    const nanoseconds: u96 = @intCast(@max(elapsed_ns, 0));
    return decimalDigits(nanoseconds / 1_000_000_000) + 3;
}

fn decimalDigits(value: anytype) usize {
    var remaining = value;
    var width: usize = 1;
    while (remaining >= 10) : (remaining /= 10) width += 1;
    return width;
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
            "  --summary    Emit only aggregate status and severity counts.\n" ++
            "  --json       Emit grouped JSON schema 1 for CI and pipelines.\n" ++
            "  --color MODE Colorize human output: auto, always, or never.\n" ++
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
            "  Summary mode reports the result for the input.\n\n" ++
            "Exit Codes\n" ++
            "  0  Validation completed without error findings.\n" ++
            "  1  Validation completed with error findings.\n" ++
            "  2  Invalid invocation or option value.\n" ++
            "  3  Validation could not complete.\n\n" ++
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
        error.ConflictingOutputMode => try writer.writeAll("error: choose either --summary or --json"),
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
        std.mem.eql(u8, arg, "--summary");
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

test "[unit]: only broken-pipe write failures stop cleanly" {
    try std.testing.expect(isBrokenPipeFailure(error.WriteFailed, error.BrokenPipe, null));
    try std.testing.expect(isBrokenPipeFailure(error.WriteFailed, null, error.BrokenPipe));
    try std.testing.expect(isBrokenPipeFailure(error.WriteFailed, error.BrokenPipe, error.BrokenPipe));
    try std.testing.expect(!isBrokenPipeFailure(error.WriteFailed, null, null));
    try std.testing.expect(!isBrokenPipeFailure(error.WriteFailed, error.InputOutput, null));
    try std.testing.expect(!isBrokenPipeFailure(error.WriteFailed, error.BrokenPipe, error.InputOutput));
    try std.testing.expect(!isBrokenPipeFailure(error.OutOfMemory, error.BrokenPipe, null));
}

test "[unit]: progress is delayed, rate limited, attributed, and cleared" {
    var progress_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer progress_writer.deinit();
    var renderer = ProgressRenderer.init(
        std.testing.io,
        &progress_writer.writer,
        "sample.mzML",
        .now(std.testing.io, .awake),
        null,
        500_000_000,
        150_000_000,
    );
    const first = progress.Update{
        .phase = .parse,
        .completed_bytes = 2_840_000_000,
        .total_bytes = 4_000_000_000,
    };

    renderer.updateAt(first, 499_000_000);
    try std.testing.expectEqualStrings("", progress_writer.written());
    renderer.updateAt(first, 15_400_000_000);
    renderer.updateAt(.{
        .phase = .parse,
        .completed_bytes = 3_200_000_000,
        .total_bytes = 4_000_000_000,
    }, 15_500_000_000);
    try std.testing.expectEqualStrings(
        "\r\x1b[2Kparse    |  71% | 2.8 GB / 4.0 GB | 15.4s | sample.mzML",
        progress_writer.written(),
    );
    renderer.updateAt(.{
        .phase = .checksum,
        .completed_bytes = 1_680_000_000,
        .total_bytes = 4_000_000_000,
    }, 15_500_000_000);
    try std.testing.expect(std.mem.indexOf(u8, progress_writer.written(), "checksum") == null);
    renderer.updateAt(.{
        .phase = .checksum,
        .completed_bytes = 1_680_000_000,
        .total_bytes = 4_000_000_000,
    }, 15_550_000_000);
    renderer.clear();
    try std.testing.expect(std.mem.indexOf(u8, progress_writer.written(), "checksum |  42%") != null);
    try std.testing.expect(std.mem.endsWith(u8, progress_writer.written(), "\r\x1b[2K"));
}

test "[unit]: progress keeps fields and fits paths on UTF-8 boundaries" {
    var progress_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer progress_writer.deinit();
    var renderer = ProgressRenderer.init(
        std.testing.io,
        &progress_writer.writer,
        "very/long/sample.mzML",
        .now(std.testing.io, .awake),
        56,
        0,
        0,
    );
    try renderer.renderAt(.{
        .phase = .parse,
        .completed_bytes = 2_840_000_000,
        .total_bytes = 4_000_000_000,
    }, 15_400_000_000);

    try std.testing.expectEqualStrings(
        "\r\x1b[2Kparse    |  71% | 2.8 GB / 4.0 GB | 15.4s | ...mple.mzML",
        progress_writer.written(),
    );

    const cases = [_]struct { path: []const u8, expected: []const u8 }{
        .{ .path = "prefix/café.mzML", .expected = "...café.mzML" },
        .{ .path = "prefix/bad\xff.mzML", .expected = "...bad\xff.mzML" },
    };
    for (cases) |case| {
        var path_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer path_writer.deinit();
        try writeProgressPath(&path_writer.writer, case.path, 12, 0);
        try std.testing.expectEqualStrings(case.expected, path_writer.written());
    }
}

test "[unit]: default and summary render parse and checksum progress on stderr" {
    const default_argv = [_][]const u8{
        "mzValidate",
        "check",
        "fixtures/mzml/valid/small.pwiz.1.1.mzML",
        "--skip-semantic",
    };
    const summary_argv = [_][]const u8{
        "mzValidate",
        "check",
        "fixtures/mzml/valid/small.pwiz.1.1.mzML",
        "--skip-semantic",
        "--summary",
    };
    const cases = [_][]const []const u8{ &default_argv, &summary_argv };

    for (cases) |argv| {
        var stdout_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer stdout_writer.deinit();
        var stderr_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer stderr_writer.deinit();
        var progress_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer progress_writer.deinit();

        const exit_code = try runArgsWithProgressWriter(
            std.testing.allocator,
            std.testing.io,
            &stdout_writer.writer,
            &stderr_writer.writer,
            &progress_writer.writer,
            argv,
            .{
                .stderr_progress = true,
                .progress_delay_ns = 0,
                .progress_refresh_ns = 0,
            },
        );
        const rendered = progress_writer.written();

        try std.testing.expectEqual(@as(u8, 0), exit_code);
        try std.testing.expect(std.mem.indexOf(u8, rendered, "parse    |") != null);
        try std.testing.expect(std.mem.indexOf(u8, rendered, "checksum |") != null);
        try std.testing.expect(std.mem.indexOf(u8, rendered, " / 5.1 MB |") != null);
        try std.testing.expect(std.mem.indexOf(u8, rendered, "fixtures/mzml/valid/small.pwiz.1.1.mzML") != null);
        try std.testing.expect(std.mem.endsWith(u8, rendered, "\r\x1b[2K"));
        try std.testing.expectEqualStrings("", stderr_writer.written());
    }
}

test "[unit]: JSON and redirected stderr disable progress" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "fixtures/examples/mzml/single-spectrum-missing-cv-terms.mzML",
        "--skip-semantic",
        "--skip-index",
        "--json",
    };
    var stdout_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer stderr_writer.deinit();
    var progress_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer progress_writer.deinit();

    _ = try runArgsWithProgressWriter(
        std.testing.allocator,
        std.testing.io,
        &stdout_writer.writer,
        &stderr_writer.writer,
        &progress_writer.writer,
        &argv,
        .{ .stderr_progress = true, .progress_delay_ns = 0 },
    );
    try std.testing.expectEqualStrings("", progress_writer.written());

    progress_writer.writer.end = 0;
    const summary_argv = [_][]const u8{
        "mzValidate",
        "check",
        "fixtures/examples/mzml/single-spectrum-missing-cv-terms.mzML",
        "--skip-semantic",
        "--skip-index",
        "--summary",
    };
    _ = try runArgsWithProgressWriter(
        std.testing.allocator,
        std.testing.io,
        &stdout_writer.writer,
        &stderr_writer.writer,
        &progress_writer.writer,
        &summary_argv,
        .{},
    );
    try std.testing.expectEqualStrings("", progress_writer.written());
}

test "[unit]: progress writer failure does not weaken validation" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "fixtures/mzml/valid/small.pwiz.1.1.mzML",
        "--skip-semantic",
        "--summary",
    };
    var stdout_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer stderr_writer.deinit();
    var progress_writer: std.Io.Writer = .failing;

    const exit_code = try runArgsWithProgressWriter(
        std.testing.allocator,
        std.testing.io,
        &stdout_writer.writer,
        &stderr_writer.writer,
        &progress_writer,
        &argv,
        .{
            .stderr_progress = true,
            .progress_delay_ns = 0,
            .progress_refresh_ns = 0,
        },
    );

    try std.testing.expectEqual(@as(u8, 0), exit_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "complete:") != null);
    try std.testing.expectEqualStrings("", stderr_writer.written());
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
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "--brief") == null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "collapses groups across inputs") == null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        stdout_writer.written(),
        "Exit Codes\n" ++
            "  0  Validation completed without error findings.\n" ++
            "  1  Validation completed with error findings.\n" ++
            "  2  Invalid invocation or option value.\n" ++
            "  3  Validation could not complete.\n",
    ) != null);
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

test "[unit]: summary keeps warning-only validation successful" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "fixtures/mzml/valid/small.pwiz.1.1.mzML",
        "--summary",
    };

    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    try std.testing.expectEqual(@as(u8, 0), exit_code);
    try std.testing.expectEqualStrings(
        "complete: warnings | warnings 3, info 97\n",
        stdout_writer.written(),
    );
    try std.testing.expectEqualStrings("", stderr_writer.written());
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
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.written(), "choose either --summary or --json") != null);
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

    try std.testing.expectEqual(@as(u8, 1), exit_code);
    try std.testing.expectEqualStrings(
        "complete: errors | errors 1\n",
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

    try expectJsonGolden(&argv, 1, "fixtures/output/json-v1-findings.json");
}

test "json contract: color presentation does not change output" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "fixtures/mzml/invalid/invalid-base64.mzML",
        "--skip-semantic",
        "--json",
        "--color",
        "always",
    };

    try expectJsonGolden(&argv, 1, "fixtures/output/json-v1-findings.json");
}

test "json contract: incomplete result matches golden" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "missing-p51.mzML",
        "--json",
    };

    try expectJsonGolden(&argv, 3, "fixtures/output/json-v1-incomplete.json");
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

    try std.testing.expectEqual(@as(u8, 3), exit_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "x001  DTD or unsupported XML construct [mzml.structure.xml]") != null);
    try std.testing.expectEqualStrings("", stderr_writer.written());
}

test "[unit]: summary uses interactive timing and automatic color" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "fixtures/examples/mzml/single-spectrum-missing-cv-terms.mzML",
        "--skip-semantic",
        "--skip-index",
        "--summary",
    };
    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    const exit_code = try runArgsWithPresentation(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv, .{
        .is_tty = true,
        .auto_color = true,
    });

    try std.testing.expectEqual(@as(u8, 0), exit_code);
    try std.testing.expect(std.mem.startsWith(u8, stdout_writer.written(), "\x1b[42;30;1mcomplete: clean\x1b[0m | no findings | "));
    try std.testing.expect(std.mem.endsWith(u8, stdout_writer.written(), "s\n"));
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

    try std.testing.expectEqual(@as(u8, 1), exit_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "input: fixtures/mzml/invalid/invalid-base64.mzML") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "x001  binary payload is not valid base64 [mzml.binary.base64]") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "examples:\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "byte ") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "spectrum ") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "complete: errors | errors 1 | 1 group") != null);
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

    try std.testing.expectEqual(@as(u8, 1), exit_code);
    try std.testing.expect(error_ten != null);
    try std.testing.expect(error_three != null);
    try std.testing.expect(warning_four != null);
    try std.testing.expect(info_nine != null);
    try std.testing.expect(error_ten.? < error_three.?);
    try std.testing.expect(error_three.? < warning_four.?);
    try std.testing.expect(warning_four.? < info_nine.?);
    try std.testing.expectEqualStrings("", stderr_writer.written());
}

test "[unit]: brief flag is rejected" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "sample.mzML",
        "--brief",
    };

    try std.testing.expectError(error.UnexpectedFlag, parseArgs(&argv));
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
        "complete: clean | no findings\n",
        stdout_writer.written(),
    );
    try std.testing.expectEqualStrings("", stderr_writer.written());
}

test "[unit]: summary reports one missing input as incomplete" {
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

    try std.testing.expectEqual(@as(u8, 3), exit_code);
    try std.testing.expectEqualStrings(
        "incomplete: errors | errors 1\n",
        stdout_writer.written(),
    );
    try std.testing.expectEqualStrings("", stderr_writer.written());
}
