//! CLI parsing, validation dispatch, and output selection.
//!
//! Regular-file validation uses bounded stream input. The explicit mmap selector is
//! retained for compatibility and returns an incomplete result without fallback.

const std = @import("std");
const diagnostic = @import("diagnostic.zig");
const output = @import("output.zig");
const validate = @import("validate.zig");
const version = @import("version.zig");

const DiagnosticSink = diagnostic.DiagnosticSink;

/// Parsed `check` subcommand flags and input paths.
pub const CheckCommand = struct {
    output_mode: output.OutputMode = .text,
    skip_binary: bool = false,
    skip_index: bool = false,
    skip_semantic: bool = false,
    input_mode: validate.InputMode = .stream,
    max_binary_size: ?usize = null,
    obo_path: ?[]const u8 = null,
    inputs: []const []const u8,

    /// Releases the owned input-path list. Path bytes remain borrowed from argv.
    pub fn deinit(command: *CheckCommand, allocator: std.mem.Allocator) void {
        allocator.free(command.inputs);
        command.* = undefined;
    }
};

/// Top-level CLI command after parsing.
pub const Command = union(enum) {
    check: CheckCommand,

    pub fn deinit(command: *Command, allocator: std.mem.Allocator) void {
        switch (command.*) {
            .check => |*check| check.deinit(allocator),
        }
    }
};

const ParseError = error{
    MissingCommand,
    MissingInputPath,
    UnsupportedCommand,
    UnexpectedFlag,
    ConflictingOutputMode,
    MissingBinarySize,
    MissingOboPath,
    InvalidValue,
    Overflow,
    MissingInputMode,
    InvalidInputMode,
};

const ParseArgsError = ParseError || std.mem.Allocator.Error;

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

    const exit_code = runArgs(gpa, init.io, stdout, stderr, args) catch |err| {
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

/// Runs borrowed argv through caller-provided writers, returning a CLI exit code.
pub fn runArgs(
    allocator: std.mem.Allocator,
    io: std.Io,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
    args: []const []const u8,
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

    var command = parseArgs(allocator, args) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.MissingCommand,
        error.MissingInputPath,
        error.UnsupportedCommand,
        error.UnexpectedFlag,
        error.ConflictingOutputMode,
        error.MissingBinarySize,
        error.MissingOboPath,
        error.InvalidValue,
        error.Overflow,
        error.MissingInputMode,
        error.InvalidInputMode,
        => {
            const parse_err: ParseError = @errorCast(err);
            try writeParseError(stderr, parse_err, args);
            try stderr.writeAll("\n");
            try writeUsageHint(stderr);
            return 2;
        },
    };
    defer command.deinit(allocator);

    return switch (command) {
        .check => |check| try runCheck(allocator, io, stdout, check),
    };
}

/// Parses argv into an allocator-owned command; path strings borrow `args`.
pub fn parseArgs(allocator: std.mem.Allocator, args: []const []const u8) ParseArgsError!Command {
    if (args.len < 2) return error.MissingCommand;
    if (!std.mem.eql(u8, args[1], "check")) return error.UnsupportedCommand;

    var input_paths: std.ArrayList([]const u8) = .empty;
    defer input_paths.deinit(allocator);

    var output_mode: output.OutputMode = .text;
    var output_mode_set = false;
    var skip_binary = false;
    var skip_index = false;
    var skip_semantic = false;
    var input_mode: validate.InputMode = .stream;
    var max_binary_size: ?usize = null;
    var obo_path: ?[]const u8 = null;

    var i: usize = 2;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-max-binary-size")) {
            i += 1;
            if (i >= args.len) return error.MissingBinarySize;
            max_binary_size = try parseSize(args[i]);
            continue;
        }
        if (std.mem.eql(u8, arg, "-skip-binary")) {
            skip_binary = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "-skip-index")) {
            skip_index = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "-skip-semantic")) {
            skip_semantic = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "-input-mode")) {
            i += 1;
            if (i >= args.len) return error.MissingInputMode;
            input_mode = parseInputMode(args[i]) catch return error.InvalidInputMode;
            continue;
        }
        if (std.mem.eql(u8, arg, "-mmap")) {
            input_mode = .mmap;
            continue;
        }
        if (std.mem.eql(u8, arg, "-obo")) {
            i += 1;
            if (i >= args.len) return error.MissingOboPath;
            obo_path = args[i];
            continue;
        }
        if (std.mem.eql(u8, arg, "-json")) {
            if (output_mode_set and output_mode != .json) return error.ConflictingOutputMode;
            output_mode = .json;
            output_mode_set = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "-summary")) {
            if (output_mode_set and output_mode != .summary) return error.ConflictingOutputMode;
            output_mode = .summary;
            output_mode_set = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "-brief")) {
            if (output_mode_set and output_mode != .brief) return error.ConflictingOutputMode;
            output_mode = .brief;
            output_mode_set = true;
            continue;
        }
        if (std.mem.startsWith(u8, arg, "-")) return error.UnexpectedFlag;

        try input_paths.append(allocator, arg);
    }

    if (input_paths.items.len == 0) return error.MissingInputPath;

    return .{ .check = .{
        .output_mode = output_mode,
        .skip_binary = skip_binary,
        .skip_index = skip_index,
        .skip_semantic = skip_semantic,
        .input_mode = input_mode,
        .max_binary_size = max_binary_size,
        .obo_path = obo_path,
        .inputs = try input_paths.toOwnedSlice(allocator),
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
    return std.mem.eql(u8, arg, "-version") or std.mem.eql(u8, arg, "--version");
}

fn runCheck(
    allocator: std.mem.Allocator,
    io: std.Io,
    writer: *std.Io.Writer,
    check: CheckCommand,
) !u8 {
    var results: std.ArrayList(diagnostic.FileResult) = .empty;
    try results.ensureTotalCapacity(allocator, check.inputs.len);
    defer results.deinit(allocator);

    const diagnostic_defaults = diagnostic.ResourceLimits{};
    var brief_groups: output.BriefGroups = .{};
    var json_stream: ?output.JsonStream = if (check.output_mode == .json)
        try output.JsonStream.init(writer, @tagName(check.input_mode))
    else
        null;

    const options = validate.CheckOptions{
        .skip_binary = check.skip_binary,
        .skip_index = check.skip_index,
        .skip_semantic = check.skip_semantic,
        .input_mode = check.input_mode,
        .max_binary_size = check.max_binary_size,
        .obo_path = check.obo_path,
    };
    var context = validate.InvocationContext.init(allocator, io, options);
    defer context.deinit();

    for (check.inputs) |path| {
        var diagnostics = DiagnosticSink.init(.{
            .max_diagnostics = if (check.output_mode == .summary) 0 else diagnostic_defaults.max_diagnostics,
            .max_rendered_bytes = if (check.output_mode == .summary) 0 else diagnostic_defaults.max_rendered_bytes,
            .retain_details = check.output_mode != .summary,
        });
        defer diagnostics.deinit(allocator);

        const result = context.validateOne(&diagnostics, path);
        try results.append(allocator, result);
        switch (check.output_mode) {
            .text => try output.renderTextFile(writer, diagnostics.items, &results.items[results.items.len - 1], path),
            .json => if (json_stream) |*stream| try stream.writeFile(diagnostics.items, &results.items[results.items.len - 1], path),
            .summary => {},
            .brief => for (diagnostics.items) |item| brief_groups.add(item),
        }
    }

    switch (check.output_mode) {
        .text => try output.renderTextFinal(writer, results.items, @tagName(check.input_mode)),
        .json => if (json_stream) |*stream| try stream.finish(),
        .summary => try output.renderSummaryResult(writer, results.items, @tagName(check.input_mode)),
        .brief => try output.renderBriefGroupsResult(writer, &brief_groups, results.items, @tagName(check.input_mode)),
    }

    return diagnostic.exitCodeForResults(results.items);
}

// --- Private Helpers ---

fn writeUsage(writer: *std.Io.Writer) std.Io.Writer.Error!void {
    try writer.writeAll(
        "mzValidate validates mzML inputs in one primary forward pass without building an XML tree.\n\n" ++
            "Usage\n" ++
            "  mzValidate check <input.mzML> [more files...] [options]\n" ++
            "  mzValidate --help\n\n" ++
            "Commands\n" ++
            "  check        Validate one or more mzML inputs in a single run.\n\n" ++
            "Options\n" ++
            "  -json        Emit a versioned JSON result report for CI and pipelines.\n" ++
            "  -summary     Emit only aggregate status and severity counts.\n" ++
            "  -brief       Group diagnostics by rule with occurrence counts.\n" ++
            "  -skip-binary Skip binary payload checks.\n" ++
            "  -skip-index  Skip index offset and checksum checks.\n" ++
            "  -skip-semantic\n" ++
            "               Skip CV term and semantic validation.\n" ++
            "  -input-mode stream|mmap\n" ++
            "               Use bounded stream input (default). mmap is refused safely.\n" ++
            "  -mmap        Compatibility alias for -input-mode mmap.\n" ++
            "  -max-binary-size N\n" ++
            "               Reject any binary array whose encodedLength exceeds N.\n" ++
            "               Suffix: K/M/G/T for KiB/MiB/GiB/TiB (binary).\n" ++
            "  -obo <path>  Override the embedded psi-ms.obo with a custom file.\n" ++
            "               Mapping policy remains the embedded mzML.xsd contract; see -version for its version.\n" ++
            "  -version, --version\n" ++
            "               Print the mzValidate version number and exit.\n" ++
            "  -h, --help   Show this help text.\n\n" ++
            "Behavior\n" ++
            "  Every input is attempted, even if an earlier input produces diagnostics.\n" ++
            "  Human result lines show completion, status, and severity counts.\n" ++
            "  A config line appears only when the input mode differs from the default.\n" ++
            "  Text mode groups diagnostics by input path and ends with the result.\n" ++
            "  JSON mode records input mode, file results, diagnostics, and one summary.\n" ++
            "  Summary mode reports the aggregate result for the whole invocation.\n" ++
            "  Brief mode groups identical diagnostics by severity, rule, and message\n" ++
            "  with occurrence counts. Ideal for spotting patterns in large files.\n\n" ++
            "Exit Codes\n" ++
            "  0  clean\n" ++
            "  1  warnings only\n" ++
            "  2  errors present or CLI usage failure\n\n" ++
            "Examples\n" ++
            "  mzValidate check sample.mzML\n" ++
            "  mzValidate check run-a.mzML run-b.mzML -summary\n" ++
            "  mzValidate check sample.mzML -json -skip-binary\n",
    );
}

fn writeUsageHint(writer: *std.Io.Writer) std.Io.Writer.Error!void {
    try writer.writeAll("usage: mzValidate check <input.mzML> [more files...] [options]\n");
}

fn writeParseError(writer: *std.Io.Writer, err: ParseError, args: []const []const u8) std.Io.Writer.Error!void {
    switch (err) {
        error.MissingCommand => try writer.writeAll("error: missing command"),
        error.MissingInputPath => try writer.writeAll("error: missing input path after `check`"),
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
        error.ConflictingOutputMode => try writer.writeAll("error: choose one of -json, -summary, or -brief"),
        error.MissingBinarySize => try writer.writeAll("error: -max-binary-size requires a value"),
        error.MissingOboPath => try writer.writeAll("error: -obo requires a path"),
        error.InvalidValue => try writer.writeAll("error: invalid -max-binary-size value"),
        error.Overflow => try writer.writeAll("error: -max-binary-size value overflow (too large)"),
        error.MissingInputMode => try writer.writeAll("error: -input-mode requires a value (stream or mmap)"),
        error.InvalidInputMode => {
            if (findFlagValue(args, "-input-mode")) |value| {
                try writer.print("error: invalid -input-mode value '{s}' (expected stream or mmap)", .{value});
            } else {
                try writer.writeAll("error: invalid -input-mode value (expected stream or mmap)");
            }
        },
    }
}

fn findFlagValue(args: []const []const u8, flag: []const u8) ?[]const u8 {
    for (0..args.len) |i| {
        if (std.mem.eql(u8, args[i], flag) and args.len - i > 1) return args[i + 1];
    }
    return null;
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
        std.mem.eql(u8, arg, "-skip-binary") or
        std.mem.eql(u8, arg, "-skip-index") or
        std.mem.eql(u8, arg, "-skip-semantic") or
        std.mem.eql(u8, arg, "-input-mode") or
        std.mem.eql(u8, arg, "-mmap") or
        std.mem.eql(u8, arg, "-max-binary-size") or
        std.mem.eql(u8, arg, "-obo") or
        std.mem.eql(u8, arg, "-json") or
        std.mem.eql(u8, arg, "-summary") or
        std.mem.eql(u8, arg, "-brief");
}

fn parseInputMode(value: []const u8) error{InvalidValue}!validate.InputMode {
    if (std.mem.eql(u8, value, "stream")) return .stream;
    if (std.mem.eql(u8, value, "mmap")) return .mmap;
    return error.InvalidValue;
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

test "parses flags and input paths" {
    const allocator = std.testing.allocator;
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "sample-a.mzML",
        "-json",
        "-skip-binary",
        "-mmap",
        "sample-b.mzML",
    };

    var command = try parseArgs(allocator, &argv);
    defer command.deinit(allocator);

    switch (command) {
        .check => |check| {
            try std.testing.expectEqual(output.OutputMode.json, check.output_mode);
            try std.testing.expect(check.skip_binary);
            try std.testing.expectEqual(validate.InputMode.mmap, check.input_mode);
            try std.testing.expectEqual(@as(usize, 2), check.inputs.len);
            try std.testing.expectEqualStrings("sample-a.mzML", check.inputs[0]);
            try std.testing.expectEqualStrings("sample-b.mzML", check.inputs[1]);
        },
    }
}

test "records explicit stream input mode" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "sample.mzML",
        "-input-mode",
        "stream",
    };

    var command = try parseArgs(std.testing.allocator, &argv);
    defer command.deinit(std.testing.allocator);

    switch (command) {
        .check => |check| {
            try std.testing.expectEqual(validate.InputMode.stream, check.input_mode);
        },
    }
}

test "defaults to stream input" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "sample.mzML",
    };

    var command = try parseArgs(std.testing.allocator, &argv);
    defer command.deinit(std.testing.allocator);

    switch (command) {
        .check => |check| {
            try std.testing.expectEqual(validate.InputMode.stream, check.input_mode);
        },
    }
}

test "records explicit mmap input mode" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "sample.mzML",
        "-input-mode",
        "mmap",
    };

    var command = try parseArgs(std.testing.allocator, &argv);
    defer command.deinit(std.testing.allocator);

    switch (command) {
        .check => |check| {
            try std.testing.expectEqual(validate.InputMode.mmap, check.input_mode);
        },
    }
}

test "rejects an invalid input mode" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "sample.mzML",
        "-input-mode",
        "auto",
    };

    try std.testing.expectError(error.InvalidInputMode, parseArgs(std.testing.allocator, &argv));
}

test "rejects the removed memory limit flag" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "sample.mzML",
        "-memory-limit",
        "2M",
    };

    try std.testing.expectError(error.UnexpectedFlag, parseArgs(std.testing.allocator, &argv));
}

test "rejects conflicting output modes" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "sample.mzML",
        "-json",
        "-summary",
    };

    try std.testing.expectError(error.ConflictingOutputMode, parseArgs(std.testing.allocator, &argv));
}

test "requires an input path after check" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "-skip-binary",
        "-summary",
    };

    try std.testing.expectError(error.MissingInputPath, parseArgs(std.testing.allocator, &argv));
}

test "rejects an unknown flag" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "-xml",
        "sample.mzML",
    };

    try std.testing.expectError(error.UnexpectedFlag, parseArgs(std.testing.allocator, &argv));
}

test "parses a raw binary size limit" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "sample.mzML",
        "-max-binary-size",
        "1048576",
    };

    var command = try parseArgs(std.testing.allocator, &argv);
    defer command.deinit(std.testing.allocator);

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
        "-max-binary-size",
        "1M",
    };

    var command = try parseArgs(std.testing.allocator, &argv);
    defer command.deinit(std.testing.allocator);

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
        "-max-binary-size",
    };

    try std.testing.expectError(error.MissingBinarySize, parseArgs(std.testing.allocator, &argv));
}

test "rejects a missing OBO path" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "sample.mzML",
        "-obo",
    };

    try std.testing.expectError(error.MissingOboPath, parseArgs(std.testing.allocator, &argv));
}

test "rejects an invalid binary size suffix" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "sample.mzML",
        "-max-binary-size",
        "1X",
    };

    try std.testing.expectError(error.InvalidValue, parseArgs(std.testing.allocator, &argv));
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

test "parses the mmap compatibility flag" {
    const allocator = std.testing.allocator;
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "sample.mzML",
        "-mmap",
    };

    var command = try parseArgs(allocator, &argv);
    defer command.deinit(allocator);

    switch (command) {
        .check => |check| {
            try std.testing.expectEqual(validate.InputMode.mmap, check.input_mode);
            try std.testing.expect(!check.skip_binary);
            try std.testing.expectEqual(@as(usize, 1), check.inputs.len);
        },
    }
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
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "-input-mode stream|mmap") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "mmap is refused safely") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "-memory-limit") == null);
    try std.testing.expectEqualStrings("", stderr_writer.written());
}

test "version reports the mapping policy" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{ "mzValidate", "-version" };

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
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "-mmap        Compatibility alias") != null);
    try std.testing.expectEqualStrings("", stderr_writer.written());
}

test "summary reports explicit mmap refusal" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "fixtures/examples/mzml/single-spectrum-missing-cv-terms.mzML",
        "-skip-binary",
        "-skip-index",
        "-skip-semantic",
        "-input-mode",
        "mmap",
        "-summary",
    };

    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    try std.testing.expectEqual(@as(u8, 2), exit_code);
    try std.testing.expectEqualStrings(
        "incomplete: errors (info=0 warnings=0 errors=1)\n" ++
            "failure: stage=input reason=input rule=runtime.input-mode input=fixtures/examples/mzml/single-spectrum-missing-cv-terms.mzML\n" ++
            "config: input=mmap behavior=explicit\n",
        stdout_writer.written(),
    );
    try std.testing.expectEqualStrings("", stderr_writer.written());
}

test "invalid input mode reports a usage error" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{ "mzValidate", "check", "sample.mzML", "-input-mode", "auto" };

    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    try std.testing.expectEqual(@as(u8, 2), exit_code);
    try std.testing.expectEqualStrings("", stdout_writer.written());
    try std.testing.expectEqualStrings(
        "error: invalid -input-mode value 'auto' (expected stream or mmap)\n" ++
            "usage: mzValidate check <input.mzML> [more files...] [options]\n",
        stderr_writer.written(),
    );
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
            "usage: mzValidate check <input.mzML> [more files...] [options]\n",
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
    const argv = [_][]const u8{ "mzValidate", "check", "-summary" };

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

test "missing OBO path reports the correct flag" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{ "mzValidate", "check", "sample.mzML", "-obo" };

    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    try std.testing.expectEqual(@as(u8, 2), exit_code);
    try std.testing.expectEqualStrings("", stdout_writer.written());
    try std.testing.expectEqualStrings(
        "error: -obo requires a path\n" ++
            "usage: mzValidate check <input.mzML> [more files...] [options]\n",
        stderr_writer.written(),
    );
}

test "conflicting output modes report a usage error" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{ "mzValidate", "check", "sample.mzML", "-json", "-summary" };

    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    try std.testing.expectEqual(@as(u8, 2), exit_code);
    try std.testing.expectEqualStrings("", stdout_writer.written());
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.written(), "choose one of -json, -summary, or -brief") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.written(), "usage: mzValidate check") != null);
}

test "summary aggregates clean and corrupt inputs" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "fixtures/examples/mzml/single-spectrum-missing-cv-terms.mzML",
        "fixtures/mzml/invalid/invalid-base64.mzML",
        "-summary",
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
        "fixtures/mzml/valid/tiny.pwiz.1.1.mzML",
        "-skip-semantic",
        "-skip-index",
        "-json",
    };

    try expectJsonGolden(&argv, 0, "fixtures/output/json-v1-clean.json");
}

test "json contract: findings result matches golden" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "fixtures/mzml/invalid/invalid-base64.mzML",
        "-skip-semantic",
        "-json",
    };

    try expectJsonGolden(&argv, 2, "fixtures/output/json-v1-findings.json");
}

test "json contract: incomplete result matches golden" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "missing-p51.mzML",
        "-json",
    };

    try expectJsonGolden(&argv, 2, "fixtures/output/json-v1-incomplete.json");
}

test "json contract: multi-file result matches golden" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "fixtures/mzml/valid/tiny.pwiz.1.1.mzML",
        "fixtures/mzml/invalid/invalid-base64.mzML",
        "-skip-semantic",
        "-skip-index",
        "-json",
    };

    try expectJsonGolden(&argv, 2, "fixtures/output/json-v1-multi-file.json");
}

test "json contract: explicit mmap refusal is recorded" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "fixtures/mzml/valid/tiny.pwiz.1.1.mzML",
        "-skip-semantic",
        "-skip-index",
        "-input-mode",
        "mmap",
        "-json",
    };
    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    try std.testing.expectEqual(@as(u8, 2), exit_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "\"input_mode\": \"mmap\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "\"completion\": \"incomplete\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "\"rule\": \"runtime.input-mode\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "\"reason\": \"input\"") != null);
    try std.testing.expectEqualStrings("", stderr_writer.written());
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
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "error [mzml.structure.xml] DTD or unsupported XML construct") != null);
    try std.testing.expectEqualStrings("", stderr_writer.written());
}

test "text output groups clean and corrupt inputs" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "fixtures/examples/mzml/single-spectrum-missing-cv-terms.mzML",
        "fixtures/mzml/invalid/invalid-base64.mzML",
    };

    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    try std.testing.expectEqual(@as(u8, 2), exit_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "input: fixtures/mzml/invalid/invalid-base64.mzML") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "error [mzml.binary.base64] binary payload is not valid base64") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "location: byte=") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "complete: errors (info=0 warnings=0 errors=1)") != null);
    try std.testing.expectEqualStrings("", stderr_writer.written());
}

test "skipping binary checks keeps valid structure clean" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "fixtures/mzml/invalid/invalid-base64.mzML",
        "-skip-binary",
        "-summary",
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

test "summary reports each missing input failure" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "missing-a.mzML",
        "missing-b.mzML",
        "-summary",
    };

    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    try std.testing.expectEqual(@as(u8, 2), exit_code);
    try std.testing.expectEqualStrings(
        "incomplete: errors (info=0 warnings=0 errors=2)\n" ++
            "failure: stage=input reason=input rule=runtime.file-open input=missing-a.mzML\n",
        stdout_writer.written(),
    );
    try std.testing.expectEqualStrings("", stderr_writer.written());
}
