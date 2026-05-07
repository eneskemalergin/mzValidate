//! Command-line parsing and top-level dispatch for mzValidate.

const std = @import("std");
const diagnostic = @import("diagnostic.zig");
const output = @import("output.zig");
const validate = @import("validate.zig");

const Diagnostic = diagnostic.Diagnostic;

/// Stores the parsed state for the `check` command.
pub const CheckCommand = struct {
    output_mode: output.OutputMode = .text,
    skip_binary: bool = false,
    inputs: []const []const u8,

    /// Frees command-owned allocations after dispatch.
    pub fn deinit(command: *CheckCommand, allocator: std.mem.Allocator) void {
        allocator.free(command.inputs);
        command.* = undefined;
    }
};

/// Represents the supported top-level CLI commands.
pub const Command = union(enum) {
    check: CheckCommand,

    /// Frees command-owned allocations regardless of the active variant.
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
};

const ParseArgsError = ParseError || std.mem.Allocator.Error;

/// Parses arguments, runs the selected command, and returns the process exit code.
pub fn run(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(gpa);
    defer gpa.free(args);

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_file_writer: std.Io.File.Writer = .init(.stdout(), init.io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;
    defer stdout.flush() catch {};

    var stderr_buffer: [1024]u8 = undefined;
    var stderr_file_writer: std.Io.File.Writer = .init(.stderr(), init.io, &stderr_buffer);
    const stderr = &stderr_file_writer.interface;
    defer stderr.flush() catch {};

    return runArgs(gpa, init.io, stdout, stderr, args);
}

/// Runs the CLI against a caller-provided argument slice and writers.
///
/// This keeps the process-based `run` entry point thin and gives tests a stable
/// public seam that does not depend on `std.process.Init` construction.
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

    var command = parseArgs(allocator, args) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.MissingCommand,
        error.MissingInputPath,
        error.UnsupportedCommand,
        error.UnexpectedFlag,
        error.ConflictingOutputMode,
        => {
            const parse_err: ParseError = @errorCast(err);
            try writeParseError(stderr, parse_err, args);
            try stderr.writeAll("\n\n");
            try writeUsage(stderr);
            return 2;
        },
    };
    defer command.deinit(allocator);

    return switch (command) {
        .check => |check| try runCheck(allocator, io, stdout, check),
    };
}

/// Parses CLI arguments into a command structure with owned inputs.
pub fn parseArgs(allocator: std.mem.Allocator, args: []const []const u8) ParseArgsError!Command {
    if (args.len < 2) return error.MissingCommand;
    if (!std.mem.eql(u8, args[1], "check")) return error.UnsupportedCommand;

    var input_paths: std.ArrayList([]const u8) = .empty;
    defer input_paths.deinit(allocator);

    var output_mode: output.OutputMode = .text;
    var output_mode_set = false;
    var skip_binary = false;

    for (args[2..]) |arg| {
        if (std.mem.eql(u8, arg, "-skip-binary")) {
            skip_binary = true;
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
        if (std.mem.startsWith(u8, arg, "-")) return error.UnexpectedFlag;

        try input_paths.append(allocator, arg);
    }

    if (input_paths.items.len == 0) return error.MissingInputPath;

    return .{ .check = .{
        .output_mode = output_mode,
        .skip_binary = skip_binary,
        .inputs = try input_paths.toOwnedSlice(allocator),
    } };
}

fn wantsHelp(args: []const []const u8) bool {
    if (args.len == 1) return true;
    if (args.len == 2 and isHelpFlag(args[1])) return true;
    if (args.len == 3 and std.mem.eql(u8, args[1], "check") and isHelpFlag(args[2])) return true;
    return false;
}

fn isHelpFlag(arg: []const u8) bool {
    return std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help");
}

fn runCheck(
    allocator: std.mem.Allocator,
    io: std.Io,
    writer: *std.Io.Writer,
    check: CheckCommand,
) !u8 {
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    for (check.inputs) |path| {
        try validate.checkPath(allocator, io, &diagnostics, path, .{
            .skip_binary = check.skip_binary,
        });
    }

    switch (check.output_mode) {
        .text => try output.renderText(writer, diagnostics.items),
        .json => try output.renderJson(writer, diagnostics.items),
        .summary => try output.renderSummary(writer, diagnostics.items),
    }

    return diagnostic.exitCode(diagnostics.items);
}

// Usage and parse helpers.

fn writeUsage(writer: *std.Io.Writer) std.Io.Writer.Error!void {
    try writer.writeAll(
        "mzValidate validates mzML inputs without loading the whole document into memory.\n\n" ++
            "Usage\n" ++
            "  mzValidate check <input.mzML> [more files...] [options]\n" ++
            "  mzValidate --help\n\n" ++
            "Commands\n" ++
            "  check        Validate one or more mzML inputs in a single run.\n\n" ++
            "Options\n" ++
            "  -json        Emit stable JSON diagnostics for CI and pipelines.\n" ++
            "  -summary     Emit only aggregate status and severity counts.\n" ++
            "  -skip-binary Skip binary payload checks. Structural work still runs when implemented.\n" ++
            "  -h, --help   Show this help text.\n\n" ++
            "Behavior\n" ++
            "  Every input is attempted, even if an earlier input produces diagnostics.\n" ++
            "  Text mode groups diagnostics by input path and ends with one aggregate summary.\n" ++
            "  JSON mode emits one diagnostic object per finding and keeps keys stable.\n" ++
            "  Summary mode reports the aggregate result for the whole invocation.\n\n" ++
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
        error.ConflictingOutputMode => try writer.writeAll("error: choose either -json or -summary, not both"),
    }
}

fn findUnexpectedFlag(args: []const []const u8) ?[]const u8 {
    for (args) |arg| {
        if (std.mem.startsWith(u8, arg, "-") and
            !std.mem.eql(u8, arg, "-skip-binary") and
            !std.mem.eql(u8, arg, "-json") and
            !std.mem.eql(u8, arg, "-summary") and
            !isHelpFlag(arg))
        {
            return arg;
        }
    }
    return null;
}

// Tests: argument parsing.

test "parseArgs_check_parsesFlagsAndInputs" {
    const allocator = std.testing.allocator;
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "sample-a.mzML",
        "-json",
        "-skip-binary",
        "sample-b.mzML",
    };

    // Arrange.

    // Act.
    var command = try parseArgs(allocator, &argv);
    defer command.deinit(allocator);

    // Assert.
    switch (command) {
        .check => |check| {
            try std.testing.expectEqual(output.OutputMode.json, check.output_mode);
            try std.testing.expect(check.skip_binary);
            try std.testing.expectEqual(@as(usize, 2), check.inputs.len);
            try std.testing.expectEqualStrings("sample-a.mzML", check.inputs[0]);
            try std.testing.expectEqualStrings("sample-b.mzML", check.inputs[1]);
        },
    }
}

test "parseArgs_rejects_conflicting_output_modes" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "sample.mzML",
        "-json",
        "-summary",
    };

    // Arrange.

    // Act.
    // Assert.
    try std.testing.expectError(error.ConflictingOutputMode, parseArgs(std.testing.allocator, &argv));
}

test "parseArgs_rejects_check_without_inputs_even_when_flags_are_present" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "-skip-binary",
        "-summary",
    };

    // Arrange.

    // Act.
    // Assert.
    try std.testing.expectError(error.MissingInputPath, parseArgs(std.testing.allocator, &argv));
}

test "parseArgs_rejects_unknown_flag_before_any_input" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "-xml",
        "sample.mzML",
    };

    // Arrange.

    // Act.
    // Assert.
    try std.testing.expectError(error.UnexpectedFlag, parseArgs(std.testing.allocator, &argv));
}

// Tests: public CLI execution.

test "runArgs_help_flag_writes_usage_to_stdout_and_returns_zero" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{ "mzValidate", "--help" };

    // Arrange.
    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    // Act.
    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    // Assert.
    try std.testing.expectEqual(@as(u8, 0), exit_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "Usage") != null);
    try std.testing.expectEqualStrings("", stderr_writer.written());
}

test "runArgs_check_help_flag_writes_usage_to_stdout_and_returns_zero" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{ "mzValidate", "check", "-h" };

    // Arrange.
    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    // Act.
    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    // Assert.
    try std.testing.expectEqual(@as(u8, 0), exit_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "Usage") != null);
    try std.testing.expectEqualStrings("", stderr_writer.written());
}

test "runArgs_unsupported_command_reports_parse_error_on_stderr" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{ "mzValidate", "scan" };

    // Arrange.
    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    // Act.
    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    // Assert.
    try std.testing.expectEqual(@as(u8, 2), exit_code);
    try std.testing.expectEqualStrings("", stdout_writer.written());
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.written(), "unsupported command: scan") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.written(), "Usage") != null);
}

test "runArgs_unexpected_flag_reports_parse_error_on_stderr" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{ "mzValidate", "check", "sample.mzML", "-wat" };

    // Arrange.
    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    // Act.
    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    // Assert.
    try std.testing.expectEqual(@as(u8, 2), exit_code);
    try std.testing.expectEqualStrings("", stdout_writer.written());
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.written(), "unexpected flag: -wat") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.written(), "Usage") != null);
}

test "runArgs_missing_input_path_reports_parse_error_on_stderr" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{ "mzValidate", "check", "-summary" };

    // Arrange.
    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    // Act.
    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    // Assert.
    try std.testing.expectEqual(@as(u8, 2), exit_code);
    try std.testing.expectEqualStrings("", stdout_writer.written());
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.written(), "missing input path after `check`") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.written(), "Usage") != null);
}

test "runArgs_conflicting_output_modes_returns_usage_failure_on_stderr" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{ "mzValidate", "check", "sample.mzML", "-json", "-summary" };

    // Arrange.
    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    // Act.
    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    // Assert.
    try std.testing.expectEqual(@as(u8, 2), exit_code);
    try std.testing.expectEqualStrings("", stdout_writer.written());
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.written(), "choose either -json or -summary") != null);
    try std.testing.expect(std.mem.indexOf(u8, stderr_writer.written(), "Usage") != null);
}

test "runArgs_mixed_clean_and_corrupt_inputs_reports_aggregate_error_summary" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "fixtures/examples/mzml/clean-single-spectrum.mzML",
        "fixtures/mzml/invalid/invalid-base64.mzML",
        "-summary",
    };

    // Arrange.
    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    // Act.
    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    // Assert.
    try std.testing.expectEqual(@as(u8, 2), exit_code);
    try std.testing.expectEqualStrings(
        "status=errors-present info=0 warnings=0 errors=1\n",
        stdout_writer.written(),
    );
    try std.testing.expectEqualStrings("", stderr_writer.written());
}

test "runArgs_corrupt_input_renders_json_diagnostic_shape" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "fixtures/mzml/invalid/invalid-base64.mzML",
        "-json",
    };

    // Arrange.
    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    // Act.
    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    // Assert.
    try std.testing.expectEqual(@as(u8, 2), exit_code);
    try std.testing.expect(std.mem.startsWith(u8, stdout_writer.written(), "[\n  {\n"));
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "\"rule\": \"mzml.binary.base64\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "\"path\": \"fixtures/mzml/invalid/invalid-base64.mzML\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "\"spectrum_index\": 7") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "\"message\": \"binary payload is not valid base64\"") != null);
    try std.testing.expectEqualStrings("", stderr_writer.written());
}

test "runArgs_mixed_clean_and_corrupt_inputs_render_text_grouping_and_summary" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "fixtures/examples/mzml/clean-single-spectrum.mzML",
        "fixtures/mzml/invalid/invalid-base64.mzML",
    };

    // Arrange.
    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    // Act.
    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    // Assert.
    try std.testing.expectEqual(@as(u8, 2), exit_code);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "input: fixtures/mzml/invalid/invalid-base64.mzML") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "error [mzml.binary.base64] binary payload is not valid base64") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "location: byte=") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout_writer.written(), "summary: errors-present (info=0 warnings=0 errors=1)") != null);
    try std.testing.expectEqualStrings("", stderr_writer.written());
}

test "runArgs_skip_binary_keeps_corrupt_payload_clean_when_structure_is_valid" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "fixtures/mzml/invalid/invalid-base64.mzML",
        "-skip-binary",
        "-summary",
    };

    // Arrange.
    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    // Act.
    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    // Assert.
    try std.testing.expectEqual(@as(u8, 0), exit_code);
    try std.testing.expectEqualStrings(
        "status=clean info=0 warnings=0 errors=0\n",
        stdout_writer.written(),
    );
    try std.testing.expectEqualStrings("", stderr_writer.written());
}

test "runArgs_multiple_missing_inputs_report_each_open_failure" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "missing-a.mzML",
        "missing-b.mzML",
        "-summary",
    };

    // Arrange.
    var stdout_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stdout_writer.deinit();
    var stderr_writer: std.Io.Writer.Allocating = .init(allocator);
    defer stderr_writer.deinit();

    // Act.
    const exit_code = try runArgs(allocator, io, &stdout_writer.writer, &stderr_writer.writer, &argv);

    // Assert.
    try std.testing.expectEqual(@as(u8, 2), exit_code);
    try std.testing.expectEqualStrings(
        "status=errors-present info=0 warnings=0 errors=2\n",
        stdout_writer.written(),
    );
    try std.testing.expectEqualStrings("", stderr_writer.written());
}
