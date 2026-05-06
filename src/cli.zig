//! Command-line parsing and top-level command dispatch.

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

    if (wantsHelp(args)) {
        try writeUsage(stdout);
        return 0;
    }

    var command = parseArgs(gpa, args) catch |err| switch (err) {
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
    defer command.deinit(gpa);

    return switch (command) {
        .check => |check| try runCheck(gpa, init.io, stdout, check),
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

    var command = try parseArgs(allocator, &argv);
    defer command.deinit(allocator);

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

    try std.testing.expectError(error.ConflictingOutputMode, parseArgs(std.testing.allocator, &argv));
}

test "parseArgs_rejects_check_without_inputs_even_when_flags_are_present" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "-skip-binary",
        "-summary",
    };

    try std.testing.expectError(error.MissingInputPath, parseArgs(std.testing.allocator, &argv));
}

test "parseArgs_rejects_unknown_flag_before_any_input" {
    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "-xml",
        "sample.mzML",
    };

    try std.testing.expectError(error.UnexpectedFlag, parseArgs(std.testing.allocator, &argv));
}

test "wantsHelp_only_matches_supported_help_positions" {
    try std.testing.expect(wantsHelp(&.{"mzValidate"}));
    try std.testing.expect(wantsHelp(&.{ "mzValidate", "--help" }));
    try std.testing.expect(wantsHelp(&.{ "mzValidate", "check", "-h" }));

    try std.testing.expect(!wantsHelp(&.{ "mzValidate", "check", "sample.mzML" }));
    try std.testing.expect(!wantsHelp(&.{ "mzValidate", "check", "sample.mzML", "--help" }));
}

test "writeParseError_names_missing_input_path" {
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    try writeParseError(&allocating_writer.writer, error.MissingInputPath, &.{ "mzValidate", "check" });
    try std.testing.expectEqualStrings("error: missing input path after `check`", allocating_writer.written());
}

test "writeParseError_names_unexpected_flag" {
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    const argv = [_][]const u8{
        "mzValidate",
        "check",
        "sample.mzML",
        "-wat",
    };

    try writeParseError(&allocating_writer.writer, error.UnexpectedFlag, &argv);
    try std.testing.expectEqualStrings("error: unexpected flag: -wat", allocating_writer.written());
}

test "writeParseError_names_unsupported_command" {
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    const argv = [_][]const u8{
        "mzValidate",
        "scan",
    };

    try writeParseError(&allocating_writer.writer, error.UnsupportedCommand, &argv);
    try std.testing.expectEqualStrings("error: unsupported command: scan", allocating_writer.written());
}
