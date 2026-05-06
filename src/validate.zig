//! Validation entry points for incremental Phase 1 work.

const std = @import("std");
const diagnostic = @import("diagnostic.zig");
const structural = @import("mzml/structural.zig");
const version = @import("version.zig");

const Diagnostic = diagnostic.Diagnostic;
const RuleId = diagnostic.RuleId;

/// Controls which validation layers run for a check command.
pub const CheckOptions = struct {
    skip_binary: bool = false,
};

/// Opens a file and runs the implemented validation layers for the current phase.
pub fn checkPath(
    allocator: std.mem.Allocator,
    io: std.Io,
    diagnostics: *std.ArrayList(Diagnostic),
    path: []const u8,
    options: CheckOptions,
) !void {
    const cwd = std.Io.Dir.cwd();
    var file = cwd.openFile(io, path, .{}) catch {
        try diagnostics.append(allocator, .{
            .severity = .@"error",
            .rule = RuleId.runtime_file_open,
            .path = path,
            .message = "unable to open input file",
        });
        return;
    };
    defer file.close(io);

    var read_buffer: [4096]u8 = undefined;
    var reader = file.readerStreaming(io, &read_buffer);
    try structural.StructuralValidator.validateReader(allocator, io, &reader.interface, diagnostics, path);

    if (!options.skip_binary) {
        try diagnostics.append(allocator, .{
            .severity = .warning,
            .rule = RuleId.runtime_stub,
            .path = path,
            .message = version.validation_not_implemented,
        });
    }
}

test "checkPath_missingFile_reportsOpenError" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, "definitely-missing-file.mzML", .{});
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqual(diagnostic.Severity.@"error", diagnostics.items[0].severity);
    try std.testing.expectEqualStrings(RuleId.runtime_file_open, diagnostics.items[0].rule);
}

test "checkPath_existingFile_runsStructuralValidationWhenSkippingBinary" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/examples/mzml/clean-single-spectrum.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();

    try temp_dir.dir.writeFile(io, .{ .sub_path = "sample.mzML", .data = fixture });

    const path = try std.fs.path.join(allocator, &.{
        ".zig-cache",
        "tmp",
        temp_dir.sub_path[0..],
        "sample.mzML",
    });
    defer allocator.free(path);

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, path, .{ .skip_binary = true });
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "checkPath_existingFile_warnsOnlyAboutBinaryLayerWhenStructureIsClean" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/examples/mzml/clean-single-spectrum.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();

    try temp_dir.dir.writeFile(io, .{ .sub_path = "sample.mzML", .data = fixture });

    const path = try std.fs.path.join(allocator, &.{
        ".zig-cache",
        "tmp",
        temp_dir.sub_path[0..],
        "sample.mzML",
    });
    defer allocator.free(path);

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, path, .{});
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqual(diagnostic.Severity.warning, diagnostics.items[0].severity);
    try std.testing.expectEqualStrings(RuleId.runtime_stub, diagnostics.items[0].rule);
}

test "checkPath_existingFile_keeps_structural_errors_and_binary_warning_together" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/examples/mzml/wrong-namespace.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();

    try temp_dir.dir.writeFile(io, .{ .sub_path = "broken.mzML", .data = fixture });

    const path = try std.fs.path.join(allocator, &.{
        ".zig-cache",
        "tmp",
        temp_dir.sub_path[0..],
        "broken.mzML",
    });
    defer allocator.free(path);

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, path, .{});
    try std.testing.expectEqual(@as(usize, 2), diagnostics.items.len);
    try std.testing.expectEqual(diagnostic.Severity.@"error", diagnostics.items[0].severity);
    try std.testing.expectEqualStrings(RuleId.mzml_structure_root, diagnostics.items[0].rule);
    try std.testing.expectEqual(diagnostic.Severity.warning, diagnostics.items[1].severity);
    try std.testing.expectEqualStrings(RuleId.runtime_stub, diagnostics.items[1].rule);
}

test "checkPath_existingFile_skips_binary_warning_when_structure_is_broken_and_skip_binary_is_enabled" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/examples/mzml/wrong-namespace.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();

    try temp_dir.dir.writeFile(io, .{ .sub_path = "broken.mzML", .data = fixture });

    const path = try std.fs.path.join(allocator, &.{
        ".zig-cache",
        "tmp",
        temp_dir.sub_path[0..],
        "broken.mzML",
    });
    defer allocator.free(path);

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, path, .{ .skip_binary = true });
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqual(diagnostic.Severity.@"error", diagnostics.items[0].severity);
    try std.testing.expectEqualStrings(RuleId.mzml_structure_root, diagnostics.items[0].rule);
}
