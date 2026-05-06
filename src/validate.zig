//! Validation entry points for incremental Phase 1 work.

const std = @import("std");
const diagnostic = @import("diagnostic.zig");

const Diagnostic = diagnostic.Diagnostic;

pub const CheckOptions = struct {
    skip_binary: bool = false,
};

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
            .rule = "runtime.file-open",
            .path = path,
            .message = "unable to open input file",
        });
        return;
    };
    defer file.close(io);

    const message = if (options.skip_binary)
        "validation is not implemented yet in 0.0.1; -skip-binary parsed successfully"
    else
        "validation is not implemented yet in 0.0.1";

    try diagnostics.append(allocator, .{
        .severity = .warning,
        .rule = "runtime.stub",
        .path = path,
        .message = message,
    });
}

test "checkPath_missingFile_reportsOpenError" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, "definitely-missing-file.mzML", .{});
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqual(diagnostic.Severity.@"error", diagnostics.items[0].severity);
    try std.testing.expectEqualStrings("runtime.file-open", diagnostics.items[0].rule);
}

test "checkPath_existingFile_reportsStubWarning" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "sample.mzML", .data = "<mzML/>" });

    const path = try std.fs.path.join(allocator, &.{
        ".zig-cache",
        "tmp",
        tmp.sub_path[0..],
        "sample.mzML",
    });
    defer allocator.free(path);

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, path, .{ .skip_binary = true });
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqual(diagnostic.Severity.warning, diagnostics.items[0].severity);
    try std.testing.expectEqualStrings("runtime.stub", diagnostics.items[0].rule);
}
