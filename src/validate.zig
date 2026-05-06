//! Validation entry points for incremental Phase 1 work.

const std = @import("std");
const binary = @import("mzml/binary.zig");
const diagnostic = @import("diagnostic.zig");
const structural = @import("mzml/structural.zig");
const xml_events = @import("xml/events.zig");
const xml_parser = @import("xml/parser.zig");

const Attribute = xml_events.Attribute;
const Diagnostic = diagnostic.Diagnostic;
const ParseError = xml_parser.ParseError;
const RuleId = diagnostic.RuleId;
const max_validation_token_bytes = 1024 * 1024;

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
    try checkReader(allocator, io, &reader.interface, diagnostics, path, options);
}

pub fn checkReader(
    allocator: std.mem.Allocator,
    io: std.Io,
    reader: *std.Io.Reader,
    diagnostics: *std.ArrayList(Diagnostic),
    path: []const u8,
    options: CheckOptions,
) !void {
    _ = io;

    const token_buffer = try allocator.alloc(u8, max_validation_token_bytes);
    defer allocator.free(token_buffer);

    var attributes: [64]Attribute = undefined;
    var namespace_bindings: [32]xml_parser.NamespaceBinding = undefined;
    var namespace_bytes: [2048]u8 = undefined;
    var element_stack: [128]xml_parser.ElementFrame = undefined;
    var element_bytes: [4096]u8 = undefined;

    var parser = xml_parser.Parser.init(reader, .{
        .token = token_buffer,
        .attributes = &attributes,
        .namespace_bindings = &namespace_bindings,
        .namespace_bytes = &namespace_bytes,
        .element_stack = &element_stack,
        .element_bytes = &element_bytes,
    });

    var structural_validator = structural.StructuralValidator.init(allocator, diagnostics, path);
    defer structural_validator.deinit();

    var binary_validator = if (options.skip_binary) null else binary.BinaryValidator.init(allocator, diagnostics, path);
    defer if (binary_validator) |*validator| validator.deinit();

    while (true) {
        const maybe_event = parser.next() catch |err| {
            try diagnostics.append(allocator, .{
                .severity = .@"error",
                .rule = RuleId.mzml_structure_xml,
                .location = .{ .byte_offset = parser.byteOffset() },
                .path = path,
                .message = parseErrorMessage(err),
            });
            return;
        };
        const event = maybe_event orelse break;

        switch (event) {
            .start_element => |start| {
                try structural_validator.consumeStart(start);
                if (binary_validator) |*validator| try validator.consumeStart(start);
            },
            .end_element => |end| {
                try structural_validator.consumeEnd(end);
                if (binary_validator) |*validator| try validator.consumeEnd(end);
            },
            .text => |text| {
                try structural_validator.consumeText(text);
                if (binary_validator) |*validator| try validator.consumeText(text);
            },
        }
    }

    try structural_validator.finish();
    if (binary_validator) |*validator| try validator.finish();
}

fn parseErrorMessage(err: ParseError) []const u8 {
    return switch (err) {
        error.UnexpectedEof => "unexpected end of XML input",
        error.InvalidUtf8 => "invalid UTF-8 in XML input",
        error.TokenTooLong => "XML token exceeds the configured parser buffer",
        error.TooManyAttributes => "XML element has more attributes than the configured parser limit",
        error.TooManyNamespaces,
        error.NamespaceStorageExceeded,
        error.ElementNestingTooDeep,
        error.ElementStorageExceeded,
        error.MalformedXml,
        error.UnknownEntity,
        error.InvalidCharacterReference,
        error.UnsupportedMarkup,
        error.MismatchedEndTag,
        error.ReadFailed,
        => "malformed XML input",
    };
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
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "checkPath_indexedMzMLFixture_runsStructuralValidationWhenSkippingBinary" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/valid/tiny.pwiz.1.1.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();

    try temp_dir.dir.writeFile(io, .{ .sub_path = "tiny-indexed.mzML", .data = fixture });

    const path = try std.fs.path.join(allocator, &.{
        ".zig-cache",
        "tmp",
        temp_dir.sub_path[0..],
        "tiny-indexed.mzML",
    });
    defer allocator.free(path);

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, path, .{ .skip_binary = true });
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "checkPath_largeIndexedMzMLFixture_runsStructuralValidationWhenSkippingBinary" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, "fixtures/mzml/valid/small.pwiz.1.1.mzML", .{ .skip_binary = true });
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "checkPath_validMzMLCorpus_runsStructuralValidationWhenSkippingBinary" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const root = "fixtures/mzml/valid";

    var corpus_dir = try std.Io.Dir.cwd().openDir(io, root, .{ .iterate = true });
    defer corpus_dir.close(io);

    var walker = try corpus_dir.walk(allocator);
    defer walker.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var fixture_count: usize = 0;
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.path, ".mzML")) continue;

        const path = try std.fs.path.join(allocator, &.{ root, entry.path });
        defer allocator.free(path);

        diagnostics.clearRetainingCapacity();
        try checkPath(allocator, io, &diagnostics, path, .{ .skip_binary = true });
        try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
        fixture_count += 1;
    }

    try std.testing.expect(fixture_count > 0);
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
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqual(diagnostic.Severity.@"error", diagnostics.items[0].severity);
    try std.testing.expectEqualStrings(RuleId.mzml_structure_root, diagnostics.items[0].rule);
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

test "checkPath_corruptBinary_reportsBinaryDiagnostic" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/invalid/invalid-base64.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    try temp_dir.dir.writeFile(io, .{ .sub_path = "corrupt-binary.mzML", .data = fixture });

    const path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", temp_dir.sub_path[0..], "corrupt-binary.mzML" });
    defer allocator.free(path);

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, path, .{});
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_binary_base64, diagnostics.items[0].rule);
}

test "checkPath_corruptBinary_is_clean_when_skip_binary_is_enabled" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/invalid/invalid-base64.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    try temp_dir.dir.writeFile(io, .{ .sub_path = "corrupt-binary.mzML", .data = fixture });

    const path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", temp_dir.sub_path[0..], "corrupt-binary.mzML" });
    defer allocator.free(path);

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, path, .{ .skip_binary = true });
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "checkPath_reports_conflictingCompression_fixture" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, "fixtures/mzml/invalid/conflicting-compression.mzML", .{});
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_binary_compression, diagnostics.items[0].rule);
}

test "checkPath_reports_unsupportedCompression_fixture" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, "fixtures/mzml/invalid/unsupported-compression.mzML", .{});
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_binary_compression, diagnostics.items[0].rule);
}

test "checkPath_invalidMzMLBinaryCorpus_reportsDiagnosticsWithoutThrowing" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const root = "fixtures/mzml/invalid";

    var corpus_dir = try std.Io.Dir.cwd().openDir(io, root, .{ .iterate = true });
    defer corpus_dir.close(io);

    var walker = try corpus_dir.walk(allocator);
    defer walker.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var fixture_count: usize = 0;
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.path, ".mzML")) continue;

        const path = try std.fs.path.join(allocator, &.{ root, entry.path });
        defer allocator.free(path);

        diagnostics.clearRetainingCapacity();
        try checkPath(allocator, io, &diagnostics, path, .{});
        try std.testing.expect(diagnostics.items.len > 0);
        fixture_count += 1;
    }

    try std.testing.expect(fixture_count > 0);
}

test "checkPath_invalidMzMLBinaryCorpus_is_clean_when_skip_binary_is_enabled" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const root = "fixtures/mzml/invalid";

    var corpus_dir = try std.Io.Dir.cwd().openDir(io, root, .{ .iterate = true });
    defer corpus_dir.close(io);

    var walker = try corpus_dir.walk(allocator);
    defer walker.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var fixture_count: usize = 0;
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.path, ".mzML")) continue;

        const path = try std.fs.path.join(allocator, &.{ root, entry.path });
        defer allocator.free(path);

        diagnostics.clearRetainingCapacity();
        try checkPath(allocator, io, &diagnostics, path, .{ .skip_binary = true });
        try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
        fixture_count += 1;
    }

    try std.testing.expect(fixture_count > 0);
}
