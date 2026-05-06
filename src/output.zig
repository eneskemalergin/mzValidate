//! Diagnostic renderers shared by text, JSON, and summary modes.

const std = @import("std");
const diagnostic = @import("diagnostic.zig");

const Diagnostic = diagnostic.Diagnostic;

/// Selects how diagnostics are rendered for humans or CI.
pub const OutputMode = enum {
    text,
    json,
    summary,
};

/// Renders diagnostics in the default human-readable format.
pub fn renderText(writer: *std.Io.Writer, diagnostics: []const Diagnostic) std.Io.Writer.Error!void {
    if (diagnostics.len == 0) {
        try writer.writeAll("OK\n");
        return;
    }

    for (diagnostics) |item| {
        try writer.print("{s} [{s}]", .{ item.severity.label(), item.rule });
        if (item.path) |path| {
            try writer.print(" path={s}", .{path});
        }
        if (item.location.byte_offset) |byte_offset| {
            try writer.print(" byte={d}", .{byte_offset});
        }
        if (item.location.spectrum_index) |spectrum_index| {
            try writer.print(" spectrum={d}", .{spectrum_index});
        }
        try writer.print(": {s}\n", .{item.message});
    }
}

/// Renders only the severity totals.
pub fn renderSummary(writer: *std.Io.Writer, diagnostics: []const Diagnostic) std.Io.Writer.Error!void {
    const summary = diagnostic.summarize(diagnostics);
    try writer.print(
        "info={d} warnings={d} errors={d}\n",
        .{ summary.totals.info, summary.totals.warnings, summary.totals.errors },
    );
}

/// Renders diagnostics in a stable JSON shape for automation.
pub fn renderJson(writer: *std.Io.Writer, diagnostics: []const Diagnostic) std.Io.Writer.Error!void {
    try writer.writeAll("[\n");
    for (diagnostics, 0..) |item, index| {
        if (index != 0) try writer.writeAll(",\n");
        try writer.writeAll("  {\n");
        try writer.writeAll("    \"severity\": ");
        try writeJsonString(writer, item.severity.label());
        try writer.writeAll(",\n    \"rule\": ");
        try writeJsonString(writer, item.rule);
        if (item.path) |path| {
            try writer.writeAll(",\n    \"path\": ");
            try writeJsonString(writer, path);
        }
        try writer.writeAll(",\n    \"location\": {\n");
        try writer.writeAll("      \"byte_offset\": ");
        if (item.location.byte_offset) |byte_offset| {
            try writer.print("{d}", .{byte_offset});
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll(",\n      \"spectrum_index\": ");
        if (item.location.spectrum_index) |spectrum_index| {
            try writer.print("{d}", .{spectrum_index});
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll("\n    },\n    \"message\": ");
        try writeJsonString(writer, item.message);
        try writer.writeAll("\n  }");
    }
    try writer.writeAll("\n]\n");
}

fn writeJsonString(writer: *std.Io.Writer, value: []const u8) std.Io.Writer.Error!void {
    try writer.writeByte('"');
    for (value) |byte| {
        switch (byte) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (byte < 0x20) {
                    try writer.print("\\u{X:0>4}", .{byte});
                } else {
                    try writer.writeByte(byte);
                }
            },
        }
    }
    try writer.writeByte('"');
}

test "renderSummary_counts severities" {
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    const diagnostics = [_]Diagnostic{
        .{ .severity = .info, .rule = "one", .message = "one" },
        .{ .severity = .warning, .rule = "two", .message = "two" },
        .{ .severity = .@"error", .rule = "three", .message = "three" },
    };

    try renderSummary(&allocating_writer.writer, &diagnostics);
    try std.testing.expectEqualStrings("info=1 warnings=1 errors=1\n", allocating_writer.written());
}

test "renderJson_keeps stable keys" {
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    const diagnostics = [_]Diagnostic{.{
        .severity = .@"error",
        .rule = diagnostic.RuleId.mzml_binary_length_mismatch,
        .location = .{ .byte_offset = 99, .spectrum_index = 7 },
        .path = "sample.mzML",
        .message = "decoded array length does not match defaultArrayLength",
    }};
    const expected_json =
        "[\n" ++
        "  {\n" ++
        "    \"severity\": \"error\",\n" ++
        "    \"rule\": \"mzml.binary.length-mismatch\",\n" ++
        "    \"path\": \"sample.mzML\",\n" ++
        "    \"location\": {\n" ++
        "      \"byte_offset\": 99,\n" ++
        "      \"spectrum_index\": 7\n" ++
        "    },\n" ++
        "    \"message\": \"decoded array length does not match defaultArrayLength\"\n" ++
        "  }\n" ++
        "]\n";

    try renderJson(&allocating_writer.writer, &diagnostics);
    try std.testing.expectEqualStrings(expected_json, allocating_writer.written());
}
