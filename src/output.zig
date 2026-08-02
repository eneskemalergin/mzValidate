//! Renders diagnostics for humans and CI consumers.
//!
//! Text, JSON, summary, and brief modes share the same bounded result metadata.

const std = @import("std");
const diagnostic = @import("diagnostic.zig");
const version = @import("version.zig");

const Diagnostic = diagnostic.Diagnostic;
const Severity = diagnostic.Severity;

/// Selects how diagnostics are rendered for humans or CI.
pub const OutputMode = enum {
    text,
    json,
    summary,
    brief,
};

/// Writes grouped text diagnostics followed by one aggregate summary.
pub fn renderText(writer: *std.Io.Writer, diagnostics: []const Diagnostic) std.Io.Writer.Error!void {
    const summary = diagnostic.summarize(diagnostics);

    try renderTextDiagnostics(writer, diagnostics);
    try writeSummaryLine(writer, summary);
}

/// Writes text diagnostics, truncation/failure details, and per-file results.
pub fn renderTextResult(
    writer: *std.Io.Writer,
    diagnostics: []const Diagnostic,
    results: []const diagnostic.FileResult,
) std.Io.Writer.Error!void {
    const emergency = hasEmergencyFailure(results);
    const truncated = hasDiagnosticTruncation(results);
    if (diagnostics.len > 0) {
        try renderTextDiagnostics(writer, diagnostics);
    } else if (!emergency and !truncated) {
        try renderTextDiagnostics(writer, diagnostics);
    }
    for (results) |result| {
        if (hasDroppedDiagnostics(result)) {
            try renderTruncationText(writer, result.dropped_diagnostics, null);
        }
    }
    var rendered_failure = false;
    for (results) |result| {
        if (result.first_failure) |failure| {
            if (!result.failure_diagnostic_emitted) {
                try renderFailureText(writer, failure);
                rendered_failure = true;
            }
        }
    }
    if (rendered_failure) try writer.writeByte('\n');
    try writeResultBlock(writer, diagnostic.summarizeResults(results));
}

/// Writes one file's text diagnostics and any retained failure metadata.
pub fn renderTextFile(
    writer: *std.Io.Writer,
    diagnostics: []const Diagnostic,
    result: *const diagnostic.FileResult,
    path: []const u8,
) std.Io.Writer.Error!void {
    var rendered = false;
    if (diagnostics.len > 0) {
        try renderTextDiagnostics(writer, diagnostics);
        rendered = true;
    }
    if (hasDroppedDiagnostics(result.*)) {
        try renderTruncationText(writer, result.dropped_diagnostics, path);
        rendered = true;
    }
    if (result.needsEmergencyDiagnostic()) {
        if (rendered) try writer.writeByte('\n');
        try renderFailureText(writer, result.first_failure.?);
        try writer.writeByte('\n');
    }
}

/// Writes the final text result block for an invocation.
pub fn renderTextFinal(
    writer: *std.Io.Writer,
    summary: diagnostic.Summary,
) std.Io.Writer.Error!void {
    if (summary.totals.info == 0 and summary.totals.warnings == 0 and summary.totals.errors == 0) {
        try writer.writeAll("OK: no diagnostics emitted\n\n");
    }
    try writeResultBlock(writer, summary);
}

fn renderTextDiagnostics(writer: *std.Io.Writer, diagnostics: []const Diagnostic) std.Io.Writer.Error!void {
    if (diagnostics.len == 0) {
        try writer.writeAll("OK: no diagnostics emitted\n\n");
        return;
    }

    var current_path: ?[]const u8 = null;
    for (diagnostics) |item| {
        const item_path = item.path;
        if (item_path) |path| {
            if (current_path == null or !std.mem.eql(u8, current_path.?, path)) {
                if (current_path != null) try writer.writeByte('\n');
                try writer.print("input: {s}\n", .{path});
                current_path = path;
            }
        } else if (current_path != null) {
            try writer.writeByte('\n');
            current_path = null;
        }

        try writer.print("  {s} [{s}] {s}\n", .{ item.severity.label(), item.rule, item.message });

        if (item.location.byte_offset != null or item.location.spectrum_index != null) {
            try writer.writeAll("    location:");
            if (item.location.byte_offset) |byte_offset| {
                try writer.print(" byte={d}", .{byte_offset});
            }
            if (item.location.spectrum_index) |spectrum_index| {
                try writer.print(" spectrum={d}", .{spectrum_index});
            }
            try writer.writeByte('\n');
        }
    }

    try writer.writeByte('\n');
}

/// Writes severity counts and the machine-oriented status label.
pub fn renderSummary(writer: *std.Io.Writer, diagnostics: []const Diagnostic) std.Io.Writer.Error!void {
    const summary = diagnostic.summarize(diagnostics);
    try writer.print(
        "status={s} info={d} warnings={d} errors={d}\n",
        .{
            summary.status().label(),
            summary.totals.info,
            summary.totals.warnings,
            summary.totals.errors,
        },
    );
}

/// Writes completion, severity, and failure metadata.
pub fn renderSummaryResult(
    writer: *std.Io.Writer,
    summary: diagnostic.Summary,
) std.Io.Writer.Error!void {
    try writeResultBlock(writer, summary);
}

/// Groups diagnostics by severity+rule+message and prints compact counts.
/// Columns auto-adjust to content width. Zero heap allocation.
/// Groups are sorted: errors first (by count desc), then warnings, then info.
pub fn renderBrief(writer: *std.Io.Writer, diagnostics: []const Diagnostic) std.Io.Writer.Error!void {
    const summary = diagnostic.summarize(diagnostics);
    try writer.print("status={s} info={d} warnings={d} errors={d}\n", .{
        summary.status().label(),
        summary.totals.info,
        summary.totals.warnings,
        summary.totals.errors,
    });
    if (diagnostics.len == 0) return;
    try renderBriefGroups(writer, diagnostics);
}

/// Fixed-capacity grouping state holding borrowed rule and message slices.
/// Borrowed text must outlive the final call to `render`.
pub const BriefGroups = struct {
    const max_groups = 256;

    severity: [max_groups]Severity = undefined,
    rule: [max_groups][]const u8 = undefined,
    message: [max_groups][]const u8 = undefined,
    count: [max_groups]usize = undefined,
    length: usize = 0,
    dropped: usize = 0,

    /// Adds a diagnostic to the bounded grouping table without allocating.
    pub fn add(groups: *BriefGroups, item: Diagnostic) void {
        for (0..groups.length) |i| {
            if (groups.severity[i] == item.severity and
                std.mem.eql(u8, groups.rule[i], item.rule) and
                std.mem.eql(u8, groups.message[i], item.message))
            {
                groups.count[i] = std.math.add(usize, groups.count[i], 1) catch std.math.maxInt(usize);
                return;
            }
        }
        if (groups.length >= max_groups) {
            groups.dropped = std.math.add(usize, groups.dropped, 1) catch std.math.maxInt(usize);
            return;
        }
        const next_length = std.math.add(usize, groups.length, 1) catch {
            groups.dropped = std.math.maxInt(usize);
            return;
        };
        const index = groups.length;
        groups.severity[index] = item.severity;
        groups.rule[index] = item.rule;
        groups.message[index] = item.message;
        groups.count[index] = 1;
        groups.length = next_length;
    }

    /// Sorts groups by severity and count, then writes the aligned table.
    pub fn render(groups: *BriefGroups, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        if (groups.length == 0) return;

        for (1..groups.length) |i| {
            var j = i;
            while (j > 0) : (j -= 1) {
                const a = @intFromEnum(groups.severity[j]);
                const b = @intFromEnum(groups.severity[j - 1]);
                const swap = if (a != b) a > b else groups.count[j] > groups.count[j - 1];
                if (!swap) break;
                std.mem.swap(Severity, &groups.severity[j], &groups.severity[j - 1]);
                std.mem.swap([]const u8, &groups.rule[j], &groups.rule[j - 1]);
                std.mem.swap([]const u8, &groups.message[j], &groups.message[j - 1]);
                std.mem.swap(usize, &groups.count[j], &groups.count[j - 1]);
            }
        }

        var count_width: usize = 1;
        var severity_width: usize = 0;
        var rule_width: usize = 0;
        for (0..groups.length) |i| {
            var n = groups.count[i];
            var width: usize = 1;
            while (n >= 10) : (n /= 10) width += 1;
            if (width > count_width) count_width = width;
            severity_width = @max(severity_width, groups.severity[i].label().len);
            rule_width = @max(rule_width, groups.rule[i].len);
        }

        try writer.writeByte('\n');
        for (0..groups.length) |i| {
            var n = groups.count[i];
            var width: usize = 1;
            while (n >= 10) : (n /= 10) width += 1;
            for (0..count_width - width) |_| try writer.writeByte(' ');
            try writer.print("{d}  ", .{groups.count[i]});
            try writer.writeAll(groups.severity[i].label());
            for (0..severity_width - groups.severity[i].label().len) |_| try writer.writeByte(' ');
            try writer.writeAll("  ");
            try writer.writeAll(groups.rule[i]);
            for (0..rule_width - groups.rule[i].len) |_| try writer.writeByte(' ');
            try writer.writeAll("  ");
            try writer.writeAll(groups.message[i]);
            try writer.writeByte('\n');
        }
        if (groups.dropped > 0) {
            try writer.print("... and {d} more unique diagnostic groups (brief limit)\n", .{groups.dropped});
        }
    }
};

fn renderBriefGroups(writer: *std.Io.Writer, diagnostics: []const Diagnostic) std.Io.Writer.Error!void {
    var groups: BriefGroups = .{};
    for (diagnostics) |item| groups.add(item);
    try groups.render(writer);
}

/// Writes a result block followed by grouped diagnostics and truncation details.
pub fn renderBriefResult(
    writer: *std.Io.Writer,
    diagnostics: []const Diagnostic,
    results: []const diagnostic.FileResult,
) std.Io.Writer.Error!void {
    try writeResultBlock(writer, diagnostic.summarizeResults(results));
    try renderEmergencyFailures(writer, results);
    if (diagnostics.len > 0) try renderBriefGroups(writer, diagnostics);
    for (results) |result| {
        if (hasDroppedDiagnostics(result)) try renderTruncationText(writer, result.dropped_diagnostics, null);
    }
}

/// Writes a result block using groups accumulated by the caller.
pub fn renderBriefGroupsResult(
    writer: *std.Io.Writer,
    groups: *BriefGroups,
    summary: diagnostic.Summary,
) std.Io.Writer.Error!void {
    try writeResultBlock(writer, summary);
    if (summary.first_emergency_failure) |failure| {
        try renderFailureText(writer, failure);
        if (summary.emergency_failures > 1) {
            try writer.print("... and {d} more emergency failures\n", .{summary.emergency_failures - 1});
        }
        try writer.writeByte('\n');
    }
    if (groups.length > 0) try groups.render(writer);
    if (hasDroppedTotals(summary.dropped_diagnostics)) {
        try renderTruncationText(writer, summary.dropped_diagnostics, null);
    }
}

/// Writes one complete JSON report using the current schema version.
pub fn renderJsonResult(
    writer: *std.Io.Writer,
    diagnostics: []const Diagnostic,
    result: *const diagnostic.FileResult,
    path: []const u8,
) std.Io.Writer.Error!void {
    var stream = try JsonStream.init(writer);
    try stream.writeFile(diagnostics, result, path);
    try stream.finish();
}

/// Incrementally writes one versioned report without retaining file diagnostics.
pub const JsonStream = struct {
    writer: *std.Io.Writer,
    first_file: bool = true,
    summary: diagnostic.Summary = .{},

    /// Writes the report header and borrows the supplied writer.
    pub fn init(writer: *std.Io.Writer) std.Io.Writer.Error!JsonStream {
        try writer.print("{{\n  \"schema_version\": {d},\n  \"files\": [", .{version.json_schema});
        return .{ .writer = writer };
    }

    /// Appends one file result and its bounded diagnostic detail.
    pub fn writeFile(
        stream: *JsonStream,
        diagnostics: []const Diagnostic,
        result: *const diagnostic.FileResult,
        path: []const u8,
    ) std.Io.Writer.Error!void {
        stream.summary.addResult(result.*);
        if (!stream.first_file) try stream.writer.writeByte(',');
        try stream.writer.writeAll("\n    {\n      \"path\": ");
        try writeJsonString(stream.writer, path);
        try stream.writer.writeAll(",\n      \"completion\": ");
        try writeJsonString(stream.writer, result.completion.label());
        try stream.writer.writeAll(",\n      \"status\": ");
        try writeJsonString(stream.writer, result.status().label());
        try stream.writer.writeAll(",\n      \"totals\": ");
        try writeJsonTotals(stream.writer, result.totals);
        try stream.writer.print(
            ",\n      \"diagnostics_truncated\": {},\n      \"dropped_diagnostics\": ",
            .{result.diagnostics_truncated},
        );
        try writeJsonTotals(stream.writer, result.dropped_diagnostics);
        try stream.writer.writeAll(",\n      \"first_failure\": ");
        try writeJsonFirstFailure(stream.writer, result.first_failure, 8);
        try stream.writer.writeAll(",\n      \"diagnostics\": ");
        try writeJsonDiagnostics(stream.writer, diagnostics, result, path);
        try stream.writer.writeAll("\n    }");
        stream.first_file = false;
    }

    /// Writes the aggregate summary and closes the report.
    pub fn finish(stream: *JsonStream) std.Io.Writer.Error!void {
        if (!stream.first_file) try stream.writer.writeByte('\n');
        try stream.writer.writeAll("  ],\n  \"summary\": ");
        try writeJsonSummary(stream.writer, stream.summary);
        try stream.writer.writeAll("\n}\n");
    }
};

fn writeJsonDiagnostics(
    writer: *std.Io.Writer,
    diagnostics: []const Diagnostic,
    result: *const diagnostic.FileResult,
    path: []const u8,
) std.Io.Writer.Error!void {
    const emergency = result.needsEmergencyDiagnostic();
    const truncated = hasDroppedDiagnostics(result.*);
    if (diagnostics.len == 0 and !emergency and !truncated) {
        try writer.writeAll("[]");
        return;
    }

    try writer.writeAll("[\n");
    var first = true;
    for (diagnostics) |item| {
        if (!first) try writer.writeAll(",\n");
        try writeJsonDiagnostic(writer, item, 8);
        first = false;
    }
    if (emergency) {
        const failure = result.first_failure.?;
        if (!first) try writer.writeAll(",\n");
        try writeJsonDiagnostic(writer, .{
            .severity = .@"error",
            .rule = failure.rule(),
            .location = failure.location,
            .path = failure.path(),
            .message = failure.message(),
        }, 8);
        first = false;
    }
    if (truncated) {
        if (!first) try writer.writeAll(",\n");
        try writeJsonTruncation(writer, result.dropped_diagnostics, path, 8);
    }
    try writer.writeAll("\n      ]");
}

fn writeJsonDiagnostic(writer: *std.Io.Writer, item: Diagnostic, indent: usize) std.Io.Writer.Error!void {
    try writeIndent(writer, indent);
    try writer.writeAll("{\n");
    try writeIndent(writer, indent + 2);
    try writer.writeAll("\"severity\": ");
    try writeJsonString(writer, item.severity.label());
    try writer.writeAll(",\n");
    try writeIndent(writer, indent + 2);
    try writer.writeAll("\"rule\": ");
    try writeJsonString(writer, item.rule);
    if (item.path) |path| {
        try writer.writeAll(",\n");
        try writeIndent(writer, indent + 2);
        try writer.writeAll("\"path\": ");
        try writeJsonString(writer, path);
    }
    try writer.writeAll(",\n");
    try writeIndent(writer, indent + 2);
    try writer.writeAll("\"location\": ");
    try writeJsonLocation(writer, item.location);
    try writer.writeAll(",\n");
    try writeIndent(writer, indent + 2);
    try writer.writeAll("\"message\": ");
    try writeJsonString(writer, item.message);
    try writer.writeByte('\n');
    try writeIndent(writer, indent);
    try writer.writeByte('}');
}

fn writeJsonTruncation(
    writer: *std.Io.Writer,
    dropped: diagnostic.Totals,
    path: []const u8,
    indent: usize,
) std.Io.Writer.Error!void {
    try writeIndent(writer, indent);
    try writer.writeAll("{\n");
    try writeIndent(writer, indent + 2);
    try writer.writeAll("\"severity\": \"warning\",\n");
    try writeIndent(writer, indent + 2);
    try writer.writeAll("\"rule\": ");
    try writeJsonString(writer, diagnostic.RuleId.runtime_diagnostics_truncated);
    try writer.writeAll(",\n");
    try writeIndent(writer, indent + 2);
    try writer.writeAll("\"path\": ");
    try writeJsonString(writer, path);
    try writer.writeAll(",\n");
    try writeIndent(writer, indent + 2);
    try writer.writeAll("\"location\": {\"byte_offset\": null, \"spectrum_index\": null},\n");
    try writeIndent(writer, indent + 2);
    try writer.writeAll("\"message\": \"diagnostic detail truncated (dropped info=");
    try writer.print("{d}", .{dropped.info});
    try writer.writeAll(" warnings=");
    try writer.print("{d}", .{dropped.warnings});
    try writer.writeAll(" errors=");
    try writer.print("{d}", .{dropped.errors});
    try writer.writeAll(")\"\n");
    try writeIndent(writer, indent);
    try writer.writeByte('}');
}

fn writeJsonSummary(writer: *std.Io.Writer, summary: diagnostic.Summary) std.Io.Writer.Error!void {
    try writer.writeAll("{\n    \"completion\": ");
    try writeJsonString(writer, summary.completion.label());
    try writer.writeAll(",\n    \"status\": ");
    try writeJsonString(writer, summary.status().label());
    try writer.print(",\n    \"files\": {d},\n    \"incomplete_files\": {d},\n    \"totals\": ", .{
        summary.files,
        summary.incomplete_files,
    });
    try writeJsonTotals(writer, summary.totals);
    try writer.print(
        ",\n    \"diagnostics_truncated\": {},\n    \"dropped_diagnostics\": ",
        .{summary.diagnostics_truncated},
    );
    try writeJsonTotals(writer, summary.dropped_diagnostics);
    try writer.writeAll(",\n    \"first_failure\": ");
    try writeJsonFirstFailure(writer, summary.first_failure, 6);
    try writer.writeAll("\n  }");
}

fn writeJsonFirstFailure(
    writer: *std.Io.Writer,
    maybe_failure: ?diagnostic.FirstFailure,
    indent: usize,
) std.Io.Writer.Error!void {
    const failure = maybe_failure orelse {
        try writer.writeAll("null");
        return;
    };
    try writer.writeAll("{\n");
    try writeIndent(writer, indent);
    try writer.writeAll("\"stage\": ");
    try writeJsonString(writer, failure.stage.label());
    try writer.writeAll(",\n");
    try writeIndent(writer, indent);
    try writer.writeAll("\"reason\": ");
    try writeJsonString(writer, failure.reason.label());
    try writer.writeAll(",\n");
    try writeIndent(writer, indent);
    try writer.writeAll("\"rule\": ");
    try writeJsonString(writer, failure.rule());
    try writer.writeAll(",\n");
    try writeIndent(writer, indent);
    try writer.writeAll("\"message\": ");
    try writeJsonString(writer, failure.message());
    try writer.writeAll(",\n");
    try writeIndent(writer, indent);
    try writer.writeAll("\"path\": ");
    if (failure.path()) |path| {
        try writeJsonString(writer, path);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\n");
    try writeIndent(writer, indent);
    try writer.writeAll("\"location\": ");
    try writeJsonLocation(writer, failure.location);
    try writer.writeByte('\n');
    try writeIndent(writer, indent - 2);
    try writer.writeByte('}');
}

fn writeJsonTotals(writer: *std.Io.Writer, totals: diagnostic.Totals) std.Io.Writer.Error!void {
    try writer.print("{{\"info\": {d}, \"warnings\": {d}, \"errors\": {d}}}", .{
        totals.info,
        totals.warnings,
        totals.errors,
    });
}

fn writeJsonLocation(writer: *std.Io.Writer, location: diagnostic.Location) std.Io.Writer.Error!void {
    try writer.writeAll("{\"byte_offset\": ");
    if (location.byte_offset) |byte_offset| {
        try writer.print("{d}", .{byte_offset});
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(", \"spectrum_index\": ");
    if (location.spectrum_index) |spectrum_index| {
        try writer.print("{d}", .{spectrum_index});
    } else {
        try writer.writeAll("null");
    }
    try writer.writeByte('}');
}

fn writeIndent(writer: *std.Io.Writer, count: usize) std.Io.Writer.Error!void {
    const spaces = "                ";
    try writer.writeAll(spaces[0..count]);
}

fn writeJsonString(writer: *std.Io.Writer, value: []const u8) std.Io.Writer.Error!void {
    try writer.writeByte('"');
    var index: usize = 0;
    while (index < value.len) {
        const byte = value[index];
        if (byte < 0x80) {
            try writeJsonAsciiByte(writer, byte);
            index += 1;
            continue;
        }

        const sequence_len = std.unicode.utf8ByteSequenceLength(byte) catch {
            try writer.writeAll("\\uFFFD");
            index += 1;
            continue;
        };
        const length: usize = sequence_len;
        if (value.len - index < length or !std.unicode.utf8ValidateSlice(value[index..][0..length])) {
            try writer.writeAll("\\uFFFD");
            index += 1;
            continue;
        }

        try writer.writeAll(value[index..][0..length]);
        index += length;
    }
    try writer.writeByte('"');
}

fn writeJsonAsciiByte(writer: *std.Io.Writer, byte: u8) std.Io.Writer.Error!void {
    switch (byte) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        '\n' => try writer.writeAll("\\n"),
        '\r' => try writer.writeAll("\\r"),
        '\t' => try writer.writeAll("\\t"),
        else => if (byte < 0x20) {
            try writer.print("\\u{X:0>4}", .{byte});
        } else {
            try writer.writeByte(byte);
        },
    }
}

fn writeSummaryLine(writer: *std.Io.Writer, summary: diagnostic.Summary) std.Io.Writer.Error!void {
    try writer.print(
        "summary: {s} (info={d} warnings={d} errors={d})\n",
        .{
            summary.status().label(),
            summary.totals.info,
            summary.totals.warnings,
            summary.totals.errors,
        },
    );
}

fn writeResultBlock(
    writer: *std.Io.Writer,
    summary: diagnostic.Summary,
) std.Io.Writer.Error!void {
    try writer.print("{s}: {s} (info={d} warnings={d} errors={d})\n", .{
        summary.completion.label(),
        humanStatusLabel(summary.status()),
        summary.totals.info,
        summary.totals.warnings,
        summary.totals.errors,
    });
    if (summary.first_failure) |failure| {
        try writer.print("failure: stage={s} reason={s} rule={s}", .{ failure.stage.label(), failure.reason.label(), failure.rule() });
        if (failure.path()) |path| try writer.print(" input={s}", .{path});
        try writer.writeByte('\n');
    }
}

fn humanStatusLabel(status: diagnostic.ResultStatus) []const u8 {
    return switch (status) {
        .clean => "clean",
        .warnings_only => "warnings",
        .errors_present => "errors",
    };
}

fn renderFailureText(writer: *std.Io.Writer, failure: diagnostic.FirstFailure) std.Io.Writer.Error!void {
    if (failure.path()) |path| try writer.print("input: {s}\n", .{path});
    try writer.print(
        "  error [{s}] {s} (stage={s} reason={s})\n",
        .{ failure.rule(), failure.message(), failure.stage.label(), failure.reason.label() },
    );
}

fn renderEmergencyFailures(writer: *std.Io.Writer, results: []const diagnostic.FileResult) std.Io.Writer.Error!void {
    var rendered = false;
    for (results) |result| {
        if (!result.needsEmergencyDiagnostic()) continue;
        try renderFailureText(writer, result.first_failure.?);
        rendered = true;
    }
    if (rendered) try writer.writeByte('\n');
}

fn renderTruncationText(writer: *std.Io.Writer, dropped: diagnostic.Totals, path: ?[]const u8) std.Io.Writer.Error!void {
    if (path) |input| try writer.print("input: {s}\n", .{input});
    try writer.print(
        "  warning [{s}] diagnostic detail truncated (dropped info={d} warnings={d} errors={d})\n",
        .{
            diagnostic.RuleId.runtime_diagnostics_truncated,
            dropped.info,
            dropped.warnings,
            dropped.errors,
        },
    );
}

fn hasDroppedDiagnostics(result: diagnostic.FileResult) bool {
    return hasDroppedTotals(result.dropped_diagnostics);
}

fn hasDroppedTotals(totals: diagnostic.Totals) bool {
    return totals.info != 0 or totals.warnings != 0 or totals.errors != 0;
}

fn hasDiagnosticTruncation(results: []const diagnostic.FileResult) bool {
    for (results) |result| {
        if (hasDroppedDiagnostics(result)) return true;
    }
    return false;
}

fn hasEmergencyFailure(results: []const diagnostic.FileResult) bool {
    for (results) |result| {
        if (result.needsEmergencyDiagnostic()) return true;
    }
    return false;
}

// --- Unit Tests ---

test "summary reports severity counts" {
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    const diagnostics = [_]Diagnostic{
        .{ .severity = .info, .rule = "one", .message = "one" },
        .{ .severity = .warning, .rule = "two", .message = "two" },
        .{ .severity = .@"error", .rule = "three", .message = "three" },
    };

    try renderSummary(&allocating_writer.writer, &diagnostics);

    try std.testing.expectEqualStrings(
        "status=errors-present info=1 warnings=1 errors=1\n",
        allocating_writer.written(),
    );
}

test "summary result reports incomplete failure" {
    var result = diagnostic.FileResult.init(diagnostic.stageBit(.parser));
    result.recordFailure(.parser, .parser, diagnostic.RuleId.runtime_incomplete, "validation stopped", .{}, "sample.mzML", false);
    result.finalize(&.{});
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    try renderSummaryResult(&allocating_writer.writer, diagnostic.summarizeResults(&.{result}));

    try std.testing.expectEqualStrings(
        "incomplete: errors (info=0 warnings=0 errors=1)\n" ++
            "failure: stage=parser reason=parser rule=runtime.incomplete input=sample.mzML\n",
        allocating_writer.written(),
    );
}

test "summary result uses human warning status" {
    var result = diagnostic.FileResult.init(0);
    const diagnostics = [_]Diagnostic{
        .{ .severity = .info, .rule = "test.info", .message = "note" },
        .{ .severity = .info, .rule = "test.info", .message = "note" },
        .{ .severity = .warning, .rule = "test.warning", .message = "warning" },
    };
    result.finalize(&diagnostics);

    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    try renderSummaryResult(&allocating_writer.writer, diagnostic.summarizeResults(&.{result}));

    try std.testing.expectEqualStrings(
        "complete: warnings (info=2 warnings=1 errors=0)\n",
        allocating_writer.written(),
    );
}

test "[unit]: text result emits emergency failure" {
    var result = diagnostic.FileResult.init(diagnostic.stageBit(.parser));
    result.recordFailure(.parser, .allocation, diagnostic.RuleId.runtime_incomplete, "validation stopped", .{}, "sample.mzML", false);
    result.finalize(&.{});

    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    try renderTextResult(&allocating_writer.writer, &.{}, &.{result});

    try std.testing.expectEqualStrings(
        "input: sample.mzML\n" ++
            "  error [runtime.incomplete] validation stopped (stage=parser reason=allocation)\n\n" ++
            "incomplete: errors (info=0 warnings=0 errors=1)\n" ++
            "failure: stage=parser reason=allocation rule=runtime.incomplete input=sample.mzML\n",
        allocating_writer.written(),
    );
}

test "[unit]: per-file text renderer emits emergency failure" {
    var result = diagnostic.FileResult.init(diagnostic.stageBit(.parser));
    result.recordFailure(.parser, .allocation, diagnostic.RuleId.runtime_incomplete, "validation stopped", .{}, "sample.mzML", false);
    result.finalize(&.{});

    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    try renderTextFile(&allocating_writer.writer, &.{}, &result, "sample.mzML");

    try std.testing.expectEqualStrings(
        "input: sample.mzML\n" ++
            "  error [runtime.incomplete] validation stopped (stage=parser reason=allocation)\n\n",
        allocating_writer.written(),
    );
}

test "json result emits emergency failure" {
    var result = diagnostic.FileResult.init(diagnostic.stageBit(.parser));
    result.recordFailure(.parser, .allocation, diagnostic.RuleId.runtime_incomplete, "validation stopped", .{}, "sample.mzML", false);
    result.finalize(&.{});

    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    try renderJsonResult(&allocating_writer.writer, &.{}, &result, "sample.mzML");

    try std.testing.expect(std.mem.indexOf(u8, allocating_writer.written(), "\"rule\": \"runtime.incomplete\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, allocating_writer.written(), "\"path\": \"sample.mzML\"") != null);
}

test "json output keeps rule IDs separate from messages" {
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    const diagnostics = [_]Diagnostic{.{
        .severity = .@"error",
        .rule = diagnostic.RuleId.mzml_binary_length_mismatch,
        .location = .{ .byte_offset = 99, .spectrum_index = 7 },
        .path = "sample.mzML",
        .message = "decoded array length does not match defaultArrayLength",
    }};
    var result = diagnostic.FileResult.init(0);
    result.finalize(&diagnostics);

    try renderJsonResult(&allocating_writer.writer, &diagnostics, &result, "sample.mzML");

    try std.testing.expect(std.mem.indexOf(u8, allocating_writer.written(), "\"schema_version\": 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, allocating_writer.written(), "\"rule\": \"mzml.binary.length-mismatch\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, allocating_writer.written(), "\"message\": \"decoded array length does not match defaultArrayLength\"") != null);
}

test "text output groups diagnostics by input" {
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    const diagnostics = [_]Diagnostic{
        .{
            .severity = .warning,
            .rule = diagnostic.RuleId.runtime_stub,
            .path = "sample-a.mzML",
            .message = "stubbed warning message",
        },
        .{
            .severity = .@"error",
            .rule = diagnostic.RuleId.runtime_file_open,
            .path = "sample-b.mzML",
            .location = .{ .byte_offset = 12 },
            .message = "unable to open input file",
        },
    };

    try renderText(&allocating_writer.writer, &diagnostics);

    try std.testing.expectEqualStrings(
        "input: sample-a.mzML\n" ++
            "  warning [runtime.stub] stubbed warning message\n" ++
            "\n" ++
            "input: sample-b.mzML\n" ++
            "  error [runtime.file-open] unable to open input file\n" ++
            "    location: byte=12\n" ++
            "\n" ++
            "summary: errors-present (info=0 warnings=1 errors=1)\n",
        allocating_writer.written(),
    );
}

test "text output separates pathless diagnostics" {
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    const diagnostics = [_]Diagnostic{.{
        .severity = .info,
        .rule = "meta.note",
        .message = "standalone note",
    }};

    try renderText(&allocating_writer.writer, &diagnostics);

    try std.testing.expectEqualStrings(
        "  info [meta.note] standalone note\n" ++
            "\n" ++
            "summary: clean (info=1 warnings=0 errors=0)\n",
        allocating_writer.written(),
    );
}

test "text output separates pathless diagnostics from the previous input" {
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    const diagnostics = [_]Diagnostic{
        .{ .severity = .warning, .rule = "runtime.warning", .path = "sample.mzML", .message = "warning" },
        .{ .severity = .info, .rule = "meta.note", .message = "standalone note" },
    };

    try renderText(&allocating_writer.writer, &diagnostics);

    try std.testing.expectEqualStrings(
        "input: sample.mzML\n" ++
            "  warning [runtime.warning] warning\n" ++
            "\n" ++
            "  info [meta.note] standalone note\n" ++
            "\n" ++
            "summary: warnings-only (info=1 warnings=1 errors=0)\n",
        allocating_writer.written(),
    );
}

test "json output escapes control characters" {
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    const diagnostics = [_]Diagnostic{.{
        .severity = .warning,
        .rule = "runtime.escape-test",
        .message = "quote=\" slash=\\ line=\n tab=\t raw=\x01",
    }};
    var result = diagnostic.FileResult.init(0);
    result.finalize(&diagnostics);

    try renderJsonResult(&allocating_writer.writer, &diagnostics, &result, "escape.mzML");

    try std.testing.expect(std.mem.indexOf(u8, allocating_writer.written(), "\"message\": \"quote=\\\" slash=\\\\ line=\\n tab=\\t raw=\\u0001\"") != null);
}

test "json output replaces invalid UTF-8" {
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    const diagnostics = [_]Diagnostic{.{
        .severity = .warning,
        .rule = "runtime.invalid-utf8",
        .message = "bad\xffvalue",
    }};
    var result = diagnostic.FileResult.init(0);
    result.finalize(&diagnostics);

    try renderJsonResult(&allocating_writer.writer, &diagnostics, &result, "invalid-utf8.mzML");

    try std.testing.expect(std.mem.indexOf(u8, allocating_writer.written(), "\"message\": \"bad\\uFFFDvalue\"") != null);
}

test "empty brief groups render no rows" {
    var groups: BriefGroups = .{};
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    try groups.render(&allocating_writer.writer);

    try std.testing.expectEqualStrings("", allocating_writer.written());
}

test "brief result emits emergency failure" {
    var result = diagnostic.FileResult.init(diagnostic.stageBit(.parser));
    result.recordFailure(.parser, .allocation, diagnostic.RuleId.runtime_incomplete, "validation stopped", .{}, "sample.mzML", false);
    result.finalize(&.{});

    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    try renderBriefResult(&allocating_writer.writer, &.{}, &.{result});

    try std.testing.expect(std.mem.indexOf(u8, allocating_writer.written(), "runtime.incomplete") != null);
    try std.testing.expect(std.mem.indexOf(u8, allocating_writer.written(), "stage=parser reason=allocation") != null);
}

test "[unit]: pre-grouped brief renderer emits emergency failure" {
    var result = diagnostic.FileResult.init(diagnostic.stageBit(.parser));
    result.recordFailure(.parser, .allocation, diagnostic.RuleId.runtime_incomplete, "validation stopped", .{}, "sample.mzML", false);
    result.finalize(&.{});
    var groups: BriefGroups = .{};

    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    try renderBriefGroupsResult(
        &allocating_writer.writer,
        &groups,
        diagnostic.summarizeResults(&.{result}),
    );

    try std.testing.expectEqualStrings(
        "incomplete: errors (info=0 warnings=0 errors=1)\n" ++
            "failure: stage=parser reason=allocation rule=runtime.incomplete input=sample.mzML\n" ++
            "input: sample.mzML\n" ++
            "  error [runtime.incomplete] validation stopped (stage=parser reason=allocation)\n\n",
        allocating_writer.written(),
    );
}

test "[unit]: brief summary counts emergency failures without retaining results" {
    var first = diagnostic.FileResult.init(diagnostic.stageBit(.parser));
    first.recordEmergencyFailure(.parser, .allocation, "first.mzML");
    first.finalize(&.{});
    var second = diagnostic.FileResult.init(diagnostic.stageBit(.parser));
    second.recordEmergencyFailure(.parser, .allocation, "second.mzML");
    second.finalize(&.{});
    var groups: BriefGroups = .{};
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    try renderBriefGroupsResult(
        &allocating_writer.writer,
        &groups,
        diagnostic.summarizeResults(&.{ first, second }),
    );

    try std.testing.expect(std.mem.indexOf(u8, allocating_writer.written(), "input=first.mzML") != null);
    try std.testing.expect(std.mem.indexOf(u8, allocating_writer.written(), "... and 1 more emergency failures") != null);
    try std.testing.expect(std.mem.indexOf(u8, allocating_writer.written(), "input: second.mzML") == null);
}

test "[unit]: brief summary reports aggregate dropped totals" {
    var groups: BriefGroups = .{};
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();
    const summary = diagnostic.Summary{
        .totals = .{ .warnings = 3, .errors = 4 },
        .diagnostics_truncated = true,
        .dropped_diagnostics = .{ .warnings = 2, .errors = 3 },
    };

    try renderBriefGroupsResult(&allocating_writer.writer, &groups, summary);

    try std.testing.expectEqualStrings(
        "complete: errors (info=0 warnings=3 errors=4)\n" ++
            "  warning [runtime.diagnostics-truncated] diagnostic detail truncated (dropped info=0 warnings=2 errors=3)\n",
        allocating_writer.written(),
    );
}

test "bounded output reports dropped severity totals" {
    var result = diagnostic.FileResult.init(0);
    result.totals = .{ .info = 2, .warnings = 3, .errors = 4 };
    result.dropped_diagnostics = .{ .info = 1, .warnings = 2, .errors = 3 };
    result.diagnostics_truncated = true;

    var text_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer text_writer.deinit();
    try renderTextResult(&text_writer.writer, &.{}, &.{result});
    try std.testing.expect(std.mem.indexOf(u8, text_writer.written(), "dropped info=1 warnings=2 errors=3") != null);

    var json_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer json_writer.deinit();
    var stream = try JsonStream.init(&json_writer.writer);
    try stream.writeFile(&.{}, &result, "sample.mzML");
    try stream.finish();
    try std.testing.expect(std.mem.indexOf(u8, json_writer.written(), "dropped info=1 warnings=2 errors=3") != null);
}

test "json contract: truncated result matches golden" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var sink = diagnostic.DiagnosticSink.init(.{ .max_diagnostics = 1 });
    defer sink.deinit(allocator);
    const mark = sink.mark();
    _ = try sink.append(allocator, .{
        .severity = .info,
        .rule = "test.retained",
        .path = "truncated.mzML",
        .message = "retained detail",
    });
    _ = try sink.append(allocator, .{
        .severity = .warning,
        .rule = "test.dropped-warning",
        .path = "truncated.mzML",
        .message = "dropped warning detail",
    });
    _ = try sink.append(allocator, .{
        .severity = .@"error",
        .rule = "test.dropped-error",
        .path = "truncated.mzML",
        .message = "dropped error detail",
    });
    var result = diagnostic.FileResult.init(0);
    result.finalizeSink(&sink, mark);
    var allocating_writer: std.Io.Writer.Allocating = .init(allocator);
    defer allocating_writer.deinit();

    try renderJsonResult(&allocating_writer.writer, sink.items, &result, "truncated.mzML");
    const expected = try std.Io.Dir.cwd().readFileAlloc(
        io,
        "fixtures/output/json-v1-truncated.json",
        allocator,
        .limited(128 * 1024),
    );
    defer allocator.free(expected);

    try std.testing.expectEqualStrings(expected, allocating_writer.written());
}
