//! Renders diagnostics for humans and machines.
//!
//! Four modes, one writer interface:
//!   text:    Grouped diagnostics followed by a result and optional config.
//!   json:    Stable JSON array for CI pipelines. Keys never reorder.
//!   summary: Result and optional config for pass/fail gating.
//!   brief:   Result and optional config followed by grouped diagnostics.
//!
//! Every renderer writes directly to a `std.Io.Writer`. stdout, buffer,
//! file, or network sink.

const std = @import("std");
const diagnostic = @import("diagnostic.zig");

const Diagnostic = diagnostic.Diagnostic;
const Severity = diagnostic.Severity;

// --- Types ---

/// Selects how diagnostics are rendered for humans or CI.
pub const OutputMode = enum {
    text,
    json,
    summary,
    brief,
};

pub fn renderText(writer: *std.Io.Writer, diagnostics: []const Diagnostic) std.Io.Writer.Error!void {
    const summary = diagnostic.summarize(diagnostics);

    try renderTextDiagnostics(writer, diagnostics);
    try writeSummaryLine(writer, summary);
}

pub fn renderTextResult(
    writer: *std.Io.Writer,
    diagnostics: []const Diagnostic,
    results: []const diagnostic.FileResult,
    requested_input_mode: []const u8,
    memory_limit: ?usize,
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
    try writeResultBlock(writer, diagnostic.summarizeResults(results), requested_input_mode, memory_limit);
}

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

pub fn renderTextFinal(
    writer: *std.Io.Writer,
    results: []const diagnostic.FileResult,
    requested_input_mode: []const u8,
    memory_limit: ?usize,
) std.Io.Writer.Error!void {
    var rendered = false;
    for (results) |result| {
        if (result.totals.info != 0 or result.totals.warnings != 0 or result.totals.errors != 0) {
            rendered = true;
            break;
        }
    }
    if (!rendered) try writer.writeAll("OK: no diagnostics emitted\n\n");
    try writeResultBlock(writer, diagnostic.summarizeResults(results), requested_input_mode, memory_limit);
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

pub fn renderSummaryResult(
    writer: *std.Io.Writer,
    results: []const diagnostic.FileResult,
    requested_input_mode: []const u8,
    memory_limit: ?usize,
) std.Io.Writer.Error!void {
    try writeResultBlock(writer, diagnostic.summarizeResults(results), requested_input_mode, memory_limit);
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

pub const BriefGroups = struct {
    const max_groups = 256;

    severity: [max_groups]Severity = undefined,
    rule: [max_groups][]const u8 = undefined,
    message: [max_groups][]const u8 = undefined,
    count: [max_groups]usize = undefined,
    length: usize = 0,
    dropped: usize = 0,

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
        if (groups.length == max_groups) {
            groups.dropped = std.math.add(usize, groups.dropped, 1) catch std.math.maxInt(usize);
            return;
        }
        groups.severity[groups.length] = item.severity;
        groups.rule[groups.length] = item.rule;
        groups.message[groups.length] = item.message;
        groups.count[groups.length] = 1;
        groups.length += 1;
    }

    pub fn render(groups: *BriefGroups, writer: *std.Io.Writer) std.Io.Writer.Error!void {
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

pub fn renderBriefResult(
    writer: *std.Io.Writer,
    diagnostics: []const Diagnostic,
    results: []const diagnostic.FileResult,
    requested_input_mode: []const u8,
    memory_limit: ?usize,
) std.Io.Writer.Error!void {
    try writeResultBlock(writer, diagnostic.summarizeResults(results), requested_input_mode, memory_limit);
    if (diagnostics.len > 0) try renderBriefGroups(writer, diagnostics);
    for (results) |result| {
        if (hasDroppedDiagnostics(result)) try renderTruncationText(writer, result.dropped_diagnostics, null);
    }
}

pub fn renderBriefGroupsResult(
    writer: *std.Io.Writer,
    groups: *BriefGroups,
    results: []const diagnostic.FileResult,
    requested_input_mode: []const u8,
    memory_limit: ?usize,
) std.Io.Writer.Error!void {
    try writeResultBlock(writer, diagnostic.summarizeResults(results), requested_input_mode, memory_limit);
    if (groups.length > 0) try groups.render(writer);
    for (results) |result| {
        if (hasDroppedDiagnostics(result)) {
            try renderTruncationText(writer, result.dropped_diagnostics, null);
        }
    }
}

/// Renders diagnostics in a stable JSON shape for automation.
pub fn renderJson(writer: *std.Io.Writer, diagnostics: []const Diagnostic) std.Io.Writer.Error!void {
    try writer.writeAll("[\n");
    try renderJsonItems(writer, diagnostics, null);
    try writer.writeAll("\n]\n");
}

pub fn renderJsonResult(
    writer: *std.Io.Writer,
    diagnostics: []const Diagnostic,
    results: []const diagnostic.FileResult,
) std.Io.Writer.Error!void {
    try writer.writeAll("[\n");
    try renderJsonItems(writer, diagnostics, results);
    try writer.writeAll("\n]\n");
}

pub const JsonStream = struct {
    writer: *std.Io.Writer,
    first: bool = true,

    pub fn init(writer: *std.Io.Writer) std.Io.Writer.Error!JsonStream {
        try writer.writeAll("[\n");
        return .{ .writer = writer };
    }

    pub fn writeFile(
        stream: *JsonStream,
        diagnostics: []const Diagnostic,
        result: *const diagnostic.FileResult,
        path: []const u8,
    ) std.Io.Writer.Error!void {
        for (diagnostics) |item| try stream.writeDiagnostic(item);
        if (result.needsEmergencyDiagnostic()) {
            try stream.writeDiagnostic(.{
                .severity = .@"error",
                .rule = result.first_failure.?.rule,
                .location = result.first_failure.?.location,
                .path = result.first_failure.?.path,
                .message = result.first_failure.?.message,
            });
        }
        if (hasDroppedDiagnostics(result.*)) {
            try stream.writeTruncation(result.dropped_diagnostics, path);
        }
    }

    pub fn finish(stream: *JsonStream) std.Io.Writer.Error!void {
        try stream.writer.writeAll("\n]\n");
    }

    fn writeDiagnostic(stream: *JsonStream, item: Diagnostic) std.Io.Writer.Error!void {
        if (!stream.first) try stream.writer.writeAll(",\n");
        try writeJsonDiagnostic(stream.writer, item);
        stream.first = false;
    }

    fn writeTruncation(stream: *JsonStream, dropped: diagnostic.Totals, path: []const u8) std.Io.Writer.Error!void {
        if (!stream.first) try stream.writer.writeAll(",\n");
        try writeJsonTruncation(stream.writer, dropped, path);
        stream.first = false;
    }
};

fn renderJsonItems(
    writer: *std.Io.Writer,
    diagnostics: []const Diagnostic,
    results: ?[]const diagnostic.FileResult,
) std.Io.Writer.Error!void {
    var first = true;
    for (diagnostics) |item| {
        if (!first) try writer.writeAll(",\n");
        try writeJsonDiagnostic(writer, item);
        first = false;
    }
    if (results) |file_results| {
        for (file_results) |result| {
            if (result.first_failure) |failure| {
                if (!result.failure_diagnostic_emitted) {
                    if (!first) try writer.writeAll(",\n");
                    try writeJsonDiagnostic(writer, .{
                        .severity = .@"error",
                        .rule = failure.rule,
                        .location = failure.location,
                        .path = failure.path,
                        .message = failure.message,
                    });
                    first = false;
                }
            }
            if (hasDroppedDiagnostics(result)) {
                if (!first) try writer.writeAll(",\n");
                const path = if (result.first_failure) |failure| failure.path orelse "" else "";
                try writeJsonTruncation(writer, result.dropped_diagnostics, path);
                first = false;
            }
        }
    }
}

fn writeJsonDiagnostic(writer: *std.Io.Writer, item: Diagnostic) std.Io.Writer.Error!void {
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

fn writeJsonTruncation(writer: *std.Io.Writer, dropped: diagnostic.Totals, path: []const u8) std.Io.Writer.Error!void {
    try writer.writeAll("  {\n    \"severity\": \"warning\",\n    \"rule\": ");
    try writeJsonString(writer, diagnostic.RuleId.runtime_diagnostics_truncated);
    try writer.writeAll(",\n    \"path\": ");
    try writeJsonString(writer, path);
    try writer.writeAll(",\n    \"location\": {\n      \"byte_offset\": null,\n      \"spectrum_index\": null\n    },\n    \"message\": \"diagnostic detail truncated (dropped info=");
    try writer.print("{d}", .{dropped.info});
    try writer.writeAll(" warnings=");
    try writer.print("{d}", .{dropped.warnings});
    try writer.writeAll(" errors=");
    try writer.print("{d}", .{dropped.errors});
    try writer.writeAll(")\"\n  }");
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
    requested_input_mode: []const u8,
    memory_limit: ?usize,
) std.Io.Writer.Error!void {
    try writer.print("{s}: {s} (info={d} warnings={d} errors={d})\n", .{
        summary.completion.label(),
        humanStatusLabel(summary.status()),
        summary.totals.info,
        summary.totals.warnings,
        summary.totals.errors,
    });
    if (summary.first_failure) |failure| {
        try writer.print("failure: stage={s} reason={s} rule={s}", .{ failure.stage.label(), failure.reason.label(), failure.rule });
        if (failure.path) |path| try writer.print(" input={s}", .{path});
        try writer.writeByte('\n');
    }
    try writeConfigLine(writer, requested_input_mode, memory_limit);
}

fn humanStatusLabel(status: diagnostic.ResultStatus) []const u8 {
    return switch (status) {
        .clean => "clean",
        .warnings_only => "warnings",
        .errors_present => "errors",
    };
}

fn writeConfigLine(
    writer: *std.Io.Writer,
    requested_input_mode: []const u8,
    memory_limit: ?usize,
) std.Io.Writer.Error!void {
    const mode_changed = !std.mem.eql(u8, requested_input_mode, "mmap");
    if (!mode_changed and memory_limit == null) return;

    try writer.writeAll("config:");
    var has_field = false;
    if (mode_changed) {
        try writer.print(" input={s} behavior=explicit", .{requested_input_mode});
        has_field = true;
    }
    if (memory_limit) |limit| {
        if (has_field) try writer.writeAll(";");
        try writer.writeAll(" limit=");
        try writeHumanSize(writer, limit);
        try writer.writeAll("; ledger=not-enforced");
    }
    try writer.writeByte('\n');
}

fn writeHumanSize(writer: *std.Io.Writer, bytes: usize) std.Io.Writer.Error!void {
    const units = [_]struct { size: usize, label: []const u8 }{
        .{ .size = 1024 * 1024 * 1024 * 1024, .label = "TiB" },
        .{ .size = 1024 * 1024 * 1024, .label = "GiB" },
        .{ .size = 1024 * 1024, .label = "MiB" },
        .{ .size = 1024, .label = "KiB" },
    };
    for (units) |unit| {
        if (bytes >= unit.size and bytes % unit.size == 0) {
            try writer.print("{d} {s}", .{ bytes / unit.size, unit.label });
            return;
        }
    }
    try writer.print("{d} bytes", .{bytes});
}

fn renderFailureText(writer: *std.Io.Writer, failure: diagnostic.FirstFailure) std.Io.Writer.Error!void {
    if (failure.path) |path| try writer.print("input: {s}\n", .{path});
    try writer.print(
        "  error [{s}] {s} (stage={s} reason={s})\n",
        .{ failure.rule, failure.message, failure.stage.label(), failure.reason.label() },
    );
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
    return result.dropped_diagnostics.info != 0 or
        result.dropped_diagnostics.warnings != 0 or
        result.dropped_diagnostics.errors != 0;
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

// --- Tests ---

test "renderSummary counts severities" {
    // Arrange.
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    const diagnostics = [_]Diagnostic{
        .{ .severity = .info, .rule = "one", .message = "one" },
        .{ .severity = .warning, .rule = "two", .message = "two" },
        .{ .severity = .@"error", .rule = "three", .message = "three" },
    };

    // Act.
    try renderSummary(&allocating_writer.writer, &diagnostics);

    // Assert.
    try std.testing.expectEqualStrings(
        "status=errors-present info=1 warnings=1 errors=1\n",
        allocating_writer.written(),
    );
}

test "renderSummaryResult reports incomplete completion and first failure" {
    var result = diagnostic.FileResult.init(diagnostic.stageBit(.parser));
    result.recordFailure(.parser, .parser, diagnostic.RuleId.runtime_incomplete, "validation stopped", .{}, "sample.mzML", false);
    result.finalize(&.{});
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    try renderSummaryResult(&allocating_writer.writer, &.{result}, "mmap", null);

    try std.testing.expectEqualStrings(
        "incomplete: errors (info=0 warnings=0 errors=1)\n" ++
            "failure: stage=parser reason=parser rule=runtime.incomplete input=sample.mzML\n",
        allocating_writer.written(),
    );
}

test "renderSummaryResult_separates_nondefault_config" {
    var result = diagnostic.FileResult.init(0);
    result.finalize(&.{});

    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    try renderSummaryResult(&allocating_writer.writer, &.{result}, "stream", 500 * 1024 * 1024);

    try std.testing.expectEqualStrings(
        "complete: clean (info=0 warnings=0 errors=0)\n" ++
            "config: input=stream behavior=explicit; limit=500 MiB; ledger=not-enforced\n",
        allocating_writer.written(),
    );
}

test "renderSummaryResult_uses_friendly_warning_status" {
    var result = diagnostic.FileResult.init(0);
    const diagnostics = [_]Diagnostic{
        .{ .severity = .info, .rule = "test.info", .message = "note" },
        .{ .severity = .info, .rule = "test.info", .message = "note" },
        .{ .severity = .warning, .rule = "test.warning", .message = "warning" },
    };
    result.finalize(&diagnostics);

    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    try renderSummaryResult(&allocating_writer.writer, &.{result}, "mmap", null);

    try std.testing.expectEqualStrings(
        "complete: warnings (info=2 warnings=1 errors=0)\n",
        allocating_writer.written(),
    );
}

test "renderTextResult_separates_result_and_config" {
    var result = diagnostic.FileResult.init(0);
    result.finalize(&.{});

    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    try renderTextResult(&allocating_writer.writer, &.{}, &.{result}, "stream", 500 * 1024 * 1024);

    try std.testing.expectEqualStrings(
        "OK: no diagnostics emitted\n\n" ++
            "complete: clean (info=0 warnings=0 errors=0)\n" ++
            "config: input=stream behavior=explicit; limit=500 MiB; ledger=not-enforced\n",
        allocating_writer.written(),
    );
}

test "renderBriefResult_uses_the_same_result_block" {
    var result = diagnostic.FileResult.init(0);
    result.finalize(&.{});

    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    try renderBriefResult(&allocating_writer.writer, &.{}, &.{result}, "stream", 500 * 1024 * 1024);

    try std.testing.expectEqualStrings(
        "complete: clean (info=0 warnings=0 errors=0)\n" ++
            "config: input=stream behavior=explicit; limit=500 MiB; ledger=not-enforced\n",
        allocating_writer.written(),
    );
}

test "renderJsonResult emits an emergency failure" {
    var result = diagnostic.FileResult.init(diagnostic.stageBit(.parser));
    result.recordFailure(.parser, .allocation, diagnostic.RuleId.runtime_incomplete, "validation stopped", .{}, "sample.mzML", false);
    result.finalize(&.{});

    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    try renderJsonResult(&allocating_writer.writer, &.{}, &.{result});

    try std.testing.expect(std.mem.indexOf(u8, allocating_writer.written(), "\"rule\": \"runtime.incomplete\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, allocating_writer.written(), "\"path\": \"sample.mzML\"") != null);
}

test "renderJson keeps stable keys" {
    // Arrange.
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

    // Act.
    try renderJson(&allocating_writer.writer, &diagnostics);

    // Assert.
    try std.testing.expectEqualStrings(expected_json, allocating_writer.written());
}

test "renderText groups diagnostics by input and appends summary" {
    // Arrange.
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

    // Act.
    try renderText(&allocating_writer.writer, &diagnostics);

    // Assert.
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

test "renderText handles pathless diagnostic without input header" {
    // Arrange.
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    const diagnostics = [_]Diagnostic{.{
        .severity = .info,
        .rule = "meta.note",
        .message = "standalone note",
    }};

    // Act.
    try renderText(&allocating_writer.writer, &diagnostics);

    // Assert.
    try std.testing.expectEqualStrings(
        "  info [meta.note] standalone note\n" ++
            "\n" ++
            "summary: clean (info=1 warnings=0 errors=0)\n",
        allocating_writer.written(),
    );
}

test "renderJson escapes quotes backslashes and control characters" {
    // Arrange.
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    const diagnostics = [_]Diagnostic{.{
        .severity = .warning,
        .rule = "runtime.escape-test",
        .message = "quote=\" slash=\\ line=\n tab=\t raw=\x01",
    }};

    const expected_json =
        "[\n" ++
        "  {\n" ++
        "    \"severity\": \"warning\",\n" ++
        "    \"rule\": \"runtime.escape-test\",\n" ++
        "    \"location\": {\n" ++
        "      \"byte_offset\": null,\n" ++
        "      \"spectrum_index\": null\n" ++
        "    },\n" ++
        "    \"message\": \"quote=\\\" slash=\\\\ line=\\n tab=\\t raw=\\u0001\"\n" ++
        "  }\n" ++
        "]\n";

    // Act.
    try renderJson(&allocating_writer.writer, &diagnostics);

    // Assert.
    try std.testing.expectEqualStrings(expected_json, allocating_writer.written());
}

test "bounded diagnostic output exposes dropped severity totals" {
    var result = diagnostic.FileResult.init(0);
    result.totals = .{ .info = 2, .warnings = 3, .errors = 4 };
    result.dropped_diagnostics = .{ .info = 1, .warnings = 2, .errors = 3 };
    result.diagnostics_truncated = true;

    var text_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer text_writer.deinit();
    try renderTextResult(&text_writer.writer, &.{}, &.{result}, "mmap", null);
    try std.testing.expect(std.mem.indexOf(u8, text_writer.written(), "dropped info=1 warnings=2 errors=3") != null);

    var json_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer json_writer.deinit();
    var stream = try JsonStream.init(&json_writer.writer);
    try stream.writeFile(&.{}, &result, "sample.mzML");
    try stream.finish();
    try std.testing.expect(std.mem.indexOf(u8, json_writer.written(), "dropped info=1 warnings=2 errors=3") != null);
}
