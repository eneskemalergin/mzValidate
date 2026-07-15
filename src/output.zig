//! Renders diagnostics for humans and machines.
//!
//! Four modes, one writer interface:
//!   text:    Grouped by input path, one line per diagnostic, aggregate summary.
//!   json:    Stable JSON array for CI pipelines. Keys never reorder.
//!   summary: One line with status and counts. Good for pass/fail gating.
//!   brief:   Grouped by severity/rule/message with occurrence counts.
//!            Errors first (most frequent), then warnings, then info.
//!
//! Every renderer writes directly to a `std.Io.Writer`. stdout, buffer,
//! file, or network sink. Zero heap allocation outside the writer.

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
) std.Io.Writer.Error!void {
    const emergency = hasEmergencyFailure(results);
    if (diagnostics.len > 0 or !emergency) try renderTextDiagnostics(writer, diagnostics);
    for (results) |result| {
        if (result.first_failure) |failure| {
            if (!result.failure_diagnostic_emitted) try renderFailureText(writer, failure);
        }
    }
    try writeResultSummaryLine(writer, diagnostic.summarizeResults(results));
}

fn renderTextDiagnostics(writer: *std.Io.Writer, diagnostics: []const Diagnostic) std.Io.Writer.Error!void {
    if (diagnostics.len == 0) {
        try writer.writeAll("OK: no diagnostics emitted\n");
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

pub fn renderSummaryResult(writer: *std.Io.Writer, results: []const diagnostic.FileResult) std.Io.Writer.Error!void {
    try writeResultStatusLine(writer, diagnostic.summarizeResults(results));
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

fn renderBriefGroups(writer: *std.Io.Writer, diagnostics: []const Diagnostic) std.Io.Writer.Error!void {
    const max_groups = 256;
    var sev: [max_groups]Severity = undefined;
    var rule: [max_groups][]const u8 = undefined;
    var msg: [max_groups][]const u8 = undefined;
    var cnt: [max_groups]usize = undefined;
    var gcnt: usize = 0;
    var dropped: usize = 0;

    // Phase 1: group all diagnostics by (severity, rule, message).
    for (diagnostics) |d| {
        var found = false;
        for (0..gcnt) |i| {
            if (sev[i] == d.severity and
                std.mem.eql(u8, rule[i], d.rule) and
                std.mem.eql(u8, msg[i], d.message))
            {
                cnt[i] += 1;
                found = true;
                break;
            }
        }
        if (!found and gcnt < max_groups) {
            sev[gcnt] = d.severity;
            rule[gcnt] = d.rule;
            msg[gcnt] = d.message;
            cnt[gcnt] = 1;
            gcnt += 1;
        } else if (!found) {
            dropped += 1;
        }
    }

    // Phase 2: sort by severity desc (error=2, warning=1, info=0),
    // then by count desc within the same severity.
    for (1..gcnt) |i| {
        var j = i;
        while (j > 0) : (j -= 1) {
            const a = @intFromEnum(sev[j]);
            const b = @intFromEnum(sev[j - 1]);
            const swap = if (a != b) a > b else cnt[j] > cnt[j - 1];
            if (!swap) break;
            std.mem.swap(Severity, &sev[j], &sev[j - 1]);
            std.mem.swap([]const u8, &rule[j], &rule[j - 1]);
            std.mem.swap([]const u8, &msg[j], &msg[j - 1]);
            std.mem.swap(usize, &cnt[j], &cnt[j - 1]);
        }
    }

    // Phase 3: measure column widths for aligned output.
    var count_w: usize = 1;
    var sev_w: usize = 0;
    var rule_w: usize = 0;
    for (0..gcnt) |i| {
        var n = cnt[i];
        var cw: usize = 1;
        while (n >= 10) : (n /= 10) cw += 1;
        if (cw > count_w) count_w = cw;

        const sl = sev[i].label().len;
        if (sl > sev_w) sev_w = sl;

        const rl = rule[i].len;
        if (rl > rule_w) rule_w = rl;
    }

    // Phase 4: render aligned table.
    // Layout: <count:count_w>  <severity:sev_w>  <rule:rule_w>  <message>
    try writer.writeByte('\n');
    for (0..gcnt) |i| {
        var n = cnt[i];
        var cw: usize = 1;
        while (n >= 10) : (n /= 10) cw += 1;
        for (0..count_w - cw) |_| try writer.writeByte(' ');
        try writer.print("{d}  ", .{cnt[i]});

        try writer.writeAll(sev[i].label());
        for (0..sev_w - sev[i].label().len) |_| try writer.writeByte(' ');
        try writer.writeAll("  ");

        try writer.writeAll(rule[i]);
        for (0..rule_w - rule[i].len) |_| try writer.writeByte(' ');
        try writer.writeAll("  ");

        // Message is last column, no padding needed.
        try writer.writeAll(msg[i]);
        try writer.writeByte('\n');
    }
    if (dropped > 0) {
        try writer.print("... and {d} more unique diagnostic groups (brief limit)\n", .{dropped});
    }
}

pub fn renderBriefResult(
    writer: *std.Io.Writer,
    diagnostics: []const Diagnostic,
    results: []const diagnostic.FileResult,
) std.Io.Writer.Error!void {
    try writeResultStatusLine(writer, diagnostic.summarizeResults(results));
    if (diagnostics.len > 0) try renderBriefGroups(writer, diagnostics);
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
                if (result.failure_diagnostic_emitted) continue;
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

fn writeResultStatusLine(writer: *std.Io.Writer, summary: diagnostic.Summary) std.Io.Writer.Error!void {
    try writer.print("status={s} completion={s} info={d} warnings={d} errors={d}", .{
        summary.status().label(),
        summary.completion.label(),
        summary.totals.info,
        summary.totals.warnings,
        summary.totals.errors,
    });
    if (summary.first_failure) |failure| {
        try writer.print(" failure_stage={s} failure_reason={s}", .{ failure.stage.label(), failure.reason.label() });
    }
    try writer.writeByte('\n');
}

fn writeResultSummaryLine(writer: *std.Io.Writer, summary: diagnostic.Summary) std.Io.Writer.Error!void {
    try writer.print(
        "summary: {s} (completion={s} info={d} warnings={d} errors={d}",
        .{
            summary.status().label(),
            summary.completion.label(),
            summary.totals.info,
            summary.totals.warnings,
            summary.totals.errors,
        },
    );
    if (summary.first_failure) |failure| {
        try writer.print(" failure_stage={s} failure_reason={s}", .{ failure.stage.label(), failure.reason.label() });
    }
    try writer.writeAll(")\n");
}

fn renderFailureText(writer: *std.Io.Writer, failure: diagnostic.FirstFailure) std.Io.Writer.Error!void {
    if (failure.path) |path| try writer.print("input: {s}\n", .{path});
    try writer.print(
        "  error [{s}] {s} (stage={s} reason={s})\n",
        .{ failure.rule, failure.message, failure.stage.label(), failure.reason.label() },
    );
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

    try renderSummaryResult(&allocating_writer.writer, &.{result});

    try std.testing.expectEqualStrings(
        "status=errors-present completion=incomplete info=0 warnings=0 errors=1 failure_stage=parser failure_reason=parser\n",
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
