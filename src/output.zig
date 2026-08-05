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

/// Per-file context for compact human output.
pub const TextFileOptions = struct {
    input_index: usize = 0,
    input_count: usize = 1,
    elapsed_ns: ?i96 = null,
    color: bool = false,
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
    options: TextFileOptions,
) std.Io.Writer.Error!void {
    if (options.input_index > 0) try writer.writeByte('\n');
    if (options.input_count > 1) {
        try writer.print("[{d}/{d}] input: {s}\n\n", .{ options.input_index + 1, options.input_count, path });
    } else {
        try writer.print("input: {s}\n\n", .{path});
    }

    const count_width = occurrenceWidth(diagnostics);
    try renderCompactDiagnostics(writer, diagnostics, count_width, options.color);
    if (hasDroppedDiagnostics(result.*)) {
        try renderCompactTruncation(writer, result.dropped_diagnostics, count_width, options.color);
    }
    if (result.needsEmergencyDiagnostic()) {
        try renderCompactFailure(writer, result.first_failure.?, count_width, options.color);
    }

    if (diagnostics.len > 0 or hasDroppedDiagnostics(result.*) or result.needsEmergencyDiagnostic()) {
        try writer.writeByte('\n');
    }
    const finding_groups = std.math.add(
        usize,
        diagnostics.len,
        @intFromBool(result.needsEmergencyDiagnostic()),
    ) catch std.math.maxInt(usize);
    try writeFileResultLine(writer, result.*, finding_groups, options.elapsed_ns, options.color);
}

/// Writes the final text result block for an invocation.
pub fn renderTextFinal(
    writer: *std.Io.Writer,
    summary: diagnostic.Summary,
    color: bool,
) std.Io.Writer.Error!void {
    if (summary.totals.info == 0 and summary.totals.warnings == 0 and summary.totals.errors == 0) {
        try writer.writeByte('\n');
        try writeResultHighlight(writer, "summary", "clean", null, color);
        try writer.print(" | {d} files | no findings\n", .{summary.files});
        return;
    }
    try writer.writeByte('\n');
    try writeResultHighlight(writer, "summary", humanStatusLabel(summary.status()), resultSeverity(summary.totals), color);
    try writer.print(" | {d} files | info {d}, warnings {d}, errors {d}\n", .{
        summary.files,
        summary.totals.info,
        summary.totals.warnings,
        summary.totals.errors,
    });
}

fn renderCompactDiagnostics(
    writer: *std.Io.Writer,
    diagnostics: []const Diagnostic,
    count_width: usize,
    color: bool,
) std.Io.Writer.Error!void {
    for (diagnostics) |item| {
        try writeSeverityCount(writer, item.severity, item.occurrences, count_width, color);
        try writer.writeAll("  ");
        try writeAnsi(writer, color, ansi_bold);
        try writer.writeAll(item.message);
        try writeAnsi(writer, color, ansi_reset);
        try writer.writeByte(' ');
        try writeAnsi(writer, color, ansi_dim);
        try writer.print("[{s}]", .{item.rule});
        try writeAnsi(writer, color, ansi_reset);
        try writer.writeByte('\n');
        try renderCompactLocations(writer, item);
    }
}

fn renderCompactLocations(writer: *std.Io.Writer, item: Diagnostic) std.Io.Writer.Error!void {
    const count = item.exampleLocationCount();
    if (count == 0) return;

    var has_bytes = false;
    var has_spectra = false;
    for (0..count) |index| {
        const location = item.exampleLocation(index);
        has_bytes = has_bytes or location.byte_offset != null;
        has_spectra = has_spectra or location.spectrum_index != null;
    }

    if (has_bytes and !has_spectra) {
        try writer.writeAll("                 examples: bytes ");
        for (0..count) |index| {
            if (index > 0) try writer.writeAll(", ");
            try writer.print("{d}", .{item.exampleLocation(index).byte_offset.?});
        }
        try writer.writeByte('\n');
        return;
    }
    if (has_spectra and !has_bytes) {
        try writer.writeAll("                 examples: spectra ");
        for (0..count) |index| {
            if (index > 0) try writer.writeAll(", ");
            try writer.print("{d}", .{item.exampleLocation(index).spectrum_index.?});
        }
        try writer.writeByte('\n');
        return;
    }

    try writer.writeAll("                 examples:\n");
    for (0..count) |index| {
        const location = item.exampleLocation(index);
        try writer.writeAll("                   ");
        if (location.byte_offset) |byte_offset| try writer.print("byte {d}", .{byte_offset});
        if (location.byte_offset != null and location.spectrum_index != null) try writer.writeAll(", ");
        if (location.spectrum_index) |spectrum_index| try writer.print("spectrum {d}", .{spectrum_index});
        try writer.writeByte('\n');
    }
}

fn renderCompactTruncation(
    writer: *std.Io.Writer,
    dropped: diagnostic.Totals,
    count_width: usize,
    color: bool,
) std.Io.Writer.Error!void {
    try writeSeverityCount(writer, .warning, 1, count_width, color);
    try writeAnsi(writer, color, ansi_bold);
    try writer.print("  diagnostic detail truncated (dropped info={d} warnings={d} errors={d}) ", .{ dropped.info, dropped.warnings, dropped.errors });
    try writeAnsi(writer, color, ansi_reset);
    try writeAnsi(writer, color, ansi_dim);
    try writer.print("[{s}]", .{diagnostic.RuleId.runtime_diagnostics_truncated});
    try writeAnsi(writer, color, ansi_reset);
    try writer.writeByte('\n');
}

fn renderCompactFailure(
    writer: *std.Io.Writer,
    failure: diagnostic.FirstFailure,
    count_width: usize,
    color: bool,
) std.Io.Writer.Error!void {
    try writeSeverityCount(writer, .@"error", 1, count_width, color);
    try writeAnsi(writer, color, ansi_bold);
    try writer.print("  {s} (stage={s} reason={s}) ", .{ failure.message(), failure.stage.label(), failure.reason.label() });
    try writeAnsi(writer, color, ansi_reset);
    try writeAnsi(writer, color, ansi_dim);
    try writer.print("[{s}]", .{failure.rule()});
    try writeAnsi(writer, color, ansi_reset);
    try writer.writeByte('\n');
}

fn writeFileResultLine(
    writer: *std.Io.Writer,
    result: diagnostic.FileResult,
    finding_groups: usize,
    elapsed_ns: ?i96,
    color: bool,
) std.Io.Writer.Error!void {
    const no_findings = result.totals.info == 0 and result.totals.warnings == 0 and result.totals.errors == 0;
    if (no_findings) {
        try writeResultHighlight(writer, result.completion.label(), "clean", null, color);
        try writer.writeAll(" | no findings");
    } else {
        try writeResultHighlight(
            writer,
            result.completion.label(),
            humanStatusLabel(result.status()),
            resultSeverity(result.totals),
            color,
        );
        try writer.print(" | info {d}, warnings {d}, errors {d}", .{
            result.totals.info,
            result.totals.warnings,
            result.totals.errors,
        });
        try writer.print(" | {d} groups", .{finding_groups});
    }
    if (elapsed_ns) |nanoseconds| {
        try writer.writeAll(" | ");
        try writeElapsed(writer, nanoseconds);
    }
    try writer.writeByte('\n');
    if (result.first_failure) |failure| {
        try writer.print("failure: stage={s} reason={s} rule={s}", .{ failure.stage.label(), failure.reason.label(), failure.rule() });
        if (failure.path()) |path| try writer.print(" input={s}", .{path});
        try writer.writeByte('\n');
    }
}

const ansi_reset = "\x1b[0m";
const ansi_bold = "\x1b[1m";
const ansi_dim = "\x1b[2m";

fn severityAnsi(severity: Severity) []const u8 {
    return switch (severity) {
        .@"error" => "\x1b[91m",
        .warning => "\x1b[93m",
        .info => "\x1b[96m",
    };
}

fn resultSeverity(totals: diagnostic.Totals) Severity {
    if (totals.errors > 0) return .@"error";
    if (totals.warnings > 0) return .warning;
    return .info;
}

fn resultHighlight(severity: ?Severity) []const u8 {
    const value = severity orelse return "\x1b[42;30;1m";
    return switch (value) {
        .@"error" => "\x1b[41;97;1m",
        .warning => "\x1b[43;30;1m",
        .info => "\x1b[46;30;1m",
    };
}

fn writeResultHighlight(
    writer: *std.Io.Writer,
    completion: []const u8,
    status: []const u8,
    severity: ?Severity,
    color: bool,
) std.Io.Writer.Error!void {
    try writeAnsi(writer, color, resultHighlight(severity));
    try writer.print("{s}: {s}", .{ completion, status });
    try writeAnsi(writer, color, ansi_reset);
}

fn writeAnsi(writer: *std.Io.Writer, color: bool, sequence: []const u8) std.Io.Writer.Error!void {
    if (color) try writer.writeAll(sequence);
}

fn writeElapsed(writer: *std.Io.Writer, elapsed_ns: i96) std.Io.Writer.Error!void {
    const nanoseconds: u96 = @intCast(@max(elapsed_ns, 0));
    const centiseconds = nanoseconds / 10_000_000;
    try writer.print("{d}.{d:0>2}s", .{ centiseconds / 100, centiseconds % 100 });
}

fn occurrenceWidth(diagnostics: []const Diagnostic) usize {
    var width: usize = 3;
    for (diagnostics) |item| width = @max(width, decimalWidth(item.occurrences));
    return width;
}

fn decimalWidth(value: usize) usize {
    var remaining = value;
    var width: usize = 1;
    while (remaining >= 10) : (remaining /= 10) width += 1;
    return width;
}

fn writePaddedCount(writer: *std.Io.Writer, value: usize, width: usize) std.Io.Writer.Error!void {
    for (decimalWidth(value)..width) |_| try writer.writeByte('0');
    try writer.print("{d}", .{value});
}

fn writeSeverityCount(
    writer: *std.Io.Writer,
    severity: Severity,
    occurrences: usize,
    count_width: usize,
    color: bool,
) std.Io.Writer.Error!void {
    const label = humanSeverityLabel(severity);
    try writer.writeAll("  ");
    try writeAnsi(writer, color, severityAnsi(severity));
    try writer.writeAll(label);
    for (label.len..7) |_| try writer.writeByte(' ');
    try writer.writeAll(" x");
    try writePaddedCount(writer, occurrences, count_width);
    try writeAnsi(writer, color, ansi_reset);
}

fn humanSeverityLabel(severity: Severity) []const u8 {
    return switch (severity) {
        .@"error" => "ERROR",
        .warning => "WARNING",
        .info => "INFO",
    };
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

        try writer.print("  {s} [{s}]", .{ item.severity.label(), item.rule });
        if (item.occurrences > 1) try writer.print(" x{d}", .{item.occurrences});
        try writer.print(": {s}\n", .{item.message});

        const location_count = item.exampleLocationCount();
        if (location_count > 0) {
            try writer.writeAll(if (item.occurrences > 1) "    examples:" else "    location:");
            for (0..location_count) |index| {
                if (index > 0) try writer.writeByte(';');
                const location = item.exampleLocation(index);
                if (location.byte_offset) |byte_offset| {
                    try writer.print(" byte={d}", .{byte_offset});
                }
                if (location.spectrum_index) |spectrum_index| {
                    try writer.print(" spectrum={d}", .{spectrum_index});
                }
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
const BriefGroups = struct {
    const max_groups = 256;

    severity: [max_groups]Severity = undefined,
    rule: [max_groups][]const u8 = undefined,
    message: [max_groups][]const u8 = undefined,
    count: [max_groups]usize = undefined,
    length: usize = 0,
    dropped: usize = 0,

    /// Adds a diagnostic to the bounded grouping table without allocating.
    fn add(groups: *BriefGroups, item: Diagnostic) void {
        for (0..groups.length) |i| {
            if (groups.severity[i] == item.severity and
                std.mem.eql(u8, groups.rule[i], item.rule) and
                std.mem.eql(u8, groups.message[i], item.message))
            {
                groups.count[i] = std.math.add(usize, groups.count[i], item.occurrences) catch std.math.maxInt(usize);
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
        groups.count[index] = item.occurrences;
        groups.length = next_length;
    }

    /// Sorts groups by severity and count, then writes the aligned table.
    fn render(groups: *BriefGroups, writer: *std.Io.Writer) std.Io.Writer.Error!void {
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

/// Writes one attributed brief result while its borrowed diagnostics are alive.
pub fn renderBriefFile(
    writer: *std.Io.Writer,
    diagnostics: []const Diagnostic,
    result: *const diagnostic.FileResult,
    path: []const u8,
    input_index: usize,
    input_count: usize,
) std.Io.Writer.Error!void {
    if (input_index > 0) try writer.writeByte('\n');
    if (input_count > 1) {
        try writer.print("[{d}/{d}] input: {s}\n", .{ input_index + 1, input_count, path });
    } else {
        try writer.print("input: {s}\n", .{path});
    }
    try renderBriefResult(writer, diagnostics, &.{result.*});
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
    finding_groups: usize = 0,

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
        const file_groups = std.math.add(
            usize,
            diagnostics.len,
            @intFromBool(result.needsEmergencyDiagnostic()),
        ) catch std.math.maxInt(usize);
        stream.finding_groups = std.math.add(usize, stream.finding_groups, file_groups) catch std.math.maxInt(usize);
        if (!stream.first_file) try stream.writer.writeByte(',');
        try stream.writer.writeAll("\n    {\n      \"path\": ");
        try writeJsonString(stream.writer, path);
        try stream.writer.writeAll(",\n      \"completion\": ");
        try writeJsonString(stream.writer, result.completion.label());
        try stream.writer.writeAll(",\n      \"status\": ");
        try writeJsonString(stream.writer, result.status().label());
        try stream.writer.writeAll(",\n      \"totals\": ");
        try writeJsonTotals(stream.writer, result.totals);
        try stream.writer.print(",\n      \"finding_groups\": {d}", .{file_groups});
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
        try writeJsonSummary(stream.writer, stream.summary, stream.finding_groups);
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
    try writer.print("\"occurrences\": {d},\n", .{item.occurrences});
    try writeIndent(writer, indent + 2);
    try writer.writeAll("\"example_locations\": [");
    for (0..item.exampleLocationCount()) |index| {
        if (index > 0) try writer.writeAll(", ");
        try writeJsonLocation(writer, item.exampleLocation(index));
    }
    try writer.writeByte(']');
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
    try writer.writeAll("\"occurrences\": 1,\n");
    try writeIndent(writer, indent + 2);
    try writer.writeAll("\"example_locations\": [],\n");
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

fn writeJsonSummary(
    writer: *std.Io.Writer,
    summary: diagnostic.Summary,
    finding_groups: usize,
) std.Io.Writer.Error!void {
    try writer.writeAll("{\n    \"completion\": ");
    try writeJsonString(writer, summary.completion.label());
    try writer.writeAll(",\n    \"status\": ");
    try writeJsonString(writer, summary.status().label());
    try writer.print(",\n    \"files\": {d},\n    \"incomplete_files\": {d},\n    \"finding_groups\": {d},\n    \"totals\": ", .{
        summary.files,
        summary.incomplete_files,
        finding_groups,
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

    try renderTextFile(&allocating_writer.writer, &.{}, &result, "sample.mzML", .{});

    try std.testing.expectEqualStrings(
        "input: sample.mzML\n\n" ++
            "  ERROR   x001  validation stopped (stage=parser reason=allocation) [runtime.incomplete]\n" ++
            "\n" ++
            "incomplete: errors | info 0, warnings 0, errors 1 | 1 groups\n" ++
            "failure: stage=parser reason=allocation rule=runtime.incomplete input=sample.mzML\n",
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
            "  warning [runtime.stub]: stubbed warning message\n" ++
            "\n" ++
            "input: sample-b.mzML\n" ++
            "  error [runtime.file-open]: unable to open input file\n" ++
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
        "  info [meta.note]: standalone note\n" ++
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
            "  warning [runtime.warning]: warning\n" ++
            "\n" ++
            "  info [meta.note]: standalone note\n" ++
            "\n" ++
            "summary: warnings-only (info=1 warnings=1 errors=0)\n",
        allocating_writer.written(),
    );
}

test "grouped text reports occurrence count and bounded examples" {
    var sink = diagnostic.DiagnosticSink.init(.{ .aggregate_occurrences = true });
    defer sink.deinit(std.testing.allocator);

    for (1..5) |offset| {
        try std.testing.expect(try sink.append(std.testing.allocator, .{
            .severity = .warning,
            .rule = "test.repeat",
            .message = "repeated",
            .location = .{ .byte_offset = offset },
        }));
    }

    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();
    try renderTextDiagnostics(&allocating_writer.writer, sink.items);

    try std.testing.expectEqualStrings(
        "  warning [test.repeat] x4: repeated\n" ++
            "    examples: byte=1; byte=2; byte=3\n\n",
        allocating_writer.written(),
    );
}

test "[unit]: compact file output aligns counts and keeps byte examples inline" {
    const diagnostics = [_]Diagnostic{
        .{
            .severity = .@"error",
            .rule = "test.single",
            .path = "sample.mzML",
            .message = "single finding",
            .location = .{ .byte_offset = 12 },
        },
        .{
            .severity = .warning,
            .rule = "test.repeated",
            .path = "sample.mzML",
            .message = "repeated finding",
            .location = .{ .byte_offset = 20 },
            .occurrences = 30,
        },
    };
    var result = diagnostic.FileResult.init(0);
    result.finalize(&diagnostics);
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    try renderTextFile(&allocating_writer.writer, &diagnostics, &result, "sample.mzML", .{});

    try std.testing.expectEqualStrings(
        "input: sample.mzML\n\n" ++
            "  ERROR   x001  single finding [test.single]\n" ++
            "                 examples: bytes 12\n" ++
            "  WARNING x030  repeated finding [test.repeated]\n" ++
            "                 examples: bytes 20\n" ++
            "\n" ++
            "complete: errors | info 0, warnings 30, errors 1 | 2 groups\n",
        allocating_writer.written(),
    );
}

test "[unit]: compact clean result includes elapsed time when supplied" {
    var result = diagnostic.FileResult.init(0);
    result.finalize(&.{});
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    try renderTextFile(&allocating_writer.writer, &.{}, &result, "clean.mzML", .{
        .elapsed_ns = 420_000_000,
    });

    try std.testing.expectEqualStrings(
        "input: clean.mzML\n\n" ++
            "complete: clean | no findings | 0.42s\n",
        allocating_writer.written(),
    );
}

test "[unit]: compact multi-file block prefixes and separates later input" {
    var result = diagnostic.FileResult.init(0);
    result.finalize(&.{});
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    try renderTextFile(&allocating_writer.writer, &.{}, &result, "second.mzML", .{
        .input_index = 1,
        .input_count = 5,
    });

    try std.testing.expectEqualStrings(
        "\n[2/5] input: second.mzML\n\n" ++
            "complete: clean | no findings\n",
        allocating_writer.written(),
    );
}

test "[unit]: compact color styles severity message rule and result" {
    const diagnostics = [_]Diagnostic{.{
        .severity = .@"error",
        .rule = "test.rule",
        .message = "human message",
    }};
    var result = diagnostic.FileResult.init(0);
    result.finalize(&diagnostics);
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    try renderTextFile(&allocating_writer.writer, &diagnostics, &result, "color.mzML", .{
        .color = true,
    });
    const rendered = allocating_writer.written();

    try std.testing.expect(std.mem.indexOf(u8, rendered, "  \x1b[91mERROR   x001\x1b[0m") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\x1b[1mhuman message\x1b[0m") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\x1b[2m[test.rule]\x1b[0m") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\x1b[41;97;1mcomplete: errors\x1b[0m") != null);
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

test "[unit]: brief file uses unnumbered single-input attribution" {
    const diagnostics = [_]Diagnostic{.{
        .severity = .warning,
        .rule = "test.rule",
        .message = "human message",
    }};
    var result = diagnostic.FileResult.init(0);
    result.finalize(&diagnostics);
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    try renderBriefFile(&allocating_writer.writer, &diagnostics, &result, "sample.mzML", 0, 1);

    try std.testing.expectEqualStrings(
        "input: sample.mzML\n" ++
            "complete: warnings (info=0 warnings=1 errors=0)\n" ++
            "\n" ++
            "1  warning  test.rule  human message\n",
        allocating_writer.written(),
    );
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

test "[unit]: grouped byte estimate bounds maximum JSON diagnostic syntax" {
    var sink = diagnostic.DiagnosticSink.init(.{ .aggregate_occurrences = true });
    defer sink.deinit(std.testing.allocator);

    const locations = [_]diagnostic.Location{
        .{ .byte_offset = std.math.maxInt(u64), .spectrum_index = std.math.maxInt(usize) },
        .{ .byte_offset = std.math.maxInt(u64) - 1, .spectrum_index = std.math.maxInt(usize) - 1 },
        .{ .byte_offset = std.math.maxInt(u64) - 2, .spectrum_index = std.math.maxInt(usize) - 2 },
    };
    for (locations) |location| {
        _ = try sink.append(std.testing.allocator, .{
            .severity = .warning,
            .rule = "\x01",
            .path = "\x03",
            .message = "\x02",
            .location = location,
        });
    }
    sink.items[0].occurrences = std.math.maxInt(usize);

    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();
    try writeJsonDiagnostic(&allocating_writer.writer, sink.items[0], 8);

    try std.testing.expect(allocating_writer.written().len <= sink.retained_bytes);
}
