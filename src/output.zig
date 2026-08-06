//! Renders diagnostics for humans and CI consumers.
//!
//! Text, JSON, and summary modes share the same bounded result metadata.

const std = @import("std");
const diagnostic = @import("diagnostic.zig");
const terminal_text = @import("terminal_text.zig");
const version = @import("version.zig");

const Diagnostic = diagnostic.Diagnostic;
const Severity = diagnostic.Severity;

/// Selects how diagnostics are rendered for humans or CI.
pub const OutputMode = enum {
    text,
    json,
    summary,
};

/// Presentation values for human result lines.
pub const HumanResultOptions = struct {
    elapsed_ns: ?i96 = null,
    color: bool = false,
    terminal_columns: ?usize = null,
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
    var finding_groups = diagnostics.len;
    for (results) |result| {
        if (result.first_failure) |failure| {
            if (!result.failure_diagnostic_emitted) {
                try renderFailureText(writer, failure);
                rendered_failure = true;
                finding_groups = std.math.add(usize, finding_groups, 1) catch std.math.maxInt(usize);
            }
        }
    }
    if (rendered_failure) try writer.writeByte('\n');
    const summary = diagnostic.summarizeResults(results);
    try writeHumanResultLine(writer, summary, finding_groups, .{});
    try writeFailureMetadata(writer, summary.first_failure);
}

/// Writes one file's text diagnostics and any retained failure metadata.
pub fn renderTextFile(
    writer: *std.Io.Writer,
    diagnostics: []const Diagnostic,
    result: *const diagnostic.FileResult,
    path: []const u8,
    options: HumanResultOptions,
) std.Io.Writer.Error!void {
    try writer.print("input: {s}\n\n", .{path});

    const count_width = occurrenceWidth(diagnostics);
    try renderCompactDiagnostics(writer, diagnostics, count_width, options.color, options.terminal_columns);
    if (hasDroppedDiagnostics(result.*)) {
        try renderCompactTruncation(
            writer,
            result.dropped_diagnostics,
            count_width,
            options.color,
            options.terminal_columns,
        );
    }
    if (result.needsEmergencyDiagnostic()) {
        try renderCompactFailure(
            writer,
            result.first_failure.?,
            count_width,
            options.color,
            options.terminal_columns,
        );
    }

    if (diagnostics.len > 0 or hasDroppedDiagnostics(result.*) or result.needsEmergencyDiagnostic()) {
        try writer.writeByte('\n');
    }
    const finding_groups = std.math.add(
        usize,
        diagnostics.len,
        @intFromBool(result.needsEmergencyDiagnostic()),
    ) catch std.math.maxInt(usize);
    const summary = diagnostic.summarizeResults(&.{result.*});
    try writeHumanResultLine(writer, summary, finding_groups, options);
    try writeFailureMetadata(writer, summary.first_failure);
}

fn renderCompactDiagnostics(
    writer: *std.Io.Writer,
    diagnostics: []const Diagnostic,
    count_width: usize,
    color: bool,
    terminal_columns: ?usize,
) std.Io.Writer.Error!void {
    for (diagnostics) |item| {
        try writeSeverityCount(writer, item.severity, item.occurrences, count_width, color);
        try renderCompactMessageRule(
            writer,
            item.message,
            item.rule,
            13 + count_width,
            terminal_columns,
            color,
            false,
        );
        try renderCompactLocations(writer, item);
    }
}

fn renderCompactMessageRule(
    writer: *std.Io.Writer,
    message: []const u8,
    rule: []const u8,
    indent: usize,
    terminal_columns: ?usize,
    color: bool,
    style_padding: bool,
) std.Io.Writer.Error!void {
    if (terminal_columns) |columns| {
        const line_width = indent + terminal_text.displayWidth(message) + 3 +
            terminal_text.displayWidth(rule);
        if (line_width > columns) {
            try writer.writeAll("  ");
            try renderWrappedMessage(writer, message, indent, columns, color);
            try writer.writeByte('\n');
            try writeIndent(writer, indent);
            try writeAnsi(writer, color, ansi_dim);
            try writer.print("[{s}]", .{rule});
            try writeAnsi(writer, color, ansi_reset);
            try writer.writeByte('\n');
            return;
        }
    }

    if (style_padding) {
        try writeAnsi(writer, color, ansi_bold);
        try writer.writeAll("  ");
        try writer.writeAll(message);
        try writer.writeByte(' ');
        try writeAnsi(writer, color, ansi_reset);
    } else {
        try writer.writeAll("  ");
        try writeAnsi(writer, color, ansi_bold);
        try writer.writeAll(message);
        try writeAnsi(writer, color, ansi_reset);
        try writer.writeByte(' ');
    }
    try writeAnsi(writer, color, ansi_dim);
    try writer.print("[{s}]", .{rule});
    try writeAnsi(writer, color, ansi_reset);
    try writer.writeByte('\n');
}

fn renderWrappedMessage(
    writer: *std.Io.Writer,
    message: []const u8,
    indent: usize,
    terminal_columns: usize,
    color: bool,
) std.Io.Writer.Error!void {
    const line_limit = @max(terminal_columns, indent + 1);
    var column = indent;
    var index: usize = 0;

    while (index < message.len) {
        while (index < message.len and message[index] == ' ') index += 1;
        if (index == message.len) break;

        const word_start = index;
        while (index < message.len and message[index] != ' ') index += 1;
        var word = message[word_start..index];
        const word_width = terminal_text.displayWidth(word);

        if (column > indent and column + 1 + word_width > line_limit) {
            try writer.writeByte('\n');
            try writeIndent(writer, indent);
            column = indent;
        } else if (column > indent) {
            try writeAnsi(writer, color, ansi_bold);
            try writer.writeByte(' ');
            try writeAnsi(writer, color, ansi_reset);
            column += 1;
        }

        while (word.len > 0) {
            const available = line_limit - column;
            const fitting_end = terminal_text.prefixBytesForWidth(word, available);
            const chunk_end = if (fitting_end > 0)
                fitting_end
            else
                terminal_text.prefixBytesForWidth(word, 1);
            const chunk = word[0..chunk_end];
            try writeAnsi(writer, color, ansi_bold);
            try writer.writeAll(chunk);
            try writeAnsi(writer, color, ansi_reset);
            column += terminal_text.displayWidth(chunk);
            word = word[chunk.len..];
            if (word.len > 0) {
                try writer.writeByte('\n');
                try writeIndent(writer, indent);
                column = indent;
            }
        }
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
    terminal_columns: ?usize,
) std.Io.Writer.Error!void {
    var message_buffer: [256]u8 = undefined;
    var message_writer = std.Io.Writer.fixed(&message_buffer);
    try message_writer.print("diagnostic detail truncated (dropped info={d} warnings={d} errors={d})", .{
        dropped.info,
        dropped.warnings,
        dropped.errors,
    });

    try writeSeverityCount(writer, .warning, 1, count_width, color);
    try renderCompactMessageRule(
        writer,
        message_buffer[0..message_writer.end],
        diagnostic.RuleId.runtime_diagnostics_truncated,
        13 + count_width,
        terminal_columns,
        color,
        true,
    );
}

fn renderCompactFailure(
    writer: *std.Io.Writer,
    failure: diagnostic.FirstFailure,
    count_width: usize,
    color: bool,
    terminal_columns: ?usize,
) std.Io.Writer.Error!void {
    // FirstFailure bounds its message at 512 bytes; 64 bytes covers the closed stage/reason suffix.
    var message_buffer: [diagnostic.first_failure_message_capacity + 64]u8 = undefined;
    var message_writer = std.Io.Writer.fixed(&message_buffer);
    try message_writer.print("{s} (stage={s} reason={s})", .{
        failure.message(),
        failure.stage.label(),
        failure.reason.label(),
    });

    try writeSeverityCount(writer, .@"error", 1, count_width, color);
    try renderCompactMessageRule(
        writer,
        message_buffer[0..message_writer.end],
        failure.rule(),
        13 + count_width,
        terminal_columns,
        color,
        true,
    );
}

fn writeHumanResultLine(
    writer: *std.Io.Writer,
    summary: diagnostic.Summary,
    finding_groups: ?usize,
    options: HumanResultOptions,
) std.Io.Writer.Error!void {
    const no_findings = summary.totals.info == 0 and summary.totals.warnings == 0 and summary.totals.errors == 0;
    if (no_findings) {
        try writeResultHighlight(writer, summary.completion.label(), "clean", null, options.color);
        try writer.writeAll(" | no findings");
    } else {
        try writeResultHighlight(
            writer,
            summary.completion.label(),
            humanStatusLabel(summary.totals),
            resultSeverity(summary.totals),
            options.color,
        );
        try writer.writeAll(" | ");
        var separator: []const u8 = "";
        if (summary.totals.errors > 0) {
            try writer.print("errors {d}", .{summary.totals.errors});
            separator = ", ";
        }
        if (summary.totals.warnings > 0) {
            try writer.print("{s}warnings {d}", .{ separator, summary.totals.warnings });
            separator = ", ";
        }
        if (summary.totals.info > 0) {
            try writer.print("{s}info {d}", .{ separator, summary.totals.info });
        }
        if (finding_groups) |count| {
            try writer.print(" | {d} {s}", .{ count, if (count == 1) "group" else "groups" });
        }
    }
    if (options.elapsed_ns) |nanoseconds| {
        try writer.writeAll(" | ");
        try writeElapsed(writer, nanoseconds);
    }
    try writer.writeByte('\n');
}

fn writeFailureMetadata(writer: *std.Io.Writer, first_failure: ?diagnostic.FirstFailure) std.Io.Writer.Error!void {
    const failure = first_failure orelse return;
    try writer.print("failure: stage={s} reason={s} rule={s}", .{ failure.stage.label(), failure.reason.label(), failure.rule() });
    if (failure.path()) |path| try writer.print(" input={s}", .{path});
    try writer.writeByte('\n');
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
    options: HumanResultOptions,
) std.Io.Writer.Error!void {
    try writeHumanResultLine(writer, summary, null, options);
}

/// Writes one complete JSON report using the current schema version.
pub fn renderJsonResult(
    writer: *std.Io.Writer,
    diagnostics: []const Diagnostic,
    result: *const diagnostic.FileResult,
    path: []const u8,
) std.Io.Writer.Error!void {
    const finding_groups = std.math.add(
        usize,
        diagnostics.len,
        @intFromBool(result.needsEmergencyDiagnostic()),
    ) catch std.math.maxInt(usize);
    try writer.print("{{\n  \"schema_version\": {d},\n  \"files\": [", .{version.json_schema});
    try writeJsonFile(writer, diagnostics, result, path, finding_groups);
    try writer.writeAll("\n  ],\n  \"summary\": ");
    try writeJsonSummary(writer, diagnostic.summarizeResults(&.{result.*}), finding_groups);
    try writer.writeAll("\n}\n");
}

fn writeJsonFile(
    writer: *std.Io.Writer,
    diagnostics: []const Diagnostic,
    result: *const diagnostic.FileResult,
    path: []const u8,
    finding_groups: usize,
) std.Io.Writer.Error!void {
    try writer.writeAll("\n    {\n      \"path\": ");
    try writeJsonString(writer, path);
    try writer.writeAll(",\n      \"completion\": ");
    try writeJsonString(writer, result.completion.label());
    try writer.writeAll(",\n      \"status\": ");
    try writeJsonString(writer, result.status().label());
    try writer.writeAll(",\n      \"totals\": ");
    try writeJsonTotals(writer, result.totals);
    try writer.print(",\n      \"finding_groups\": {d}", .{finding_groups});
    try writer.print(
        ",\n      \"diagnostics_truncated\": {},\n      \"dropped_diagnostics\": ",
        .{result.diagnostics_truncated},
    );
    try writeJsonTotals(writer, result.dropped_diagnostics);
    try writer.writeAll(",\n      \"first_failure\": ");
    try writeJsonFirstFailure(writer, result.first_failure, 8);
    try writer.writeAll(",\n      \"diagnostics\": ");
    try writeJsonDiagnostics(writer, diagnostics, result, path);
    try writer.writeAll("\n    }");
}

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
            humanStatusLabel(summary.totals),
            summary.totals.info,
            summary.totals.warnings,
            summary.totals.errors,
        },
    );
}

fn humanStatusLabel(totals: diagnostic.Totals) []const u8 {
    if (totals.errors > 0) return "errors";
    if (totals.warnings > 0) return "warnings";
    if (totals.info > 0) return "info";
    return "clean";
}

fn renderFailureText(writer: *std.Io.Writer, failure: diagnostic.FirstFailure) std.Io.Writer.Error!void {
    if (failure.path()) |path| try writer.print("input: {s}\n", .{path});
    try writer.print(
        "  error [{s}] {s} (stage={s} reason={s})\n",
        .{ failure.rule(), failure.message(), failure.stage.label(), failure.reason.label() },
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

test "summary result reports incomplete status" {
    var result = diagnostic.FileResult.init(diagnostic.stageBit(.parser));
    result.recordFailure(.parser, .parser, diagnostic.RuleId.runtime_incomplete, "validation stopped", .{}, "sample.mzML", false);
    result.finalize(&.{});
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    try renderSummaryResult(&allocating_writer.writer, diagnostic.summarizeResults(&.{result}), .{});

    try std.testing.expectEqualStrings(
        "incomplete: errors | errors 1\n",
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

    try renderSummaryResult(&allocating_writer.writer, diagnostic.summarizeResults(&.{result}), .{ .color = true });

    try std.testing.expectEqualStrings(
        "\x1b[43;30;1mcomplete: warnings\x1b[0m | warnings 1, info 2\n",
        allocating_writer.written(),
    );
}

test "[unit]: summary result uses info status timing and color" {
    const diagnostics = [_]Diagnostic{.{ .severity = .info, .rule = "test.info", .message = "note", .occurrences = 2 }};
    var result = diagnostic.FileResult.init(0);
    result.finalize(&diagnostics);
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    try renderSummaryResult(&allocating_writer.writer, diagnostic.summarizeResults(&.{result}), .{
        .elapsed_ns = 420_000_000,
        .color = true,
    });

    try std.testing.expectEqualStrings(
        "\x1b[46;30;1mcomplete: info\x1b[0m | info 2 | 0.42s\n",
        allocating_writer.written(),
    );
}

test "[unit]: elapsed time handles centisecond boundaries" {
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    try writeElapsed(&allocating_writer.writer, -1);
    try allocating_writer.writer.writeByte(' ');
    try writeElapsed(&allocating_writer.writer, 9_999_999);
    try allocating_writer.writer.writeByte(' ');
    try writeElapsed(&allocating_writer.writer, 10_000_000);
    try allocating_writer.writer.writeByte(' ');
    try writeElapsed(&allocating_writer.writer, 1_000_000_000);

    try std.testing.expectEqualStrings("0.00s 0.00s 0.01s 1.00s", allocating_writer.written());
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
            "incomplete: errors | errors 1 | 1 group\n" ++
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
            "incomplete: errors | errors 1 | 1 group\n" ++
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
            "summary: errors (info=0 warnings=1 errors=1)\n",
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
            "summary: info (info=1 warnings=0 errors=0)\n",
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
            "summary: warnings (info=1 warnings=1 errors=0)\n",
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
            "complete: errors | errors 1, warnings 30 | 2 groups\n",
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

test "[unit]: compact output wraps messages and preserves rule IDs" {
    const diagnostics = [_]Diagnostic{.{
        .severity = .@"error",
        .rule = "test.long-rule",
        .message = "alpha beta gamma delta",
    }};
    var result = diagnostic.FileResult.init(0);
    result.finalize(&diagnostics);
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    try renderTextFile(&allocating_writer.writer, &diagnostics, &result, "wrap.mzML", .{
        .terminal_columns = 32,
    });

    try std.testing.expectEqualStrings(
        "input: wrap.mzML\n\n" ++
            "  ERROR   x001  alpha beta gamma\n" ++
            "                delta\n" ++
            "                [test.long-rule]\n" ++
            "\n" ++
            "complete: errors | errors 1 | 1 group\n",
        allocating_writer.written(),
    );
}

test "[unit]: compact output retains exact wide colored output" {
    const diagnostics = [_]Diagnostic{.{
        .severity = .warning,
        .rule = "test.utf8",
        .message = "valid café message",
    }};
    var result = diagnostic.FileResult.init(0);
    result.finalize(&diagnostics);
    var baseline: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer baseline.deinit();
    var wide: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer wide.deinit();

    try renderTextFile(&baseline.writer, &diagnostics, &result, "wide.mzML", .{ .color = true });
    try renderTextFile(&wide.writer, &diagnostics, &result, "wide.mzML", .{
        .color = true,
        .terminal_columns = 120,
    });

    try std.testing.expectEqualStrings(baseline.written(), wide.written());
}

test "[unit]: wrapped color resets before newlines" {
    const diagnostics = [_]Diagnostic{.{
        .severity = .info,
        .rule = "test.color-wrap",
        .message = "alpha beta gamma delta",
    }};
    var result = diagnostic.FileResult.init(0);
    result.finalize(&diagnostics);
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    try renderTextFile(&allocating_writer.writer, &diagnostics, &result, "color-wrap.mzML", .{
        .color = true,
        .terminal_columns = 32,
    });
    const rendered = allocating_writer.written();

    try std.testing.expect(std.mem.indexOf(u8, rendered, "gamma\x1b[0m\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "delta\x1b[0m\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "[test.color-wrap]\x1b[0m\n") != null);
}

test "[unit]: compact truncation uses the shared terminal wrapper" {
    var result = diagnostic.FileResult.init(0);
    result.diagnostics_truncated = true;
    result.dropped_diagnostics = .{ .info = 2, .warnings = 3, .errors = 4 };
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    try renderTextFile(&allocating_writer.writer, &.{}, &result, "truncated.mzML", .{
        .terminal_columns = 40,
    });
    const rendered = allocating_writer.written();

    try std.testing.expect(std.mem.indexOf(u8, rendered, "  WARNING x001  diagnostic detail\n") != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        rendered,
        "                [runtime.diagnostics-truncated]\n",
    ) != null);

    var colored_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer colored_writer.deinit();
    try renderTextFile(&colored_writer.writer, &.{}, &result, "truncated.mzML", .{ .color = true });

    try std.testing.expect(std.mem.indexOf(
        u8,
        colored_writer.written(),
        "\x1b[93mWARNING x001\x1b[0m\x1b[1m  diagnostic detail truncated " ++
            "(dropped info=2 warnings=3 errors=4) \x1b[0m" ++
            "\x1b[2m[runtime.diagnostics-truncated]\x1b[0m\n",
    ) != null);
}

test "[unit]: compact failure wraps the maximum retained message" {
    var message: [diagnostic.first_failure_message_capacity]u8 = @splat('q');
    var result = diagnostic.FileResult.init(0);
    result.recordFailure(
        .parser,
        .file_stability,
        "runtime.long-failure",
        &message,
        .{},
        null,
        false,
    );
    result.finalize(&.{});
    var allocating_writer: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer allocating_writer.deinit();

    try renderTextFile(&allocating_writer.writer, &.{}, &result, "failure.mzML", .{
        .terminal_columns = 40,
    });
    const rendered = allocating_writer.written();

    try std.testing.expectEqual(
        @as(usize, diagnostic.first_failure_message_capacity),
        std.mem.count(u8, rendered, "q"),
    );
    try std.testing.expect(std.mem.indexOf(u8, rendered, "[runtime.long-failure]\n") != null);
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
    try renderJsonResult(&json_writer.writer, &.{}, &result, "sample.mzML");
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
