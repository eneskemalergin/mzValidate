//! Shared diagnostic types and exit-code mapping.

const std = @import("std");

/// Defines the stable rule IDs used in diagnostics and serialized output.
pub const RuleId = struct {
    pub const runtime_file_open = "runtime.file-open";
    pub const runtime_stub = "runtime.stub";

    pub const mzml_structure_root = "mzml.structure.root";
    pub const mzml_structure_xml = "mzml.structure.xml";
    pub const mzml_structure_nesting = "mzml.structure.nesting";
    pub const mzml_structure_attribute = "mzml.structure.attribute";
    pub const mzml_structure_missing_child = "mzml.structure.missing-child";
    pub const mzml_binary_base64 = "mzml.binary.base64";
    pub const mzml_binary_decompress = "mzml.binary.decompress";
    pub const mzml_binary_length_mismatch = "mzml.binary.length-mismatch";
    pub const mzml_binary_precision_mismatch = "mzml.binary.precision-mismatch";
};

/// Classifies diagnostics so CLI exit codes and renderers stay consistent.
pub const Severity = enum {
    info,
    warning,
    @"error",

    /// Returns the stable text label used in text and JSON output.
    pub fn label(severity: Severity) []const u8 {
        return switch (severity) {
            .info => "info",
            .warning => "warning",
            .@"error" => "error",
        };
    }
};

/// Carries optional source coordinates for a diagnostic.
pub const Location = struct {
    byte_offset: ?u64 = null,
    spectrum_index: ?usize = null,
};

/// Describes a single validation result in the shared reporting format.
pub const Diagnostic = struct {
    severity: Severity,
    rule: []const u8,
    location: Location = .{},
    path: ?[]const u8 = null,
    message: []const u8,
};

/// Tracks aggregate counts so renderers and exit-code mapping share one source of truth.
pub const Totals = struct {
    info: usize = 0,
    warnings: usize = 0,
    errors: usize = 0,
};

/// Distills a run into the three states the CLI cares about.
pub const ResultStatus = enum {
    clean,
    warnings_only,
    errors_present,

    /// Returns the stable label used in human summaries.
    pub fn label(status: ResultStatus) []const u8 {
        return switch (status) {
            .clean => "clean",
            .warnings_only => "warnings-only",
            .errors_present => "errors-present",
        };
    }
};

/// Bundles severity totals with the derived result status.
pub const Summary = struct {
    totals: Totals,

    /// Reports the overall result without forcing callers to inspect counters.
    pub fn status(summary: Summary) ResultStatus {
        if (summary.totals.errors > 0) return .errors_present;
        if (summary.totals.warnings > 0) return .warnings_only;
        return .clean;
    }
};

/// Counts severities across all diagnostics.
pub fn count(diagnostics: []const Diagnostic) Totals {
    var totals: Totals = .{};
    for (diagnostics) |diagnostic| {
        switch (diagnostic.severity) {
            .info => totals.info += 1,
            .warning => totals.warnings += 1,
            .@"error" => totals.errors += 1,
        }
    }
    return totals;
}

/// Aggregates diagnostics into totals plus a derived result state.
pub fn summarize(diagnostics: []const Diagnostic) Summary {
    return .{ .totals = count(diagnostics) };
}

/// Maps diagnostics to the process exit code contract.
pub fn exitCode(diagnostics: []const Diagnostic) u8 {
    return switch (summarize(diagnostics).status()) {
        .clean => 0,
        .warnings_only => 1,
        .errors_present => 2,
    };
}

test "exitCode prefers errors over warnings" {
    const diagnostics = [_]Diagnostic{
        .{ .severity = .warning, .rule = RuleId.runtime_stub, .message = "stub" },
        .{ .severity = .@"error", .rule = RuleId.runtime_file_open, .message = "open failed" },
    };

    try std.testing.expectEqual(@as(u8, 2), exitCode(&diagnostics));
}

test "summarize distinguishes clean warnings and errors" {
    const clean_summary = summarize(&.{});
    try std.testing.expectEqual(ResultStatus.clean, clean_summary.status());

    const warning_diagnostics = [_]Diagnostic{
        .{ .severity = .warning, .rule = RuleId.runtime_stub, .message = "stub" },
    };
    try std.testing.expectEqual(ResultStatus.warnings_only, summarize(&warning_diagnostics).status());

    const error_diagnostics = [_]Diagnostic{
        .{ .severity = .@"error", .rule = RuleId.runtime_file_open, .message = "open failed" },
    };
    try std.testing.expectEqual(ResultStatus.errors_present, summarize(&error_diagnostics).status());
}
