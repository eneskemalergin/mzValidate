//! Diagnostic types, stable rule IDs, severity levels, and exit-code mapping.
//!
//! Every public symbol here is part of the external contract between the validator
//! and consumers (CLI, tests, JSON output). Change them carefully.

const std = @import("std");

// --- Types ---

/// Stable rule IDs emitted in diagnostics and serialized output.
///
/// Naming convention: `domain.category.slug`. The slug appears verbatim in JSON
/// so it is a breaking change to rename or remove an existing entry.
pub const RuleId = struct {
    /// File could not be opened. Carries the OS error in the message.
    pub const runtime_file_open = "runtime.file-open";
    /// Reserved placeholder. Used in tests and output contract assertions.
    pub const runtime_stub = "runtime.stub";

    pub const mzml_structure_root = "mzml.structure.root";
    pub const mzml_structure_xml = "mzml.structure.xml";
    pub const mzml_structure_nesting = "mzml.structure.nesting";
    pub const mzml_structure_attribute = "mzml.structure.attribute";
    pub const mzml_structure_count = "mzml.structure.count";
    pub const mzml_structure_missing_child = "mzml.structure.missing-child";
    pub const mzml_binary_base64 = "mzml.binary.base64";
    pub const mzml_binary_compression = "mzml.binary.compression";
    pub const mzml_binary_decompress = "mzml.binary.decompress";
    pub const mzml_binary_length_mismatch = "mzml.binary.length-mismatch";
    pub const mzml_binary_precision_mismatch = "mzml.binary.precision-mismatch";
    /// Binary payload encodedLength exceeds the -max-binary-size limit.
    pub const mzml_binary_oversized = "mzml.binary.oversized";

    // Index and checksum rules (Phase 2).
    /// Declared indexListOffset does not match the actual byte offset of indexList.
    pub const mzml_index_offset_list = "mzml.index.offset-list";
    /// Index offset does not match the recorded spectrum/chromatogram position,
    /// or references a non-existent element.
    pub const mzml_index_offset = "mzml.index.offset";
    /// Index offset points past the end of the file (truncated file).
    pub const mzml_index_truncated = "mzml.index.truncated";
    /// fileChecksum SHA-1 digest does not match the recomputed value.
    pub const mzml_index_checksum = "mzml.index.checksum";

    // CV and semantic rules (Phase 3).
    /// CV accession does not exist in the controlled vocabulary.
    pub const mzml_cv_accession = "mzml.cv.accession";
    /// CV term is obsolete and has been replaced.
    pub const mzml_cv_obsolete = "mzml.cv.obsolete";
    /// cvRef does not match the term's declared namespace.
    pub const mzml_cv_namespace = "mzml.cv.namespace";
    /// Unit term accession is not recognised.
    pub const mzml_cv_unit = "mzml.cv.unit";
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
///
/// 0 = clean, 1 = warnings only, 2 = any errors present.
pub fn exitCode(diagnostics: []const Diagnostic) u8 {
    return switch (summarize(diagnostics).status()) {
        .clean => 0,
        .warnings_only => 1,
        .errors_present => 2,
    };
}

// --- Tests ---

test "exitCode prefers errors over warnings" {
    // Arrange.
    const diagnostics = [_]Diagnostic{
        .{ .severity = .warning, .rule = RuleId.runtime_stub, .message = "stub" },
        .{ .severity = .@"error", .rule = RuleId.runtime_file_open, .message = "open failed" },
    };

    // Act.
    // Assert.
    try std.testing.expectEqual(@as(u8, 2), exitCode(&diagnostics));
}

test "summarize distinguishes clean warnings and errors" {
    // Arrange.
    const clean_summary = summarize(&.{});

    // Act.
    // Assert.
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
