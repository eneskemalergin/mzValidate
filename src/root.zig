//! Public face of the mzValidate library.
//!
//! Re-exports every submodule and the most common types (Diagnostic,
//! Severity, OutputMode, CheckOptions) so callers do not dig through
//! internal paths. Import as `mzvalidate` from executables, tests,
//! or downstream tools that want to reuse the validation engine.
//!
//! Namespace layout:
//!   mzvalidate.cli           CLI parsing and dispatch
//!   mzvalidate.diagnostic    Diagnostic model and rule IDs
//!   mzvalidate.output        Text, JSON, summary renderers
//!   mzvalidate.validate      I/O dispatch and orchestration
//!   mzvalidate.xml           Streaming XML parser + events
//!   mzvalidate.mzml          Structural, binary, index, semantic
//!   mzvalidate.obo           OBO/psi-ms parser + rule engine

const std = @import("std");

// --- Submodule exports ---

/// CLI argument parsing, dispatch, and output modes.
pub const cli = @import("cli.zig");
/// Shared diagnostic types and helpers.
pub const diagnostic = @import("diagnostic.zig");
/// Text and JSON rendering helpers.
pub const output = @import("output.zig");
/// Project version constants.
pub const version = @import("version.zig");
/// I/O dispatch and validation orchestration.
pub const validate = @import("validate.zig");
/// XML parser surface for focused tooling.
pub const xml = struct {
    pub const events = @import("xml/events.zig");
    pub const parser = @import("xml/parser.zig");
    pub const scan = @import("xml/scan.zig");
};
/// mzML validators for focused tooling.
pub const mzml = struct {
    pub const elements = @import("mzml/elements.zig");
    pub const structural = @import("mzml/structural.zig");
    pub const binary = @import("mzml/binary.zig");
    pub const index = @import("mzml/index.zig");
    pub const semantic = @import("mzml/semantic.zig");
};

/// OBO parser for controlled vocabulary (PSI-MS, Unit Ontology).
pub const obo = struct {
    pub const parser = @import("obo/parser.zig");
    pub const rule_engine = @import("obo/rule_engine.zig");
};

// --- Re-exports for convenience ---

/// Shared diagnostic record. Avoid reaching through `diagnostic.Diagnostic`.
pub const Diagnostic = diagnostic.Diagnostic;
/// Bounded per-file diagnostic storage and severity totals.
pub const DiagnosticSink = diagnostic.DiagnosticSink;
/// Per-file completion and stage result.
pub const FileResult = diagnostic.FileResult;
/// Completion state independent of diagnostic severity.
pub const CompletionState = diagnostic.CompletionState;
/// Severity levels. Avoid reaching through `diagnostic.Severity`.
pub const Severity = diagnostic.Severity;
/// Output mode selector. Avoid reaching through `output.OutputMode`.
pub const OutputMode = output.OutputMode;
/// Check options. Avoid reaching through `validate.CheckOptions`.
pub const CheckOptions = validate.CheckOptions;

/// CLI entry for library consumers (tests, downstream tools).
pub fn run(init: std.process.Init) !u8 {
    return cli.run(init);
}

// --- Tests ---

test {
    _ = @import("xml/events.zig");
    _ = @import("xml/parse_errors.zig");
    _ = @import("xml/parser.zig");
    _ = @import("xml/scan.zig");
    _ = @import("mzml/elements.zig");
    _ = @import("mzml/structural.zig");
    _ = @import("mzml/binary.zig");
    _ = @import("mzml/index.zig");
    _ = @import("mzml/semantic.zig");
    _ = @import("obo/parser.zig");
    _ = @import("obo/rule_engine.zig");
    _ = @import("validate.zig");
}
