//! Public library surface for mzValidate.
//!
//! Re-exports validation modules and common types for library consumers.

const std = @import("std");

pub const cli = @import("cli.zig");
pub const diagnostic = @import("diagnostic.zig");
pub const output = @import("output.zig");
pub const progress = @import("progress.zig");
pub const version = @import("version.zig");
pub const validate = @import("validate.zig");

/// XML validation modules.
pub const xml = struct {
    pub const events = @import("xml/events.zig");
    pub const parser = @import("xml/parser.zig");
    pub const scan = @import("xml/scan.zig");
};

/// mzML validation modules.
pub const mzml = struct {
    pub const elements = @import("mzml/elements.zig");
    pub const structural = @import("mzml/structural.zig");
    pub const binary = @import("mzml/binary.zig");
    pub const index = @import("mzml/index.zig");
    pub const semantic = @import("mzml/semantic.zig");
};

/// OBO parsing and rule modules.
pub const obo = struct {
    pub const parser = @import("obo/parser.zig");
    pub const rule_engine = @import("obo/rule_engine.zig");
};

pub const Diagnostic = diagnostic.Diagnostic;
pub const DiagnosticSink = diagnostic.DiagnosticSink;
pub const FirstFailure = diagnostic.FirstFailure;
pub const FileResult = diagnostic.FileResult;
pub const CompletionState = diagnostic.CompletionState;
pub const Severity = diagnostic.Severity;
pub const ResourceLimits = diagnostic.ResourceLimits;
pub const OutputMode = output.OutputMode;
pub const ProgressObserver = progress.Observer;
pub const CheckOptions = validate.CheckOptions;
pub const InvocationContext = validate.InvocationContext;
pub const InvocationResourceUsage = validate.InvocationResourceUsage;
pub const json_schema_version = version.json_schema;

/// Runs the CLI and returns its process exit code.
pub fn run(init: std.process.Init) !u8 {
    return cli.run(init);
}

// --- Unit Tests ---

test "library imports compile" {
    _ = @import("cli.zig");
    _ = @import("output.zig");
    _ = @import("progress.zig");
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
