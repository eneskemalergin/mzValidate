//! Public API surface for the mzValidate library.
//!
//! Import this module as `mzvalidate` from executables or integration tests.
//! Submodule namespaces (`cli`, `diagnostic`, `output`) are re-exported so
//! callers can reach individual helpers without knowing the internal layout.

const std = @import("std");

// --- Submodule exports ---

/// CLI parsing and dispatch.
pub const cli = @import("cli.zig");
/// Shared diagnostic types and helpers.
pub const diagnostic = @import("diagnostic.zig");
/// Text and JSON rendering helpers.
pub const output = @import("output.zig");
/// Project version constants.
pub const version = @import("version.zig");
/// Validation entry points.
pub const validate = @import("validate.zig");

// --- Re-exports for convenience ---

/// Shared diagnostic record. Avoid reaching through `diagnostic.Diagnostic`.
pub const Diagnostic = diagnostic.Diagnostic;
/// Severity levels. Avoid reaching through `diagnostic.Severity`.
pub const Severity = diagnostic.Severity;
/// Output mode selector. Avoid reaching through `output.OutputMode`.
pub const OutputMode = output.OutputMode;
/// Check options. Avoid reaching through `validate.CheckOptions`.
pub const CheckOptions = validate.CheckOptions;

/// Runs the top-level CLI through the library entry point.
pub fn run(init: std.process.Init) !u8 {
    return cli.run(init);
}

// --- Tests ---

test {
    _ = @import("xml/events.zig");
    _ = @import("xml/parser.zig");
    _ = @import("mzml/structural.zig");
    _ = @import("mzml/binary.zig");
    _ = @import("validate.zig");
}
