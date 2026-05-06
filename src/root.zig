//! Public API surface for mzValidate.

const std = @import("std");

/// Exposes CLI parsing and dispatch for embedding tests.
pub const cli = @import("cli.zig");
/// Exposes shared diagnostic types and helpers.
pub const diagnostic = @import("diagnostic.zig");
/// Exposes text and JSON rendering helpers.
pub const output = @import("output.zig");
/// Exposes the validation entry points.
pub const validate = @import("validate.zig");

/// Re-exports the shared diagnostic type from the library root.
pub const Diagnostic = diagnostic.Diagnostic;
/// Re-exports severity so callers do not need to reach through submodules.
pub const Severity = diagnostic.Severity;
/// Re-exports output mode for CLI-adjacent tests.
pub const OutputMode = output.OutputMode;
/// Re-exports check options for library callers.
pub const CheckOptions = validate.CheckOptions;

/// Runs the top-level CLI through the library entry point.
pub fn run(init: std.process.Init) !u8 {
    return cli.run(init);
}

test {
    _ = @import("xml/events.zig");
    _ = @import("xml/parser.zig");
    _ = @import("mzml/structural.zig");
    _ = @import("mzml/binary.zig");
}
