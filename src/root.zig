//! Public API surface for mzValidate.

const std = @import("std");

pub const cli = @import("cli.zig");
pub const diagnostic = @import("diagnostic.zig");
pub const output = @import("output.zig");
pub const validate = @import("validate.zig");

pub const Diagnostic = diagnostic.Diagnostic;
pub const Severity = diagnostic.Severity;
pub const OutputMode = output.OutputMode;
pub const CheckOptions = validate.CheckOptions;

pub fn run(init: std.process.Init) !u8 {
    return cli.run(init);
}

test {
    _ = @import("xml/events.zig");
    _ = @import("xml/parser.zig");
    _ = @import("mzml/structural.zig");
    _ = @import("mzml/binary.zig");
}
