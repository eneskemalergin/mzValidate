//! Executable entry point.
//!
//! Delegates validation to the library and preserves its exit code.

const std = @import("std");
const mzvalidate = @import("mzvalidate");

pub fn main(init: std.process.Init) !void {
    const exit_code = try mzvalidate.run(init);
    std.process.exit(exit_code);
}

// --- Unit Tests ---

test {
    _ = @import("mzvalidate");
}
