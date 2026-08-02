//! Executable entry point.
//!
//! Delegates validation to the library and preserves its exit code.

const std = @import("std");
const mzvalidate = @import("mzvalidate");

pub fn main(init: std.process.Init) !u8 {
    return mzvalidate.run(init);
}

// --- Unit Tests ---

test {
    _ = @import("mzvalidate");
}
