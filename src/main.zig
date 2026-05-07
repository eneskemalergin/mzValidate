//! Executable entry point. Delegates everything to the library.

const std = @import("std");
const mzvalidate = @import("mzvalidate");

pub fn main(init: std.process.Init) !void {
    const exit_code = try mzvalidate.run(init);
    std.process.exit(exit_code);
}

// --- Tests ---

test {
    _ = @import("mzvalidate");
}
