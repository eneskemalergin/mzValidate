//! Executable entry point. Three lines, one job.
//!
//! Juicy Main (`std.process.Init`) provides the allocator, I/O, and args.
//! Everything else lives in the library so tests and downstream tools
//! import `mzvalidate` and call `run(init)` directly.

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
