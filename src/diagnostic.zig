//! Shared diagnostic types and exit-code mapping.

const std = @import("std");

pub const Severity = enum {
    info,
    warning,
    @"error",

    pub fn label(severity: Severity) []const u8 {
        return switch (severity) {
            .info => "info",
            .warning => "warning",
            .@"error" => "error",
        };
    }
};

pub const Location = struct {
    byte_offset: ?u64 = null,
    spectrum_index: ?usize = null,
};

pub const Diagnostic = struct {
    severity: Severity,
    rule: []const u8,
    location: Location = .{},
    path: ?[]const u8 = null,
    message: []const u8,
};

pub const Totals = struct {
    info: usize = 0,
    warnings: usize = 0,
    errors: usize = 0,
};

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

pub fn exitCode(diagnostics: []const Diagnostic) u8 {
    const totals = count(diagnostics);
    if (totals.errors > 0) return 2;
    if (totals.warnings > 0) return 1;
    return 0;
}

test "exitCode prefers errors over warnings" {
    const diagnostics = [_]Diagnostic{
        .{ .severity = .warning, .rule = "runtime.stub", .message = "stub" },
        .{ .severity = .@"error", .rule = "runtime.file-open", .message = "open failed" },
    };

    try std.testing.expectEqual(@as(u8, 2), exitCode(&diagnostics));
}
