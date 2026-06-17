//! Single source of truth for benchmark scenarios, zebrac profiles, and gates.
//!
//! Throughput scenarios (CI + local) and RSS scenarios (resource) live here.
//! Levels are flag sets, not separate modules or files.

const std = @import("std");

pub const ZebracProfile = struct {
    discard_ms: u32,
    inner: u32,
    outer: u32,

    pub const ci_small: ZebracProfile = .{
        .discard_ms = 250,
        .inner = 1,
        .outer = 5,
    };
    pub const local_large: ZebracProfile = .{
        .discard_ms = 2000,
        .inner = 2,
        .outer = 3,
    };
    pub const resource: ZebracProfile = .{
        .discard_ms = 200,
        .inner = 2,
        .outer = 2,
    };
};

pub const SkipFlags = struct {
    skip_binary: bool = false,
    skip_semantic: bool = false,
    skip_index: bool = false,

    pub const l1: SkipFlags = .{ .skip_binary = true, .skip_semantic = true };
    pub const l2: SkipFlags = .{ .skip_semantic = true };
    pub const l3: SkipFlags = .{ .skip_binary = true };
    pub const l4: SkipFlags = .{};
};

pub const Tier = enum {
    ci,
    local,
};

pub const GateKind = union(enum) {
    min_throughput_mib_s: f64,
    max_wall_s: f64,
    max_peak_rss_bytes: u64,
};

pub const ThroughputScenario = struct {
    id: []const u8,
    fixture_rel: []const u8,
    skips: SkipFlags,
    tier: Tier,
    profile: ZebracProfile,
    gate: GateKind,
    /// Skip when `data/` fixture is absent (local tier only).
    optional_fixture: bool = false,
};

pub const ResourceScenario = struct {
    id: []const u8,
    fixture_rel: []const u8,
    skips: SkipFlags,
    gate: GateKind,
};

/// CI throughput gates: small/tiny fixtures only (~15 s total).
pub const throughput_ci: []const ThroughputScenario = &.{
    .{
        .id = "small_l1",
        .fixture_rel = "fixtures/mzml/valid/small.pwiz.1.1.mzML",
        .skips = SkipFlags.l1,
        .tier = .ci,
        .profile = ZebracProfile.ci_small,
        .gate = .{ .min_throughput_mib_s = 98.0 },
    },
    .{
        .id = "small_l2",
        .fixture_rel = "fixtures/mzml/valid/small.pwiz.1.1.mzML",
        .skips = SkipFlags.l2,
        .tier = .ci,
        .profile = ZebracProfile.ci_small,
        .gate = .{ .min_throughput_mib_s = 79.0 },
    },
    .{
        .id = "small_zlib_l2",
        .fixture_rel = "fixtures/mzml/valid/small_zlib.pwiz.1.1.mzML",
        .skips = SkipFlags.l2,
        .tier = .ci,
        .profile = ZebracProfile.ci_small,
        .gate = .{ .min_throughput_mib_s = 36.0 },
    },
    .{
        .id = "tiny_l3",
        .fixture_rel = "fixtures/mzml/valid/tiny.pwiz.1.1.mzML",
        .skips = SkipFlags.l3,
        .tier = .ci,
        .profile = ZebracProfile.ci_small,
        .gate = .{ .max_wall_s = 0.020 },
    },
    .{
        .id = "tiny_l4",
        .fixture_rel = "fixtures/mzml/valid/tiny.pwiz.1.1.mzML",
        .skips = SkipFlags.l4,
        .tier = .ci,
        .profile = ZebracProfile.ci_small,
        .gate = .{ .max_wall_s = 0.020 },
    },
};

/// Opt-in large/stress fixtures under `data/` (not in CI).
pub const throughput_local: []const ThroughputScenario = &.{
    .{
        .id = "astral_l1",
        .fixture_rel = "data/20240614_Astral_Neo6_TH026_AU25_DI_run69p2_H460_50SPD_E3.mzML",
        .skips = SkipFlags.l1,
        .tier = .local,
        .profile = ZebracProfile.local_large,
        .gate = .{ .max_wall_s = 15.0 },
        .optional_fixture = true,
    },
    .{
        .id = "prm_l4",
        .fixture_rel = "data/1fmol_HSP90_SILpepmix_PRM.mzML",
        .skips = SkipFlags.l4,
        .tier = .local,
        .profile = ZebracProfile.local_large,
        .gate = .{ .max_wall_s = 20.0 },
        .optional_fixture = true,
    },
};

/// Peak RSS gates on synthetic workloads (`.zig-cache/tmp/resource-check/`).
pub const resource_scenarios: []const ResourceScenario = &.{
    .{
        .id = "level1_stream_many_spectra",
        .fixture_rel = ".zig-cache/tmp/resource-check/stream-many-spectra.mzML",
        .skips = SkipFlags.l1,
        .gate = .{ .max_peak_rss_bytes = 64 * 1024 * 1024 },
    },
    .{
        .id = "level2_stream_many_spectra",
        .fixture_rel = ".zig-cache/tmp/resource-check/stream-many-spectra.mzML",
        .skips = SkipFlags.l2,
        .gate = .{ .max_peak_rss_bytes = 64 * 1024 * 1024 },
    },
    .{
        .id = "level2_large_array_workspace",
        .fixture_rel = ".zig-cache/tmp/resource-check/large-array.mzML",
        .skips = SkipFlags.l2,
        .gate = .{ .max_peak_rss_bytes = 40 * 1024 * 1024 },
    },
    .{
        .id = "level2_invalid_zlib_error_path",
        .fixture_rel = "fixtures/mzml/invalid/invalid-zlib.mzML",
        .skips = SkipFlags.l2,
        .gate = .{ .max_peak_rss_bytes = 16 * 1024 * 1024 },
    },
    .{
        .id = "level4_semantic_many_spectra",
        .fixture_rel = ".zig-cache/tmp/resource-check/stream-many-spectra.mzML",
        .skips = SkipFlags.l4,
        .gate = .{ .max_peak_rss_bytes = 64 * 1024 * 1024 },
    },
    .{
        .id = "level4_reftable_many_spectra",
        .fixture_rel = ".zig-cache/tmp/resource-check/stream-many-spectra.mzML",
        .skips = .{ .skip_binary = true, .skip_index = true },
        .gate = .{ .max_peak_rss_bytes = 64 * 1024 * 1024 },
    },
};

pub fn buildCheckCommand(
    allocator: std.mem.Allocator,
    bench_path: []const u8,
    fixture_abs: []const u8,
    skips: SkipFlags,
) ![]u8 {
    var parts: std.ArrayList(u8) = .empty;
    errdefer parts.deinit(allocator);
    try parts.appendSlice(allocator, bench_path);
    try parts.appendSlice(allocator, " check ");
    try parts.appendSlice(allocator, fixture_abs);
    try parts.appendSlice(allocator, " -summary");
    if (skips.skip_binary) try parts.appendSlice(allocator, " -skip-binary");
    if (skips.skip_semantic) try parts.appendSlice(allocator, " -skip-semantic");
    if (skips.skip_index) try parts.appendSlice(allocator, " -skip-index");
    return try parts.toOwnedSlice(allocator);
}

pub fn evaluateThroughputGate(gate: GateKind, throughput_mib_s: f64, wall_s: f64) []const u8 {
    return switch (gate) {
        .min_throughput_mib_s => |min| if (throughput_mib_s >= min) "ok" else "regressed",
        .max_wall_s => |max| if (wall_s <= max) "ok" else "regressed",
        .max_peak_rss_bytes => unreachable,
    };
}

pub fn profilesMatch(a: ZebracProfile, b: ZebracProfile) bool {
    return a.discard_ms == b.discard_ms and a.inner == b.inner and a.outer == b.outer;
}

test "throughput scenario ids are unique" {
    var seen = std.AutoHashMapUnmanaged([]const u8, void){};
    defer seen.deinit(std.testing.allocator);
    for (throughput_ci) |s| {
        const gop = try seen.getOrPut(std.testing.allocator, s.id);
        try std.testing.expect(!gop.found_existing);
    }
    for (throughput_local) |s| {
        const gop = try seen.getOrPut(std.testing.allocator, s.id);
        try std.testing.expect(!gop.found_existing);
    }
}

test "resource scenario ids are unique" {
    var seen = std.AutoHashMapUnmanaged([]const u8, void){};
    defer seen.deinit(std.testing.allocator);
    for (resource_scenarios) |s| {
        const gop = try seen.getOrPut(std.testing.allocator, s.id);
        try std.testing.expect(!gop.found_existing);
    }
}

test "ci throughput scenarios share zebrac profile" {
    const expected = throughput_ci[0].profile;
    for (throughput_ci) |s| {
        try std.testing.expect(profilesMatch(s.profile, expected));
    }
}

test "evaluate throughput gates" {
    try std.testing.expectEqualStrings("ok", evaluateThroughputGate(.{ .min_throughput_mib_s = 100.0 }, 150.0, 0));
    try std.testing.expectEqualStrings("regressed", evaluateThroughputGate(.{ .min_throughput_mib_s = 100.0 }, 50.0, 0));
    try std.testing.expectEqualStrings("ok", evaluateThroughputGate(.{ .max_wall_s = 1.0 }, 0, 0.5));
    try std.testing.expectEqualStrings("regressed", evaluateThroughputGate(.{ .max_wall_s = 1.0 }, 0, 1.5));
}
