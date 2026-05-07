//! Build script for mzValidate.
//!
//! Key steps:
//!   test          - run all unit tests
//!   cli-contract  - run the binary against valid and expected-invalid fixtures
//!   ci            - test + cli-contract (what CI runs)
//!   resource-check - profile representative workloads with zebrac and gate peak RSS
//!   throughput-baseline - record and gate representative throughput metrics with zebrac
//!   fuzz-smoke    - run deterministic random and mutation-based smoke fuzzing
//!   bump-version  - rewrite version.zig and build.zig.zon
//!   run           - execute the binary directly

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const release_version = b.option([]const u8, "release-version", "Semantic version for the bump-version step, for example 0.0.3");

    // --- Version tool ---

    const version_tool = b.addExecutable(.{
        .name = "bump_version",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/bump_version.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });

    const resource_check_tool = b.addExecutable(.{
        .name = "resource_check",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/resource_check.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });

    const throughput_baseline_tool = b.addExecutable(.{
        .name = "throughput_baseline",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/throughput_baseline.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });

    const fuzz_smoke_tool = b.addExecutable(.{
        .name = "fuzz_smoke",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/fuzz_smoke.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });

    // --- Library and executable ---

    const mzvalidate_mod = b.addModule("mzvalidate", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const xml_fuzz_target = b.addExecutable(.{
        .name = "xml_fuzz_target",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/xml_fuzz_target.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
            .imports = &.{
                .{ .name = "mzvalidate", .module = mzvalidate_mod },
            },
        }),
    });

    const binary_fuzz_target = b.addExecutable(.{
        .name = "binary_fuzz_target",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/binary_fuzz_target.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
            .imports = &.{
                .{ .name = "mzvalidate", .module = mzvalidate_mod },
            },
        }),
    });

    const exe = b.addExecutable(.{
        .name = "mzValidate",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "mzvalidate", .module = mzvalidate_mod },
            },
        }),
    });

    const throughput_bench_exe = b.addExecutable(.{
        .name = "mzValidate_throughput",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "mzvalidate", .module = mzvalidate_mod },
            },
        }),
    });

    b.installArtifact(exe);

    // --- Run step ---

    const run_step = b.step("run", "Run mzValidate");
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_step.dependOn(&run_cmd.step);
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // --- Unit tests ---

    const mod_tests = b.addTest(.{
        .root_module = mzvalidate_mod,
    });
    const run_mod_tests = b.addRunArtifact(mod_tests);

    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });
    const run_exe_tests = b.addRunArtifact(exe_tests);

    // --- CLI contract ---

    const valid_fixtures = collectMzmlFixturePaths(b, "fixtures/mzml/valid") catch @panic("failed to collect valid mzML fixtures");
    const invalid_fixtures = collectMzmlFixturePaths(b, "fixtures/mzml/invalid") catch @panic("failed to collect invalid mzML fixtures");

    const cli_valid_cmd = b.addRunArtifact(exe);
    cli_valid_cmd.step.dependOn(b.getInstallStep());
    cli_valid_cmd.addArg("check");
    addFixtureArgs(cli_valid_cmd, valid_fixtures);
    cli_valid_cmd.addArg("fixtures/examples/mzml/clean-single-spectrum.mzML");
    cli_valid_cmd.addArg("-summary");
    cli_valid_cmd.expectStdOutEqual("status=clean info=0 warnings=0 errors=0\n");

    const cli_invalid_cmd = b.addRunArtifact(exe);
    cli_invalid_cmd.step.dependOn(b.getInstallStep());
    cli_invalid_cmd.addArg("check");
    addFixtureArgs(cli_invalid_cmd, invalid_fixtures);
    cli_invalid_cmd.addArg("-summary");
    cli_invalid_cmd.expectExitCode(2);
    cli_invalid_cmd.expectStdOutMatch("status=errors-present info=0 warnings=0 errors=");

    // --- Build steps ---

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);

    const cli_contract_step = b.step("cli-contract", "Run CLI contract checks for valid and expected-invalid fixtures");
    cli_contract_step.dependOn(&cli_valid_cmd.step);
    cli_contract_step.dependOn(&cli_invalid_cmd.step);

    const legacy_cli_step = b.step("test-cli", "Alias for cli-contract");
    legacy_cli_step.dependOn(cli_contract_step);

    const ci_step = b.step("ci", "Run unit tests and CLI contract checks");
    ci_step.dependOn(test_step);
    ci_step.dependOn(cli_contract_step);

    const resource_check_step = b.step("resource-check", "Profile representative workloads and gate peak RSS with zebrac");
    const resource_check_cmd = b.addRunArtifact(resource_check_tool);
    resource_check_cmd.step.dependOn(b.getInstallStep());
    resource_check_step.dependOn(&resource_check_cmd.step);

    const throughput_baseline_step = b.step("throughput-baseline", "Record and gate representative throughput baselines with zebrac");
    const throughput_baseline_cmd = b.addRunArtifact(throughput_baseline_tool);
    throughput_baseline_cmd.addArtifactArg(throughput_bench_exe);
    throughput_baseline_step.dependOn(&throughput_baseline_cmd.step);

    const xml_fuzz_target_step = b.step("xml-fuzz-target", "Build the focused XML fuzz-entry executable");
    xml_fuzz_target_step.dependOn(&xml_fuzz_target.step);

    const binary_fuzz_target_step = b.step("binary-fuzz-target", "Build the focused binary fuzz-entry executable");
    binary_fuzz_target_step.dependOn(&binary_fuzz_target.step);

    const fuzz_targets_step = b.step("fuzz-targets", "Build all focused fuzz-entry executables");
    fuzz_targets_step.dependOn(xml_fuzz_target_step);
    fuzz_targets_step.dependOn(binary_fuzz_target_step);

    const fuzz_smoke_step = b.step("fuzz-smoke", "Run deterministic random and mutation-based smoke fuzzing");
    const fuzz_smoke_cmd = b.addRunArtifact(fuzz_smoke_tool);
    fuzz_smoke_cmd.addArtifactArg(xml_fuzz_target);
    fuzz_smoke_cmd.addArtifactArg(binary_fuzz_target);
    fuzz_smoke_step.dependOn(&fuzz_smoke_cmd.step);

    ci_step.dependOn(fuzz_smoke_step);
    ci_step.dependOn(throughput_baseline_step);

    const bump_version_step = b.step("bump-version", "Update the project version and manifest fingerprint");
    const bump_version_cmd = b.addRunArtifact(version_tool);
    bump_version_cmd.addArg(release_version orelse "--help");
    bump_version_step.dependOn(&bump_version_cmd.step);
}

/// Appends each fixture path as a CLI argument to `run`.
fn addFixtureArgs(run: *std.Build.Step.Run, fixtures: []const []const u8) void {
    for (fixtures) |fixture| run.addArg(fixture);
}

/// Walks `root`, collects paths of all `.mzML` files, and returns them sorted.
/// Build allocator owns all strings; no cleanup needed.
fn collectMzmlFixturePaths(b: *std.Build, root: []const u8) ![]const []const u8 {
    const io = b.graph.io;
    var dir = try std.Io.Dir.cwd().openDir(io, root, .{ .iterate = true });
    defer dir.close(io);

    var walker = try dir.walk(b.allocator);
    defer walker.deinit();

    var paths: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (paths.items) |path| b.allocator.free(path);
        paths.deinit(b.allocator);
    }

    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.path, ".mzML")) continue;

        const joined = try std.fs.path.join(b.allocator, &.{ root, entry.path });
        try paths.append(b.allocator, joined);
    }

    std.mem.sortUnstable([]const u8, paths.items, {}, struct {
        fn lessThan(_: void, lhs: []const u8, rhs: []const u8) bool {
            return std.mem.lessThan(u8, lhs, rhs);
        }
    }.lessThan);

    return try paths.toOwnedSlice(b.allocator);
}
