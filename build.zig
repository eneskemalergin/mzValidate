const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const release_version = b.option([]const u8, "release-version", "Semantic version for the bump-version step, for example 0.0.3");
    const version_tool = b.addExecutable(.{
        .name = "bump_version",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/bump_version.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });

    const mzvalidate_mod = b.addModule("mzvalidate", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
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

    b.installArtifact(exe);

    const run_step = b.step("run", "Run mzValidate");
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_step.dependOn(&run_cmd.step);
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const mod_tests = b.addTest(.{
        .root_module = mzvalidate_mod,
    });
    const run_mod_tests = b.addRunArtifact(mod_tests);

    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });
    const run_exe_tests = b.addRunArtifact(exe_tests);

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

    const bump_version_step = b.step("bump-version", "Update the project version and manifest fingerprint");
    const bump_version_cmd = b.addRunArtifact(version_tool);
    bump_version_cmd.addArg(release_version orelse "--help");
    bump_version_step.dependOn(&bump_version_cmd.step);
}

fn addFixtureArgs(run: *std.Build.Step.Run, fixtures: []const []const u8) void {
    for (fixtures) |fixture| run.addArg(fixture);
}

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
