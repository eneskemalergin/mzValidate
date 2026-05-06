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

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);

    const bump_version_step = b.step("bump-version", "Update the project version and manifest fingerprint");
    const bump_version_cmd = b.addRunArtifact(version_tool);
    bump_version_cmd.addArg(release_version orelse "--help");
    bump_version_step.dependOn(&bump_version_cmd.step);
}
