const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const enable_libdeflate = b.option(bool, "enable-libdeflate", "Use vendored libdeflate for zlib decompression (default: true)") orelse true;

    const mzvalidate_mod = b.addModule("mzvalidate", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const mzvalidate_options = b.addOptions();
    mzvalidate_options.addOption(bool, "enable_libdeflate", enable_libdeflate);
    mzvalidate_mod.addOptions("build_options", mzvalidate_options);

    if (enable_libdeflate) {
        addVendoredLibdeflateToModule(mzvalidate_mod, b, optimize, target);
    }

    const exe = b.addExecutable(.{
        .name = "mzValidate",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .single_threaded = true,
            .imports = &.{
                .{ .name = "mzvalidate", .module = mzvalidate_mod },
            },
        }),
    });

    if (optimize != .Debug) {
        exe.lto = .full;
    }
    b.installArtifact(exe);

    const mutation_tools_step = b.step("mutation-tools", "Build development mutation checkers");
    const xml_mutation_tool = addMutationTool(b, target, optimize, "xml-mutation-check", "tools/xml-mutation-check.zig", mzvalidate_mod);
    const obo_mutation_tool = addMutationTool(b, target, optimize, "obo-mutation-check", "tools/obo-mutation-check.zig", mzvalidate_mod);
    mutation_tools_step.dependOn(&b.addInstallArtifact(xml_mutation_tool, .{}).step);
    mutation_tools_step.dependOn(&b.addInstallArtifact(obo_mutation_tool, .{}).step);

    const mod_tests = b.addTest(.{
        .root_module = mzvalidate_mod,
    });
    const run_mod_tests = b.addRunArtifact(mod_tests);

    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });
    const run_exe_tests = b.addRunArtifact(exe_tests);

    const run_step = b.step("run", "Run mzValidate");
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_step.dependOn(&run_cmd.step);
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const test_step = b.step("test", "Run unit tests (library and CLI; allocator leak detection)");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);

    const valid_fixtures = collectMzmlFixturePaths(b, "fixtures/mzml/valid") catch @panic("failed to collect valid mzML fixtures");
    const invalid_fixtures = collectMzmlFixturePaths(b, "fixtures/mzml/invalid") catch @panic("failed to collect invalid mzML fixtures");

    const cli_valid_cmd = b.addRunArtifact(exe);
    cli_valid_cmd.step.dependOn(b.getInstallStep());
    cli_valid_cmd.addArg("check");
    addFixtureArgs(cli_valid_cmd, valid_fixtures);
    cli_valid_cmd.addArg("fixtures/examples/mzml/single-spectrum-missing-cv-terms.mzML");
    cli_valid_cmd.addArg("-skip-semantic");
    cli_valid_cmd.addArg("-skip-index");
    cli_valid_cmd.addArg("-summary");
    cli_valid_cmd.expectStdOutEqual("status=clean info=0 warnings=0 errors=0\n");

    const cli_invalid_cmd = b.addRunArtifact(exe);
    cli_invalid_cmd.step.dependOn(b.getInstallStep());
    cli_invalid_cmd.addArg("check");
    addFixtureArgs(cli_invalid_cmd, invalid_fixtures);
    cli_invalid_cmd.addArg("-skip-semantic");
    cli_invalid_cmd.addArg("-summary");
    cli_invalid_cmd.expectExitCode(2);
    cli_invalid_cmd.expectStdOutMatch("status=errors-present info=0 warnings=0 errors=");

    const cli_contract_step = b.step("cli-contract", "Run CLI contract checks for valid and expected-invalid fixtures");
    cli_contract_step.dependOn(&cli_valid_cmd.step);
    cli_contract_step.dependOn(&cli_invalid_cmd.step);

    const ci_step = b.step("ci", "test + cli-contract");
    ci_step.dependOn(test_step);
    ci_step.dependOn(cli_contract_step);
}

fn addFixtureArgs(run: *std.Build.Step.Run, fixtures: []const []const u8) void {
    for (fixtures) |fixture| run.addArg(fixture);
}

fn addMutationTool(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    name: []const u8,
    root_source: []const u8,
    mzvalidate_mod: *std.Build.Module,
) *std.Build.Step.Compile {
    return b.addExecutable(.{
        .name = name,
        .root_module = b.createModule(.{
            .root_source_file = b.path(root_source),
            .target = target,
            .optimize = optimize,
            .single_threaded = true,
            .imports = &.{
                .{ .name = "mzvalidate", .module = mzvalidate_mod },
            },
        }),
    });
}

fn addVendoredLibdeflateToModule(mod: *std.Build.Module, b: *std.Build, optimize: std.builtin.OptimizeMode, target: std.Build.ResolvedTarget) void {
    mod.linkSystemLibrary("c", .{});
    mod.addIncludePath(b.path("vendor/libdeflate"));
    mod.addIncludePath(b.path("vendor/libdeflate/lib"));

    const opt = switch (optimize) {
        .Debug => "-Og",
        .ReleaseSafe => "-O2",
        .ReleaseFast, .ReleaseSmall => "-O3",
    };

    const march: []const u8 = switch (target.result.cpu.arch) {
        .x86_64 => "-march=x86-64-v2",
        .aarch64 => "-march=armv8-a",
        else => "",
    };

    const common_flags = &.{ opt, march };

    mod.addCSourceFile(.{ .file = b.path("vendor/libdeflate/lib/deflate_decompress.c"), .flags = common_flags });
    mod.addCSourceFile(.{ .file = b.path("vendor/libdeflate/lib/zlib_decompress.c"), .flags = common_flags });
    mod.addCSourceFile(.{ .file = b.path("vendor/libdeflate/lib/utils.c"), .flags = common_flags });

    switch (target.result.cpu.arch) {
        .x86_64 => {
            const adler32_flags = &.{ opt, march, "-DLIBDEFLATE_ASSEMBLER_DOES_NOT_SUPPORT_AVX512VNNI" };
            mod.addCSourceFile(.{ .file = b.path("vendor/libdeflate/lib/adler32.c"), .flags = adler32_flags });
            mod.addCSourceFile(.{ .file = b.path("vendor/libdeflate/lib/x86/cpu_features.c"), .flags = common_flags });
        },
        .aarch64, .arm => {
            mod.addCSourceFile(.{ .file = b.path("vendor/libdeflate/lib/adler32.c"), .flags = common_flags });
            mod.addCSourceFile(.{ .file = b.path("vendor/libdeflate/lib/arm/cpu_features.c"), .flags = common_flags });
        },
        else => {
            mod.addCSourceFile(.{ .file = b.path("vendor/libdeflate/lib/adler32.c"), .flags = common_flags });
        },
    }
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
