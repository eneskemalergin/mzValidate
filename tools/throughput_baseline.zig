const std = @import("std");

const Scenario = struct {
    name: []const u8,
    input_path: []const u8,
    command: []const u8,
    min_throughput_mib_s: f64,
};

const ZebracResults = struct {
    results: []const Result = &.{},

    const Result = struct {
        wall_time: Metric = .{},
    };

    const Metric = struct {
        mean: f64 = 0,
        unit: []const u8 = "",
    };
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const cwd = std.Io.Dir.cwd();
    const args = try init.minimal.args.toSlice(allocator);
    defer allocator.free(args);
    const repo_root = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(repo_root);

    if (args.len != 2) {
        try fail(io, "usage: throughput_baseline <mzvalidate-benchmark-path>", .{});
    }

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_file_writer: std.Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;
    defer stdout.flush() catch {};

    const zebrac_path = try std.fs.path.join(allocator, &.{ repo_root, "tools", "zebrac" });
    defer allocator.free(zebrac_path);
    const json_path = try std.fs.path.join(allocator, &.{ repo_root, ".zig-cache", "zebrac-throughput-baseline.json" });
    defer allocator.free(json_path);

    const scenarios = try buildScenarios(allocator, repo_root, args[1]);
    defer {
        for (scenarios) |scenario| allocator.free(scenario.command);
        allocator.free(scenarios);
    }

    try stdout.print("Throughput baseline via zebrac\n", .{});
    try stdout.print("json_report={s}\n", .{json_path});

    var gate_failed = false;
    for (scenarios) |scenario| {
        const input_bytes = try fileSize(io, cwd, scenario.input_path);
        const wall_time_ns = try runZebracScenario(allocator, io, cwd, zebrac_path, json_path, scenario.command);
        const throughput_mib_s = throughputMiBPerSecond(input_bytes, wall_time_ns);
        const status = if (throughput_mib_s >= scenario.min_throughput_mib_s) "ok" else "regressed";
        if (throughput_mib_s < scenario.min_throughput_mib_s) gate_failed = true;

        try stdout.print(
            "{s}: bytes={d} wall_time_mean_ns={d:.0} throughput_mib_s={d:.2} min_throughput_mib_s={d:.2} status={s}\n",
            .{ scenario.name, input_bytes, wall_time_ns, throughput_mib_s, scenario.min_throughput_mib_s, status },
        );
    }

    if (gate_failed) {
        try fail(io, "throughput regression gate failed", .{});
    }
}

fn buildScenarios(allocator: std.mem.Allocator, repo_root: []const u8, mzvalidate_path: []const u8) ![]Scenario {
    const small_uncompressed = try std.fs.path.join(allocator, &.{ repo_root, "fixtures", "mzml", "valid", "small.pwiz.1.1.mzML" });
    defer allocator.free(small_uncompressed);
    const small_zlib = try std.fs.path.join(allocator, &.{ repo_root, "fixtures", "mzml", "valid", "small_zlib.pwiz.1.1.mzML" });
    defer allocator.free(small_zlib);
    const tiny_indexed = try std.fs.path.join(allocator, &.{ repo_root, "fixtures", "mzml", "valid", "tiny.pwiz.1.1.mzML" });
    defer allocator.free(tiny_indexed);

    var scenarios: std.ArrayList(Scenario) = .empty;
    errdefer {
        for (scenarios.items) |scenario| allocator.free(scenario.command);
        scenarios.deinit(allocator);
    }

    try scenarios.append(allocator, .{
        .name = "level1_small_uncompressed",
        .input_path = "fixtures/mzml/valid/small.pwiz.1.1.mzML",
        .command = try std.fmt.allocPrint(allocator, "{s} check {s} -summary -skip-binary", .{ mzvalidate_path, small_uncompressed }),
        .min_throughput_mib_s = 100.0,
    });
    try scenarios.append(allocator, .{
        .name = "level1_small_uncompressed_mmap",
        .input_path = "fixtures/mzml/valid/small.pwiz.1.1.mzML",
        .command = try std.fmt.allocPrint(allocator, "{s} check {s} -summary -skip-binary -mmap", .{ mzvalidate_path, small_uncompressed }),
        .min_throughput_mib_s = 100.0,
    });
    try scenarios.append(allocator, .{
        .name = "level2_small_uncompressed",
        .input_path = "fixtures/mzml/valid/small.pwiz.1.1.mzML",
        .command = try std.fmt.allocPrint(allocator, "{s} check {s} -summary", .{ mzvalidate_path, small_uncompressed }),
        .min_throughput_mib_s = 50.0,
    });
    try scenarios.append(allocator, .{
        .name = "level2_small_uncompressed_mmap",
        .input_path = "fixtures/mzml/valid/small.pwiz.1.1.mzML",
        .command = try std.fmt.allocPrint(allocator, "{s} check {s} -summary -mmap", .{ mzvalidate_path, small_uncompressed }),
        .min_throughput_mib_s = 50.0,
    });
    try scenarios.append(allocator, .{
        .name = "level2_small_zlib",
        .input_path = "fixtures/mzml/valid/small_zlib.pwiz.1.1.mzML",
        .command = try std.fmt.allocPrint(allocator, "{s} check {s} -summary", .{ mzvalidate_path, small_zlib }),
        .min_throughput_mib_s = 25.0,
    });
    try scenarios.append(allocator, .{
        .name = "level2_small_zlib_mmap",
        .input_path = "fixtures/mzml/valid/small_zlib.pwiz.1.1.mzML",
        .command = try std.fmt.allocPrint(allocator, "{s} check {s} -summary -mmap", .{ mzvalidate_path, small_zlib }),
        .min_throughput_mib_s = 25.0,
    });
    // Level 3: index validation on an indexed file.
    try scenarios.append(allocator, .{
        .name = "level3_tiny_indexed",
        .input_path = "fixtures/mzml/valid/tiny.pwiz.1.1.mzML",
        .command = try std.fmt.allocPrint(allocator, "{s} check {s} -summary -skip-binary", .{ mzvalidate_path, tiny_indexed }),
        .min_throughput_mib_s = 100.0,
    });
    try scenarios.append(allocator, .{
        .name = "level3_tiny_indexed_mmap",
        .input_path = "fixtures/mzml/valid/tiny.pwiz.1.1.mzML",
        .command = try std.fmt.allocPrint(allocator, "{s} check {s} -summary -skip-binary -mmap", .{ mzvalidate_path, tiny_indexed }),
        .min_throughput_mib_s = 100.0,
    });
    // Level 3: semantic validation (CV + reference resolution).
    try scenarios.append(allocator, .{
        .name = "level3_semantic_tiny",
        .input_path = "fixtures/mzml/valid/tiny.pwiz.1.1.mzML",
        .command = try std.fmt.allocPrint(allocator, "{s} check {s} -summary -skip-binary", .{ mzvalidate_path, tiny_indexed }),
        .min_throughput_mib_s = 50.0,
    });

    return try scenarios.toOwnedSlice(allocator);
}

fn fileSize(io: std.Io, cwd: std.Io.Dir, path: []const u8) !u64 {
    var file = try cwd.openFile(io, path, .{});
    defer file.close(io);
    const stat = try file.stat(io);
    return stat.size;
}

fn runZebracScenario(
    allocator: std.mem.Allocator,
    io: std.Io,
    cwd: std.Io.Dir,
    zebrac_path: []const u8,
    json_path: []const u8,
    command: []const u8,
) !f64 {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);

    try argv.appendSlice(allocator, &.{
        zebrac_path,
        "-d",
        "250",
        "-i",
        "1",
        "-a",
        "5",
        "-w",
        "1",
        "--json",
        json_path,
        "-q",
        command,
    });

    const run_result = try std.process.run(allocator, io, .{
        .argv = argv.items,
        .stdout_limit = .limited(128 * 1024),
        .stderr_limit = .limited(128 * 1024),
    });
    defer allocator.free(run_result.stdout);
    defer allocator.free(run_result.stderr);

    switch (run_result.term) {
        .exited => |code| if (code != 0) {
            try fail(io, "zebrac failed with exit code {d}\n{s}{s}", .{ code, run_result.stdout, run_result.stderr });
        },
        else => try fail(io, "zebrac terminated abnormally\n{s}{s}", .{ run_result.stdout, run_result.stderr }),
    }

    const parsed = try parseZebracJson(allocator, io, cwd, json_path);
    defer parsed.deinit();

    if (parsed.value.results.len == 0) {
        try fail(io, "zebrac produced no benchmark results", .{});
    }

    const result = parsed.value.results[0];
    if (!std.mem.eql(u8, result.wall_time.unit, "ns") and !std.mem.eql(u8, result.wall_time.unit, "nanoseconds")) {
        try fail(io, "unexpected wall_time unit: {s}", .{result.wall_time.unit});
    }

    return result.wall_time.mean;
}

fn parseZebracJson(
    allocator: std.mem.Allocator,
    io: std.Io,
    cwd: std.Io.Dir,
    json_rel_path: []const u8,
) !std.json.Parsed(ZebracResults) {
    const json_text = try cwd.readFileAlloc(io, json_rel_path, allocator, .limited(512 * 1024));
    defer allocator.free(json_text);
    return std.json.parseFromSlice(ZebracResults, allocator, json_text, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
}

fn throughputMiBPerSecond(input_bytes: u64, wall_time_ns: f64) f64 {
    if (wall_time_ns <= 0) return 0;
    const bytes_per_second = (@as(f64, @floatFromInt(input_bytes)) * @as(f64, std.time.ns_per_s)) / wall_time_ns;
    return bytes_per_second / (1024.0 * 1024.0);
}

fn fail(io: std.Io, comptime fmt: []const u8, args: anytype) !noreturn {
    var stderr_buffer: [1024]u8 = undefined;
    var stderr_file_writer: std.Io.File.Writer = .init(.stderr(), io, &stderr_buffer);
    const stderr = &stderr_file_writer.interface;

    try stderr.print(fmt, args);
    try stderr.print("\n", .{});
    try stderr.flush();
    std.process.exit(1);
}
