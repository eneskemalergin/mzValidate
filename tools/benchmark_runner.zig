//! Unified benchmark runner: zebrac timing, RSS profiling, gates, JSON reports.
//!
//! Modes (argv[1]):
//!   throughput-ci   CI throughput gates (fixtures only, ~15 s)
//!   resource        Peak RSS gates on synthetic workloads
//!   record          CI + available local scenarios, JSON only, no gate fail
//!   local           Local `data/` scenarios with gates (skip missing files)

const std = @import("std");
const manifest = @import("benchmark_manifest.zig");
const fixtures = @import("benchmark_fixtures.zig");

const ThroughputScenario = manifest.ThroughputScenario;
const ResourceScenario = manifest.ResourceScenario;
const ZebracProfile = manifest.ZebracProfile;

pub const Mode = enum {
    throughput_ci,
    @"resource",
    record,
    local,

    pub fn parse(text: []const u8) ?Mode {
        if (std.mem.eql(u8, text, "throughput-ci")) return .throughput_ci;
        if (std.mem.eql(u8, text, "resource")) return .@"resource";
        if (std.mem.eql(u8, text, "record")) return .record;
        if (std.mem.eql(u8, text, "local")) return .local;
        inline for (std.meta.fields(Mode)) |field| {
            if (std.mem.eql(u8, text, field.name)) return @field(Mode, field.name);
        }
        return null;
    }
};

const ZebracResults = struct {
    results: []const Result = &.{},

    const Result = struct {
        command: []const u8 = "",
        wall_time: Metric = .{},
        peak_rss: Metric = .{},
    };

    const Metric = struct {
        mean: f64 = 0,
        unit: []const u8 = "",
    };
};

const ReportRow = struct {
    scenario_id: []const u8,
    command: []const u8,
    input_bytes: u64,
    wall_time_ns: f64,
    throughput_mib_s: f64,
    peak_rss_bytes: ?u64,
    gate_status: []const u8,
    skipped: bool = false,
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(allocator);
    defer allocator.free(args);

    const mode_str, const bench_path = switch (args.len) {
        2 => .{ args[0], args[1] },
        3 => .{ args[1], args[2] },
        else => {
            try printUsage(io);
            std.process.exit(2);
        },
    };

    const mode = Mode.parse(mode_str) orelse {
        try printUsage(io);
        std.process.exit(2);
    };
    try run(init, mode, bench_path);
}

pub fn run(init: std.process.Init, mode: Mode, bench_path: []const u8) !void {
    const allocator = init.gpa;
    const io = init.io;

    const repo_root = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(repo_root);

    try verifyBenchBinary(io, bench_path);

    const zebrac_path = try std.fs.path.join(allocator, &.{ repo_root, "tools", "zebrac" });
    defer allocator.free(zebrac_path);

    var stdout_buffer: [8192]u8 = undefined;
    var stdout_file_writer: std.Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;
    defer stdout.flush() catch {};

    switch (mode) {
        .throughput_ci => try runThroughput(allocator, io, stdout, repo_root, zebrac_path, bench_path, manifest.throughput_ci, false),
        .local => try runThroughput(allocator, io, stdout, repo_root, zebrac_path, bench_path, manifest.throughput_local, true),
        .record => {
            try stdout.print("benchmark throughput (ReleaseFast bench binary)\n", .{});
            try stdout.print("bench_binary={s}\n", .{bench_path});
            var rows: std.ArrayList(ReportRow) = .empty;
            defer {
                freeReportRows(allocator, &rows);
                rows.deinit(allocator);
            }
            _ = try runThroughputCollect(allocator, io, stdout, repo_root, zebrac_path, bench_path, manifest.throughput_ci, false, &rows, false);
            _ = try runThroughputCollect(allocator, io, stdout, repo_root, zebrac_path, bench_path, manifest.throughput_local, true, &rows, false);
            const json_path = try std.fs.path.join(allocator, &.{ repo_root, ".zig-cache", "benchmark-report.json" });
            defer allocator.free(json_path);
            try writeReport(allocator, io, repo_root, bench_path, json_path, rows.items);
            try stdout.print("benchmark-report={s}\n", .{json_path});
        },
        .@"resource" => try runResource(allocator, io, stdout, repo_root, zebrac_path, bench_path),
    }
}

pub fn printUsage(io: std.Io) !void {
    var stderr_buffer: [512]u8 = undefined;
    var stderr_writer: std.Io.File.Writer = .init(.stderr(), io, &stderr_buffer);
    const stderr = &stderr_writer.interface;
    try stderr.writeAll(
        "usage: benchmark <mode> <mzValidate_bench-path>\n" ++
            "  modes: throughput-ci | resource | record | local\n",
    );
    try stderr.flush();
}

fn runThroughput(
    allocator: std.mem.Allocator,
    io: std.Io,
    stdout: *std.Io.Writer,
    repo_root: []const u8,
    zebrac_path: []const u8,
    bench_path: []const u8,
    scenarios: []const ThroughputScenario,
    allow_skip_optional: bool,
) !void {
    const gate_failed = try runThroughputCollect(allocator, io, stdout, repo_root, zebrac_path, bench_path, scenarios, allow_skip_optional, null, true);
    if (gate_failed) std.process.exit(1);
}

fn freeReportRows(allocator: std.mem.Allocator, rows: *std.ArrayList(ReportRow)) void {
    for (rows.items) |row| {
        if (!row.skipped) {
            allocator.free(row.command);
            allocator.free(row.gate_status);
        }
    }
}

fn runThroughputCollect(
    allocator: std.mem.Allocator,
    io: std.Io,
    stdout: *std.Io.Writer,
    repo_root: []const u8,
    zebrac_path: []const u8,
    bench_path: []const u8,
    scenarios: []const ThroughputScenario,
    allow_skip_optional: bool,
    rows: ?*std.ArrayList(ReportRow),
    print_header: bool,
) !bool {
    const cwd = std.Io.Dir.cwd();
    const json_path = try std.fs.path.join(allocator, &.{ repo_root, ".zig-cache", "zebrac-throughput.json" });
    defer allocator.free(json_path);

    if (print_header) {
        try stdout.print("benchmark throughput (ReleaseFast bench binary)\n", .{});
        try stdout.print("bench_binary={s}\n", .{bench_path});
    }

    const PendingRun = struct {
        scenario: ThroughputScenario,
        command: []const u8,
        input_bytes: u64,
    };

    var pending: std.ArrayList(PendingRun) = .empty;
    defer {
        for (pending.items) |pending_run| allocator.free(pending_run.command);
        pending.deinit(allocator);
    }

    var commands: std.ArrayList([]const u8) = .empty;
    defer commands.deinit(allocator);

    for (scenarios) |scenario| {
        const fixture_abs = try std.fs.path.join(allocator, &.{ repo_root, scenario.fixture_rel });
        defer allocator.free(fixture_abs);

        if (scenario.optional_fixture and !fixtureExists(io, fixture_abs)) {
            if (allow_skip_optional) {
                try stdout.print("{s}: skipped (fixture missing)\n", .{scenario.id});
                if (rows) |list| {
                    try list.append(allocator, .{
                        .scenario_id = scenario.id,
                        .command = "",
                        .input_bytes = 0,
                        .wall_time_ns = 0,
                        .throughput_mib_s = 0,
                        .peak_rss_bytes = null,
                        .gate_status = "skipped",
                        .skipped = true,
                    });
                }
                continue;
            }
            try fail(io, "missing fixture for {s}: {s}", .{ scenario.id, scenario.fixture_rel });
        }

        const command = try manifest.buildCheckCommand(allocator, bench_path, fixture_abs, scenario.skips);
        const input_bytes = try fileSize(io, cwd, scenario.fixture_rel);
        try commands.append(allocator, command);
        try pending.append(allocator, .{
            .scenario = scenario,
            .command = command,
            .input_bytes = input_bytes,
        });
    }

    if (pending.items.len == 0) return false;

    const profile = pending.items[0].scenario.profile;
    for (pending.items) |pending_run| {
        if (!manifest.profilesMatch(pending_run.scenario.profile, profile)) {
            try fail(io, "throughput batch requires a single zebrac profile (mixed profiles in one collect)", .{});
        }
    }

    const wall_times = try runZebracBatch(allocator, io, zebrac_path, json_path, profile, commands.items, false);
    defer allocator.free(wall_times);

    var gate_failed = false;
    for (pending.items, wall_times) |pending_run, wall_time_ns| {
        const throughput_mib_s = throughputMiBPerSecond(pending_run.input_bytes, wall_time_ns);
        const wall_s = wall_time_ns / @as(f64, @floatFromInt(std.time.ns_per_s));
        const status = manifest.evaluateThroughputGate(pending_run.scenario.gate, throughput_mib_s, wall_s);
        if (std.mem.eql(u8, status, "regressed")) gate_failed = true;

        try stdout.print(
            "{s}: bytes={d} wall_time_mean_ns={d:.0} throughput_mib_s={d:.2} status={s}\n",
            .{ pending_run.scenario.id, pending_run.input_bytes, wall_time_ns, throughput_mib_s, status },
        );
        try stdout.flush();

        if (rows) |list| {
            try list.append(allocator, .{
                .scenario_id = pending_run.scenario.id,
                .command = try allocator.dupe(u8, pending_run.command),
                .input_bytes = pending_run.input_bytes,
                .wall_time_ns = wall_time_ns,
                .throughput_mib_s = throughput_mib_s,
                .peak_rss_bytes = null,
                .gate_status = try allocator.dupe(u8, status),
            });
        }
    }
    return gate_failed;
}

fn runResource(
    allocator: std.mem.Allocator,
    io: std.Io,
    stdout: *std.Io.Writer,
    repo_root: []const u8,
    zebrac_path: []const u8,
    bench_path: []const u8,
) !void {
    const cwd = std.Io.Dir.cwd();
    try fixtures.ensureSyntheticFixtures(io, cwd, allocator);

    const json_path = try std.fs.path.join(allocator, &.{ repo_root, ".zig-cache", "zebrac-resource-check.json" });
    defer allocator.free(json_path);

    var commands: std.ArrayList([]const u8) = .empty;
    defer {
        for (commands.items) |cmd| allocator.free(cmd);
        commands.deinit(allocator);
    }

    for (manifest.resource_scenarios) |scenario| {
        const fixture_abs = try std.fs.path.join(allocator, &.{ repo_root, scenario.fixture_rel });
        defer allocator.free(fixture_abs);
        const command = try manifest.buildCheckCommand(allocator, bench_path, fixture_abs, scenario.skips);
        try commands.append(allocator, command);
    }
    errdefer for (commands.items) |cmd| allocator.free(cmd);

    const batch_results = try runZebracBatch(allocator, io, zebrac_path, json_path, ZebracProfile.resource, commands.items, true);
    defer allocator.free(batch_results);

    const parsed = try parseZebracJson(allocator, io, cwd, ".zig-cache/zebrac-resource-check.json");
    defer parsed.deinit();

    try stdout.writeAll("resource-check: peak RSS report\n");
    try stdout.print("bench_binary={s}\n", .{bench_path});

    for (manifest.resource_scenarios, commands.items) |scenario, command| {
        const rss_bytes = findPeakRssBytes(parsed.value.results, command) orelse {
            try fail(io, "missing zebrac result for scenario: {s}", .{scenario.id});
        };
        const max_bytes = scenario.gate.max_peak_rss_bytes;
        const status = if (rss_bytes <= max_bytes) "ok" else "regressed";
        try stdout.print(
            "  {s}: mean_peak_rss={d} bytes limit={d} bytes status={s}\n",
            .{ scenario.id, rss_bytes, max_bytes, status },
        );
        if (rss_bytes > max_bytes) {
            try fail(io, "resource gate failed for {s}", .{scenario.id});
        }
    }
    try stdout.print("  zebrac_json: {s}\n", .{json_path});
    try stdout.flush();
}

fn runZebracBatch(
    allocator: std.mem.Allocator,
    io: std.Io,
    zebrac_path: []const u8,
    json_path: []const u8,
    profile: ZebracProfile,
    commands: []const []const u8,
    measure_rss: bool,
) ![]f64 {
    const cwd = std.Io.Dir.cwd();

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);

    var discard_buf: [16]u8 = undefined;
    const discard = try std.fmt.bufPrint(&discard_buf, "{d}", .{profile.discard_ms});
    var inner_buf: [8]u8 = undefined;
    const inner = try std.fmt.bufPrint(&inner_buf, "{d}", .{profile.inner});
    var outer_buf: [8]u8 = undefined;
    const outer = try std.fmt.bufPrint(&outer_buf, "{d}", .{profile.outer});

    try argv.appendSlice(allocator, &.{
        zebrac_path,
        "-d",
        discard,
        "-i",
        inner,
        "-a",
        outer,
        "-w",
        "1",
        "--json",
        json_path,
    });
    if (measure_rss) {
        try argv.append(allocator, "-f");
        try argv.append(allocator, "--quiet");
    } else if (commands.len == 1) {
        try argv.append(allocator, "-q");
    }
    for (commands) |command| try argv.append(allocator, command);

    const run_result = try std.process.run(allocator, io, .{
        .argv = argv.items,
        .stdout_limit = .limited(256 * 1024),
        .stderr_limit = .limited(256 * 1024),
    });
    defer allocator.free(run_result.stdout);
    defer allocator.free(run_result.stderr);

    switch (run_result.term) {
        .exited => |code| if (code != 0) {
            try fail(io, "zebrac failed exit={d}\n{s}{s}", .{ code, run_result.stdout, run_result.stderr });
        },
        else => try fail(io, "zebrac terminated abnormally\n{s}{s}", .{ run_result.stdout, run_result.stderr }),
    }

    const parsed = try parseZebracJson(allocator, io, cwd, jsonRelFromAbs(json_path));
    defer parsed.deinit();

    var wall_times: std.ArrayList(f64) = .empty;
    errdefer wall_times.deinit(allocator);

    for (commands) |command| {
        const wall = findWallTimeNs(parsed.value.results, command) orelse {
            try fail(io, "zebrac missing wall_time for command", .{});
        };
        try wall_times.append(allocator, wall);
    }
    return try wall_times.toOwnedSlice(allocator);
}

fn jsonRelFromAbs(json_path: []const u8) []const u8 {
    if (std.mem.indexOf(u8, json_path, ".zig-cache/")) |idx| {
        return json_path[idx..];
    }
    return json_path;
}

fn findWallTimeNs(results: []const ZebracResults.Result, command: []const u8) ?f64 {
    for (results) |result| {
        if (!std.mem.eql(u8, result.command, command)) continue;
        if (!std.mem.eql(u8, result.wall_time.unit, "ns") and
            !std.mem.eql(u8, result.wall_time.unit, "nanoseconds"))
        {
            return null;
        }
        return result.wall_time.mean;
    }
    return null;
}

fn findPeakRssBytes(results: []const ZebracResults.Result, command: []const u8) ?u64 {
    for (results) |result| {
        if (!std.mem.eql(u8, result.command, command)) continue;
        if (!std.mem.eql(u8, result.peak_rss.unit, "bytes")) return null;
        return @intFromFloat(result.peak_rss.mean);
    }
    return null;
}

fn parseZebracJson(
    allocator: std.mem.Allocator,
    io: std.Io,
    cwd: std.Io.Dir,
    json_rel_path: []const u8,
) !std.json.Parsed(ZebracResults) {
    const json_text = try cwd.readFileAlloc(io, json_rel_path, allocator, .limited(1024 * 1024));
    defer allocator.free(json_text);
    return std.json.parseFromSlice(ZebracResults, allocator, json_text, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
}

fn fileSize(io: std.Io, cwd: std.Io.Dir, path: []const u8) !u64 {
    var file = try cwd.openFile(io, path, .{});
    defer file.close(io);
    const stat = try file.stat(io);
    return stat.size;
}

fn fixtureExists(io: std.Io, abs_path: []const u8) bool {
    var file = std.Io.Dir.openFileAbsolute(io, abs_path, .{}) catch return false;
    file.close(io);
    return true;
}

fn throughputMiBPerSecond(input_bytes: u64, wall_time_ns: f64) f64 {
    if (wall_time_ns <= 0) return 0;
    const bytes_per_second = (@as(f64, @floatFromInt(input_bytes)) * @as(f64, @floatFromInt(std.time.ns_per_s))) / wall_time_ns;
    return bytes_per_second / (1024.0 * 1024.0);
}

fn appendJsonString(allocator: std.mem.Allocator, out: *std.ArrayList(u8), text: []const u8) !void {
    try out.append(allocator, '"');
    for (text) |byte| {
        switch (byte) {
            '\\', '"' => {
                try out.append(allocator, '\\');
                try out.append(allocator, byte);
            },
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            else => {
                if (byte < 0x20) {
                    const esc = try std.fmt.allocPrint(allocator, "\\u{x:0>4}", .{byte});
                    defer allocator.free(esc);
                    try out.appendSlice(allocator, esc);
                } else {
                    try out.append(allocator, byte);
                }
            },
        }
    }
    try out.append(allocator, '"');
}

fn writeReport(
    allocator: std.mem.Allocator,
    io: std.Io,
    repo_root: []const u8,
    bench_path: []const u8,
    json_path: []const u8,
    rows: []const ReportRow,
) !void {
    const cwd = std.Io.Dir.cwd();
    const git_rev = readGitRev(allocator, io) catch "unknown";
    defer if (!std.mem.eql(u8, git_rev, "unknown")) allocator.free(git_rev);

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);

    try out.appendSlice(allocator, "{\n  ");
    try appendJsonString(allocator, &out, "git_rev");
    try out.appendSlice(allocator, ": ");
    try appendJsonString(allocator, &out, git_rev);
    try out.appendSlice(allocator, ",\n  ");
    try appendJsonString(allocator, &out, "optimize");
    try out.appendSlice(allocator, ": ");
    try appendJsonString(allocator, &out, "ReleaseFast");
    try out.appendSlice(allocator, ",\n  ");
    try appendJsonString(allocator, &out, "bench_binary");
    try out.appendSlice(allocator, ": ");
    try appendJsonString(allocator, &out, bench_path);
    try out.appendSlice(allocator, ",\n  \"results\": [\n");

    for (rows, 0..) |row, i| {
        if (i > 0) try out.appendSlice(allocator, ",\n");
        try out.appendSlice(allocator, "    {\n      ");
        try appendJsonString(allocator, &out, "scenario_id");
        try out.appendSlice(allocator, ": ");
        try appendJsonString(allocator, &out, row.scenario_id);
        try out.appendSlice(allocator, ",\n      ");
        try appendFmt(allocator, &out, "\"skipped\": {},\n", .{row.skipped});
        if (!row.skipped) {
            try out.appendSlice(allocator, "      ");
            try appendJsonString(allocator, &out, "command");
            try out.appendSlice(allocator, ": ");
            try appendJsonString(allocator, &out, row.command);
            try out.appendSlice(allocator, ",\n      ");
            try appendFmt(allocator, &out, "\"input_bytes\": {d},\n", .{row.input_bytes});
            try appendFmt(allocator, &out, "      \"wall_time_ns\": {d:.0},\n", .{row.wall_time_ns});
            try appendFmt(allocator, &out, "      \"throughput_mib_s\": {d:.2},\n", .{row.throughput_mib_s});
            try out.appendSlice(allocator, "      ");
            try appendJsonString(allocator, &out, "gate_status");
            try out.appendSlice(allocator, ": ");
            try appendJsonString(allocator, &out, row.gate_status);
            try out.appendSlice(allocator, "\n");
        } else {
            try out.appendSlice(allocator, "      ");
            try appendJsonString(allocator, &out, "gate_status");
            try out.appendSlice(allocator, ": ");
            try appendJsonString(allocator, &out, "skipped");
            try out.appendSlice(allocator, "\n");
        }
        try out.appendSlice(allocator, "    }");
    }
    try out.appendSlice(allocator, "\n  ]\n}\n");

    try cwd.writeFile(io, .{ .sub_path = jsonRelFromAbs(json_path), .data = out.items });
    _ = repo_root;
}

fn appendFmt(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    comptime fmt: []const u8,
    args: anytype,
) !void {
    const chunk = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(chunk);
    try out.appendSlice(allocator, chunk);
}

fn verifyBenchBinary(io: std.Io, bench_path: []const u8) !void {
    const base = std.fs.path.basename(bench_path);
    if (std.mem.eql(u8, base, "mzValidate")) {
        try fail(
            io,
            "refusing {s}: zig-out/bin/mzValidate is the debug install. Benchmarks require mzValidate_bench (ReleaseFast) from `zig build benchmark-ci`.",
            .{bench_path},
        );
    }
    if (std.mem.eql(u8, base, "mzValidate_throughput")) {
        try fail(
            io,
            "refusing {s}: mzValidate_throughput was renamed to mzValidate_bench. Run `zig build benchmark-ci` again.",
            .{bench_path},
        );
    }
    if (!std.mem.eql(u8, base, "mzValidate_bench")) {
        try fail(
            io,
            "refusing {s}: expected basename mzValidate_bench, got {s}",
            .{ bench_path, base },
        );
    }
    std.Io.Dir.cwd().access(io, bench_path, .{}) catch {
        try fail(io, "bench binary not found: {s}", .{bench_path});
    };
}

fn readGitRev(allocator: std.mem.Allocator, io: std.Io) ![]const u8 {
    const result = try std.process.run(allocator, io, .{
        .argv = &.{ "git", "rev-parse", "--short", "HEAD" },
        .stdout_limit = .limited(64),
        .stderr_limit = .limited(256),
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .exited => |code| if (code != 0) return error.GitFailed,
        else => return error.GitFailed,
    }
    const trimmed = std.mem.trim(u8, result.stdout, " \t\r\n");
    return try allocator.dupe(u8, trimmed);
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

test "mode parse accepts hyphenated names" {
    try std.testing.expectEqual(Mode.throughput_ci, Mode.parse("throughput-ci").?);
    try std.testing.expectEqual(Mode.@"resource", Mode.parse("resource").?);
    try std.testing.expectEqual(Mode.record, Mode.parse("record").?);
}

test "throughput mib per second" {
    const ns_per_s: f64 = @floatFromInt(std.time.ns_per_s);
    const one_mib: u64 = 1024 * 1024;
    try std.testing.expectApproxEqAbs(@as(f64, 1.0), throughputMiBPerSecond(one_mib, ns_per_s), 0.001);
}

test "json string escaping" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    try appendJsonString(std.testing.allocator, &out, "a\"b\\c");
    try std.testing.expectEqualStrings("\"a\\\"b\\\\c\"", out.items);
}
