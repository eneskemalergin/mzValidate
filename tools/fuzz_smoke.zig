const std = @import("std");

const max_case_bytes = 16 * 1024;
const process_timeout: std.Io.Clock.Duration = .{
    .raw = std.Io.Duration.fromMilliseconds(1000),
    .clock = .awake,
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const cwd = std.Io.Dir.cwd();
    const args = try init.minimal.args.toSlice(allocator);
    defer allocator.free(args);

    if (args.len != 3) {
        try fail(io, "usage: fuzz_smoke <xml_fuzz_target> <binary_fuzz_target>", .{});
    }

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_file_writer: std.Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;
    defer stdout.flush() catch {};

    try cwd.createDirPath(io, ".zig-cache/fuzz-smoke/xml");
    try cwd.createDirPath(io, ".zig-cache/fuzz-smoke/binary");

    var prng = std.Random.DefaultPrng.init(0x6d7a56616c696461);
    const random = prng.random();

    try stdout.print("fuzz-smoke: xml target={s}\n", .{args[1]});
    try runXmlSeedCorpus(allocator, io, cwd, random, args[1]);
    try stdout.print("fuzz-smoke: binary target={s}\n", .{args[2]});
    try runBinarySeedCorpus(allocator, io, cwd, random, args[2]);
}

fn runXmlSeedCorpus(
    allocator: std.mem.Allocator,
    io: std.Io,
    cwd: std.Io.Dir,
    random: std.Random,
    target_path: []const u8,
) !void {
    const seeds = [_][]const u8{
        "fixtures/xml/valid/namespaces-and-entities.xml",
        "fixtures/xml/invalid/mismatched-end-tag.xml",
        "fixtures/examples/mzml/clean-single-spectrum.mzML",
    };

    for (seeds) |seed_path| {
        try runCaseFile(allocator, io, target_path, seed_path, "xml-seed");
        const seed_bytes = try cwd.readFileAlloc(io, seed_path, allocator, .limited(max_case_bytes));
        defer allocator.free(seed_bytes);
        try runMutatedCases(allocator, io, cwd, random, target_path, seed_bytes, ".zig-cache/fuzz-smoke/xml", "xml");
    }

    for (0..24) |index| {
        const random_case = try randomBytes(allocator, random, 1 + random.uintLessThan(usize, 4096));
        defer allocator.free(random_case);
        const path = try writeCase(allocator, io, cwd, ".zig-cache/fuzz-smoke/xml", "xml-random", index, random_case);
        defer allocator.free(path);
        try runCaseFile(allocator, io, target_path, path, "xml-random");
    }
}

fn runBinarySeedCorpus(
    allocator: std.mem.Allocator,
    io: std.Io,
    cwd: std.Io.Dir,
    random: std.Random,
    target_path: []const u8,
) !void {
    const seeds = [_][]const u8{
        "AAAAAA==",
        "eJxjYGBgAAAABAAB",
        "%%%%%%%%",
        "AQIDBAUGBwgJAA==",
    };

    for (seeds, 0..) |seed, index| {
        const seed_path = try writeCase(allocator, io, cwd, ".zig-cache/fuzz-smoke/binary", "binary-seed", index, seed);
        defer allocator.free(seed_path);
        try runCaseFile(allocator, io, target_path, seed_path, "binary-seed");
        try runMutatedCases(allocator, io, cwd, random, target_path, seed, ".zig-cache/fuzz-smoke/binary", "binary");
    }

    for (0..24) |index| {
        const random_case = try randomBytes(allocator, random, 1 + random.uintLessThan(usize, 2048));
        defer allocator.free(random_case);
        const path = try writeCase(allocator, io, cwd, ".zig-cache/fuzz-smoke/binary", "binary-random", index, random_case);
        defer allocator.free(path);
        try runCaseFile(allocator, io, target_path, path, "binary-random");
    }
}

fn runMutatedCases(
    allocator: std.mem.Allocator,
    io: std.Io,
    cwd: std.Io.Dir,
    random: std.Random,
    target_path: []const u8,
    seed: []const u8,
    dir_path: []const u8,
    prefix: []const u8,
) !void {
    for (0..16) |index| {
        const mutated = try mutateBytes(allocator, random, seed);
        defer allocator.free(mutated);
        const path = try writeCase(allocator, io, cwd, dir_path, prefix, index, mutated);
        defer allocator.free(path);
        try runCaseFile(allocator, io, target_path, path, prefix);
    }
}

fn runCaseFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    target_path: []const u8,
    input_path: []const u8,
    case_label: []const u8,
) !void {
    const run_result = std.process.run(allocator, io, .{
        .argv = &.{ target_path, input_path },
        .stdout_limit = .limited(16 * 1024),
        .stderr_limit = .limited(16 * 1024),
        .timeout = .{ .duration = process_timeout },
    }) catch |err| switch (err) {
        error.Timeout => try fail(io, "{s} target timed out for {s}", .{ case_label, input_path }),
        else => return err,
    };
    defer allocator.free(run_result.stdout);
    defer allocator.free(run_result.stderr);

    switch (run_result.term) {
        .exited => |code| if (code != 0) {
            try fail(io, "{s} target failed for {s} with exit code {d}\n{s}{s}", .{ case_label, input_path, code, run_result.stdout, run_result.stderr });
        },
        else => try fail(io, "{s} target terminated abnormally for {s}\n{s}{s}", .{ case_label, input_path, run_result.stdout, run_result.stderr }),
    }
}

fn writeCase(
    allocator: std.mem.Allocator,
    io: std.Io,
    cwd: std.Io.Dir,
    dir_path: []const u8,
    prefix: []const u8,
    index: usize,
    bytes: []const u8,
) ![]u8 {
    const file_path = try std.fmt.allocPrint(allocator, "{s}/{s}-{d:0>3}.bin", .{ dir_path, prefix, index });
    var file = try cwd.createFile(io, file_path, .{ .truncate = true });
    defer file.close(io);
    try std.Io.File.writeStreamingAll(file, io, bytes);
    return file_path;
}

fn randomBytes(allocator: std.mem.Allocator, random: std.Random, len: usize) ![]u8 {
    const bytes = try allocator.alloc(u8, len);
    random.bytes(bytes);
    return bytes;
}

fn mutateBytes(allocator: std.mem.Allocator, random: std.Random, seed: []const u8) ![]u8 {
    const bounded_len = @max(@min(seed.len + 16, max_case_bytes), 1);
    var mutated = try allocator.alloc(u8, bounded_len);
    const copy_len = @min(seed.len, mutated.len);
    @memcpy(mutated[0..copy_len], seed[0..copy_len]);
    if (mutated.len > copy_len) @memset(mutated[copy_len..], 0);

    const operation = random.uintLessThan(u8, 5);
    switch (operation) {
        0 => {
            if (copy_len != 0) {
                const idx = random.uintLessThan(usize, copy_len);
                const bit: u3 = @intCast(random.uintLessThan(u8, 8));
                mutated[idx] ^= @as(u8, 1) << bit;
            }
        },
        1 => {
            const count = 1 + random.uintLessThan(usize, @min(mutated.len, 32));
            for (0..count) |_| {
                const idx = random.uintLessThan(usize, mutated.len);
                mutated[idx] = random.int(u8);
            }
        },
        2 => {
            if (copy_len != 0) {
                const truncate_at = random.uintLessThan(usize, copy_len);
                @memset(mutated[truncate_at..], 0);
            }
        },
        3 => {
            if (copy_len != 0) {
                const src = random.uintLessThan(usize, copy_len);
                const dst = random.uintLessThan(usize, mutated.len);
                const len = @min(copy_len - src, mutated.len - dst);
                if (len != 0) {
                    std.mem.copyBackwards(u8, mutated[dst .. dst + len], mutated[src .. src + len]);
                }
            }
        },
        else => random.bytes(mutated),
    }
    return mutated;
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
