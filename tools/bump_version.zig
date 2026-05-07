//! Version bump tool: rewrites `src/version.zig` and `build.zig.zon` atomically.
//!
//! Usage: `./zig build bump-version -Drelease-version=<major.minor.patch>`
//!
//! The tool computes the manifest fingerprint by running a minimal `zig build test`
//! in a temporary copy of the repo, then inserts the computed hash back into
//! `build.zig.zon`. This keeps the manifest self-consistent without requiring a
//! published package server.

const std = @import("std");

// --- Constants ---

const usage =
    "usage: ./zig build bump-version -Drelease-version=<major.minor.patch>\n";

const fingerprint_marker = "suggested value: ";
const temp_work_subpath = ".zig-cache/tmp/bump-version-work";

// --- Entry point ---

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    if (args.len != 2 or std.mem.eql(u8, args[1], "-h") or std.mem.eql(u8, args[1], "--help")) {
        var stdout_buffer: [256]u8 = undefined;
        var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buffer);
        try stdout_writer.interface.writeAll(usage);
        try stdout_writer.interface.flush();
        return;
    }

    const new_version = args[1];
    _ = std.SemanticVersion.parse(new_version) catch {
        return fail(io, "error: invalid semantic version: {s}\n", .{new_version});
    };

    const fingerprint = try bumpVersion(gpa, io, new_version);
    defer gpa.free(fingerprint);

    var stdout_buffer: [256]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buffer);
    const stdout = &stdout_writer.interface;
    try stdout.print("updated version to {s} with fingerprint {s}\n", .{ new_version, fingerprint });
    try stdout.flush();
}

// --- Implementation ---

/// Rewrites both version files and returns the computed fingerprint string.
/// Caller owns the returned slice and must free it.
fn bumpVersion(gpa: std.mem.Allocator, io: std.Io, new_version: []const u8) ![]u8 {
    const cwd = std.Io.Dir.cwd();

    const manifest_text = try cwd.readFileAlloc(io, "build.zig.zon", gpa, .limited(64 * 1024));
    defer gpa.free(manifest_text);

    const version_text = try cwd.readFileAlloc(io, "src/version.zig", gpa, .limited(8 * 1024));
    defer gpa.free(version_text);

    const manifest_without_fingerprint = try rewriteManifestWithoutFingerprint(gpa, manifest_text, new_version);
    defer gpa.free(manifest_without_fingerprint);

    const updated_version_text = try rewriteVersionFile(gpa, version_text, new_version);
    defer gpa.free(updated_version_text);

    const fingerprint = try deriveFingerprint(gpa, io, manifest_without_fingerprint);

    const finalized_manifest = try insertFingerprintAfterVersion(gpa, manifest_without_fingerprint, fingerprint);
    defer gpa.free(finalized_manifest);

    try cwd.writeFile(io, .{ .sub_path = "build.zig.zon", .data = finalized_manifest });
    try cwd.writeFile(io, .{ .sub_path = "src/version.zig", .data = updated_version_text });

    return fingerprint;
}

/// Runs `zig build test` in a scratch directory to extract the manifest fingerprint.
/// The Zig toolchain prints "suggested value: <hash>" to stderr on a fingerprint mismatch.
fn deriveFingerprint(gpa: std.mem.Allocator, io: std.Io, manifest_text: []const u8) ![]u8 {
    const cwd = std.Io.Dir.cwd();
    cwd.deleteTree(io, temp_work_subpath) catch {};
    defer cwd.deleteTree(io, temp_work_subpath) catch {};

    try cwd.createDirPath(io, temp_work_subpath);
    try copyRepoInputs(gpa, io);
    try cwd.writeFile(io, .{ .sub_path = temp_work_subpath ++ "/build.zig.zon", .data = manifest_text });

    const repo_root = try std.process.currentPathAlloc(io, gpa);
    defer gpa.free(repo_root);

    const zig_executable = try std.fs.path.join(gpa, &.{ repo_root, "zig-0.16.0", "zig" });
    defer gpa.free(zig_executable);

    const temp_cwd = try std.fs.path.join(gpa, &.{ repo_root, temp_work_subpath });
    defer gpa.free(temp_cwd);

    const run_result = try std.process.run(gpa, io, .{
        .argv = &.{ zig_executable, "build", "test" },
        .cwd = .{ .path = temp_cwd },
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
    defer gpa.free(run_result.stdout);
    defer gpa.free(run_result.stderr);

    if (findFingerprint(run_result.stderr)) |fingerprint| {
        return gpa.dupe(u8, fingerprint);
    }
    if (findFingerprint(run_result.stdout)) |fingerprint| {
        return gpa.dupe(u8, fingerprint);
    }

    return error.UnexpectedFingerprintOutput;
}

/// Copies build inputs into the temporary scratch directory.
fn copyRepoInputs(gpa: std.mem.Allocator, io: std.Io) !void {
    const cwd = std.Io.Dir.cwd();
    try cwd.copyFile("build.zig", cwd, temp_work_subpath ++ "/build.zig", io, .{ .make_path = true, .replace = true });
    try cwd.copyFile("tools/bump_version.zig", cwd, temp_work_subpath ++ "/tools/bump_version.zig", io, .{ .make_path = true, .replace = true });
    try copyTree(gpa, io, "src", temp_work_subpath ++ "/src");
}

/// Recursively copies a source directory tree into the destination path.
fn copyTree(gpa: std.mem.Allocator, io: std.Io, source_subpath: []const u8, dest_subpath: []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    var source_dir = try cwd.openDir(io, source_subpath, .{ .iterate = true });
    defer source_dir.close(io);

    var walker = try source_dir.walk(gpa);
    defer walker.deinit();

    while (try walker.next(io)) |entry| {
        const dest_path = try std.fs.path.join(gpa, &.{ dest_subpath, entry.path });
        defer gpa.free(dest_path);

        switch (entry.kind) {
            .directory => try cwd.createDirPath(io, dest_path),
            else => try source_dir.copyFile(entry.path, cwd, dest_path, io, .{ .make_path = true, .replace = true }),
        }
    }
}

/// Rewrites the `.version` field and removes the `.fingerprint` line.
/// Returns the stripped manifest text; caller owns it.
fn rewriteManifestWithoutFingerprint(gpa: std.mem.Allocator, manifest_text: []const u8, new_version: []const u8) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(gpa);

    var replaced_version = false;
    var removed_fingerprint = false;
    var lines = std.mem.splitScalar(u8, manifest_text, '\n');
    while (lines.next()) |line| {
        if (std.mem.indexOf(u8, line, ".fingerprint = ") != null) {
            removed_fingerprint = true;
            continue;
        }

        if (std.mem.indexOf(u8, line, ".version = \"") != null) {
            try appendLineReplacingQuotedValue(gpa, &output, line, ".version = \"", "\",", new_version);
            replaced_version = true;
        } else {
            try output.appendSlice(gpa, line);
        }
        try output.append(gpa, '\n');
    }

    if (!replaced_version) return error.VersionLineMissing;
    if (!removed_fingerprint) return error.FingerprintLineMissing;

    return output.toOwnedSlice(gpa);
}

/// Inserts the `.fingerprint` line immediately after the `.version` line.
fn insertFingerprintAfterVersion(gpa: std.mem.Allocator, manifest_text: []const u8, fingerprint: []const u8) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(gpa);

    var inserted = false;
    var lines = std.mem.splitScalar(u8, manifest_text, '\n');
    while (lines.next()) |line| {
        try output.appendSlice(gpa, line);
        try output.append(gpa, '\n');

        if (!inserted and std.mem.indexOf(u8, line, ".version = \"") != null) {
            const dot_index = std.mem.indexOfScalar(u8, line, '.') orelse return error.VersionLineMissing;
            try output.appendSlice(gpa, line[0..dot_index]);
            try output.appendSlice(gpa, ".fingerprint = ");
            try output.appendSlice(gpa, fingerprint);
            try output.appendSlice(gpa, ",\n");
            inserted = true;
        }
    }

    if (!inserted) return error.VersionLineMissing;
    return output.toOwnedSlice(gpa);
}

/// Rewrites the `pub const semantic` line in `src/version.zig`.
fn rewriteVersionFile(gpa: std.mem.Allocator, version_text: []const u8, new_version: []const u8) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(gpa);

    var replaced = false;
    var lines = std.mem.splitScalar(u8, version_text, '\n');
    while (lines.next()) |line| {
        if (std.mem.indexOf(u8, line, "pub const semantic = \"") != null) {
            try appendLineReplacingQuotedValue(gpa, &output, line, "pub const semantic = \"", "\";", new_version);
            replaced = true;
        } else {
            try output.appendSlice(gpa, line);
        }
        try output.append(gpa, '\n');
    }

    if (!replaced) return error.CodeVersionLineMissing;
    return output.toOwnedSlice(gpa);
}

/// Replaces the quoted value between `marker` and `suffix` on a single line.
fn appendLineReplacingQuotedValue(
    gpa: std.mem.Allocator,
    output: *std.ArrayList(u8),
    line: []const u8,
    marker: []const u8,
    suffix: []const u8,
    new_value: []const u8,
) !void {
    const marker_index = std.mem.indexOf(u8, line, marker) orelse return error.VersionLineMissing;
    const value_start = marker_index + marker.len;
    const suffix_index = std.mem.indexOfPos(u8, line, value_start, suffix) orelse return error.VersionLineMissing;

    try output.appendSlice(gpa, line[0..value_start]);
    try output.appendSlice(gpa, new_value);
    try output.appendSlice(gpa, line[suffix_index..]);
}

/// Scans `output` for the fingerprint marker and returns the hash slice.
/// Returns null when the toolchain output does not contain the expected line.
fn findFingerprint(output: []const u8) ?[]const u8 {
    const start = std.mem.indexOf(u8, output, fingerprint_marker) orelse return null;
    const fingerprint_start = start + fingerprint_marker.len;
    const rest = output[fingerprint_start..];
    const fingerprint_len = std.mem.indexOfAny(u8, rest, "\r\n \t") orelse rest.len;
    return rest[0..fingerprint_len];
}

/// Writes an error to stderr and exits with code 2.
fn fail(io: std.Io, comptime format: []const u8, args: anytype) !void {
    var stderr_buffer: [256]u8 = undefined;
    var stderr_writer = std.Io.File.stderr().writer(io, &stderr_buffer);
    const stderr = &stderr_writer.interface;
    try stderr.print(format, args);
    try stderr.print("{s}", .{usage});
    try stderr.flush();
    std.process.exit(2);
}
