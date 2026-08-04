//! Bounded streaming SHA-1 with optional x86 SHA-extension compression.
//!
//! Runtime dispatch selects the accelerated path only when it was compiled and
//! the host reports every required instruction; all other builds use Zig SHA-1.

const std = @import("std");
const build_options = @import("build_options");

const ScalarSha1 = std.crypto.hash.Sha1;
const block_bytes = ScalarSha1.block_length;
const x86_enabled = build_options.sha1_x86_enabled;

extern fn mzv_sha1_x86_available() c_int;
extern fn mzv_sha1_x86_compress(state: *[5]u32, blocks: [*]const u8, block_count: usize) void;

pub const Sha1 = struct {
    implementation: if (x86_enabled) union(enum) {
        scalar: ScalarSha1,
        accelerated: Accelerated,
    } else ScalarSha1,

    pub fn init() Sha1 {
        if (comptime x86_enabled) {
            if (acceleratedAvailable()) {
                return .{ .implementation = .{ .accelerated = .{} } };
            }
            return .{ .implementation = .{ .scalar = ScalarSha1.init(.{}) } };
        }
        return .{ .implementation = ScalarSha1.init(.{}) };
    }

    pub fn update(hasher: *Sha1, bytes: []const u8) void {
        if (comptime x86_enabled) {
            switch (hasher.implementation) {
                .scalar => |*scalar| scalar.update(bytes),
                .accelerated => |*accelerated| accelerated.update(bytes),
            }
        } else {
            hasher.implementation.update(bytes);
        }
    }

    pub fn final(hasher: *Sha1, digest: *[20]u8) void {
        if (comptime x86_enabled) {
            switch (hasher.implementation) {
                .scalar => |*scalar| scalar.final(digest),
                .accelerated => |*accelerated| accelerated.final(digest),
            }
        } else {
            hasher.implementation.final(digest);
        }
    }

    fn initAccelerated() ?Sha1 {
        if (comptime x86_enabled) {
            if (acceleratedAvailable()) {
                return .{ .implementation = .{ .accelerated = .{} } };
            }
        }
        return null;
    }
};

fn acceleratedAvailable() bool {
    if (comptime x86_enabled) return mzv_sha1_x86_available() != 0;
    return false;
}

const Accelerated = struct {
    state: [5]u32 = .{ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 },
    buffer: [block_bytes]u8 = undefined,
    buffer_len: u8 = 0,
    total_len: u64 = 0,

    fn update(hasher: *Accelerated, bytes: []const u8) void {
        var offset: usize = 0;
        if (hasher.buffer_len != 0) {
            const available = block_bytes - hasher.buffer_len;
            const copied = @min(available, bytes.len);
            @memcpy(hasher.buffer[hasher.buffer_len..][0..copied], bytes[0..copied]);
            hasher.buffer_len += @intCast(copied);
            offset = copied;
            if (hasher.buffer_len == block_bytes) {
                mzv_sha1_x86_compress(&hasher.state, &hasher.buffer, 1);
                hasher.buffer_len = 0;
            }
        }

        const complete_bytes = (bytes.len - offset) / block_bytes * block_bytes;
        if (complete_bytes != 0) {
            mzv_sha1_x86_compress(
                &hasher.state,
                bytes[offset..].ptr,
                complete_bytes / block_bytes,
            );
            offset += complete_bytes;
        }

        const remaining = bytes.len - offset;
        if (remaining != 0) {
            @memcpy(hasher.buffer[0..remaining], bytes[offset..]);
            hasher.buffer_len = @intCast(remaining);
        }
        hasher.total_len +%= bytes.len;
    }

    fn final(hasher: *Accelerated, digest: *[20]u8) void {
        @memset(hasher.buffer[hasher.buffer_len..], 0);
        hasher.buffer[hasher.buffer_len] = 0x80;
        hasher.buffer_len += 1;
        if (block_bytes - hasher.buffer_len < 8) {
            mzv_sha1_x86_compress(&hasher.state, &hasher.buffer, 1);
            @memset(&hasher.buffer, 0);
        }
        std.mem.writeInt(u64, hasher.buffer[56..64], hasher.total_len *% 8, .big);
        mzv_sha1_x86_compress(&hasher.state, &hasher.buffer, 1);
        for (hasher.state, 0..) |word, index| {
            std.mem.writeInt(u32, digest[index * 4 ..][0..4], word, .big);
        }
    }
};

// --- Unit Tests ---

test "sha1: accelerated implementation matches the standard vector" {
    var hasher = Sha1.initAccelerated() orelse return error.SkipZigTest;
    hasher.update("a");
    hasher.update("bc");
    var actual: [20]u8 = undefined;
    hasher.final(&actual);

    const expected = [_]u8{
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
        0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
    };
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

test "sha1: accelerated boundary and split updates match scalar SHA-1" {
    var input: [257]u8 = undefined;
    for (&input, 0..) |*byte, index| byte.* = @truncate(index *% 131 +% 17);
    const lengths = [_]usize{ 0, 1, 55, 56, 63, 64, 65, 127, 128, 129, 255, 256, 257 };
    const splits = [_]usize{ 0, 1, 31, 55, 56, 63, 64, 65, 127 };

    for (lengths) |length| {
        for (splits) |requested_split| {
            const split = @min(requested_split, length);
            var scalar = ScalarSha1.init(.{});
            scalar.update(input[0..length]);
            var scalar_digest: [20]u8 = undefined;
            scalar.final(&scalar_digest);

            var accelerated = Sha1.initAccelerated() orelse return error.SkipZigTest;
            accelerated.update(input[0..split]);
            accelerated.update(input[split..length]);
            var accelerated_digest: [20]u8 = undefined;
            accelerated.final(&accelerated_digest);

            try std.testing.expectEqualSlices(u8, &scalar_digest, &accelerated_digest);
        }
    }
}

test "sha1: selected implementation handles unaligned fragmented input" {
    var storage: [1026]u8 = undefined;
    for (&storage, 0..) |*byte, index| byte.* = @truncate(index *% 193 +% 29);
    const input = storage[1..];

    var expected: [20]u8 = undefined;
    ScalarSha1.hash(input, &expected, .{});

    var hasher = Sha1.init();
    const fragment_lengths = [_]usize{ 1, 3, 7, 31, 64, 2, 127 };
    var offset: usize = 0;
    var fragment_index: usize = 0;
    while (offset < input.len) : (fragment_index += 1) {
        const end = @min(offset + fragment_lengths[fragment_index % fragment_lengths.len], input.len);
        hasher.update(input[offset..end]);
        offset = end;
    }
    var actual: [20]u8 = undefined;
    hasher.final(&actual);

    try std.testing.expectEqualSlices(u8, &expected, &actual);
}
