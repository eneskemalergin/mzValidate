//! SIMD-assisted byte scanning for the XML parser slice path.
//!
//! Scalar tail handling keeps behavior identical at chunk boundaries.
//! Used only when the parser reads from a contiguous slice (mmap).

const std = @import("std");

const chunk_len = 32;

fn loadChunk(bytes: []const u8, offset: usize) @Vector(chunk_len, u8) {
    var buf: [chunk_len]u8 = undefined;
    @memcpy(&buf, bytes[offset..][0..chunk_len]);
    return buf;
}

fn eqMask(eq: @Vector(chunk_len, bool)) u32 {
    const lanes: [chunk_len]bool = eq;
    var mask: u32 = 0;
    for (lanes, 0..) |lane, i| {
        if (lane) mask |= @as(u32, 1) << @intCast(i);
    }
    return mask;
}

fn firstIndexOfAny(bytes: []const u8, needles: []const u8) ?usize {
    var offset: usize = 0;
    while (offset + chunk_len <= bytes.len) {
        const chunk = loadChunk(bytes, offset);
        var chunk_mask: u32 = 0;
        for (needles) |needle| {
            chunk_mask |= eqMask(chunk == @as(@Vector(chunk_len, u8), @splat(needle)));
        }
        if (chunk_mask != 0) return offset + @ctz(chunk_mask);
        offset += chunk_len;
    }
    while (offset < bytes.len) : (offset += 1) {
        for (needles) |needle| {
            if (bytes[offset] == needle) return offset;
        }
    }
    return null;
}

fn isWhitespaceByte(byte: u8) bool {
    return switch (byte) {
        ' ', '\t', '\r', '\n' => true,
        else => false,
    };
}

/// Counts leading ASCII whitespace bytes.
pub fn skipWhitespaceRun(bytes: []const u8) usize {
    var offset: usize = 0;
    while (offset + chunk_len <= bytes.len) {
        const chunk = loadChunk(bytes, offset);
        var all_whitespace = true;
        const lanes: [chunk_len]u8 = @bitCast(chunk);
        for (lanes) |byte| {
            if (!isWhitespaceByte(byte)) {
                all_whitespace = false;
                break;
            }
        }
        if (!all_whitespace) {
            while (offset < bytes.len and isWhitespaceByte(bytes[offset])) : (offset += 1) {}
            return offset;
        }
        offset += chunk_len;
    }
    while (offset < bytes.len and isWhitespaceByte(bytes[offset])) : (offset += 1) {}
    return offset;
}

const name_terminators = [_]u8{ ' ', '\t', '\r', '\n', '/', '>', '=', '?', '"', '\'' };

/// Counts bytes until a name terminator or end of `bytes`.
pub fn nameCharRunLen(bytes: []const u8) usize {
    return firstIndexOfAny(bytes, &name_terminators) orelse bytes.len;
}

const text_stops = [_]u8{ '<', '&' };

/// Counts plain text bytes until `<` or `&`.
pub fn textPlainRunLen(bytes: []const u8) usize {
    return firstIndexOfAny(bytes, &text_stops) orelse bytes.len;
}

/// Counts attribute value bytes until `quote` or `&`.
pub fn attrValuePlainRunLen(bytes: []const u8, quote: u8) usize {
    const stops = [_]u8{ quote, '&' };
    return firstIndexOfAny(bytes, &stops) orelse bytes.len;
}

// --- Tests ---

test "skipWhitespaceRun counts spaces tabs and newlines" {
    // Arrange.
    const input = "  \t\n\rhello";

    // Act.
    const n = skipWhitespaceRun(input);

    // Assert.
    try std.testing.expectEqual(@as(usize, 5), n);
}

test "nameCharRunLen stops at whitespace and markup" {
    // Arrange.
    const input = "spectrum id";

    // Act.
    const n = nameCharRunLen(input);

    // Assert.
    try std.testing.expectEqual(@as(usize, 8), n);
}

test "textPlainRunLen stops at lt or ampersand" {
    // Arrange.
    const plain = "AAAA";
    const at_lt = "AAA<";
    const at_amp = "AA&";

    // Act.
    // Assert.
    try std.testing.expectEqual(@as(usize, 4), textPlainRunLen(plain));
    try std.testing.expectEqual(@as(usize, 3), textPlainRunLen(at_lt));
    try std.testing.expectEqual(@as(usize, 2), textPlainRunLen(at_amp));
}

test "attrValuePlainRunLen stops at quote or entity" {
    // Arrange.
    const input = "value&amp;more\"rest";

    // Act.
    const n = attrValuePlainRunLen(input, '"');

    // Assert.
    try std.testing.expectEqual(@as(usize, 5), n);
}
