//! SIMD-assisted byte scanning for the XML parser slice path.
//!
//! Scalar tail handling keeps behavior identical at chunk boundaries.
//! Used only when the parser reads from a contiguous slice (mmap).

const std = @import("std");

const chunk_len: comptime_int = std.simd.suggestVectorLength(u8) orelse 32;
const V = @Vector(chunk_len, u8);

fn isWhitespaceByte(byte: u8) bool {
    return switch (byte) {
        ' ', '\t', '\r', '\n' => true,
        else => false,
    };
}

// Returns the first occurrence of any needle byte in `bytes`, or null.
// Uses direct vector loads + firstTrue (movemask + tzcnt equivalent).
fn firstIndexOfAny(bytes: []const u8, needles: []const u8) ?usize {
    var offset: usize = 0;
    while (offset + chunk_len <= bytes.len) {
        const chunk: V = bytes[offset..][0..chunk_len].*;
        var combined: @Vector(chunk_len, bool) = @splat(false);
        for (needles) |needle| {
            combined = combined | (chunk == @as(V, @splat(needle)));
        }
        if (std.simd.firstTrue(combined)) |pos| return offset + pos;
        offset += chunk_len;
    }
    for (bytes[offset..], 0..) |b, i| {
        for (needles) |n| {
            if (b == n) return offset + i;
        }
    }
    return null;
}

/// Leading ASCII whitespace run length. Uses firstTrue (movemask + tzcnt equivalent).
pub fn skipWhitespaceRun(bytes: []const u8) usize {
    var offset: usize = 0;
    while (offset + chunk_len <= bytes.len) {
        const chunk: V = bytes[offset..][0..chunk_len].*;
        const is_ws = (chunk == @as(V, @splat(' '))) |
            (chunk == @as(V, @splat('\t'))) |
            (chunk == @as(V, @splat('\r'))) |
            (chunk == @as(V, @splat('\n')));
        if (std.simd.firstTrue(!is_ws)) |pos| return offset + pos;
        offset += chunk_len;
    }
    for (bytes[offset..], 0..) |b, i| {
        if (!isWhitespaceByte(b)) return offset + i;
    }
    return bytes.len;
}

const name_terminators = [_]u8{ ' ', '\t', '\r', '\n', '/', '>', '=', '?', '"', '\'' };

/// Run of XML name characters before a delimiter or end of slice.
pub fn nameCharRunLen(bytes: []const u8) usize {
    return firstIndexOfAny(bytes, &name_terminators) orelse bytes.len;
}

const text_stops = [_]u8{ '<', '&' };

/// Plain text run before `<` or `&` (no entity decoding needed).
pub fn textPlainRunLen(bytes: []const u8) usize {
    return firstIndexOfAny(bytes, &text_stops) orelse bytes.len;
}

/// CDATA payload length before `]]>`, or `null` if unterminated.
pub fn cdataContentLen(bytes: []const u8) ?usize {
    var offset: usize = 0;
    while (offset < bytes.len) {
        if (bytes[offset] != ']') {
            offset += 1;
            continue;
        }
        if (offset + 2 < bytes.len and bytes[offset + 1] == ']' and bytes[offset + 2] == '>') {
            return offset;
        }
        offset += 1;
    }
    return null;
}

/// Quoted attribute value run before the closing quote or `&`.
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

test "cdataContentLen finds terminator" {
    // Arrange.
    const terminated = "abcd]]>more";
    const with_fake = "a]]b]]>rest";

    // Act.
    // Assert.
    try std.testing.expectEqual(@as(?usize, 4), cdataContentLen(terminated));
    try std.testing.expectEqual(@as(?usize, 4), cdataContentLen(with_fake));
    try std.testing.expectEqual(@as(?usize, null), cdataContentLen("no end"));
}

test "attrValuePlainRunLen stops at quote or entity" {
    // Arrange.
    const input = "value&amp;more\"rest";

    // Act.
    const n = attrValuePlainRunLen(input, '"');

    // Assert.
    try std.testing.expectEqual(@as(usize, 5), n);
}
