//! SIMD-assisted byte scanning for the XML parser slice path and raw start tags.
//!
//! Raw attribute views borrow the supplied tag bytes and never decode values.
//! Scalar tail handling keeps behavior identical at chunk boundaries.
//! Raw-tag helpers operate on any supplied contiguous tag slice.

const std = @import("std");

const chunk_len: comptime_int = std.simd.suggestVectorLength(u8) orelse 32;
const V = @Vector(chunk_len, u8);

fn isWhitespaceByte(byte: u8) bool {
    return switch (byte) {
        ' ', '\t', '\r', '\n' => true,
        else => false,
    };
}

pub const RawAttributeError = error{
    Malformed,
    InvalidUtf8,
};

/// Raw start-tag boundary; `end` excludes the unquoted `>` delimiter.
pub const RawTagInfo = struct {
    end: usize,
    self_closing: bool,
};

/// Borrowed raw attribute names and values from one start tag.
pub const RawAttribute = struct {
    name_start: usize,
    name: []const u8,
    local_name: []const u8,
    value: []const u8,
    has_entity: bool,
    is_namespace_declaration: bool,
};

/// Iterates one raw start tag without allocating or decoding values.
pub const RawAttributeScanner = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn init(bytes: []const u8) RawAttributeScanner {
        return .{ .bytes = bytes };
    }

    /// Returns the next borrowed attribute, or null after the tag body.
    pub fn next(scanner: *RawAttributeScanner) RawAttributeError!?RawAttribute {
        while (scanner.pos < scanner.bytes.len and isWhitespaceByte(scanner.bytes[scanner.pos])) : (scanner.pos += 1) {}
        if (scanner.pos == scanner.bytes.len) return null;

        if (scanner.bytes[scanner.pos] == '/') {
            scanner.pos += 1;
            if (scanner.pos != scanner.bytes.len) return error.Malformed;
            return null;
        }

        const name_start = scanner.pos;
        while (scanner.pos < scanner.bytes.len and !isRawNameTerminator(scanner.bytes[scanner.pos])) : (scanner.pos += 1) {}
        if (scanner.pos == name_start) return error.Malformed;
        const name = scanner.bytes[name_start..scanner.pos];
        if (!std.unicode.utf8ValidateSlice(name)) return error.InvalidUtf8;
        const local_name = try rawLocalName(name);

        while (scanner.pos < scanner.bytes.len and isWhitespaceByte(scanner.bytes[scanner.pos])) : (scanner.pos += 1) {}
        if (scanner.pos == scanner.bytes.len or scanner.bytes[scanner.pos] != '=') return error.Malformed;
        scanner.pos += 1;
        while (scanner.pos < scanner.bytes.len and isWhitespaceByte(scanner.bytes[scanner.pos])) : (scanner.pos += 1) {}
        if (scanner.pos == scanner.bytes.len) return error.Malformed;

        const quote = scanner.bytes[scanner.pos];
        if (quote != '"' and quote != '\'') return error.Malformed;
        scanner.pos += 1;
        const value_start = scanner.pos;
        var has_entity = false;
        while (scanner.pos < scanner.bytes.len and scanner.bytes[scanner.pos] != quote) : (scanner.pos += 1) {
            if (scanner.bytes[scanner.pos] == '&') has_entity = true;
        }
        if (scanner.pos == scanner.bytes.len) return error.Malformed;
        const value = scanner.bytes[value_start..scanner.pos];
        if (!has_entity and !std.unicode.utf8ValidateSlice(value)) return error.InvalidUtf8;
        scanner.pos += 1;

        const colon = std.mem.indexOfScalar(u8, name, ':');
        return .{
            .name_start = name_start,
            .name = name,
            .local_name = local_name,
            .value = value,
            .has_entity = has_entity,
            .is_namespace_declaration = std.mem.eql(u8, name, "xmlns") or
                (colon != null and std.mem.eql(u8, name[0..colon.?], "xmlns")),
        };
    }
};

/// Finds the first `>` outside a quoted value without allocating.
pub fn rawStartTagInfo(bytes: []const u8) ?RawTagInfo {
    var quote: u8 = 0;
    var after_equals = false;
    for (bytes, 0..) |byte, index| {
        if (quote != 0) {
            if (byte == quote) quote = 0;
            continue;
        }
        if (byte == '=') {
            after_equals = true;
        } else if (after_equals and isWhitespaceByte(byte)) {
            continue;
        } else if (after_equals and (byte == '"' or byte == '\'')) {
            quote = byte;
            after_equals = false;
        } else if (byte == '>') {
            var last = index;
            while (last > 0 and isWhitespaceByte(bytes[last - 1])) : (last -= 1) {}
            return .{ .end = index, .self_closing = last > 0 and bytes[last - 1] == '/' };
        } else {
            after_equals = false;
        }
    }
    return null;
}

fn rawLocalName(name: []const u8) RawAttributeError![]const u8 {
    var colon: ?usize = null;
    for (name, 0..) |byte, index| {
        if (byte != ':') continue;
        if (colon != null or index == 0 or index + 1 == name.len) return error.Malformed;
        colon = index;
    }
    return if (colon) |index| name[index + 1 ..] else name;
}

fn isRawNameTerminator(byte: u8) bool {
    return std.ascii.isWhitespace(byte) or switch (byte) {
        '/', '>', '=', '?', '"', '\'' => true,
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

/// Run of XML name characters before a delimiter or end of slice.
pub fn nameCharRunLen(bytes: []const u8) usize {
    const spec = comptime [_]u8{ '/', '>', '=', '?', '"', '\'' };
    var offset: usize = 0;
    while (offset + chunk_len <= bytes.len) {
        const chunk: V = bytes[offset..][0..chunk_len].*;
        const is_whitespace_or_ctrl = chunk < @as(V, @splat('!'));
        var combined = is_whitespace_or_ctrl;
        inline for (spec) |c| {
            combined = combined | (chunk == @as(V, @splat(c)));
        }
        if (std.simd.firstTrue(combined)) |pos| return offset + pos;
        offset += chunk_len;
    }
    for (bytes[offset..], 0..) |b, i| {
        if (b <= ' ' or b == '/' or b == '>' or b == '=' or b == '?' or b == '"' or b == '\'')
            return offset + i;
    }
    return bytes.len;
}

const text_stops = [_]u8{ '<', '&' };

/// Plain text run before `<` or `&` (no entity decoding needed).
pub fn textPlainRunLen(bytes: []const u8) usize {
    return firstIndexOfAny(bytes, &text_stops) orelse bytes.len;
}

/// CDATA payload length before `]]>`, or `null` if unterminated.
pub fn cdataContentLen(bytes: []const u8) ?usize {
    var offset: usize = 0;
    while (offset + chunk_len <= bytes.len) {
        const chunk: V = bytes[offset..][0..chunk_len].*;
        const is_bracket = chunk == @as(V, @splat(']'));
        if (std.simd.firstTrue(is_bracket)) |pos| {
            const abs_pos = offset + pos;
            if (abs_pos + 2 < bytes.len and bytes[abs_pos + 1] == ']' and bytes[abs_pos + 2] == '>') {
                return abs_pos;
            }
            offset = abs_pos + 1;
        } else {
            offset += chunk_len;
        }
    }
    for (bytes[offset..], 0..) |b, i| {
        if (b == ']' and offset + i + 2 < bytes.len and bytes[offset + i + 1] == ']' and bytes[offset + i + 2] == '>') {
            return offset + i;
        }
    }
    return null;
}

/// Position of `-->` in bytes, or `null` if unterminated.
/// Returns the index of the first `-` in the terminating `-->`.
pub fn commentEndLen(bytes: []const u8) ?usize {
    var offset: usize = 0;
    while (offset + chunk_len <= bytes.len) {
        const chunk: V = bytes[offset..][0..chunk_len].*;
        const is_dash = chunk == @as(V, @splat('-'));
        if (std.simd.firstTrue(is_dash)) |pos| {
            const abs_pos = offset + pos;
            if (abs_pos + 2 < bytes.len and bytes[abs_pos + 1] == '-' and bytes[abs_pos + 2] == '>') {
                return abs_pos;
            }
            offset = abs_pos + 1;
        } else {
            offset += chunk_len;
        }
    }
    for (bytes[offset..], 0..) |b, i| {
        if (b == '-' and offset + i + 2 < bytes.len and bytes[offset + i + 1] == '-' and bytes[offset + i + 2] == '>') {
            return offset + i;
        }
    }
    return null;
}

/// Position of `?>` in bytes, or `null` if unterminated.
/// Returns the index of `?` in the terminating `?>`.
pub fn piEndLen(bytes: []const u8) ?usize {
    var offset: usize = 0;
    while (offset + chunk_len <= bytes.len) {
        const chunk: V = bytes[offset..][0..chunk_len].*;
        const is_qmark = chunk == @as(V, @splat('?'));
        if (std.simd.firstTrue(is_qmark)) |pos| {
            const abs_pos = offset + pos;
            if (abs_pos + 1 < bytes.len and bytes[abs_pos + 1] == '>') {
                return abs_pos;
            }
            offset = abs_pos + 1;
        } else {
            offset += chunk_len;
        }
    }
    for (bytes[offset..], 0..) |b, i| {
        if (b == '?' and offset + i + 1 < bytes.len and bytes[offset + i + 1] == '>') {
            return offset + i;
        }
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

test "raw start tag scanner keeps quoted greater-than bytes inside values" {
    const bytes = " accession=\"MS:1000130\" unitName=\"text > still\"/>";
    const info = rawStartTagInfo(bytes).?;

    try std.testing.expectEqual(bytes.len - 1, info.end);
    try std.testing.expect(info.self_closing);

    var scanner = RawAttributeScanner.init(bytes[0..info.end]);
    const accession = (try scanner.next()).?;
    const unit_name = (try scanner.next()).?;
    try std.testing.expectEqualStrings("accession", accession.local_name);
    try std.testing.expectEqualStrings("MS:1000130", accession.value);
    try std.testing.expectEqualStrings("unitName", unit_name.local_name);
    try std.testing.expectEqualStrings("text > still", unit_name.value);
    try std.testing.expectEqual(@as(?RawAttribute, null), try scanner.next());
}

test "raw start tag scanner reports entities and namespace declarations" {
    const bytes = " unitName=\"a &amp; b\" xmlns:ms=\"urn:ms\"/>";
    const info = rawStartTagInfo(bytes).?;
    var scanner = RawAttributeScanner.init(bytes[0..info.end]);

    const unit_name = (try scanner.next()).?;
    const namespace = (try scanner.next()).?;
    try std.testing.expect(unit_name.has_entity);
    try std.testing.expect(namespace.is_namespace_declaration);
}

test "raw start tag scanner rejects an unterminated quoted value" {
    var scanner = RawAttributeScanner.init(" value=\"unfinished");

    try std.testing.expectError(error.Malformed, scanner.next());
    try std.testing.expectEqual(@as(?RawTagInfo, null), rawStartTagInfo(" value=\"unfinished"));
}

test "cdataContentLen uses SIMD for large content" {
    const buf = "abcd]]>" ++ "x";
    try std.testing.expectEqual(@as(?usize, 4), cdataContentLen(buf));

    const unterminated = "no end marker here";
    try std.testing.expectEqual(@as(?usize, null), cdataContentLen(unterminated));

    const empty_slice: []const u8 = "";
    try std.testing.expectEqual(@as(?usize, null), cdataContentLen(empty_slice));
}

test "commentEndLen finds terminator" {
    // "comment text " = 13 chars, then "-->"
    const terminated = "comment text -->more";
    try std.testing.expectEqual(@as(?usize, 13), commentEndLen(terminated));

    // stray `--` before the real `-->`: "a - b -- c " = 11 chars, then "-->"
    const with_stray = "a - b -- c -->end";
    try std.testing.expectEqual(@as(?usize, 11), commentEndLen(with_stray));

    const unterminated = "no end marker";
    try std.testing.expectEqual(@as(?usize, null), commentEndLen(unterminated));

    const empty_slice: []const u8 = "";
    try std.testing.expectEqual(@as(?usize, null), commentEndLen(empty_slice));
}

test "piEndLen finds terminator" {
    // "processing instruction" = 22 chars, then "?>"
    const terminated = "processing instruction?>more";
    try std.testing.expectEqual(@as(?usize, 22), piEndLen(terminated));

    // "version=\"1.0\" encoding=\"UTF-8\"" = 30 chars, then "?>"
    const with_stray = "version=\"1.0\" encoding=\"UTF-8\"?>";
    try std.testing.expectEqual(@as(?usize, 30), piEndLen(with_stray));

    const unterminated = "no end marker";
    try std.testing.expectEqual(@as(?usize, null), piEndLen(unterminated));

    const empty_slice: []const u8 = "";
    try std.testing.expectEqual(@as(?usize, null), piEndLen(empty_slice));
}
