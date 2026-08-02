//! SIMD and scalar scanning helpers for contiguous XML bytes.
//! Raw attribute views borrow contiguous tag bytes and do not decode values.

const std = @import("std");
const characters = @import("characters.zig");

const chunk_len: comptime_int = std.simd.suggestVectorLength(u8) orelse 32;
const ByteVector = @Vector(chunk_len, u8);
const BoolVector = @Vector(chunk_len, bool);

fn isXmlWhitespaceByte(byte: u8) bool {
    return characters.isWhitespaceByte(byte);
}

pub const RawAttributeError = error{
    Malformed,
    InvalidUtf8,
    InvalidCharacter,
};

/// Raw start-tag boundary; `end` excludes the `>` delimiter outside quotes.
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
    version: characters.Version = .xml_1_0,
    pos: usize = 0,

    pub fn init(bytes: []const u8) RawAttributeScanner {
        return .{ .bytes = bytes };
    }

    pub fn initVersion(bytes: []const u8, version: characters.Version) RawAttributeScanner {
        return .{ .bytes = bytes, .version = version };
    }

    /// Returns the next borrowed attribute, or null after the tag body.
    pub fn next(scanner: *RawAttributeScanner) RawAttributeError!?RawAttribute {
        while (scanner.pos < scanner.bytes.len and isXmlWhitespaceByte(scanner.bytes[scanner.pos])) : (scanner.pos += 1) {}
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
        characters.validateQName(name) catch |err| {
            return switch (err) {
                error.InvalidUtf8 => error.InvalidUtf8,
                error.InvalidName => error.Malformed,
            };
        };
        const local_name = try rawLocalName(name);

        while (scanner.pos < scanner.bytes.len and isXmlWhitespaceByte(scanner.bytes[scanner.pos])) : (scanner.pos += 1) {}
        if (scanner.pos == scanner.bytes.len or scanner.bytes[scanner.pos] != '=') return error.Malformed;
        scanner.pos += 1;
        while (scanner.pos < scanner.bytes.len and isXmlWhitespaceByte(scanner.bytes[scanner.pos])) : (scanner.pos += 1) {}
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
        // Entity-bearing values are validated after decoding by the eager parser path.
        if (!has_entity) {
            const less_than = std.mem.indexOfScalar(u8, value, '<');
            const literal_failure = characters.firstLiteralFailure(value, scanner.version);
            if (literal_failure) |failure| {
                if (less_than == null or failure.index < less_than.?) {
                    return switch (failure.kind) {
                        .invalid_utf8 => error.InvalidUtf8,
                        .invalid_character => error.InvalidCharacter,
                    };
                }
            }
            if (less_than != null) return error.InvalidCharacter;
        }
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
        } else if (after_equals and isXmlWhitespaceByte(byte)) {
            continue;
        } else if (after_equals and (byte == '"' or byte == '\'')) {
            quote = byte;
            after_equals = false;
        } else if (byte == '>') {
            var last = index;
            while (last > 0 and isXmlWhitespaceByte(bytes[last - 1])) : (last -= 1) {}
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
    return isXmlWhitespaceByte(byte) or switch (byte) {
        '/', '>', '=', '?', '"', '\'' => true,
        else => false,
    };
}

fn firstIndexOfAny(bytes: []const u8, needles: []const u8) ?usize {
    var offset: usize = 0;
    while (bytes.len - offset >= chunk_len) {
        const chunk: ByteVector = bytes[offset..][0..chunk_len].*;
        var combined: BoolVector = @splat(false);
        for (needles) |needle| {
            combined = combined | (chunk == @as(ByteVector, @splat(needle)));
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

/// Returns the leading XML whitespace run length.
pub fn skipWhitespaceRun(bytes: []const u8) usize {
    var offset: usize = 0;
    while (bytes.len - offset >= chunk_len) {
        const chunk: ByteVector = bytes[offset..][0..chunk_len].*;
        const is_ws = (chunk == @as(ByteVector, @splat(' '))) |
            (chunk == @as(ByteVector, @splat('\t'))) |
            (chunk == @as(ByteVector, @splat('\r'))) |
            (chunk == @as(ByteVector, @splat('\n')));
        if (std.simd.firstTrue(!is_ws)) |pos| return offset + pos;
        offset += chunk_len;
    }
    for (bytes[offset..], 0..) |b, i| {
        if (!isXmlWhitespaceByte(b)) return offset + i;
    }
    return bytes.len;
}

/// Run of XML name characters before a delimiter or end of slice.
pub fn nameCharRunLen(bytes: []const u8) usize {
    const spec = comptime [_]u8{ '/', '>', '=', '?', '"', '\'' };
    var offset: usize = 0;
    while (bytes.len - offset >= chunk_len) {
        const chunk: ByteVector = bytes[offset..][0..chunk_len].*;
        var combined = (chunk == @as(ByteVector, @splat(' '))) |
            (chunk == @as(ByteVector, @splat('\t'))) |
            (chunk == @as(ByteVector, @splat('\r'))) |
            (chunk == @as(ByteVector, @splat('\n')));
        inline for (spec) |c| {
            combined = combined | (chunk == @as(ByteVector, @splat(c)));
        }
        if (std.simd.firstTrue(combined)) |pos| return offset + pos;
        offset += chunk_len;
    }
    for (bytes[offset..], 0..) |b, i| {
        if (isXmlWhitespaceByte(b) or b == '/' or b == '>' or b == '=' or b == '?' or b == '"' or b == '\'')
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
    while (bytes.len - offset >= chunk_len) {
        const chunk: ByteVector = bytes[offset..][0..chunk_len].*;
        const is_bracket = chunk == @as(ByteVector, @splat(']'));
        if (std.simd.firstTrue(is_bracket)) |pos| {
            const abs_pos = offset + pos;
            if (bytes.len - abs_pos > 2 and bytes[abs_pos + 1] == ']' and bytes[abs_pos + 2] == '>') {
                return abs_pos;
            }
            offset = abs_pos + 1;
        } else {
            offset += chunk_len;
        }
    }
    for (bytes[offset..], 0..) |b, i| {
        const pos = offset + i;
        if (b == ']' and bytes.len - pos > 2 and bytes[pos + 1] == ']' and bytes[pos + 2] == '>') {
            return offset + i;
        }
    }
    return null;
}

/// Position of `-->` in bytes, or `null` if unterminated.
/// Returns the index of the first `-` in the terminating `-->`.
pub fn commentEndLen(bytes: []const u8) ?usize {
    var offset: usize = 0;
    while (bytes.len - offset >= chunk_len) {
        const chunk: ByteVector = bytes[offset..][0..chunk_len].*;
        const is_dash = chunk == @as(ByteVector, @splat('-'));
        if (std.simd.firstTrue(is_dash)) |pos| {
            const abs_pos = offset + pos;
            if (bytes.len - abs_pos > 2 and bytes[abs_pos + 1] == '-' and bytes[abs_pos + 2] == '>') {
                return abs_pos;
            }
            offset = abs_pos + 1;
        } else {
            offset += chunk_len;
        }
    }
    for (bytes[offset..], 0..) |b, i| {
        const pos = offset + i;
        if (b == '-' and bytes.len - pos > 2 and bytes[pos + 1] == '-' and bytes[pos + 2] == '>') {
            return offset + i;
        }
    }
    return null;
}

/// Position of `?>` in bytes, or `null` if unterminated.
/// Returns the index of `?` in the terminating `?>`.
pub fn piEndLen(bytes: []const u8) ?usize {
    var offset: usize = 0;
    while (bytes.len - offset >= chunk_len) {
        const chunk: ByteVector = bytes[offset..][0..chunk_len].*;
        const is_qmark = chunk == @as(ByteVector, @splat('?'));
        if (std.simd.firstTrue(is_qmark)) |pos| {
            const abs_pos = offset + pos;
            if (bytes.len - abs_pos > 1 and bytes[abs_pos + 1] == '>') {
                return abs_pos;
            }
            offset = abs_pos + 1;
        } else {
            offset += chunk_len;
        }
    }
    for (bytes[offset..], 0..) |b, i| {
        const pos = offset + i;
        if (b == '?' and bytes.len - pos > 1 and bytes[pos + 1] == '>') {
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

// --- Unit Tests ---

test "scanner skips XML whitespace" {
    const input = "  \t\n\rhello";

    const n = skipWhitespaceRun(input);

    try std.testing.expectEqual(@as(usize, 5), n);
}

test "scanner stops names at whitespace and markup" {
    const input = "spectrum id";

    const n = nameCharRunLen(input);

    try std.testing.expectEqual(@as(usize, 8), n);
}

test "scanner leaves non-XML control bytes for name validation" {
    const input = "root\x0Battr";

    const n = nameCharRunLen(input);

    try std.testing.expectEqual(input.len, n);
}

test "scanner stops plain text at markup" {
    const plain = "AAAA";
    const at_lt = "AAA<";
    const at_amp = "AA&";

    try std.testing.expectEqual(@as(usize, 4), textPlainRunLen(plain));
    try std.testing.expectEqual(@as(usize, 3), textPlainRunLen(at_lt));
    try std.testing.expectEqual(@as(usize, 2), textPlainRunLen(at_amp));
}

test "scanner finds CDATA terminators" {
    const terminated = "abcd]]>more";
    const with_fake = "a]]b]]>rest";

    try std.testing.expectEqual(@as(?usize, 4), cdataContentLen(terminated));
    try std.testing.expectEqual(@as(?usize, 4), cdataContentLen(with_fake));
    try std.testing.expectEqual(@as(?usize, null), cdataContentLen("no end"));
}

test "scanner stops attribute values at quote or entity" {
    const input = "value&amp;more\"rest";

    const n = attrValuePlainRunLen(input, '"');

    try std.testing.expectEqual(@as(usize, 5), n);
}

test "scanner handles delimiters at SIMD boundaries" {
    var whitespace: [chunk_len + 2]u8 = @splat(' ');
    whitespace[chunk_len - 1] = 'x';
    try std.testing.expectEqual(chunk_len - 1, skipWhitespaceRun(&whitespace));

    var name: [chunk_len + 2]u8 = @splat('a');
    name[chunk_len - 1] = '>';
    try std.testing.expectEqual(chunk_len - 1, nameCharRunLen(&name));

    var text: [chunk_len + 2]u8 = @splat('a');
    text[chunk_len - 1] = '&';
    try std.testing.expectEqual(chunk_len - 1, textPlainRunLen(&text));

    var attribute: [chunk_len + 2]u8 = @splat('a');
    attribute[chunk_len - 1] = '"';
    try std.testing.expectEqual(chunk_len - 1, attrValuePlainRunLen(&attribute, '"'));

    var cdata: [chunk_len + 3]u8 = @splat('x');
    cdata[chunk_len - 1] = ']';
    cdata[chunk_len] = ']';
    cdata[chunk_len + 1] = '>';
    try std.testing.expectEqual(@as(?usize, chunk_len - 1), cdataContentLen(&cdata));

    var comment: [chunk_len + 3]u8 = @splat('x');
    comment[chunk_len - 1] = '-';
    comment[chunk_len] = '-';
    comment[chunk_len + 1] = '>';
    try std.testing.expectEqual(@as(?usize, chunk_len - 1), commentEndLen(&comment));

    var pi: [chunk_len + 2]u8 = @splat('x');
    pi[chunk_len - 1] = '?';
    pi[chunk_len] = '>';
    try std.testing.expectEqual(@as(?usize, chunk_len - 1), piEndLen(&pi));
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

test "raw attribute scanner rejects invalid names and literal characters" {
    var invalid_name = RawAttributeScanner.init(" bad$name=\"value\"");
    try std.testing.expectError(error.Malformed, invalid_name.next());

    var invalid_value = RawAttributeScanner.init(" unitName=\"literal < value\"");
    try std.testing.expectError(error.InvalidCharacter, invalid_value.next());

    var xml11_restricted = RawAttributeScanner.initVersion(" unitName=\"\x7F\"", .xml_1_1);
    try std.testing.expectError(error.InvalidCharacter, xml11_restricted.next());
}

test "CDATA scanner handles large input" {
    var buf: [chunk_len + 8]u8 = @splat('x');
    buf[chunk_len + 1] = ']';
    buf[chunk_len + 2] = ']';
    buf[chunk_len + 3] = '>';
    try std.testing.expectEqual(@as(?usize, chunk_len + 1), cdataContentLen(&buf));

    const unterminated = "no end marker here";
    try std.testing.expectEqual(@as(?usize, null), cdataContentLen(unterminated));

    const empty_slice: []const u8 = "";
    try std.testing.expectEqual(@as(?usize, null), cdataContentLen(empty_slice));
}

test "commentEndLen finds terminator" {
    const terminated = "comment text -->more";
    try std.testing.expectEqual(@as(?usize, 13), commentEndLen(terminated));

    const with_stray = "a - b -- c -->end";
    try std.testing.expectEqual(@as(?usize, 11), commentEndLen(with_stray));

    const unterminated = "no end marker";
    try std.testing.expectEqual(@as(?usize, null), commentEndLen(unterminated));

    const empty_slice: []const u8 = "";
    try std.testing.expectEqual(@as(?usize, null), commentEndLen(empty_slice));
}

test "piEndLen finds terminator" {
    const terminated = "processing instruction?>more";
    try std.testing.expectEqual(@as(?usize, 22), piEndLen(terminated));

    const with_stray = "version=\"1.0\" encoding=\"UTF-8\"?>";
    try std.testing.expectEqual(@as(?usize, 30), piEndLen(with_stray));

    const unterminated = "no end marker";
    try std.testing.expectEqual(@as(?usize, null), piEndLen(unterminated));

    const empty_slice: []const u8 = "";
    try std.testing.expectEqual(@as(?usize, null), piEndLen(empty_slice));
}
