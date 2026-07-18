//! XML 1.0 and XML 1.1 character, whitespace, and name productions.
//!
//! Literal validation is incremental so reader input can split UTF-8 sequences
//! without weakening the character rules used by contiguous slice input.

const std = @import("std");

pub const Version = enum {
    xml_1_0,
    xml_1_1,
};

pub const ValidationError = error{
    InvalidUtf8,
    InvalidCharacter,
};

pub const NameError = error{
    InvalidUtf8,
    InvalidName,
};

pub const LiteralFailure = struct {
    index: usize,
    kind: enum {
        invalid_utf8,
        invalid_character,
    },
};

pub const LiteralValidator = struct {
    pending: [4]u8 = undefined,
    pending_len: u3 = 0,
    expected_len: u3 = 0,

    pub fn feedByte(validator: *LiteralValidator, byte: u8, version: Version) ValidationError!void {
        if (validator.expected_len == 0) {
            const sequence_len = std.unicode.utf8ByteSequenceLength(byte) catch return error.InvalidUtf8;
            if (sequence_len == 1) {
                if (!isLiteralCharacter(byte, version)) return error.InvalidCharacter;
                return;
            }
            validator.pending[0] = byte;
            validator.pending_len = 1;
            validator.expected_len = sequence_len;
            return;
        }

        validator.pending[validator.pending_len] = byte;
        validator.pending_len += 1;
        if (validator.pending_len != validator.expected_len) return;

        const codepoint = std.unicode.utf8Decode(validator.pending[0..validator.pending_len]) catch {
            validator.reset();
            return error.InvalidUtf8;
        };
        validator.reset();
        if (!isLiteralCharacter(codepoint, version)) return error.InvalidCharacter;
    }

    pub fn finish(validator: *LiteralValidator) ValidationError!void {
        if (validator.expected_len != 0) {
            validator.reset();
            return error.InvalidUtf8;
        }
    }

    pub fn reset(validator: *LiteralValidator) void {
        validator.pending_len = 0;
        validator.expected_len = 0;
    }
};

pub fn isWhitespaceByte(byte: u8) bool {
    return switch (byte) {
        ' ', '\t', '\r', '\n' => true,
        else => false,
    };
}

pub fn validateLiteral(bytes: []const u8, version: Version) ValidationError!void {
    const failure = firstLiteralFailure(bytes, version) orelse return;
    return switch (failure.kind) {
        .invalid_utf8 => error.InvalidUtf8,
        .invalid_character => error.InvalidCharacter,
    };
}

pub fn firstLiteralFailure(bytes: []const u8, version: Version) ?LiteralFailure {
    var index: usize = 0;
    while (index < bytes.len) {
        const sequence_len = std.unicode.utf8ByteSequenceLength(bytes[index]) catch {
            return .{ .index = index, .kind = .invalid_utf8 };
        };
        const end = std.math.add(usize, index, sequence_len) catch {
            return .{ .index = index, .kind = .invalid_utf8 };
        };
        if (end > bytes.len) return .{ .index = bytes.len - 1, .kind = .invalid_utf8 };
        const codepoint = std.unicode.utf8Decode(bytes[index..end]) catch {
            return .{ .index = end - 1, .kind = .invalid_utf8 };
        };
        if (!isLiteralCharacter(codepoint, version)) {
            return .{ .index = end - 1, .kind = .invalid_character };
        }
        index = end;
    }
    return null;
}

pub fn validateName(bytes: []const u8) NameError!void {
    const view = std.unicode.Utf8View.init(bytes) catch return error.InvalidUtf8;
    var iterator = view.iterator();
    const first = iterator.nextCodepoint() orelse return error.InvalidName;
    if (!isNameStartCharacter(first)) return error.InvalidName;
    while (iterator.nextCodepoint()) |codepoint| {
        if (!isNameCharacter(codepoint)) return error.InvalidName;
    }
}

pub fn validateQName(bytes: []const u8) NameError!void {
    const view = std.unicode.Utf8View.init(bytes) catch return error.InvalidUtf8;
    var iterator = view.iterator();
    var part_start = true;
    var colon_seen = false;

    while (iterator.nextCodepoint()) |codepoint| {
        if (codepoint == ':') {
            if (part_start or colon_seen) return error.InvalidName;
            colon_seen = true;
            part_start = true;
            continue;
        }
        if (part_start) {
            if (!isNameStartCharacter(codepoint)) return error.InvalidName;
            part_start = false;
        } else if (!isNameCharacter(codepoint)) {
            return error.InvalidName;
        }
    }

    if (part_start) return error.InvalidName;
}

pub fn isReferenceCharacter(codepoint: u21, version: Version) bool {
    return switch (version) {
        .xml_1_0 => isXml10Character(codepoint),
        .xml_1_1 => isXml11Character(codepoint),
    };
}

fn isLiteralCharacter(codepoint: u21, version: Version) bool {
    return switch (version) {
        .xml_1_0 => isXml10Character(codepoint),
        .xml_1_1 => isXml11Character(codepoint) and !isXml11RestrictedCharacter(codepoint),
    };
}

fn isXml10Character(codepoint: u21) bool {
    return codepoint == 0x9 or codepoint == 0xA or codepoint == 0xD or
        (codepoint >= 0x20 and codepoint <= 0xD7FF) or
        (codepoint >= 0xE000 and codepoint <= 0xFFFD) or
        (codepoint >= 0x10000 and codepoint <= 0x10FFFF);
}

fn isXml11Character(codepoint: u21) bool {
    return (codepoint >= 0x1 and codepoint <= 0xD7FF) or
        (codepoint >= 0xE000 and codepoint <= 0xFFFD) or
        (codepoint >= 0x10000 and codepoint <= 0x10FFFF);
}

fn isXml11RestrictedCharacter(codepoint: u21) bool {
    return (codepoint >= 0x1 and codepoint <= 0x8) or
        (codepoint >= 0xB and codepoint <= 0xC) or
        (codepoint >= 0xE and codepoint <= 0x1F) or
        (codepoint >= 0x7F and codepoint <= 0x84) or
        (codepoint >= 0x86 and codepoint <= 0x9F);
}

fn isNameStartCharacter(codepoint: u21) bool {
    return codepoint == ':' or
        (codepoint >= 'A' and codepoint <= 'Z') or
        codepoint == '_' or
        (codepoint >= 'a' and codepoint <= 'z') or
        (codepoint >= 0xC0 and codepoint <= 0xD6) or
        (codepoint >= 0xD8 and codepoint <= 0xF6) or
        (codepoint >= 0xF8 and codepoint <= 0x2FF) or
        (codepoint >= 0x370 and codepoint <= 0x37D) or
        (codepoint >= 0x37F and codepoint <= 0x1FFF) or
        (codepoint >= 0x200C and codepoint <= 0x200D) or
        (codepoint >= 0x2070 and codepoint <= 0x218F) or
        (codepoint >= 0x2C00 and codepoint <= 0x2FEF) or
        (codepoint >= 0x3001 and codepoint <= 0xD7FF) or
        (codepoint >= 0xF900 and codepoint <= 0xFDCF) or
        (codepoint >= 0xFDF0 and codepoint <= 0xFFFD) or
        (codepoint >= 0x10000 and codepoint <= 0xEFFFF);
}

fn isNameCharacter(codepoint: u21) bool {
    return isNameStartCharacter(codepoint) or
        codepoint == '-' or
        codepoint == '.' or
        (codepoint >= '0' and codepoint <= '9') or
        codepoint == 0xB7 or
        (codepoint >= 0x300 and codepoint <= 0x36F) or
        (codepoint >= 0x203F and codepoint <= 0x2040);
}

// --- Unit Tests ---

test "XML character productions distinguish literals and references" {
    try validateLiteral("plain\ttext", .xml_1_0);
    try std.testing.expectError(error.InvalidCharacter, validateLiteral("\x01", .xml_1_0));
    try std.testing.expectError(error.InvalidCharacter, validateLiteral("\x01", .xml_1_1));
    try std.testing.expect(isReferenceCharacter(0x1, .xml_1_1));
    try std.testing.expect(!isReferenceCharacter(0x1, .xml_1_0));
    try std.testing.expect(!isReferenceCharacter(0, .xml_1_1));
}

test "XML character productions preserve range boundaries" {
    try std.testing.expect(isReferenceCharacter(0xD7FF, .xml_1_0));
    try std.testing.expect(!isReferenceCharacter(0xD800, .xml_1_0));
    try std.testing.expect(isReferenceCharacter(0xE000, .xml_1_0));
    try std.testing.expect(isReferenceCharacter(0xFFFD, .xml_1_0));
    try std.testing.expect(!isReferenceCharacter(0xFFFE, .xml_1_0));
    try std.testing.expect(isReferenceCharacter(0x10FFFF, .xml_1_0));

    try std.testing.expect(!isLiteralCharacter(0x84, .xml_1_1));
    try std.testing.expect(isLiteralCharacter(0x85, .xml_1_1));
    try std.testing.expect(!isLiteralCharacter(0x86, .xml_1_1));
    try std.testing.expect(!isLiteralCharacter(0x9F, .xml_1_1));
    try std.testing.expect(isLiteralCharacter(0xA0, .xml_1_1));
    try std.testing.expect(isReferenceCharacter(0x84, .xml_1_1));
    try std.testing.expect(isReferenceCharacter(0x9F, .xml_1_1));
}

test "XML QName production accepts Unicode boundaries and rejects punctuation" {
    try validateQName("\xC3\x80root:attr\xC2\xB7name");
    try validateQName("\xF0\x90\x80\x80node");
    try std.testing.expectError(error.InvalidName, validateQName("1root"));
    try std.testing.expectError(error.InvalidName, validateQName("root:$attr"));
    try std.testing.expectError(error.InvalidName, validateQName("root:child:leaf"));
}

test "XML name productions preserve included ranges and excluded gaps" {
    const valid_starts = [_]u21{ 0xD6, 0xD8, 0xF6, 0xF8, 0x2FF, 0x370, 0x37D, 0x37F, 0xEFFFF };
    for (valid_starts) |codepoint| try std.testing.expect(isNameStartCharacter(codepoint));

    const invalid_starts = [_]u21{ 0xD7, 0xF7, 0x300, 0x36F, 0x37E, 0xF0000 };
    for (invalid_starts) |codepoint| try std.testing.expect(!isNameStartCharacter(codepoint));

    try std.testing.expect(isNameCharacter(0x300));
    try std.testing.expect(isNameCharacter(0x36F));
    try std.testing.expect(isNameCharacter(0x203F));
    try std.testing.expect(isNameCharacter(0x2040));
}
