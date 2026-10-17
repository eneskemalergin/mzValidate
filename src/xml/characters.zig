//! XML 1.0 name productions for the QName lexical checks of structural validation.

const std = @import("std");

pub const NameError = error{
    InvalidUtf8,
    InvalidName,
};

pub fn validateQName(bytes: []const u8) NameError!void {
    var part_start = true;
    var colon_seen = false;
    for (bytes) |byte| {
        if (byte >= 0x80) break;
        if (byte == ':') {
            if (part_start or colon_seen) return validateQNameUnicode(bytes);
            colon_seen = true;
            part_start = true;
            continue;
        }
        const valid = if (part_start)
            byte == '_' or std.ascii.isAlphabetic(byte)
        else
            byte == '_' or byte == '-' or byte == '.' or std.ascii.isAlphanumeric(byte);
        if (!valid) return validateQNameUnicode(bytes);
        part_start = false;
    } else {
        if (part_start) return error.InvalidName;
        return;
    }

    return validateQNameUnicode(bytes);
}

fn validateQNameUnicode(bytes: []const u8) NameError!void {
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

test "XML QName production accepts Unicode boundaries and rejects punctuation" {
    try validateQName("\xC3\x80root:attr\xC2\xB7name");
    try validateQName("\xF0\x90\x80\x80node");
    try std.testing.expectError(error.InvalidName, validateQName("1root"));
    try std.testing.expectError(error.InvalidName, validateQName("root:$attr"));
    try std.testing.expectError(error.InvalidName, validateQName("root:child:leaf"));
}

test "[unit]: QName validation preserves invalid UTF-8 precedence" {
    try std.testing.expectError(error.InvalidUtf8, validateQName("1\xff"));
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
