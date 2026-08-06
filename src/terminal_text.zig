//! UTF-8-safe measurement and slicing for terminal presentation.
//!
//! Invalid bytes count as one display unit so arbitrary path bytes remain renderable.

const std = @import("std");

/// Counts valid UTF-8 code points and invalid bytes as terminal columns.
pub fn displayWidth(text: []const u8) usize {
    var index: usize = 0;
    var width: usize = 0;
    while (index < text.len) {
        index += unitLength(text[index..]);
        width += 1;
    }
    return width;
}

/// Returns a byte boundary containing at most `max_width` display units.
pub fn prefixBytesForWidth(text: []const u8, max_width: usize) usize {
    var index: usize = 0;
    var width: usize = 0;
    while (index < text.len and width < max_width) {
        index += unitLength(text[index..]);
        width += 1;
    }
    return index;
}

/// Returns the byte boundary of the last `max_width` display units.
pub fn suffixStartForWidth(text: []const u8, max_width: usize) usize {
    const width = displayWidth(text);
    if (width <= max_width) return 0;

    var index: usize = 0;
    var skipped: usize = 0;
    const skip = width - max_width;
    while (skipped < skip) : (skipped += 1) {
        index += unitLength(text[index..]);
    }
    return index;
}

fn unitLength(text: []const u8) usize {
    const length: usize = std.unicode.utf8ByteSequenceLength(text[0]) catch return 1;
    if (length > text.len or !std.unicode.utf8ValidateSlice(text[0..length])) return 1;
    return length;
}

// --- Unit Tests ---

test "terminal text boundaries preserve UTF-8 and invalid bytes" {
    const valid = "abé日z";
    try std.testing.expectEqual(@as(usize, 5), displayWidth(valid));
    try std.testing.expectEqualStrings("abé", valid[0..prefixBytesForWidth(valid, 3)]);
    try std.testing.expectEqualStrings("日z", valid[suffixStartForWidth(valid, 2)..]);

    const invalid = "ab\xffz";
    try std.testing.expectEqual(@as(usize, 4), displayWidth(invalid));
    try std.testing.expectEqualStrings("\xffz", invalid[suffixStartForWidth(invalid, 2)..]);
}
