//! Single-pass streaming XML parser for mzML validation.
//!
//! Design notes:
//! - Input is consumed from `std.Io.Reader` in a single forward pass.
//! - Event slices borrow caller-provided buffers and are only valid until
//!   the next `next()` call. Copy any value you need to keep.
//! - Comments and processing instructions are skipped silently.
//! - CDATA sections surface as `text` with `from_cdata = true`.
//! - Built-in XML entities and numeric character references are decoded.
//! - DTD declarations (`<!...>`) are rejected: mzML does not need them.

const std = @import("std");
const events = @import("events.zig");

const Attribute = events.Attribute;
const EndElement = events.EndElement;
const Event = events.Event;
const QName = events.QName;
const StartElement = events.StartElement;
const Text = events.Text;

// --- Public types ---

pub const ParseError = error{
    UnexpectedEof,
    MalformedXml,
    InvalidUtf8,
    TokenTooLong,
    TooManyAttributes,
    TooManyNamespaces,
    NamespaceStorageExceeded,
    ElementNestingTooDeep,
    ElementStorageExceeded,
    UnknownEntity,
    InvalidCharacterReference,
    UnsupportedMarkup,
    MismatchedEndTag,
} || error{ReadFailed};

// --- Private types ---

// Byte range within a flat backing buffer.
const Range = struct {
    start: usize,
    len: usize,

    fn slice(range: Range, backing: []const u8) []const u8 {
        return backing[range.start..][0..range.len];
    }
};

// Prefix + local name positions within the token buffer before namespace resolution.
const NameParts = struct {
    prefix: ?Range,
    local_name: Range,
};

pub const NamespaceBinding = struct {
    prefix: ?Range,
    namespace_uri: Range,
};

pub const ElementFrame = struct {
    namespace_count_before: usize,
    namespace_bytes_before: usize,
    element_bytes_before: usize,
    prefix: ?Range,
    local_name: Range,
    namespace_uri: ?Range,
    synthetic_end_byte_offset: ?u64 = null,
};

pub const Buffers = struct {
    token: []u8,
    attributes: []Attribute,
    namespace_bindings: []NamespaceBinding,
    namespace_bytes: []u8,
    element_stack: []ElementFrame,
    element_bytes: []u8,
};

// --- Parser ---

pub const Parser = struct {
    reader: *std.Io.Reader,
    token_buffer: []u8,
    attribute_storage: []Attribute,
    namespace_storage: []NamespaceBinding,
    namespace_bytes: []u8,
    element_storage: []ElementFrame,
    element_bytes: []u8,

    token_len: usize = 0,
    attribute_count: usize = 0,
    namespace_count: usize = 0,
    namespace_bytes_len: usize = 0,
    element_count: usize = 0,
    element_bytes_len: usize = 0,

    lookahead: ?u8 = null,
    lookahead_offset: u64 = 0,
    absolute_offset: u64 = 0,
    last_byte_offset: u64 = 0,
    pending_self_closing_end: bool = false,

    /// Constructs a parser from a reader and caller-supplied buffers.
    ///
    /// All buffers are borrowed. Size them for worst-case document depth and
    /// attribute counts before calling `next` in a loop.
    pub fn init(reader: *std.Io.Reader, buffers: Buffers) Parser {
        return .{
            .reader = reader,
            .token_buffer = buffers.token,
            .attribute_storage = buffers.attributes,
            .namespace_storage = buffers.namespace_bindings,
            .namespace_bytes = buffers.namespace_bytes,
            .element_storage = buffers.element_stack,
            .element_bytes = buffers.element_bytes,
        };
    }

    /// Returns the next event, or `null` when the document ends cleanly.
    pub fn next(parser: *Parser) ParseError!?Event {
        if (parser.pending_self_closing_end) {
            return try parser.emitSyntheticEnd();
        }

        while (true) {
            parser.resetEventStorage();

            const first_byte = (try parser.takeOptionalByte()) orelse {
                if (parser.element_count != 0) return error.UnexpectedEof;
                return null;
            };
            const start_offset = parser.last_byte_offset;

            if (first_byte != '<') {
                if (try parser.parseText(start_offset, first_byte, false)) |event| {
                    return event;
                }
                continue;
            }

            const markup = try parser.takeRequiredByte();
            switch (markup) {
                '/' => return try parser.parseEndElement(start_offset),
                '?' => {
                    try parser.skipProcessingInstruction();
                    continue;
                },
                '!' => {
                    if (try parser.handleBangMarkup(start_offset)) |event| return event;
                    continue;
                },
                else => return try parser.parseStartElement(start_offset, markup),
            }
        }
    }

    /// Current byte offset of the last consumed byte. Useful for diagnostics.
    pub fn byteOffset(parser: *const Parser) u64 {
        return parser.last_byte_offset;
    }

    fn parseText(parser: *Parser, byte_offset: u64, first_byte: u8, from_cdata: bool) ParseError!?Event {
        try parser.appendDecodedTextByte(first_byte);

        while (true) {
            const next_byte = try parser.peekOptionalByte();
            if (next_byte == null or next_byte.? == '<') break;
            _ = try parser.takeRequiredByte();
            try parser.appendDecodedTextByte(next_byte.?);
        }

        const value = parser.currentToken();
        if (!from_cdata and isWhitespaceOnly(value)) return null;
        if (!std.unicode.utf8ValidateSlice(value)) return error.InvalidUtf8;

        return .{ .text = .{
            .byte_offset = byte_offset,
            .value = value,
            .from_cdata = from_cdata,
        } };
    }

    fn parseStartElement(parser: *Parser, byte_offset: u64, first_name_byte: u8) ParseError!Event {
        const namespace_count_before = parser.namespace_count;
        const namespace_bytes_before = parser.namespace_bytes_len;

        const name_parts = try parser.parseName(first_name_byte);

        while (true) {
            try parser.skipWhitespace();
            const next_byte = try parser.peekRequiredByte();

            switch (next_byte) {
                '>' => {
                    _ = try parser.takeRequiredByte();
                    break;
                },
                '/' => {
                    _ = try parser.takeRequiredByte();
                    try parser.expectByte('>');
                    const event = try parser.finishStartElement(
                        byte_offset,
                        name_parts,
                        namespace_count_before,
                        namespace_bytes_before,
                        true,
                        parser.last_byte_offset - 1,
                    );
                    parser.pending_self_closing_end = true;
                    return event;
                },
                else => try parser.parseAttribute(),
            }
        }

        return parser.finishStartElement(
            byte_offset,
            name_parts,
            namespace_count_before,
            namespace_bytes_before,
            false,
            null,
        );
    }

    fn finishStartElement(
        parser: *Parser,
        byte_offset: u64,
        name_parts: NameParts,
        namespace_count_before: usize,
        namespace_bytes_before: usize,
        self_closing: bool,
        synthetic_end_byte_offset: ?u64,
    ) ParseError!Event {
        const name = try parser.resolveQName(name_parts, true);
        try parser.resolveAttributeNamespaces();
        try parser.pushElementFrame(name, namespace_count_before, namespace_bytes_before, synthetic_end_byte_offset);

        return .{ .start_element = .{
            .byte_offset = byte_offset,
            .name = name,
            .attributes = parser.attribute_storage[0..parser.attribute_count],
            .self_closing = self_closing,
        } };
    }

    fn parseEndElement(parser: *Parser, byte_offset: u64) ParseError!Event {
        if (parser.element_count == 0) return error.MalformedXml;

        const first_name_byte = try parser.takeRequiredByte();
        const actual_name = try parser.parseName(first_name_byte);
        try parser.skipWhitespace();
        try parser.expectByte('>');

        const frame = parser.topElementFrame();
        if (!parser.frameMatches(frame, actual_name)) return error.MismatchedEndTag;

        const event_name = try parser.materializeFrameName(frame);
        parser.popElementFrame();

        return .{ .end_element = .{
            .byte_offset = byte_offset,
            .name = event_name,
        } };
    }

    fn parseAttribute(parser: *Parser) ParseError!void {
        if (parser.attribute_count >= parser.attribute_storage.len) return error.TooManyAttributes;

        const byte = try parser.takeRequiredByte();
        const byte_offset = parser.last_byte_offset;
        const name = try parser.parseName(byte);

        try parser.skipWhitespace();
        try parser.expectByte('=');
        try parser.skipWhitespace();

        const quote = try parser.takeRequiredByte();
        if (quote != '"' and quote != '\'') return error.MalformedXml;

        const value_start = parser.token_len;
        while (true) {
            const next_byte = try parser.takeRequiredByte();
            if (next_byte == quote) break;
            try parser.appendDecodedTextByte(next_byte);
        }
        const value = parser.token_buffer[value_start..parser.token_len];
        if (!std.unicode.utf8ValidateSlice(value)) return error.InvalidUtf8;

        const is_namespace_declaration = parser.isNamespaceDeclaration(name);
        if (is_namespace_declaration) {
            try parser.appendNamespaceBinding(name, value);
        }

        parser.attribute_storage[parser.attribute_count] = .{
            .byte_offset = byte_offset,
            .name = .{
                .prefix = if (name.prefix) |prefix| prefix.slice(parser.token_buffer) else null,
                .local_name = name.local_name.slice(parser.token_buffer),
                .namespace_uri = null,
            },
            .value = value,
            .is_namespace_declaration = is_namespace_declaration,
        };
        parser.attribute_count += 1;
    }

    fn resolveAttributeNamespaces(parser: *Parser) ParseError!void {
        for (parser.attribute_storage[0..parser.attribute_count]) |*attribute| {
            if (attribute.is_namespace_declaration) continue;
            if (attribute.name.prefix) |prefix| {
                attribute.name.namespace_uri = try parser.lookupNamespace(prefix, false);
            }
        }
    }

    fn emitSyntheticEnd(parser: *Parser) ParseError!Event {
        const frame = parser.topElementFrame();
        const byte_offset = frame.synthetic_end_byte_offset orelse return error.MalformedXml;
        parser.pending_self_closing_end = false;
        parser.resetEventStorage();
        const name = try parser.materializeFrameName(frame);
        parser.popElementFrame();
        return .{ .end_element = .{
            .byte_offset = byte_offset,
            .name = name,
        } };
    }

    fn handleBangMarkup(parser: *Parser, start_offset: u64) ParseError!?Event {
        const next_byte = try parser.takeRequiredByte();
        switch (next_byte) {
            '-' => {
                try parser.expectByte('-');
                try parser.skipComment();
                return null;
            },
            '[' => {
                try parser.expectBytes("CDATA[");
                parser.resetEventStorage();
                const content_offset = parser.absolute_offset;
                return try parser.parseCdata(content_offset);
            },
            else => {
                _ = start_offset;
                return error.UnsupportedMarkup;
            },
        }
    }

    fn parseCdata(parser: *Parser, byte_offset: u64) ParseError!Event {
        while (true) {
            const byte = try parser.takeRequiredByte();
            if (byte == ']') {
                if (try parser.peekOptionalByte()) |second| {
                    if (second == ']') {
                        _ = try parser.takeRequiredByte();
                        if (try parser.peekOptionalByte()) |third| {
                            if (third == '>') {
                                _ = try parser.takeRequiredByte();
                                break;
                            }
                        } else return error.UnexpectedEof;
                        try parser.appendTokenByte(']');
                        try parser.appendTokenByte(']');
                        continue;
                    }
                } else return error.UnexpectedEof;
            }
            try parser.appendTokenByte(byte);
        }

        const value = parser.currentToken();
        if (!std.unicode.utf8ValidateSlice(value)) return error.InvalidUtf8;
        return .{ .text = .{
            .byte_offset = byte_offset,
            .value = value,
            .from_cdata = true,
        } };
    }

    fn skipProcessingInstruction(parser: *Parser) ParseError!void {
        while (true) {
            const byte = try parser.takeRequiredByte();
            if (byte == '?') {
                if (try parser.peekOptionalByte()) |next_byte| {
                    if (next_byte == '>') {
                        _ = try parser.takeRequiredByte();
                        return;
                    }
                } else return error.UnexpectedEof;
            }
        }
    }

    fn skipComment(parser: *Parser) ParseError!void {
        while (true) {
            const byte = try parser.takeRequiredByte();
            if (byte == '-') {
                if (try parser.peekOptionalByte()) |second| {
                    if (second == '-') {
                        _ = try parser.takeRequiredByte();
                        try parser.expectByte('>');
                        return;
                    }
                } else return error.UnexpectedEof;
            }
        }
    }

    fn parseName(parser: *Parser, first_byte: u8) ParseError!NameParts {
        const start = parser.token_len;
        try parser.appendTokenByte(first_byte);

        while (true) {
            const next_byte = try parser.peekOptionalByte();
            if (next_byte == null or isNameTerminator(next_byte.?)) break;
            _ = try parser.takeRequiredByte();
            try parser.appendTokenByte(next_byte.?);
        }

        const bytes = parser.token_buffer[start..parser.token_len];
        if (bytes.len == 0 or !std.unicode.utf8ValidateSlice(bytes)) return error.InvalidUtf8;

        var colon_index: ?usize = null;
        for (bytes, 0..) |byte, index| {
            if (byte == ':') {
                if (colon_index != null or index == 0 or index + 1 == bytes.len) return error.MalformedXml;
                colon_index = index;
            }
        }

        return if (colon_index) |index|
            .{
                .prefix = .{ .start = start, .len = index },
                .local_name = .{ .start = start + index + 1, .len = bytes.len - index - 1 },
            }
        else
            .{
                .prefix = null,
                .local_name = .{ .start = start, .len = bytes.len },
            };
    }

    fn resolveQName(parser: *Parser, name: NameParts, allow_default_namespace: bool) ParseError!QName {
        const prefix = if (name.prefix) |range| range.slice(parser.token_buffer) else null;
        return .{
            .prefix = prefix,
            .local_name = name.local_name.slice(parser.token_buffer),
            .namespace_uri = try parser.lookupNamespace(prefix, allow_default_namespace),
        };
    }

    fn lookupNamespace(parser: *Parser, prefix: ?[]const u8, allow_default_namespace: bool) ParseError!?[]const u8 {
        if (prefix == null and !allow_default_namespace) return null;

        var index = parser.namespace_count;
        while (index > 0) {
            index -= 1;
            const binding = parser.namespace_storage[index];
            const binding_prefix = if (binding.prefix) |range| range.slice(parser.namespace_bytes) else null;
            if (optionalSliceEql(binding_prefix, prefix)) {
                return binding.namespace_uri.slice(parser.namespace_bytes);
            }
        }

        return null;
    }

    fn isNamespaceDeclaration(parser: *Parser, name: NameParts) bool {
        if (name.prefix) |prefix| {
            return std.mem.eql(u8, prefix.slice(parser.token_buffer), "xmlns");
        }
        return std.mem.eql(u8, name.local_name.slice(parser.token_buffer), "xmlns");
    }

    fn appendNamespaceBinding(parser: *Parser, name: NameParts, value: []const u8) ParseError!void {
        if (parser.namespace_count >= parser.namespace_storage.len) return error.TooManyNamespaces;

        const prefix = if (name.prefix) |_| name.local_name.slice(parser.token_buffer) else null;
        const prefix_range = if (prefix) |prefix_bytes|
            try parser.appendNamespaceBytes(prefix_bytes)
        else
            null;
        const uri_range = try parser.appendNamespaceBytes(value);

        parser.namespace_storage[parser.namespace_count] = .{
            .prefix = prefix_range,
            .namespace_uri = uri_range,
        };
        parser.namespace_count += 1;
    }

    fn pushElementFrame(
        parser: *Parser,
        name: QName,
        namespace_count_before: usize,
        namespace_bytes_before: usize,
        synthetic_end_byte_offset: ?u64,
    ) ParseError!void {
        if (parser.element_count >= parser.element_storage.len) return error.ElementNestingTooDeep;

        const element_bytes_before = parser.element_bytes_len;
        const prefix_range = if (name.prefix) |prefix|
            try parser.appendElementBytes(prefix)
        else
            null;
        const local_name_range = try parser.appendElementBytes(name.local_name);
        const namespace_uri_range = if (name.namespace_uri) |namespace_uri|
            try parser.appendElementBytes(namespace_uri)
        else
            null;

        parser.element_storage[parser.element_count] = .{
            .namespace_count_before = namespace_count_before,
            .namespace_bytes_before = namespace_bytes_before,
            .element_bytes_before = element_bytes_before,
            .prefix = prefix_range,
            .local_name = local_name_range,
            .namespace_uri = namespace_uri_range,
            .synthetic_end_byte_offset = synthetic_end_byte_offset,
        };
        parser.element_count += 1;
    }

    fn frameMatches(parser: *Parser, frame: ElementFrame, actual_name: NameParts) bool {
        const expected_prefix = if (frame.prefix) |range| range.slice(parser.element_bytes) else null;
        const actual_prefix = if (actual_name.prefix) |range| range.slice(parser.token_buffer) else null;
        if (!optionalSliceEql(expected_prefix, actual_prefix)) return false;
        return std.mem.eql(u8, frame.local_name.slice(parser.element_bytes), actual_name.local_name.slice(parser.token_buffer));
    }

    fn materializeFrameName(parser: *Parser, frame: ElementFrame) ParseError!QName {
        parser.resetEventStorage();

        const prefix = if (frame.prefix) |range|
            try parser.copyIntoToken(range.slice(parser.element_bytes))
        else
            null;
        const local_name = try parser.copyIntoToken(frame.local_name.slice(parser.element_bytes));
        const namespace_uri = if (frame.namespace_uri) |range|
            try parser.copyIntoToken(range.slice(parser.element_bytes))
        else
            null;

        return .{
            .prefix = prefix,
            .local_name = local_name,
            .namespace_uri = namespace_uri,
        };
    }

    fn popElementFrame(parser: *Parser) void {
        const frame = parser.topElementFrame();
        parser.element_count -= 1;
        parser.namespace_count = frame.namespace_count_before;
        parser.namespace_bytes_len = frame.namespace_bytes_before;
        parser.element_bytes_len = frame.element_bytes_before;
    }

    fn topElementFrame(parser: *Parser) ElementFrame {
        return parser.element_storage[parser.element_count - 1];
    }

    fn appendDecodedTextByte(parser: *Parser, byte: u8) ParseError!void {
        if (byte == '&') {
            try parser.decodeEntityReference();
            return;
        }
        try parser.appendTokenByte(byte);
    }

    fn decodeEntityReference(parser: *Parser) ParseError!void {
        var entity_buffer: [16]u8 = undefined;
        var entity_len: usize = 0;

        while (true) {
            const byte = try parser.takeRequiredByte();
            if (byte == ';') break;
            if (entity_len >= entity_buffer.len) return error.UnknownEntity;
            entity_buffer[entity_len] = byte;
            entity_len += 1;
        }

        const entity = entity_buffer[0..entity_len];
        if (std.mem.eql(u8, entity, "amp")) return parser.appendTokenByte('&');
        if (std.mem.eql(u8, entity, "lt")) return parser.appendTokenByte('<');
        if (std.mem.eql(u8, entity, "gt")) return parser.appendTokenByte('>');
        if (std.mem.eql(u8, entity, "apos")) return parser.appendTokenByte('\'');
        if (std.mem.eql(u8, entity, "quot")) return parser.appendTokenByte('"');

        if (entity.len >= 2 and entity[0] == '#') {
            const codepoint = try parseCharacterReference(entity[1..]);
            var utf8_buffer: [4]u8 = undefined;
            const utf8_len = std.unicode.utf8Encode(codepoint, &utf8_buffer) catch return error.InvalidCharacterReference;
            try parser.appendTokenSlice(utf8_buffer[0..utf8_len]);
            return;
        }

        return error.UnknownEntity;
    }

    fn appendTokenByte(parser: *Parser, byte: u8) ParseError!void {
        if (parser.token_len >= parser.token_buffer.len) return error.TokenTooLong;
        parser.token_buffer[parser.token_len] = byte;
        parser.token_len += 1;
    }

    fn appendTokenSlice(parser: *Parser, bytes: []const u8) ParseError!void {
        if (parser.token_len + bytes.len > parser.token_buffer.len) return error.TokenTooLong;
        @memcpy(parser.token_buffer[parser.token_len..][0..bytes.len], bytes);
        parser.token_len += bytes.len;
    }

    fn copyIntoToken(parser: *Parser, bytes: []const u8) ParseError![]const u8 {
        const start = parser.token_len;
        try parser.appendTokenSlice(bytes);
        return parser.token_buffer[start..parser.token_len];
    }

    fn appendNamespaceBytes(parser: *Parser, bytes: []const u8) ParseError!Range {
        if (parser.namespace_bytes_len + bytes.len > parser.namespace_bytes.len) return error.NamespaceStorageExceeded;
        const start = parser.namespace_bytes_len;
        @memcpy(parser.namespace_bytes[start..][0..bytes.len], bytes);
        parser.namespace_bytes_len += bytes.len;
        return .{ .start = start, .len = bytes.len };
    }

    fn appendElementBytes(parser: *Parser, bytes: []const u8) ParseError!Range {
        if (parser.element_bytes_len + bytes.len > parser.element_bytes.len) return error.ElementStorageExceeded;
        const start = parser.element_bytes_len;
        @memcpy(parser.element_bytes[start..][0..bytes.len], bytes);
        parser.element_bytes_len += bytes.len;
        return .{ .start = start, .len = bytes.len };
    }

    fn currentToken(parser: *Parser) []const u8 {
        return parser.token_buffer[0..parser.token_len];
    }

    fn resetEventStorage(parser: *Parser) void {
        parser.token_len = 0;
        parser.attribute_count = 0;
    }

    fn skipWhitespace(parser: *Parser) ParseError!void {
        while (try parser.peekOptionalByte()) |byte| {
            if (!std.ascii.isWhitespace(byte)) break;
            _ = try parser.takeRequiredByte();
        }
    }

    fn expectByte(parser: *Parser, expected: u8) ParseError!void {
        const actual = try parser.takeRequiredByte();
        if (actual != expected) return error.MalformedXml;
    }

    fn expectBytes(parser: *Parser, expected: []const u8) ParseError!void {
        for (expected) |byte| try parser.expectByte(byte);
    }

    fn peekRequiredByte(parser: *Parser) ParseError!u8 {
        return (try parser.peekOptionalByte()) orelse error.UnexpectedEof;
    }

    fn takeRequiredByte(parser: *Parser) ParseError!u8 {
        return (try parser.takeOptionalByte()) orelse error.UnexpectedEof;
    }

    fn peekOptionalByte(parser: *Parser) ParseError!?u8 {
        if (parser.lookahead) |byte| return byte;

        const byte = parser.reader.takeByte() catch |err| switch (err) {
            error.EndOfStream => return null,
            error.ReadFailed => return error.ReadFailed,
        };
        parser.lookahead = byte;
        parser.lookahead_offset = parser.absolute_offset;
        parser.last_byte_offset = parser.absolute_offset;
        parser.absolute_offset += 1;
        return byte;
    }

    fn takeOptionalByte(parser: *Parser) ParseError!?u8 {
        if (parser.lookahead) |byte| {
            parser.lookahead = null;
            parser.last_byte_offset = parser.lookahead_offset;
            return byte;
        }

        const byte = parser.reader.takeByte() catch |err| switch (err) {
            error.EndOfStream => return null,
            error.ReadFailed => return error.ReadFailed,
        };
        parser.last_byte_offset = parser.absolute_offset;
        parser.absolute_offset += 1;
        return byte;
    }
};

// --- Helpers ---

fn optionalSliceEql(left: ?[]const u8, right: ?[]const u8) bool {
    if (left) |left_bytes| {
        if (right) |right_bytes| {
            return std.mem.eql(u8, left_bytes, right_bytes);
        }
        return false;
    }
    return right == null;
}

fn isNameTerminator(byte: u8) bool {
    return std.ascii.isWhitespace(byte) or switch (byte) {
        '/', '>', '=', '?', '"', '\'' => true,
        else => false,
    };
}

fn parseCharacterReference(bytes: []const u8) ParseError!u21 {
    if (bytes.len == 0) return error.InvalidCharacterReference;

    var base: u8 = 10;
    var digits = bytes;
    if (bytes.len >= 2 and bytes[0] == 'x') {
        base = 16;
        digits = bytes[1..];
    }
    if (digits.len == 0) return error.InvalidCharacterReference;

    var value: u32 = 0;
    for (digits) |byte| {
        const digit: u8 = switch (byte) {
            '0'...'9' => byte - '0',
            'a'...'f' => if (base == 16) byte - 'a' + 10 else return error.InvalidCharacterReference,
            'A'...'F' => if (base == 16) byte - 'A' + 10 else return error.InvalidCharacterReference,
            else => return error.InvalidCharacterReference,
        };
        value = value * base + digit;
        if (value > std.math.maxInt(u21)) return error.InvalidCharacterReference;
    }

    return @intCast(value);
}

// --- Tests: inline smoke ---

test "parser emits elements text attributes and namespaces" {
    const xml =
        "<?xml version=\"1.0\"?>" ++
        "<mzML xmlns=\"urn:psi:ms:mzml\">" ++
        "<run id=\"main\">hello &amp; goodbye</run>" ++
        "</mzML>";

    // Arrange.
    var harness: InlineParserHarness = undefined;
    harness.init(xml);

    // Act and assert.
    const event_1 = (try harness.parser.next()).?.start_element;
    try std.testing.expect(event_1.name.matches("urn:psi:ms:mzml", "mzML"));
    try std.testing.expectEqual(@as(usize, 1), event_1.attributes.len);
    try std.testing.expect(event_1.attributes[0].is_namespace_declaration);

    const event_2 = (try harness.parser.next()).?.start_element;
    try std.testing.expect(event_2.name.matches("urn:psi:ms:mzml", "run"));
    try std.testing.expectEqualStrings("main", event_2.attributes[0].value);

    const event_3 = (try harness.parser.next()).?.text;
    try std.testing.expectEqualStrings("hello & goodbye", event_3.value);
    try std.testing.expect(!event_3.from_cdata);

    const event_4 = (try harness.parser.next()).?.end_element;
    try std.testing.expect(event_4.name.matches("urn:psi:ms:mzml", "run"));

    const event_5 = (try harness.parser.next()).?.end_element;
    try std.testing.expect(event_5.name.matches("urn:psi:ms:mzml", "mzML"));

    const terminal = try harness.parser.next();
    try std.testing.expectEqual(@as(?Event, null), terminal);
}

test "parser skips comments and processing instructions and emits cdata as text" {
    const xml =
        "<root><?ignored test?><child/><!--comment--><![CDATA[a<b>]]></root>";

    // Arrange.
    var harness: InlineParserHarness = undefined;
    harness.init(xml);

    // Act and assert.
    _ = (try harness.parser.next()).?.start_element;
    const child_start = (try harness.parser.next()).?.start_element;
    try std.testing.expect(child_start.self_closing);

    const child_end = (try harness.parser.next()).?.end_element;
    try std.testing.expect(child_end.name.matches(null, "child"));

    const text = (try harness.parser.next()).?.text;
    try std.testing.expect(text.from_cdata);
    try std.testing.expectEqualStrings("a<b>", text.value);

    const root_end = (try harness.parser.next()).?.end_element;
    try std.testing.expect(root_end.name.matches(null, "root"));

    const terminal = try harness.parser.next();
    try std.testing.expectEqual(@as(?Event, null), terminal);
}

test "parser skips whitespace-only text between elements" {
    const xml =
        "<root>\n" ++
        "  <child/>\n" ++
        "</root>";

    var harness: InlineParserHarness = undefined;
    harness.init(xml);

    const root_start = (try harness.parser.next()).?.start_element;
    try std.testing.expect(root_start.name.matches(null, "root"));

    const child_start = (try harness.parser.next()).?.start_element;
    try std.testing.expect(child_start.name.matches(null, "child"));
    try std.testing.expect(child_start.self_closing);

    const child_end = (try harness.parser.next()).?.end_element;
    try std.testing.expect(child_end.name.matches(null, "child"));

    const root_end = (try harness.parser.next()).?.end_element;
    try std.testing.expect(root_end.name.matches(null, "root"));

    try std.testing.expectEqual(@as(?Event, null), try harness.parser.next());
}

test "parser resolves prefixed attributes without applying the default namespace" {
    const xml =
        "<doc xmlns=\"urn:default\" xmlns:ms=\"urn:ms\" ms:scan=\"7\" plain=\"ok\"/>";

    // Arrange.
    var harness: InlineParserHarness = undefined;
    harness.init(xml);

    // Act and assert.
    const event = (try harness.parser.next()).?.start_element;
    try std.testing.expect(event.name.matches("urn:default", "doc"));
    try std.testing.expectEqual(@as(usize, 4), event.attributes.len);
    try std.testing.expectEqual(@as(?[]const u8, null), event.attributes[3].name.namespace_uri);
    try std.testing.expectEqualStrings("urn:ms", event.attributes[2].name.namespace_uri.?);

    const terminal_end = (try harness.parser.next()).?.end_element;
    try std.testing.expect(terminal_end.name.matches("urn:default", "doc"));

    const terminal = try harness.parser.next();
    try std.testing.expectEqual(@as(?Event, null), terminal);
}

test "parser rejects invalid utf8 text" {
    const xml = "<root>\xc0</root>";

    // Arrange.
    var harness: InlineParserHarness = undefined;
    harness.init(xml);

    // Act.
    _ = (try harness.parser.next()).?.start_element;

    // Assert.
    try std.testing.expectError(error.InvalidUtf8, harness.parser.next());
}

test "parser rejects mismatched end tags" {
    const xml = "<root><child></root>";

    // Arrange.
    var harness: InlineParserHarness = undefined;
    harness.init(xml);

    // Act.
    _ = (try harness.parser.next()).?.start_element;
    _ = (try harness.parser.next()).?.start_element;

    // Assert.
    try std.testing.expectError(error.MismatchedEndTag, harness.parser.next());
}

test "parser repeated clean inline parses keep event count stable" {
    const xml =
        "<?xml version=\"1.0\"?>" ++
        "<mzML xmlns=\"urn:psi:ms:mzml\"><run id=\"main\">hello &amp; goodbye</run></mzML>";

    // Arrange.

    // Act.
    for (0..32) |_| {
        var harness: InlineParserHarness = undefined;
        harness.init(xml);
        var event_count: usize = 0;
        while (try harness.parser.next()) |_| {
            event_count += 1;
        }

        // Assert.
        try std.testing.expectEqual(@as(usize, 5), event_count);
    }
}

// --- Tests: limit pressure ---

test "parser accepts text token at exact buffer boundary" {
    const xml = "<root>abcdefghijklmnop</root>";

    // Arrange.
    var reader = std.Io.Reader.fixed(xml);
    var token_buffer: [16]u8 = undefined;
    var attributes: [4]Attribute = undefined;
    var namespace_bindings: [4]NamespaceBinding = undefined;
    var namespace_bytes: [64]u8 = undefined;
    var element_stack: [4]ElementFrame = undefined;
    var element_bytes: [64]u8 = undefined;
    var parser = Parser.init(&reader, .{
        .token = &token_buffer,
        .attributes = &attributes,
        .namespace_bindings = &namespace_bindings,
        .namespace_bytes = &namespace_bytes,
        .element_stack = &element_stack,
        .element_bytes = &element_bytes,
    });

    // Act and assert.
    _ = (try parser.next()).?.start_element;
    const text = (try parser.next()).?.text;
    try std.testing.expectEqualStrings("abcdefghijklmnop", text.value);
    _ = (try parser.next()).?.end_element;
    try std.testing.expectEqual(@as(?Event, null), try parser.next());
}

test "parser rejects text token that exceeds buffer boundary by one byte" {
    const xml = "<root>abcdefghijklmnopq</root>";

    // Arrange.
    var reader = std.Io.Reader.fixed(xml);
    var token_buffer: [16]u8 = undefined;
    var attributes: [4]Attribute = undefined;
    var namespace_bindings: [4]NamespaceBinding = undefined;
    var namespace_bytes: [64]u8 = undefined;
    var element_stack: [4]ElementFrame = undefined;
    var element_bytes: [64]u8 = undefined;
    var parser = Parser.init(&reader, .{
        .token = &token_buffer,
        .attributes = &attributes,
        .namespace_bindings = &namespace_bindings,
        .namespace_bytes = &namespace_bytes,
        .element_stack = &element_stack,
        .element_bytes = &element_bytes,
    });

    // Act.
    _ = (try parser.next()).?.start_element;

    // Assert.
    try std.testing.expectError(error.TokenTooLong, parser.next());
}

test "parser accepts exact attribute count and rejects one more" {
    const exact_xml = "<root a=\"1\" b=\"2\"/>";
    const overflow_xml = "<root a=\"1\" b=\"2\" c=\"3\"/>";

    // Arrange.
    var exact_reader = std.Io.Reader.fixed(exact_xml);
    var token_buffer: [128]u8 = undefined;
    var exact_attributes: [2]Attribute = undefined;
    var exact_namespace_bindings: [4]NamespaceBinding = undefined;
    var exact_namespace_bytes: [64]u8 = undefined;
    var exact_element_stack: [4]ElementFrame = undefined;
    var exact_element_bytes: [64]u8 = undefined;
    var exact_parser = Parser.init(&exact_reader, .{
        .token = &token_buffer,
        .attributes = &exact_attributes,
        .namespace_bindings = &exact_namespace_bindings,
        .namespace_bytes = &exact_namespace_bytes,
        .element_stack = &exact_element_stack,
        .element_bytes = &exact_element_bytes,
    });

    // Act and assert.
    const exact_start = (try exact_parser.next()).?.start_element;
    try std.testing.expectEqual(@as(usize, 2), exact_start.attributes.len);
    _ = (try exact_parser.next()).?.end_element;
    try std.testing.expectEqual(@as(?Event, null), try exact_parser.next());

    var overflow_reader = std.Io.Reader.fixed(overflow_xml);
    var overflow_attributes: [2]Attribute = undefined;
    var overflow_namespace_bindings: [4]NamespaceBinding = undefined;
    var overflow_namespace_bytes: [64]u8 = undefined;
    var overflow_element_stack: [4]ElementFrame = undefined;
    var overflow_element_bytes: [64]u8 = undefined;
    var overflow_parser = Parser.init(&overflow_reader, .{
        .token = &token_buffer,
        .attributes = &overflow_attributes,
        .namespace_bindings = &overflow_namespace_bindings,
        .namespace_bytes = &overflow_namespace_bytes,
        .element_stack = &overflow_element_stack,
        .element_bytes = &overflow_element_bytes,
    });
    try std.testing.expectError(error.TooManyAttributes, overflow_parser.next());
}

test "parser accepts exact namespace binding capacity and rejects one more" {
    const exact_xml = "<root xmlns:a=\"urn:a\" xmlns:b=\"urn:b\" a:x=\"1\" b:y=\"2\"/>";
    const overflow_xml = "<root xmlns:a=\"urn:a\" xmlns:b=\"urn:b\" xmlns:c=\"urn:c\" a:x=\"1\"/>";

    // Arrange.
    var exact_reader = std.Io.Reader.fixed(exact_xml);
    var token_buffer: [256]u8 = undefined;
    var exact_attributes: [6]Attribute = undefined;
    var exact_namespace_bindings: [2]NamespaceBinding = undefined;
    var exact_namespace_bytes: [64]u8 = undefined;
    var exact_element_stack: [4]ElementFrame = undefined;
    var exact_element_bytes: [64]u8 = undefined;
    var exact_parser = Parser.init(&exact_reader, .{
        .token = &token_buffer,
        .attributes = &exact_attributes,
        .namespace_bindings = &exact_namespace_bindings,
        .namespace_bytes = &exact_namespace_bytes,
        .element_stack = &exact_element_stack,
        .element_bytes = &exact_element_bytes,
    });

    // Act and assert.
    const exact_start = (try exact_parser.next()).?.start_element;
    try std.testing.expect(exact_start.name.matches(null, "root"));
    _ = (try exact_parser.next()).?.end_element;
    try std.testing.expectEqual(@as(?Event, null), try exact_parser.next());

    var overflow_reader = std.Io.Reader.fixed(overflow_xml);
    var overflow_attributes: [6]Attribute = undefined;
    var overflow_namespace_bindings: [2]NamespaceBinding = undefined;
    var overflow_namespace_bytes: [64]u8 = undefined;
    var overflow_element_stack: [4]ElementFrame = undefined;
    var overflow_element_bytes: [64]u8 = undefined;
    var overflow_parser = Parser.init(&overflow_reader, .{
        .token = &token_buffer,
        .attributes = &overflow_attributes,
        .namespace_bindings = &overflow_namespace_bindings,
        .namespace_bytes = &overflow_namespace_bytes,
        .element_stack = &overflow_element_stack,
        .element_bytes = &overflow_element_bytes,
    });
    try std.testing.expectError(error.TooManyNamespaces, overflow_parser.next());
}

test "parser accepts exact namespace byte capacity and rejects overflow" {
    const exact_xml = "<root xmlns=\"12345678\"/>";
    const overflow_xml = "<root xmlns=\"123456789\"/>";

    // Arrange.
    var exact_reader = std.Io.Reader.fixed(exact_xml);
    var token_buffer: [128]u8 = undefined;
    var exact_attributes: [2]Attribute = undefined;
    var exact_namespace_bindings: [2]NamespaceBinding = undefined;
    var exact_namespace_bytes: [8]u8 = undefined;
    var exact_element_stack: [4]ElementFrame = undefined;
    var exact_element_bytes: [64]u8 = undefined;
    var exact_parser = Parser.init(&exact_reader, .{
        .token = &token_buffer,
        .attributes = &exact_attributes,
        .namespace_bindings = &exact_namespace_bindings,
        .namespace_bytes = &exact_namespace_bytes,
        .element_stack = &exact_element_stack,
        .element_bytes = &exact_element_bytes,
    });

    // Act and assert.
    const exact_start = (try exact_parser.next()).?.start_element;
    try std.testing.expect(exact_start.name.matches("12345678", "root"));
    _ = (try exact_parser.next()).?.end_element;
    try std.testing.expectEqual(@as(?Event, null), try exact_parser.next());

    var overflow_reader = std.Io.Reader.fixed(overflow_xml);
    var overflow_attributes: [2]Attribute = undefined;
    var overflow_namespace_bindings: [2]NamespaceBinding = undefined;
    var overflow_namespace_bytes: [8]u8 = undefined;
    var overflow_element_stack: [4]ElementFrame = undefined;
    var overflow_element_bytes: [64]u8 = undefined;
    var overflow_parser = Parser.init(&overflow_reader, .{
        .token = &token_buffer,
        .attributes = &overflow_attributes,
        .namespace_bindings = &overflow_namespace_bindings,
        .namespace_bytes = &overflow_namespace_bytes,
        .element_stack = &overflow_element_stack,
        .element_bytes = &overflow_element_bytes,
    });
    try std.testing.expectError(error.NamespaceStorageExceeded, overflow_parser.next());
}

test "parser accepts exact element nesting depth and rejects one more" {
    const exact_xml = "<a><b/></a>";
    const overflow_xml = "<a><b/></a>";

    // Arrange.
    var exact_reader = std.Io.Reader.fixed(exact_xml);
    var token_buffer: [128]u8 = undefined;
    var exact_attributes: [2]Attribute = undefined;
    var exact_namespace_bindings: [2]NamespaceBinding = undefined;
    var exact_namespace_bytes: [32]u8 = undefined;
    var exact_element_stack: [2]ElementFrame = undefined;
    var exact_element_bytes: [32]u8 = undefined;
    var exact_parser = Parser.init(&exact_reader, .{
        .token = &token_buffer,
        .attributes = &exact_attributes,
        .namespace_bindings = &exact_namespace_bindings,
        .namespace_bytes = &exact_namespace_bytes,
        .element_stack = &exact_element_stack,
        .element_bytes = &exact_element_bytes,
    });

    // Act and assert.
    _ = (try exact_parser.next()).?.start_element;
    const child = (try exact_parser.next()).?.start_element;
    try std.testing.expect(child.self_closing);
    _ = (try exact_parser.next()).?.end_element;
    _ = (try exact_parser.next()).?.end_element;
    try std.testing.expectEqual(@as(?Event, null), try exact_parser.next());

    var overflow_reader = std.Io.Reader.fixed(overflow_xml);
    var overflow_attributes: [2]Attribute = undefined;
    var overflow_namespace_bindings: [2]NamespaceBinding = undefined;
    var overflow_namespace_bytes: [32]u8 = undefined;
    var overflow_element_stack: [1]ElementFrame = undefined;
    var overflow_element_bytes: [32]u8 = undefined;
    var overflow_parser = Parser.init(&overflow_reader, .{
        .token = &token_buffer,
        .attributes = &overflow_attributes,
        .namespace_bindings = &overflow_namespace_bindings,
        .namespace_bytes = &overflow_namespace_bytes,
        .element_stack = &overflow_element_stack,
        .element_bytes = &overflow_element_bytes,
    });
    _ = (try overflow_parser.next()).?.start_element;
    try std.testing.expectError(error.ElementNestingTooDeep, overflow_parser.next());
}

test "parser accepts exact element name storage and rejects overflow" {
    const exact_xml = "<abcdefgh></abcdefgh>";
    const overflow_xml = "<abcdefghi></abcdefghi>";

    // Arrange.
    var exact_reader = std.Io.Reader.fixed(exact_xml);
    var token_buffer: [128]u8 = undefined;
    var exact_attributes: [2]Attribute = undefined;
    var exact_namespace_bindings: [2]NamespaceBinding = undefined;
    var exact_namespace_bytes: [32]u8 = undefined;
    var exact_element_stack: [2]ElementFrame = undefined;
    var exact_element_bytes: [8]u8 = undefined;
    var exact_parser = Parser.init(&exact_reader, .{
        .token = &token_buffer,
        .attributes = &exact_attributes,
        .namespace_bindings = &exact_namespace_bindings,
        .namespace_bytes = &exact_namespace_bytes,
        .element_stack = &exact_element_stack,
        .element_bytes = &exact_element_bytes,
    });

    // Act and assert.
    const exact_start = (try exact_parser.next()).?.start_element;
    try std.testing.expect(exact_start.name.matches(null, "abcdefgh"));
    const exact_end = (try exact_parser.next()).?.end_element;
    try std.testing.expect(exact_end.name.matches(null, "abcdefgh"));
    try std.testing.expectEqual(@as(?Event, null), try exact_parser.next());

    var overflow_reader = std.Io.Reader.fixed(overflow_xml);
    var overflow_attributes: [2]Attribute = undefined;
    var overflow_namespace_bindings: [2]NamespaceBinding = undefined;
    var overflow_namespace_bytes: [32]u8 = undefined;
    var overflow_element_stack: [2]ElementFrame = undefined;
    var overflow_element_bytes: [8]u8 = undefined;
    var overflow_parser = Parser.init(&overflow_reader, .{
        .token = &token_buffer,
        .attributes = &overflow_attributes,
        .namespace_bindings = &overflow_namespace_bindings,
        .namespace_bytes = &overflow_namespace_bytes,
        .element_stack = &overflow_element_stack,
        .element_bytes = &overflow_element_bytes,
    });
    try std.testing.expectError(error.ElementStorageExceeded, overflow_parser.next());
}

test "parser repeats boundary failures without changing error kind" {
    const xml = "<root>abcdefghijklmnopq</root>";

    // Arrange.

    // Act.
    for (0..32) |_| {
        var reader = std.Io.Reader.fixed(xml);
        var token_buffer: [16]u8 = undefined;
        var attributes: [4]Attribute = undefined;
        var namespace_bindings: [4]NamespaceBinding = undefined;
        var namespace_bytes: [64]u8 = undefined;
        var element_stack: [4]ElementFrame = undefined;
        var element_bytes: [64]u8 = undefined;
        var parser = Parser.init(&reader, .{
            .token = &token_buffer,
            .attributes = &attributes,
            .namespace_bindings = &namespace_bindings,
            .namespace_bytes = &namespace_bytes,
            .element_stack = &element_stack,
            .element_bytes = &element_bytes,
        });

        _ = (try parser.next()).?.start_element;

        // Assert.
        try std.testing.expectError(error.TokenTooLong, parser.next());
    }
}

// --- Tests: fixture corpus ---

test "xml10 declaration fixture asserts root child and text behavior" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/xml/valid/xml10-declaration-basic.xml", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var reader = std.Io.Reader.fixed(fixture);
    const token_capacity = @max(@as(usize, 1024), fixture.len);
    const token_buffer = try allocator.alloc(u8, token_capacity);
    defer allocator.free(token_buffer);
    var attributes: [16]Attribute = undefined;
    var namespace_bindings: [16]NamespaceBinding = undefined;
    var namespace_bytes: [512]u8 = undefined;
    var element_stack: [32]ElementFrame = undefined;
    var element_bytes: [512]u8 = undefined;

    var parser = Parser.init(&reader, .{
        .token = token_buffer,
        .attributes = &attributes,
        .namespace_bindings = &namespace_bindings,
        .namespace_bytes = &namespace_bytes,
        .element_stack = &element_stack,
        .element_bytes = &element_bytes,
    });

    const root = (try nextSignificantEvent(&parser)).?.start_element;
    try std.testing.expect(root.name.matches("urn:mzvalidate:test", "root"));
    try std.testing.expectEqual(@as(usize, 1), root.attributes.len);
    try std.testing.expect(root.attributes[0].is_namespace_declaration);

    const child = (try nextSignificantEvent(&parser)).?.start_element;
    try std.testing.expect(child.name.matches("urn:mzvalidate:test", "child"));
    try std.testing.expectEqual(@as(usize, 1), child.attributes.len);
    try std.testing.expectEqualStrings("attr", child.attributes[0].name.local_name);
    try std.testing.expectEqual(@as(?[]const u8, null), child.attributes[0].name.namespace_uri);
    try std.testing.expectEqualStrings("value", child.attributes[0].value);

    const text = (try nextSignificantEvent(&parser)).?.text;
    try std.testing.expectEqualStrings("plain-text", text.value);
    try std.testing.expect(!text.from_cdata);

    const child_end = (try nextSignificantEvent(&parser)).?.end_element;
    try std.testing.expect(child_end.name.matches("urn:mzvalidate:test", "child"));
    const root_end = (try nextSignificantEvent(&parser)).?.end_element;
    try std.testing.expect(root_end.name.matches("urn:mzvalidate:test", "root"));
    try std.testing.expectEqual(@as(?Event, null), try nextSignificantEvent(&parser));
}

test "xml11 declaration fixture asserts pi skipping and cdata text behavior" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/xml/valid/xml11-declaration-basic.xml", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var reader = std.Io.Reader.fixed(fixture);
    const token_capacity = @max(@as(usize, 1024), fixture.len);
    const token_buffer = try allocator.alloc(u8, token_capacity);
    defer allocator.free(token_buffer);
    var attributes: [16]Attribute = undefined;
    var namespace_bindings: [16]NamespaceBinding = undefined;
    var namespace_bytes: [512]u8 = undefined;
    var element_stack: [32]ElementFrame = undefined;
    var element_bytes: [512]u8 = undefined;

    var parser = Parser.init(&reader, .{
        .token = token_buffer,
        .attributes = &attributes,
        .namespace_bindings = &namespace_bindings,
        .namespace_bytes = &namespace_bytes,
        .element_stack = &element_stack,
        .element_bytes = &element_bytes,
    });

    const root = (try nextSignificantEvent(&parser)).?.start_element;
    try std.testing.expect(root.name.matches(null, "root"));

    const child = (try nextSignificantEvent(&parser)).?.start_element;
    try std.testing.expect(child.name.matches(null, "child"));

    const text = (try nextSignificantEvent(&parser)).?.text;
    try std.testing.expect(text.from_cdata);
    try std.testing.expectEqualStrings("a<b>", text.value);

    const child_end = (try nextSignificantEvent(&parser)).?.end_element;
    try std.testing.expect(child_end.name.matches(null, "child"));
    const root_end = (try nextSignificantEvent(&parser)).?.end_element;
    try std.testing.expect(root_end.name.matches(null, "root"));
    try std.testing.expectEqual(@as(?Event, null), try nextSignificantEvent(&parser));
}

test "w3c prolog corpus fixture asserts declaration comment pi and namespaced child flow" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/xml/corpus/w3c-versioned-prolog.xml", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var reader = std.Io.Reader.fixed(fixture);
    const token_capacity = @max(@as(usize, 1024), fixture.len);
    const token_buffer = try allocator.alloc(u8, token_capacity);
    defer allocator.free(token_buffer);
    var attributes: [16]Attribute = undefined;
    var namespace_bindings: [16]NamespaceBinding = undefined;
    var namespace_bytes: [512]u8 = undefined;
    var element_stack: [32]ElementFrame = undefined;
    var element_bytes: [512]u8 = undefined;

    var parser = Parser.init(&reader, .{
        .token = token_buffer,
        .attributes = &attributes,
        .namespace_bindings = &namespace_bindings,
        .namespace_bytes = &namespace_bytes,
        .element_stack = &element_stack,
        .element_bytes = &element_bytes,
    });

    const root = (try nextSignificantEvent(&parser)).?.start_element;
    try std.testing.expect(root.name.matches(null, "root"));
    try std.testing.expectEqual(@as(usize, 1), root.attributes.len);
    try std.testing.expect(root.attributes[0].is_namespace_declaration);

    const child = (try nextSignificantEvent(&parser)).?.start_element;
    try std.testing.expect(child.self_closing);
    try std.testing.expect(child.name.matches("urn:w3c-prolog", "child"));
    const child_end = (try nextSignificantEvent(&parser)).?.end_element;
    try std.testing.expect(child_end.name.matches("urn:w3c-prolog", "child"));
    const root_end = (try nextSignificantEvent(&parser)).?.end_element;
    try std.testing.expect(root_end.name.matches(null, "root"));
    try std.testing.expectEqual(@as(?Event, null), try nextSignificantEvent(&parser));
}

test "libxml2 namespace rebinding corpus fixture asserts nested namespace resolution" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/xml/corpus/libxml2-namespace-rebind.xml", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var reader = std.Io.Reader.fixed(fixture);
    const token_capacity = @max(@as(usize, 1024), fixture.len);
    const token_buffer = try allocator.alloc(u8, token_capacity);
    defer allocator.free(token_buffer);
    var attributes: [16]Attribute = undefined;
    var namespace_bindings: [16]NamespaceBinding = undefined;
    var namespace_bytes: [512]u8 = undefined;
    var element_stack: [32]ElementFrame = undefined;
    var element_bytes: [512]u8 = undefined;

    var parser = Parser.init(&reader, .{
        .token = token_buffer,
        .attributes = &attributes,
        .namespace_bindings = &namespace_bindings,
        .namespace_bytes = &namespace_bytes,
        .element_stack = &element_stack,
        .element_bytes = &element_bytes,
    });

    const root = (try nextSignificantEvent(&parser)).?.start_element;
    try std.testing.expect(root.name.matches("urn:outer", "root"));

    const branch = (try nextSignificantEvent(&parser)).?.start_element;
    try std.testing.expect(branch.name.matches("urn:inner", "branch"));

    const first_leaf = (try nextSignificantEvent(&parser)).?.start_element;
    try std.testing.expect(first_leaf.self_closing);
    try std.testing.expect(first_leaf.name.matches("urn:a1", "leaf"));
    try std.testing.expectEqual(@as(usize, 1), first_leaf.attributes.len);
    try std.testing.expectEqualStrings("id", first_leaf.attributes[0].name.local_name);
    try std.testing.expectEqualStrings("urn:a1", first_leaf.attributes[0].name.namespace_uri.?);
    try std.testing.expectEqualStrings("one", first_leaf.attributes[0].value);
    const first_leaf_end = (try nextSignificantEvent(&parser)).?.end_element;
    try std.testing.expect(first_leaf_end.name.matches("urn:a1", "leaf"));

    const branch_end = (try nextSignificantEvent(&parser)).?.end_element;
    try std.testing.expect(branch_end.name.matches("urn:inner", "branch"));

    const second_leaf = (try nextSignificantEvent(&parser)).?.start_element;
    try std.testing.expect(second_leaf.self_closing);
    try std.testing.expect(second_leaf.name.matches("urn:a2", "leaf"));
    try std.testing.expectEqual(@as(usize, 2), second_leaf.attributes.len);
    try std.testing.expect(second_leaf.attributes[0].is_namespace_declaration);
    try std.testing.expectEqualStrings("id", second_leaf.attributes[1].name.local_name);
    try std.testing.expectEqualStrings("urn:a2", second_leaf.attributes[1].name.namespace_uri.?);
    try std.testing.expectEqualStrings("two", second_leaf.attributes[1].value);
    const second_leaf_end = (try nextSignificantEvent(&parser)).?.end_element;
    try std.testing.expect(second_leaf_end.name.matches("urn:a2", "leaf"));

    const root_end = (try nextSignificantEvent(&parser)).?.end_element;
    try std.testing.expect(root_end.name.matches("urn:outer", "root"));
    try std.testing.expectEqual(@as(?Event, null), try nextSignificantEvent(&parser));
}

test "nested default prefix corpus fixture asserts nested namespaced text flow" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/xml/corpus/nested-default-prefix.xml", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var parser = try initFixtureParser(allocator, fixture);
    defer parser.deinit(allocator);

    const feed = (try nextSignificantEvent(&parser.parser)).?.start_element;
    try std.testing.expect(feed.name.matches("urn:feed", "feed"));
    const entry = (try nextSignificantEvent(&parser.parser)).?.start_element;
    try std.testing.expect(entry.name.matches("urn:feed", "entry"));
    const item = (try nextSignificantEvent(&parser.parser)).?.start_element;
    try std.testing.expect(item.name.matches("urn:a", "item"));
    const value = (try nextSignificantEvent(&parser.parser)).?.start_element;
    try std.testing.expect(value.name.matches("urn:b", "value"));
    try std.testing.expectEqualStrings("42", value.attributes[0].value);
    const text = (try nextSignificantEvent(&parser.parser)).?.text;
    try std.testing.expectEqualStrings("ok", text.value);
    try std.testing.expectEqual(@as(usize, 9), try countRemainingSignificantEvents(&parser.parser, 5));
}

test "self closing mixed corpus fixture asserts self closing nested and text flow" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/xml/corpus/self-closing-mixed.xml", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var parser = try initFixtureParser(allocator, fixture);
    defer parser.deinit(allocator);

    const root = (try nextSignificantEvent(&parser.parser)).?.start_element;
    try std.testing.expect(root.name.matches(null, "root"));
    const empty = (try nextSignificantEvent(&parser.parser)).?.start_element;
    try std.testing.expect(empty.self_closing);
    try std.testing.expect(empty.name.matches(null, "empty"));
    const empty_end = (try nextSignificantEvent(&parser.parser)).?.end_element;
    try std.testing.expect(empty_end.name.matches(null, "empty"));
    const parent = (try nextSignificantEvent(&parser.parser)).?.start_element;
    try std.testing.expect(parent.name.matches(null, "parent"));
    const nested = (try nextSignificantEvent(&parser.parser)).?.start_element;
    try std.testing.expect(nested.self_closing);
    try std.testing.expectEqualStrings("yes", nested.attributes[0].value);
    const nested_end = (try nextSignificantEvent(&parser.parser)).?.end_element;
    try std.testing.expect(nested_end.name.matches(null, "nested"));
    const text = (try nextSignificantEvent(&parser.parser)).?.text;
    try std.testing.expectEqualStrings("text", std.mem.trim(u8, text.value, &std.ascii.whitespace));
    try std.testing.expectEqual(@as(usize, 9), try countRemainingSignificantEvents(&parser.parser, 7));
}

test "processing instruction and tail corpus fixture asserts child and cdata tail flow" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/xml/corpus/processing-instruction-and-tail.xml", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var parser = try initFixtureParser(allocator, fixture);
    defer parser.deinit(allocator);

    const root = (try nextSignificantEvent(&parser.parser)).?.start_element;
    try std.testing.expect(root.name.matches(null, "root"));
    const child = (try nextSignificantEvent(&parser.parser)).?.start_element;
    try std.testing.expect(child.name.matches(null, "child"));
    const child_text = (try nextSignificantEvent(&parser.parser)).?.text;
    try std.testing.expectEqualStrings("value", child_text.value);
    const child_end = (try nextSignificantEvent(&parser.parser)).?.end_element;
    try std.testing.expect(child_end.name.matches(null, "child"));
    const tail = (try nextSignificantEvent(&parser.parser)).?.start_element;
    try std.testing.expect(tail.name.matches(null, "tail"));
    const tail_text = (try nextSignificantEvent(&parser.parser)).?.text;
    try std.testing.expect(tail_text.from_cdata);
    try std.testing.expectEqualStrings("done", tail_text.value);
    try std.testing.expectEqual(@as(usize, 8), try countRemainingSignificantEvents(&parser.parser, 6));
}

test "mzdata corpus fixture reaches second spectrum and drains cleanly" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/xml/corpus/mzdata/tiny1.mzData1.05.xml", allocator, .limited(512 * 1024));
    defer allocator.free(fixture);

    var parser = try initFixtureParser(allocator, fixture);
    defer parser.deinit(allocator);

    const root = (try nextSignificantEvent(&parser.parser)).?.start_element;
    try std.testing.expect(root.name.matches(null, "mzData"));

    var spectrum_count: usize = 0;
    while (try nextSignificantEvent(&parser.parser)) |event| {
        switch (event) {
            .start_element => |start| {
                if (start.name.matches(null, "spectrum")) {
                    spectrum_count += 1;
                }
            },
            else => {},
        }
    }

    try std.testing.expect(spectrum_count >= 2);
}

test "namespace misuse fixture fails immediately with malformed xml" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/xml/invalid/namespace-empty-prefix-declaration.xml", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var reader = std.Io.Reader.fixed(fixture);
    const token_capacity = @max(@as(usize, 1024), fixture.len);
    const token_buffer = try allocator.alloc(u8, token_capacity);
    defer allocator.free(token_buffer);
    var attributes: [16]Attribute = undefined;
    var namespace_bindings: [16]NamespaceBinding = undefined;
    var namespace_bytes: [512]u8 = undefined;
    var element_stack: [32]ElementFrame = undefined;
    var element_bytes: [512]u8 = undefined;

    var parser = Parser.init(&reader, .{
        .token = token_buffer,
        .attributes = &attributes,
        .namespace_bindings = &namespace_bindings,
        .namespace_bytes = &namespace_bytes,
        .element_stack = &element_stack,
        .element_bytes = &element_bytes,
    });

    try std.testing.expectError(error.MalformedXml, parser.next());
}

test "malformed processing instruction fixture fails before emitting any event" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/xml/invalid/malformed-processing-instruction.xml", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var reader = std.Io.Reader.fixed(fixture);
    const token_capacity = @max(@as(usize, 1024), fixture.len);
    const token_buffer = try allocator.alloc(u8, token_capacity);
    defer allocator.free(token_buffer);
    var attributes: [16]Attribute = undefined;
    var namespace_bindings: [16]NamespaceBinding = undefined;
    var namespace_bytes: [512]u8 = undefined;
    var element_stack: [32]ElementFrame = undefined;
    var element_bytes: [512]u8 = undefined;

    var parser = Parser.init(&reader, .{
        .token = token_buffer,
        .attributes = &attributes,
        .namespace_bindings = &namespace_bindings,
        .namespace_bytes = &namespace_bytes,
        .element_stack = &element_stack,
        .element_bytes = &element_bytes,
    });

    try std.testing.expectError(error.UnexpectedEof, parser.next());
}

// --- Tests: fixture sweep ---

test "parser accepts valid xml fixtures" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    try expectFixtureParses(allocator, io, "fixtures/xml/valid/namespaces-and-entities.xml");
    try expectFixtureParses(allocator, io, "fixtures/xml/valid/comments-cdata.xml");
    try expectFixtureParses(allocator, io, "fixtures/xml/valid/xml10-declaration-basic.xml");
    try expectFixtureParses(allocator, io, "fixtures/xml/valid/xml11-declaration-basic.xml");
}

test "parser rejects invalid xml fixtures" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    try expectFixtureError(allocator, io, "fixtures/xml/invalid/mismatched-end-tag.xml", error.MismatchedEndTag);
    try expectFixtureError(allocator, io, "fixtures/xml/invalid/unknown-entity.xml", error.UnknownEntity);
    try expectFixtureError(allocator, io, "fixtures/xml/invalid/unsupported-doctype.xml", error.UnsupportedMarkup);
    try expectFixtureError(allocator, io, "fixtures/xml/invalid/namespace-empty-prefix-declaration.xml", error.MalformedXml);
    try expectFixtureError(allocator, io, "fixtures/xml/invalid/malformed-processing-instruction.xml", error.UnexpectedEof);
    try expectFixtureError(allocator, io, "fixtures/xml/invalid/xml11-unclosed-declaration.xml", error.UnexpectedEof);
}

test "parser handles xml corpus fixtures" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    try expectFixtureParses(allocator, io, "fixtures/xml/corpus/nested-default-prefix.xml");
    try expectFixtureParses(allocator, io, "fixtures/xml/corpus/self-closing-mixed.xml");
    try expectFixtureParses(allocator, io, "fixtures/xml/corpus/processing-instruction-and-tail.xml");
    try expectFixtureParses(allocator, io, "fixtures/xml/corpus/w3c-versioned-prolog.xml");
    try expectFixtureParses(allocator, io, "fixtures/xml/corpus/libxml2-namespace-rebind.xml");
    try expectFixtureParses(allocator, io, "fixtures/xml/corpus/mzdata/tiny1.mzData1.05.xml");
}

// --- Test helpers ---

const InlineParserHarness = struct {
    reader: std.Io.Reader,
    token_buffer: [512]u8 = undefined,
    attributes: [8]Attribute = undefined,
    namespace_bindings: [8]NamespaceBinding = undefined,
    namespace_bytes: [256]u8 = undefined,
    element_stack: [8]ElementFrame = undefined,
    element_bytes: [256]u8 = undefined,
    parser: Parser = undefined,

    fn init(harness: *InlineParserHarness, xml: []const u8) void {
        harness.reader = std.Io.Reader.fixed(xml);
        harness.parser = Parser.init(&harness.reader, .{
            .token = &harness.token_buffer,
            .attributes = &harness.attributes,
            .namespace_bindings = &harness.namespace_bindings,
            .namespace_bytes = &harness.namespace_bytes,
            .element_stack = &harness.element_stack,
            .element_bytes = &harness.element_bytes,
        });
    }
};

fn expectFixtureParses(allocator: std.mem.Allocator, io: std.Io, sub_path: []const u8) !void {
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, sub_path, allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var parser = try initFixtureParser(allocator, fixture);
    defer parser.deinit(allocator);

    var event_count: usize = 0;
    var significant_event_count: usize = 0;
    var start_count: usize = 0;
    var end_count: usize = 0;
    while (try parser.parser.next()) |event| {
        event_count += 1;
        switch (event) {
            .start_element => start_count += 1,
            .end_element => end_count += 1,
            .text => |text| {
                if (!isWhitespaceOnly(text.value)) significant_event_count += 1;
                continue;
            },
        }
        significant_event_count += 1;
    }
    try std.testing.expect(event_count > 0);
    try std.testing.expect(significant_event_count > 0);
    try std.testing.expect(start_count > 0);
    try std.testing.expectEqual(start_count, end_count);
}

fn nextSignificantEvent(parser: *Parser) ParseError!?Event {
    while (try parser.next()) |event| {
        switch (event) {
            .text => |text| {
                if (isWhitespaceOnly(text.value)) continue;
                return event;
            },
            else => return event,
        }
    }

    return null;
}

fn countRemainingSignificantEvents(parser: *Parser, already_seen: usize) !usize {
    var count = already_seen;
    while (try nextSignificantEvent(parser)) |_| {
        count += 1;
    }
    return count;
}

fn isWhitespaceOnly(bytes: []const u8) bool {
    for (bytes) |byte| {
        switch (byte) {
            ' ', '\t', '\n', '\r' => {},
            else => return false,
        }
    }

    return true;
}

fn expectFixtureError(allocator: std.mem.Allocator, io: std.Io, sub_path: []const u8, expected: anyerror) !void {
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, sub_path, allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var parser = try initFixtureParser(allocator, fixture);
    defer parser.deinit(allocator);

    while (true) {
        const maybe_event = parser.parser.next() catch |err| {
            try std.testing.expectEqual(expected, err);
            return;
        };
        if (maybe_event == null) break;
    }

    return error.TestExpectedError;
}

const FixtureParser = struct {
    reader: std.Io.Reader,
    token_buffer: []u8,
    attributes: [16]Attribute = undefined,
    namespace_bindings: [16]NamespaceBinding = undefined,
    namespace_bytes: [512]u8 = undefined,
    element_stack: [32]ElementFrame = undefined,
    element_bytes: [512]u8 = undefined,
    parser: Parser = undefined,

    fn deinit(fixture_parser: *FixtureParser, allocator: std.mem.Allocator) void {
        allocator.free(fixture_parser.token_buffer);
    }
};

fn initFixtureParser(allocator: std.mem.Allocator, fixture: []const u8) !FixtureParser {
    var fixture_parser: FixtureParser = .{
        .reader = std.Io.Reader.fixed(fixture),
        .token_buffer = try allocator.alloc(u8, @max(@as(usize, 1024), fixture.len)),
    };
    fixture_parser.parser = Parser.init(&fixture_parser.reader, .{
        .token = fixture_parser.token_buffer,
        .attributes = &fixture_parser.attributes,
        .namespace_bindings = &fixture_parser.namespace_bindings,
        .namespace_bytes = &fixture_parser.namespace_bytes,
        .element_stack = &fixture_parser.element_stack,
        .element_bytes = &fixture_parser.element_bytes,
    });
    return fixture_parser;
}
