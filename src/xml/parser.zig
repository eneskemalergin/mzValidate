//! Bounded pull parser for XML input.
//!
//! Emits borrowed events from reader or contiguous-slice input in one pass.
//! Caller-supplied buffers bound token, attribute, namespace, and nesting state;
//! DTDs and user-defined entities are rejected without external access.

const std = @import("std");
const elements = @import("../mzml/elements.zig");
const characters = @import("characters.zig");
const events = @import("events.zig");
const scan = @import("scan.zig");

const Attribute = events.Attribute;
const EndElement = events.EndElement;
const Event = events.Event;
const QName = events.QName;
const StartElement = events.StartElement;
const Text = events.Text;

pub const ParseError = error{
    UnexpectedEof,
    MalformedXml,
    InvalidUtf8,
    TokenTooLong,
    StartTagTooLong,
    AttributeTooLong,
    ScalarTextTooLong,
    BinaryTextTooLong,
    TooManyAttributes,
    TooManyNamespaces,
    NamespaceStorageExceeded,
    ElementNestingTooDeep,
    ElementStorageExceeded,
    UnknownEntity,
    InvalidCharacterReference,
    InvalidXmlCharacter,
    UnsupportedXmlVersion,
    UnsupportedMarkup,
    MismatchedEndTag,
} || error{ReadFailed};

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
    element_id: elements.ElementId = .unknown,
    synthetic_end_byte_offset: ?u64 = null,
};

/// Caller-owned scratch for one parser event. Size for worst-case token and nesting depth.
pub const Buffers = struct {
    token: []u8,
    attributes: []Attribute,
    namespace_bindings: []NamespaceBinding,
    namespace_bytes: []u8,
    element_stack: []ElementFrame,
    element_bytes: []u8,
    limits: Limits = .{},
};

pub const Limits = struct {
    max_start_tag_bytes: usize = 1024 * 1024,
    max_attribute_bytes: usize = 64 * 1024,
    max_scalar_text_bytes: usize = 64 * 1024,
    max_binary_text_bytes: usize = 256 * 1024 * 1024,
};

/// Reader-backed or mmap slice input for `Parser`.
pub const Input = union(enum) {
    reader: *std.Io.Reader,
    slice: SliceInput,
};

/// Streaming pull parser. Emits borrowed events; call `next()` until `null`.
pub const Parser = struct {
    input: Input,
    token_buffer: []u8,
    attribute_storage: []Attribute,
    namespace_storage: []NamespaceBinding,
    namespace_bytes: []u8,
    element_storage: []ElementFrame,
    element_bytes: []u8,
    limits: Limits,

    token_len: usize = 0,
    attribute_count: usize = 0,
    namespace_count: usize = 0,
    namespace_bytes_len: usize = 0,
    element_count: usize = 0,
    element_bytes_len: usize = 0,

    xml_version: characters.Version = .xml_1_0,
    xml_declaration_allowed: bool = true,
    literal_validator: characters.LiteralValidator = .{},

    lookahead: ?u8 = null,
    lookahead_offset: u64 = 0,
    absolute_offset: u64 = 0,
    last_byte_offset: u64 = 0,
    pending_self_closing_end: bool = false,
    text_state: ?TextState = null,
    text_bytes: usize = 0,
    plain_text_brackets: u2 = 0,
    attribute_token_start: ?usize = null,
    start_tag_offset: ?u64 = null,
    // True once the UTF-8 BOM (if any) has been checked and skipped.
    bom_checked: bool = false,
    // Bytes replayed after a partial UTF-8 BOM prefix (0xEF without 0xBB 0xBF).
    pending: [2]u8 = undefined,
    pending_offset: [2]u64 = undefined,
    pending_len: u8 = 0,
    pending_pos: u8 = 0,

    /// Constructs a parser from a reader and caller-supplied buffers.
    ///
    /// All buffers are borrowed. Size them for worst-case document depth and
    /// attribute counts before calling `next` in a loop.
    pub fn init(reader: *std.Io.Reader, buffers: Buffers) Parser {
        return .{
            .input = .{ .reader = reader },
            .token_buffer = buffers.token,
            .attribute_storage = buffers.attributes,
            .namespace_storage = buffers.namespace_bindings,
            .namespace_bytes = buffers.namespace_bytes,
            .element_storage = buffers.element_stack,
            .element_bytes = buffers.element_bytes,
            .limits = buffers.limits,
        };
    }

    /// Like `init`, but reads directly from a contiguous byte slice with no
    /// `std.Io.Reader` per-byte overhead. Used for mmap'd mzML files.
    pub fn initSlice(bytes: []const u8, buffers: Buffers) Parser {
        return .{
            .input = .{ .slice = .{ .bytes = bytes, .pos = 0 } },
            .token_buffer = buffers.token,
            .attribute_storage = buffers.attributes,
            .namespace_storage = buffers.namespace_bindings,
            .namespace_bytes = buffers.namespace_bytes,
            .element_storage = buffers.element_stack,
            .element_bytes = buffers.element_bytes,
            .limits = buffers.limits,
        };
    }

    /// Returns the next event, `null` at EOF, or a parse error.
    pub fn next(parser: *Parser) ParseError!?Event {
        if (parser.pending_self_closing_end) {
            return try parser.emitSyntheticEnd();
        }

        if (!parser.bom_checked) {
            parser.bom_checked = true;
            try parser.skipBom();
        }

        while (true) {
            parser.resetEventStorage();

            if (parser.text_state != null) {
                if (try parser.continueText()) |event| return event;
                continue;
            }

            const first_byte = (try parser.takeOptionalByte()) orelse {
                if (parser.element_count != 0) {
                    @branchHint(.cold);
                    return error.UnexpectedEof;
                }
                return null;
            };
            const start_offset = parser.last_byte_offset;

            if (first_byte != '<') {
                parser.xml_declaration_allowed = false;
                if (try parser.parseText(start_offset, first_byte, false)) |event| {
                    return event;
                }
                continue;
            }

            const markup = try parser.takeRequiredByte();
            switch (markup) {
                '/' => return try parser.parseEndElement(start_offset),
                '?' => {
                    @branchHint(.cold);
                    try parser.skipProcessingInstruction();
                    continue;
                },
                '!' => {
                    @branchHint(.cold);
                    parser.xml_declaration_allowed = false;
                    if (try parser.handleBangMarkup(start_offset)) |event| return event;
                    continue;
                },
                else => {
                    parser.xml_declaration_allowed = false;
                    return try parser.parseStartElement(start_offset, markup);
                },
            }
        }
    }

    /// Useful for diagnostics: byte offset of the last consumed byte.
    pub fn byteOffset(parser: *const Parser) u64 {
        return parser.last_byte_offset;
    }

    fn textField(parser: *const Parser, from_cdata: bool) LimitField {
        if (!from_cdata and parser.element_count > 0 and parser.topElementFrame().element_id == .binary) {
            return .binary_text;
        }
        return .scalar_text;
    }

    fn limitForField(parser: *const Parser, field: LimitField) usize {
        return switch (field) {
            .start_tag => parser.limits.max_start_tag_bytes,
            .attribute => parser.limits.max_attribute_bytes,
            .scalar_text => parser.limits.max_scalar_text_bytes,
            .binary_text => parser.limits.max_binary_text_bytes,
        };
    }

    fn errorForField(field: LimitField) ParseError {
        return switch (field) {
            .start_tag => error.StartTagTooLong,
            .attribute => error.AttributeTooLong,
            .scalar_text => error.ScalarTextTooLong,
            .binary_text => error.BinaryTextTooLong,
        };
    }

    fn ensureTokenAppend(parser: *const Parser, field: LimitField, bytes: usize) ParseError!void {
        const current = switch (field) {
            .attribute => parser.token_len - (parser.attribute_token_start orelse parser.token_len),
            .scalar_text, .binary_text => std.math.add(usize, parser.text_bytes, parser.token_len) catch return errorForField(field),
            .start_tag => 0,
        };
        const total = std.math.add(usize, current, bytes) catch return errorForField(field);
        if (total > parser.limitForField(field)) return errorForField(field);
        if (parser.token_len > parser.token_buffer.len or bytes > parser.token_buffer.len - parser.token_len) {
            return errorForField(field);
        }
    }

    fn ensureStartTagLimit(parser: *const Parser, extra: usize) ParseError!void {
        const start = parser.start_tag_offset orelse return;
        const consumed = std.math.sub(u64, parser.absolute_offset, start) catch return error.StartTagTooLong;
        const current = std.math.add(u64, consumed, @intCast(extra)) catch return error.StartTagTooLong;
        if (current > parser.limits.max_start_tag_bytes) return error.StartTagTooLong;
    }

    fn parseText(parser: *Parser, byte_offset: u64, first_byte: u8, from_cdata: bool) ParseError!?Event {
        const field = parser.textField(from_cdata);
        parser.literal_validator.reset();
        parser.plain_text_brackets = 0;
        if (parser.lookahead == null and parser.input == .slice and first_byte != '&') {
            const slice = &parser.input.slice;
            const start = slice.pos - 1;
            const tail = slice.bytes[slice.pos..];
            const plain_len = scan.textPlainRunLen(tail);
            if (plain_len == tail.len or tail[plain_len] != '&') {
                const value_len = std.math.add(usize, plain_len, 1) catch return errorForField(field);
                const value = slice.bytes[start..][0..value_len];
                const limit = parser.limitForField(field);
                const limit_failure: ?usize = if (value_len > limit) limit else null;
                const literal_failure = characters.firstLiteralFailure(value, parser.xml_version);
                if (!from_cdata) {
                    if (std.mem.indexOf(u8, value, "]]>")) |close_start| {
                        const close_offset = close_start + 2;
                        const before_literal = literal_failure == null or close_offset < literal_failure.?.index;
                        const before_limit = limit_failure == null or close_offset <= limit_failure.?;
                        if (before_literal and before_limit) {
                            parser.consumeSliceBytes(close_offset);
                            return error.MalformedXml;
                        }
                    }
                }
                if (literal_failure) |failure| {
                    if (limit_failure == null or failure.index <= limit_failure.?) {
                        return parser.sliceLiteralError(failure, 1);
                    }
                }
                if (limit_failure) |failure_index| {
                    if (failure_index >= 1) parser.consumeSliceBytes(failure_index);
                    return errorForField(field);
                }
                parser.consumeSliceBytes(plain_len);
                if (!from_cdata and isWhitespaceOnly(value)) return null;
                return .{ .text = .{
                    .byte_offset = byte_offset,
                    .value = value,
                    .from_cdata = from_cdata,
                } };
            }
        }

        if (parser.input == .reader) {
            if (parser.token_buffer.len <= 4) return errorForField(field);
            parser.text_state = .{
                .byte_offset = byte_offset,
                .from_cdata = from_cdata,
            };
            parser.text_bytes = 0;
            try parser.appendDecodedTextByte(first_byte, field);
            return try parser.continueText();
        }

        parser.text_bytes = 0;
        try parser.appendDecodedTextByte(first_byte, field);

        try parser.consumeSliceTextPlainRun(field);

        while (true) {
            const next_byte = try parser.peekOptionalByte();
            if (next_byte == null or next_byte.? == '<') break;
            _ = try parser.takeRequiredByte();
            try parser.appendDecodedTextByte(next_byte.?, field);
        }

        const value = parser.currentToken();
        try finishLiteral(&parser.literal_validator);
        if (!from_cdata and isWhitespaceOnly(value)) return null;
        parser.plain_text_brackets = 0;

        return .{ .text = .{
            .byte_offset = byte_offset,
            .value = value,
            .from_cdata = from_cdata,
        } };
    }

    fn continueText(parser: *Parser) ParseError!?Event {
        if (parser.text_state.?.from_cdata) return @as(?Event, try parser.continueCdata());
        const field = parser.textField(false);

        while (true) {
            const state = &parser.text_state.?;
            const next_byte = try parser.peekOptionalByte();
            if (next_byte == null or next_byte.? == '<') {
                try finishLiteral(&parser.literal_validator);
                if (!state.saw_non_whitespace and isWhitespaceOnly(parser.currentToken())) {
                    try parser.ensureTokenAppend(field, 0);
                    parser.text_state = null;
                    parser.token_len = 0;
                    parser.text_bytes = 0;
                    parser.plain_text_brackets = 0;
                    return null;
                }
                return try parser.emitTextChunk(true);
            }

            if (parser.token_len >= parser.textChunkCapacity()) {
                if (std.unicode.utf8ValidateSlice(parser.currentToken())) {
                    if (!state.saw_non_whitespace) {
                        if (!isWhitespaceOnly(parser.currentToken())) state.saw_non_whitespace = true;
                    }
                    return try parser.emitTextChunk(false);
                }
                if (parser.token_len >= parser.token_buffer.len) return error.InvalidUtf8;
            }

            _ = try parser.takeRequiredByte();
            try parser.appendDecodedTextByte(next_byte.?, field);
        }
    }

    fn continueCdata(parser: *Parser) ParseError!Event {
        const field = LimitField.scalar_text;
        while (true) {
            const state = &parser.text_state.?;
            const byte = try parser.peekOptionalByte() orelse return error.UnexpectedEof;
            switch (state.cdata_brackets) {
                0 => {
                    if (parser.token_len >= parser.textChunkCapacity() and byte != ']') {
                        if (!std.unicode.utf8ValidateSlice(parser.currentToken())) return error.InvalidUtf8;
                        return try parser.emitTextChunk(false);
                    }
                    _ = try parser.takeRequiredByte();
                    if (byte == ']') {
                        state.cdata_brackets = 1;
                    } else {
                        try parser.appendCdataByte(byte, field);
                    }
                },
                1 => {
                    if (byte == ']') {
                        _ = try parser.takeRequiredByte();
                        state.cdata_brackets = 2;
                    } else {
                        if (parser.token_len > parser.token_buffer.len or 2 > parser.token_buffer.len - parser.token_len) {
                            if (!std.unicode.utf8ValidateSlice(parser.currentToken())) return error.InvalidUtf8;
                            return try parser.emitTextChunk(false);
                        }
                        _ = try parser.takeRequiredByte();
                        try parser.appendCdataByte(']', field);
                        state.cdata_brackets = 0;
                        try parser.appendCdataByte(byte, field);
                    }
                },
                2 => {
                    if (byte == '>') {
                        _ = try parser.takeRequiredByte();
                        state.cdata_brackets = 0;
                        return try parser.emitTextChunk(true);
                    }
                    const required = if (byte == ']') @as(usize, 2) else 3;
                    if (parser.token_len > parser.token_buffer.len or required > parser.token_buffer.len - parser.token_len) {
                        if (!std.unicode.utf8ValidateSlice(parser.currentToken())) return error.InvalidUtf8;
                        return try parser.emitTextChunk(false);
                    }
                    _ = try parser.takeRequiredByte();
                    try parser.appendCdataByte(']', field);
                    try parser.appendCdataByte(']', field);
                    if (byte == ']') {
                        state.cdata_brackets = 1;
                    } else {
                        state.cdata_brackets = 0;
                        try parser.appendCdataByte(byte, field);
                    }
                },
                else => return error.MalformedXml,
            }
        }
    }

    fn emitTextChunk(parser: *Parser, is_final: bool) ParseError!Event {
        const state = parser.text_state orelse return error.MalformedXml;
        const value = parser.currentToken();
        try finishLiteral(&parser.literal_validator);
        const field = if (state.from_cdata) LimitField.scalar_text else parser.textField(false);
        const total = std.math.add(usize, parser.text_bytes, value.len) catch return errorForField(field);
        if (total > parser.limitForField(field)) return errorForField(field);
        if (is_final) {
            parser.text_state = null;
            parser.text_bytes = 0;
            parser.plain_text_brackets = 0;
        } else {
            parser.text_bytes = total;
        }
        return .{ .text = .{
            .byte_offset = state.byte_offset,
            .value = value,
            .from_cdata = state.from_cdata,
            .is_final = is_final,
        } };
    }

    fn textChunkCapacity(parser: *const Parser) usize {
        return parser.token_buffer.len - 4;
    }

    fn parseStartElement(parser: *Parser, byte_offset: u64, first_name_byte: u8) ParseError!Event {
        parser.start_tag_offset = byte_offset;
        defer parser.start_tag_offset = null;

        const namespace_count_before = parser.namespace_count;
        const namespace_bytes_before = parser.namespace_bytes_len;

        const name_parts = try parser.parseName(first_name_byte, .start_tag);
        const local_name = name_parts.local_name.slice(parser.token_buffer);
        const lazy_attrs = (std.mem.eql(u8, local_name, "cvParam") or
            std.mem.eql(u8, local_name, "userParam")) and parser.input == .slice;

        if (lazy_attrs) {
            const slice = &parser.input.slice;
            const raw_start = if (parser.lookahead != null) slice.pos - 1 else slice.pos;
            const raw_source = slice.bytes[raw_start..];
            const consumed = std.math.sub(u64, parser.absolute_offset, byte_offset) catch return error.StartTagTooLong;
            const remaining = if (consumed >= parser.limits.max_start_tag_bytes)
                0
            else
                parser.limits.max_start_tag_bytes - @as(usize, @intCast(consumed));
            const scan_len = @min(raw_source.len, remaining);
            const tag_info = scan.rawStartTagInfo(raw_source[0..scan_len]) orelse if (raw_source.len > scan_len)
                return error.StartTagTooLong
            else
                null;
            if (tag_info) |info| {
                try parser.ensureStartTagLimit(info.end);
                const raw_tag = raw_source[0..info.end];
                var raw_scanner = scan.RawAttributeScanner.initVersion(raw_tag, parser.xml_version);
                var use_lazy_attributes = true;
                while (raw_scanner.next() catch fallback: {
                    use_lazy_attributes = false;
                    break :fallback null;
                }) |attribute| {
                    if (parser.attribute_count >= parser.attribute_storage.len) return error.TooManyAttributes;
                    const attribute_bytes = std.math.add(usize, attribute.name.len, attribute.value.len) catch return error.AttributeTooLong;
                    if (attribute_bytes > parser.limits.max_attribute_bytes) return error.AttributeTooLong;
                    const name_colon = std.mem.indexOfScalar(u8, attribute.name, ':');
                    const attribute_offset = std.math.add(usize, raw_start, attribute.name_start) catch return error.UnexpectedEof;
                    parser.attribute_storage[parser.attribute_count] = .{
                        .byte_offset = @intCast(attribute_offset),
                        .name = .{
                            .prefix = if (name_colon) |index| attribute.name[0..index] else null,
                            .local_name = attribute.local_name,
                            .namespace_uri = null,
                        },
                        .value = attribute.value,
                        .is_namespace_declaration = attribute.is_namespace_declaration,
                    };
                    parser.attribute_count += 1;
                    if (attribute.has_entity or attribute.is_namespace_declaration) {
                        use_lazy_attributes = false;
                        break;
                    }
                }
                if (use_lazy_attributes) {
                    const raw_end = std.math.add(usize, raw_start, info.end) catch return error.UnexpectedEof;
                    const after_tag = std.math.add(usize, raw_end, 1) catch return error.UnexpectedEof;
                    slice.pos = after_tag;
                    parser.lookahead = null;
                    parser.last_byte_offset = @intCast(raw_end);
                    parser.absolute_offset = @intCast(after_tag);

                    var event = try parser.finishStartElement(
                        byte_offset,
                        name_parts,
                        namespace_count_before,
                        namespace_bytes_before,
                        info.self_closing,
                        if (info.self_closing) @intCast(raw_end) else null,
                    );
                    if (info.self_closing) parser.pending_self_closing_end = true;
                    event.start_element.raw_tag = raw_tag;
                    return event;
                }
                parser.attribute_count = 0;
            }
        }

        while (true) {
            try parser.skipWhitespace();
            try parser.ensureStartTagLimit(0);
            const next_byte = try parser.peekRequiredByte();

            switch (next_byte) {
                '>' => {
                    _ = try parser.takeRequiredByte();
                    try parser.ensureStartTagLimit(0);
                    break;
                },
                '/' => {
                    _ = try parser.takeRequiredByte();
                    try parser.expectByte('>');
                    try parser.ensureStartTagLimit(0);
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
                else => {
                    try parser.parseAttribute();
                    try parser.ensureStartTagLimit(0);
                },
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
        const element_id = elements.idFromParts(name.local_name, name.namespace_uri);
        try parser.pushElementFrame(name, namespace_count_before, namespace_bytes_before, synthetic_end_byte_offset, element_id);

        return .{ .start_element = .{
            .byte_offset = byte_offset,
            .end_byte_offset = parser.last_byte_offset,
            .name = name,
            .element_id = element_id,
            .attributes = parser.attribute_storage[0..parser.attribute_count],
            .self_closing = self_closing,
        } };
    }

    fn parseEndElement(parser: *Parser, byte_offset: u64) ParseError!Event {
        parser.xml_declaration_allowed = false;
        if (parser.element_count == 0) return error.MalformedXml;

        const first_name_byte = try parser.takeRequiredByte();
        const actual_name = try parser.parseName(first_name_byte, .start_tag);
        try parser.skipWhitespace();
        try parser.expectByte('>');

        const frame = parser.topElementFrame();
        if (!parser.frameMatches(frame, actual_name)) return error.MismatchedEndTag;

        const event_name = try parser.materializeFrameName(frame);
        const element_id = frame.element_id;
        parser.popElementFrame();

        return .{ .end_element = .{
            .byte_offset = byte_offset,
            .name = event_name,
            .element_id = element_id,
        } };
    }

    fn parseAttribute(parser: *Parser) ParseError!void {
        if (parser.attribute_count >= parser.attribute_storage.len) return error.TooManyAttributes;

        parser.attribute_token_start = parser.token_len;
        defer parser.attribute_token_start = null;

        const byte = try parser.takeRequiredByte();
        const byte_offset = parser.last_byte_offset;
        const name = try parser.parseName(byte, .attribute);

        try parser.skipWhitespace();
        try parser.expectByte('=');
        try parser.skipWhitespace();

        const quote = try parser.takeRequiredByte();
        if (quote != '"' and quote != '\'') return error.MalformedXml;

        const value_start = parser.token_len;
        parser.literal_validator.reset();
        while (true) {
            try parser.consumeSliceAttrValuePlainRun(quote, .attribute);
            const next_byte = try parser.takeRequiredByte();
            if (next_byte == quote) break;
            try parser.appendDecodedTextByte(next_byte, .attribute);
        }
        const value = parser.token_buffer[value_start..parser.token_len];
        try finishLiteral(&parser.literal_validator);

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
        const element_id = frame.element_id;
        parser.popElementFrame();
        return .{ .end_element = .{
            .byte_offset = byte_offset,
            .name = name,
            .element_id = element_id,
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
        if (parser.lookahead == null and parser.input == .slice) {
            const slice = &parser.input.slice;
            const start = slice.pos;
            const tail = slice.bytes[start..];
            const content_len = scan.cdataContentLen(tail) orelse return error.UnexpectedEof;
            const value = slice.bytes[start..][0..content_len];
            const literal_failure = characters.firstLiteralFailure(value, parser.xml_version);
            if (literal_failure) |failure| {
                if (content_len <= parser.limits.max_scalar_text_bytes or failure.index <= parser.limits.max_scalar_text_bytes) {
                    return parser.sliceLiteralError(failure, 0);
                }
            }
            if (content_len > parser.limits.max_scalar_text_bytes) {
                parser.consumeSliceBytes(parser.limits.max_scalar_text_bytes + 1);
                return error.ScalarTextTooLong;
            }
            const consumed_len = std.math.add(usize, content_len, 3) catch return error.UnexpectedEof;
            parser.consumeSliceBytes(consumed_len);
            return .{ .text = .{
                .byte_offset = byte_offset,
                .value = value,
                .from_cdata = true,
            } };
        }

        if (parser.token_buffer.len <= 4) return error.ScalarTextTooLong;
        parser.text_state = .{
            .byte_offset = byte_offset,
            .from_cdata = true,
        };
        parser.text_bytes = 0;
        parser.literal_validator.reset();
        return try parser.continueCdata();
    }

    fn skipProcessingInstruction(parser: *Parser) ParseError!void {
        parser.token_len = 0;
        defer parser.token_len = 0;
        const content_offset = parser.absolute_offset;

        if (parser.lookahead == null and parser.input == .slice) {
            const slice = &parser.input.slice;
            const tail = slice.bytes[slice.pos..];
            const end = scan.piEndLen(tail) orelse return error.UnexpectedEof;
            if (end > parser.token_buffer.len) return error.TokenTooLong;
            try parser.handleProcessingInstruction(tail[0..end], content_offset);
            const consumed_len = std.math.add(usize, end, 2) catch return error.UnexpectedEof;
            parser.consumeSliceBytes(consumed_len);
            return;
        }
        while (true) {
            const byte = try parser.takeRequiredByte();
            if (byte == '?') {
                if (try parser.peekOptionalByte()) |next_byte| {
                    if (next_byte == '>') {
                        _ = try parser.takeRequiredByte();
                        try parser.handleProcessingInstruction(parser.currentToken(), content_offset);
                        return;
                    }
                } else return error.UnexpectedEof;
            }
            if (parser.token_len >= parser.token_buffer.len) return error.TokenTooLong;
            parser.token_buffer[parser.token_len] = byte;
            parser.token_len += 1;
        }
    }

    fn handleProcessingInstruction(parser: *Parser, content: []const u8, content_offset: u64) ParseError!void {
        const target_end = for (content, 0..) |byte, index| {
            if (characters.isWhitespaceByte(byte)) break index;
        } else content.len;
        const target = content[0..target_end];
        characters.validateName(target) catch |err| {
            parser.last_byte_offset = std.math.add(u64, content_offset, @intCast(target_end)) catch return error.UnexpectedEof;
            return switch (err) {
                error.InvalidUtf8 => error.InvalidUtf8,
                error.InvalidName => error.MalformedXml,
            };
        };

        if (std.ascii.eqlIgnoreCase(target, "xml")) {
            if (!std.mem.eql(u8, target, "xml") or !parser.xml_declaration_allowed) return error.MalformedXml;
            parser.xml_version = parseXmlDeclarationVersion(content) catch |err| {
                parser.last_byte_offset = std.math.add(u64, content_offset, @intCast(content.len)) catch return error.UnexpectedEof;
                return err;
            };
        }
        try parser.validateLiteralAtOffset(content, content_offset);
        parser.xml_declaration_allowed = false;
    }

    fn skipComment(parser: *Parser) ParseError!void {
        if (parser.lookahead == null and parser.input == .slice) {
            const slice = &parser.input.slice;
            const tail = slice.bytes[slice.pos..];
            const end = scan.commentEndLen(tail) orelse return error.UnexpectedEof;
            try parser.validateSliceLiteral(tail[0..end], 0);
            const consumed_len = std.math.add(usize, end, 3) catch return error.UnexpectedEof;
            parser.consumeSliceBytes(consumed_len);
            return;
        }
        var literal_validator: characters.LiteralValidator = .{};
        while (true) {
            const byte = try parser.takeRequiredByte();
            if (byte == '-') {
                if (try parser.peekOptionalByte()) |second| {
                    if (second == '-') {
                        _ = try parser.takeRequiredByte();
                        try parser.expectByte('>');
                        try finishLiteral(&literal_validator);
                        return;
                    }
                } else return error.UnexpectedEof;
            }
            try feedLiteralByte(&literal_validator, byte, parser.xml_version);
        }
    }

    fn parseName(parser: *Parser, first_byte: u8, field: LimitField) ParseError!NameParts {
        const start = parser.token_len;
        try parser.appendTokenByte(first_byte, field);

        try parser.consumeSliceNameCharRun(field);

        while (true) {
            const next_byte = try parser.peekOptionalByte();
            if (next_byte == null or isNameTerminator(next_byte.?)) break;
            if (field == .start_tag) try parser.ensureStartTagLimit(0);
            _ = try parser.takeRequiredByte();
            try parser.appendTokenByte(next_byte.?, field);
        }

        const bytes = parser.token_buffer[start..parser.token_len];
        characters.validateQName(bytes) catch |err| switch (err) {
            error.InvalidUtf8 => return error.InvalidUtf8,
            error.InvalidName => return error.MalformedXml,
        };
        const colon_index = std.mem.indexOfScalar(u8, bytes, ':');

        return if (colon_index) |index|
            .{
                .prefix = .{ .start = start, .len = index },
                .local_name = .{
                    .start = std.math.add(usize, start, std.math.add(usize, index, 1) catch return error.MalformedXml) catch return error.MalformedXml,
                    .len = bytes.len - index - 1,
                },
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
        element_id: elements.ElementId,
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
            .element_id = element_id,
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

    fn topElementFrame(parser: *const Parser) ElementFrame {
        return parser.element_storage[parser.element_count - 1];
    }

    fn appendDecodedTextByte(parser: *Parser, byte: u8, field: LimitField) ParseError!void {
        if (byte == '&') {
            try finishLiteral(&parser.literal_validator);
            parser.plain_text_brackets = 0;
            try parser.decodeEntityReference(field);
            return;
        }
        try parser.appendLiteralTokenByte(byte, field);
    }

    fn appendLiteralTokenByte(parser: *Parser, byte: u8, field: LimitField) ParseError!void {
        if (field == .attribute and byte == '<') return error.InvalidXmlCharacter;
        try feedLiteralByte(&parser.literal_validator, byte, parser.xml_version);
        if (field == .scalar_text or field == .binary_text) try parser.notePlainTextByte(byte);
        try parser.appendTokenByte(byte, field);
    }

    fn appendCdataByte(parser: *Parser, byte: u8, field: LimitField) ParseError!void {
        try feedLiteralByte(&parser.literal_validator, byte, parser.xml_version);
        try parser.appendTokenByte(byte, field);
    }

    fn appendLiteralTokenSlice(parser: *Parser, bytes: []const u8, field: LimitField) ParseError!void {
        for (bytes, 0..) |byte, index| {
            if (field == .attribute and byte == '<') {
                parser.consumeSliceBytes(index + 1);
                return error.InvalidXmlCharacter;
            }
            parser.literal_validator.feedByte(byte, parser.xml_version) catch |err| {
                parser.consumeSliceBytes(index + 1);
                return switch (err) {
                    error.InvalidUtf8 => error.InvalidUtf8,
                    error.InvalidCharacter => error.InvalidXmlCharacter,
                };
            };
            if (field == .scalar_text or field == .binary_text) {
                parser.notePlainTextByte(byte) catch |err| {
                    parser.consumeSliceBytes(index + 1);
                    return err;
                };
            }
            parser.appendTokenByte(byte, field) catch |err| {
                parser.consumeSliceBytes(index + 1);
                return err;
            };
        }
    }

    fn validateSliceLiteral(parser: *Parser, bytes: []const u8, already_consumed: usize) ParseError!void {
        const failure = characters.firstLiteralFailure(bytes, parser.xml_version) orelse return;
        return parser.sliceLiteralError(failure, already_consumed);
    }

    fn sliceLiteralError(parser: *Parser, failure: characters.LiteralFailure, already_consumed: usize) ParseError {
        if (failure.index >= already_consumed) parser.consumeSliceBytes(failure.index - already_consumed + 1);
        return switch (failure.kind) {
            .invalid_utf8 => error.InvalidUtf8,
            .invalid_character => error.InvalidXmlCharacter,
        };
    }

    fn validateLiteralAtOffset(parser: *Parser, bytes: []const u8, byte_offset: u64) ParseError!void {
        const failure = characters.firstLiteralFailure(bytes, parser.xml_version) orelse return;
        parser.last_byte_offset = std.math.add(u64, byte_offset, @intCast(failure.index)) catch return error.UnexpectedEof;
        return switch (failure.kind) {
            .invalid_utf8 => error.InvalidUtf8,
            .invalid_character => error.InvalidXmlCharacter,
        };
    }

    fn notePlainTextByte(parser: *Parser, byte: u8) ParseError!void {
        switch (byte) {
            ']' => if (parser.plain_text_brackets < 2) {
                parser.plain_text_brackets += 1;
            },
            '>' => {
                if (parser.plain_text_brackets == 2) return error.MalformedXml;
                parser.plain_text_brackets = 0;
            },
            else => parser.plain_text_brackets = 0,
        }
    }

    fn decodeEntityReference(parser: *Parser, field: LimitField) ParseError!void {
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
        if (std.mem.eql(u8, entity, "amp")) return parser.appendTokenByte('&', field);
        if (std.mem.eql(u8, entity, "lt")) return parser.appendTokenByte('<', field);
        if (std.mem.eql(u8, entity, "gt")) return parser.appendTokenByte('>', field);
        if (std.mem.eql(u8, entity, "apos")) return parser.appendTokenByte('\'', field);
        if (std.mem.eql(u8, entity, "quot")) return parser.appendTokenByte('"', field);

        if (entity.len >= 2 and entity[0] == '#') {
            const codepoint = try parseCharacterReference(entity[1..], parser.xml_version);
            var utf8_buffer: [4]u8 = undefined;
            const utf8_len = std.unicode.utf8Encode(codepoint, &utf8_buffer) catch return error.InvalidCharacterReference;
            try parser.appendTokenSlice(utf8_buffer[0..utf8_len], field);
            return;
        }

        return error.UnknownEntity;
    }

    fn appendTokenByte(parser: *Parser, byte: u8, field: LimitField) ParseError!void {
        try parser.ensureTokenAppend(field, 1);
        parser.token_buffer[parser.token_len] = byte;
        parser.token_len += 1;
    }

    fn appendTokenSlice(parser: *Parser, bytes: []const u8, field: LimitField) ParseError!void {
        try parser.ensureTokenAppend(field, bytes.len);
        @memcpy(parser.token_buffer[parser.token_len..][0..bytes.len], bytes);
        parser.token_len += bytes.len;
    }

    fn copyIntoToken(parser: *Parser, bytes: []const u8) ParseError![]const u8 {
        const start = parser.token_len;
        try parser.appendTokenSlice(bytes, .start_tag);
        return parser.token_buffer[start..parser.token_len];
    }

    fn appendNamespaceBytes(parser: *Parser, bytes: []const u8) ParseError!Range {
        if (parser.namespace_bytes_len > parser.namespace_bytes.len or bytes.len > parser.namespace_bytes.len - parser.namespace_bytes_len) return error.NamespaceStorageExceeded;
        const start = parser.namespace_bytes_len;
        @memcpy(parser.namespace_bytes[start..][0..bytes.len], bytes);
        parser.namespace_bytes_len += bytes.len;
        return .{ .start = start, .len = bytes.len };
    }

    fn appendElementBytes(parser: *Parser, bytes: []const u8) ParseError!Range {
        if (parser.element_bytes_len > parser.element_bytes.len or bytes.len > parser.element_bytes.len - parser.element_bytes_len) return error.ElementStorageExceeded;
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
        if (parser.lookahead == null) {
            if (parser.consumeSliceWhitespaceRun()) return;
        }

        while (try parser.peekOptionalByte()) |byte| {
            if (!characters.isWhitespaceByte(byte)) break;
            _ = try parser.takeRequiredByte();
        }
    }

    fn sliceTail(parser: *Parser) ?[]const u8 {
        return switch (parser.input) {
            .slice => |*slice| if (slice.pos >= slice.bytes.len) null else slice.bytes[slice.pos..],
            .reader => null,
        };
    }

    fn consumeSliceBytes(parser: *Parser, count: usize) void {
        switch (parser.input) {
            .slice => |*slice| {
                slice.pos += count;
                parser.absolute_offset += @intCast(count);
                if (count > 0) parser.last_byte_offset = parser.absolute_offset - 1;
            },
            .reader => {},
        }
    }

    fn consumeSliceWhitespaceRun(parser: *Parser) bool {
        const tail = parser.sliceTail() orelse return false;
        const run_len = scan.skipWhitespaceRun(tail);
        if (run_len == 0) return false;
        parser.consumeSliceBytes(run_len);
        return true;
    }

    fn consumeSliceNameCharRun(parser: *Parser, field: LimitField) ParseError!void {
        if (parser.lookahead != null) return;
        const tail = parser.sliceTail() orelse return;
        const run_len = scan.nameCharRunLen(tail);
        if (run_len == 0) return;
        if (field == .start_tag) try parser.ensureStartTagLimit(run_len);
        try parser.appendTokenSlice(tail[0..run_len], field);
        parser.consumeSliceBytes(run_len);
    }

    fn consumeSliceTextPlainRun(parser: *Parser, field: LimitField) ParseError!void {
        if (parser.lookahead != null) return;
        const tail = parser.sliceTail() orelse return;
        const run_len = scan.textPlainRunLen(tail);
        if (run_len == 0) return;
        try parser.appendLiteralTokenSlice(tail[0..run_len], field);
        parser.consumeSliceBytes(run_len);
    }

    fn consumeSliceAttrValuePlainRun(parser: *Parser, quote: u8, field: LimitField) ParseError!void {
        if (parser.lookahead != null) return;
        const tail = parser.sliceTail() orelse return;
        const run_len = scan.attrValuePlainRunLen(tail, quote);
        if (run_len == 0) return;
        try parser.appendLiteralTokenSlice(tail[0..run_len], field);
        parser.consumeSliceBytes(run_len);
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

    // UTF-8 BOM: consume EF BB BF when present. A partial EF prefix is replayed
    // through lookahead + pending so no input bytes are dropped.
    fn skipBom(parser: *Parser) ParseError!void {
        const b0 = try parser.peekOptionalByte() orelse return;
        if (b0 != 0xEF) return;
        var tmp: [3]u8 = undefined;
        tmp[0] = try parser.takeRequiredByte();
        tmp[1] = try parser.takeRequiredByte();
        tmp[2] = try parser.takeRequiredByte();
        if (tmp[0] == 0xEF and tmp[1] == 0xBB and tmp[2] == 0xBF) return;
        parser.lookahead = tmp[0];
        parser.lookahead_offset = 0;
        parser.pending[0] = tmp[1];
        parser.pending_offset[0] = 1;
        parser.pending[1] = tmp[2];
        parser.pending_offset[1] = 2;
        parser.pending_len = 2;
        parser.pending_pos = 0;
    }

    inline fn takeRequiredByte(parser: *Parser) ParseError!u8 {
        return (try parser.takeOptionalByte()) orelse error.UnexpectedEof;
    }

    inline fn peekOptionalByte(parser: *Parser) ParseError!?u8 {
        if (parser.lookahead) |byte| return byte;
        if (parser.pending_pos < parser.pending_len) return parser.pending[parser.pending_pos];

        const byte = switch (parser.input) {
            .reader => |reader| reader.takeByte() catch |err| switch (err) {
                error.EndOfStream => return null,
                error.ReadFailed => return error.ReadFailed,
            },
            .slice => |*slice| blk: {
                if (slice.pos >= slice.bytes.len) return null;
                break :blk slice.bytes[slice.pos];
            },
        };
        switch (parser.input) {
            .slice => |*slice| slice.pos += 1,
            .reader => {},
        }
        parser.lookahead = byte;
        parser.lookahead_offset = parser.absolute_offset;
        parser.last_byte_offset = parser.absolute_offset;
        parser.absolute_offset += 1;
        return byte;
    }

    inline fn takeOptionalByte(parser: *Parser) ParseError!?u8 {
        if (parser.lookahead) |byte| {
            parser.lookahead = null;
            parser.last_byte_offset = parser.lookahead_offset;
            return byte;
        }

        if (parser.pending_pos < parser.pending_len) {
            const byte = parser.pending[parser.pending_pos];
            parser.last_byte_offset = parser.pending_offset[parser.pending_pos];
            parser.pending_pos += 1;
            if (parser.pending_pos >= parser.pending_len) {
                parser.pending_len = 0;
                parser.pending_pos = 0;
            }
            return byte;
        }

        const byte = switch (parser.input) {
            .reader => |reader| reader.takeByte() catch |err| switch (err) {
                error.EndOfStream => return null,
                error.ReadFailed => return error.ReadFailed,
            },
            .slice => |*slice| blk: {
                if (slice.pos >= slice.bytes.len) return null;
                const b = slice.bytes[slice.pos];
                slice.pos += 1;
                break :blk b;
            },
        };
        parser.last_byte_offset = parser.absolute_offset;
        parser.absolute_offset += 1;
        return byte;
    }
};

const Range = struct {
    start: usize,
    len: usize,

    fn slice(range: Range, backing: []const u8) []const u8 {
        return backing[range.start..][0..range.len];
    }
};

const NameParts = struct {
    prefix: ?Range,
    local_name: Range,
};

const TextState = struct {
    byte_offset: u64,
    from_cdata: bool,
    cdata_brackets: u2 = 0,
    saw_non_whitespace: bool = false,
};

const LimitField = enum {
    start_tag,
    attribute,
    scalar_text,
    binary_text,
};

const SliceInput = struct {
    bytes: []const u8,
    pos: usize,
};

fn optionalSliceEql(left: ?[]const u8, right: ?[]const u8) bool {
    if (left) |left_bytes| {
        if (right) |right_bytes| {
            return std.mem.eql(u8, left_bytes, right_bytes);
        }
        return false;
    }
    return right == null;
}

fn qnameEql(left: QName, right: QName) bool {
    return optionalSliceEql(left.prefix, right.prefix) and
        std.mem.eql(u8, left.local_name, right.local_name) and
        optionalSliceEql(left.namespace_uri, right.namespace_uri);
}

fn eventsSemanticallyEqual(left: Event, right: Event) bool {
    switch (left) {
        .start_element => |left_start| {
            const right_start = right.start_element;
            if (!qnameEql(left_start.name, right_start.name)) return false;
            if (left_start.byte_offset != right_start.byte_offset) return false;
            if (left_start.end_byte_offset != right_start.end_byte_offset) return false;
            if (left_start.element_id != right_start.element_id) return false;
            if (left_start.self_closing != right_start.self_closing) return false;
            if (left_start.attributes.len != right_start.attributes.len) return false;
            for (left_start.attributes, right_start.attributes) |left_attr, right_attr| {
                if (!qnameEql(left_attr.name, right_attr.name)) return false;
                if (!std.mem.eql(u8, left_attr.value, right_attr.value)) return false;
                if (left_attr.byte_offset != right_attr.byte_offset) return false;
                if (left_attr.is_namespace_declaration != right_attr.is_namespace_declaration) return false;
            }
            return true;
        },
        .end_element => |left_end| {
            const right_end = right.end_element;
            return left_end.byte_offset == right_end.byte_offset and
                left_end.element_id == right_end.element_id and
                qnameEql(left_end.name, right_end.name);
        },
        .text => |left_text| {
            const right_text = right.text;
            return left_text.byte_offset == right_text.byte_offset and
                left_text.from_cdata == right_text.from_cdata and
                left_text.is_final == right_text.is_final and
                std.mem.eql(u8, left_text.value, right_text.value);
        },
    }
}

fn isNameTerminator(byte: u8) bool {
    return characters.isWhitespaceByte(byte) or switch (byte) {
        '/', '>', '=', '?', '"', '\'' => true,
        else => false,
    };
}

fn feedLiteralByte(validator: *characters.LiteralValidator, byte: u8, version: characters.Version) ParseError!void {
    validator.feedByte(byte, version) catch |err| switch (err) {
        error.InvalidUtf8 => return error.InvalidUtf8,
        error.InvalidCharacter => return error.InvalidXmlCharacter,
    };
}

fn finishLiteral(validator: *characters.LiteralValidator) ParseError!void {
    validator.finish() catch |err| switch (err) {
        error.InvalidUtf8 => return error.InvalidUtf8,
        error.InvalidCharacter => return error.InvalidXmlCharacter,
    };
}

fn parseXmlDeclarationVersion(content: []const u8) ParseError!characters.Version {
    var pos: usize = 3;
    if (pos >= content.len or !characters.isWhitespaceByte(content[pos])) return error.MalformedXml;
    while (pos < content.len and characters.isWhitespaceByte(content[pos])) : (pos += 1) {}

    const version_name = "version";
    if (content.len - pos < version_name.len or !std.mem.eql(u8, content[pos..][0..version_name.len], version_name)) {
        return error.MalformedXml;
    }
    pos += version_name.len;
    while (pos < content.len and characters.isWhitespaceByte(content[pos])) : (pos += 1) {}
    if (pos >= content.len or content[pos] != '=') return error.MalformedXml;
    pos += 1;
    while (pos < content.len and characters.isWhitespaceByte(content[pos])) : (pos += 1) {}
    if (pos >= content.len or (content[pos] != '"' and content[pos] != '\'')) return error.MalformedXml;

    const quote = content[pos];
    pos += 1;
    const value_start = pos;
    while (pos < content.len and content[pos] != quote) : (pos += 1) {}
    if (pos >= content.len) return error.MalformedXml;
    const value = content[value_start..pos];

    if (std.mem.eql(u8, value, "1.0")) return .xml_1_0;
    if (std.mem.eql(u8, value, "1.1")) return .xml_1_1;
    return error.UnsupportedXmlVersion;
}

fn parseCharacterReference(bytes: []const u8, version: characters.Version) ParseError!u21 {
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
        value = std.math.mul(u32, value, @as(u32, base)) catch return error.InvalidCharacterReference;
        value = std.math.add(u32, value, @as(u32, digit)) catch return error.InvalidCharacterReference;
        if (value > std.math.maxInt(u21)) return error.InvalidCharacterReference;
    }

    const codepoint: u21 = @intCast(value);
    if (!characters.isReferenceCharacter(codepoint, version)) return error.InvalidCharacterReference;
    return codepoint;
}

const ChunkedReader = struct {
    reader: std.Io.Reader,
    input: []const u8,
    offset: usize,
    chunk_size: usize,
    buffer: [64]u8 = undefined,

    fn init(self: *ChunkedReader, input: []const u8, chunk_size: usize) void {
        self.* = .{
            .reader = undefined,
            .input = input,
            .offset = 0,
            .chunk_size = chunk_size,
        };
        self.reader = .{
            .vtable = &.{ .stream = stream },
            .buffer = &self.buffer,
            .seek = 0,
            .end = 0,
        };
    }

    fn readerPtr(self: *ChunkedReader) *std.Io.Reader {
        return &self.reader;
    }

    fn stream(reader: *std.Io.Reader, writer: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *ChunkedReader = @alignCast(@fieldParentPtr("reader", reader));
        if (self.offset == self.input.len) return error.EndOfStream;
        const available = self.input.len - self.offset;
        const allowed = limit.toInt() orelse available;
        const count = @min(self.chunk_size, @min(available, allowed));
        if (count == 0) return error.EndOfStream;
        try writer.writeAll(self.input[self.offset..][0..count]);
        self.offset += count;
        return count;
    }
};

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
        harness.initWithLimits(xml, .{});
    }

    fn initWithLimits(harness: *InlineParserHarness, xml: []const u8, limits: Limits) void {
        harness.reader = std.Io.Reader.fixed(xml);
        harness.parser = Parser.init(&harness.reader, .{
            .token = &harness.token_buffer,
            .attributes = &harness.attributes,
            .namespace_bindings = &harness.namespace_bindings,
            .namespace_bytes = &harness.namespace_bytes,
            .element_stack = &harness.element_stack,
            .element_bytes = &harness.element_bytes,
            .limits = limits,
        });
    }
};

const InlineSliceParserHarness = struct {
    token_buffer: [512]u8 = undefined,
    attributes: [8]Attribute = undefined,
    namespace_bindings: [8]NamespaceBinding = undefined,
    namespace_bytes: [256]u8 = undefined,
    element_stack: [8]ElementFrame = undefined,
    element_bytes: [256]u8 = undefined,
    parser: Parser = undefined,

    fn init(harness: *InlineSliceParserHarness, xml: []const u8) void {
        harness.initWithLimits(xml, .{});
    }

    fn initWithLimits(harness: *InlineSliceParserHarness, xml: []const u8, limits: Limits) void {
        harness.parser = Parser.initSlice(xml, .{
            .token = &harness.token_buffer,
            .attributes = &harness.attributes,
            .namespace_bindings = &harness.namespace_bindings,
            .namespace_bytes = &harness.namespace_bytes,
            .element_stack = &harness.element_stack,
            .element_bytes = &harness.element_bytes,
            .limits = limits,
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

fn firstParserError(parser: *Parser) ?ParseError {
    while (true) {
        const event = parser.next() catch |err| return err;
        if (event == null) return null;
    }
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
        allocator.destroy(fixture_parser);
    }
};

fn initFixtureParser(allocator: std.mem.Allocator, fixture: []const u8) !*FixtureParser {
    const fixture_parser = try allocator.create(FixtureParser);
    errdefer allocator.destroy(fixture_parser);
    fixture_parser.* = .{
        .reader = std.Io.Reader.fixed(fixture),
        .token_buffer = try allocator.alloc(u8, @max(@as(usize, 1024), fixture.len)),
    };
    errdefer allocator.free(fixture_parser.token_buffer);
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

// --- Unit Tests ---

// --- Inline Smoke ---

test "parser character reference rejects overflow" {
    // Regression: unchecked u32 arithmetic accepted this as codepoint 0.
    try std.testing.expectError(error.InvalidCharacterReference, parseCharacterReference("x20000000", .xml_1_0));
}

test "parser rejects invalid XML names with reader and slice parity" {
    const cases = [_][]const u8{
        "<1root/>",
        "<root><bad$name/></root>",
        "<root 1attr=\"value\"/>",
        "<root bad$name=\"value\"/>",
        "<cvParam bad$name=\"value\"/>",
        "<root><\xCC\x80combining/></root>",
    };

    for (cases) |xml| {
        var reader_harness: InlineParserHarness = undefined;
        reader_harness.init(xml);
        const reader_error = firstParserError(&reader_harness.parser);

        var slice_harness: InlineSliceParserHarness = undefined;
        slice_harness.init(xml);
        const slice_error = firstParserError(&slice_harness.parser);

        try std.testing.expectEqual(@as(?ParseError, error.MalformedXml), reader_error);
        try std.testing.expectEqual(reader_error, slice_error);
        try std.testing.expectEqual(reader_harness.parser.byteOffset(), slice_harness.parser.byteOffset());
    }
}

test "parser accepts XML name production boundaries" {
    const xml = "<\xC3\x80root attr\xC2\xB7name=\"ok\"><\xF0\x90\x80\x80node/></\xC3\x80root>";

    var reader_harness: InlineParserHarness = undefined;
    reader_harness.init(xml);
    const reader_error = firstParserError(&reader_harness.parser);

    var slice_harness: InlineSliceParserHarness = undefined;
    slice_harness.init(xml);
    const slice_error = firstParserError(&slice_harness.parser);

    try std.testing.expectEqual(@as(?ParseError, null), reader_error);
    try std.testing.expectEqual(reader_error, slice_error);
}

test "parser rejects illegal literal XML characters with reader and slice parity" {
    const cases = [_][]const u8{
        "<root>\x01</root>",
        "<root>\xEF\xBF\xBE</root>",
        "<root attr=\"\x01\"/>",
        "<root attr=\"literal < value\"/>",
        "<cvParam unitName=\"\x01\"/>",
        "<cvParam unitName=\"literal < value\"/>",
    };

    for (cases) |xml| {
        var reader_harness: InlineParserHarness = undefined;
        reader_harness.init(xml);
        const reader_error = firstParserError(&reader_harness.parser);

        var slice_harness: InlineSliceParserHarness = undefined;
        slice_harness.init(xml);
        const slice_error = firstParserError(&slice_harness.parser);

        try std.testing.expectEqual(@as(?ParseError, error.InvalidXmlCharacter), reader_error);
        try std.testing.expectEqual(reader_error, slice_error);
        try std.testing.expectEqual(reader_harness.parser.byteOffset(), slice_harness.parser.byteOffset());
    }
}

test "parser applies XML version rules to character references" {
    const invalid_xml10 = [_][]const u8{
        "<root>&#0;</root>",
        "<root>&#x1;</root>",
        "<root>&#xD800;</root>",
        "<root>&#xFFFE;</root>",
    };

    for (invalid_xml10) |xml| {
        var reader_harness: InlineParserHarness = undefined;
        reader_harness.init(xml);
        const reader_error = firstParserError(&reader_harness.parser);

        var slice_harness: InlineSliceParserHarness = undefined;
        slice_harness.init(xml);
        const slice_error = firstParserError(&slice_harness.parser);

        try std.testing.expectEqual(@as(?ParseError, error.InvalidCharacterReference), reader_error);
        try std.testing.expectEqual(reader_error, slice_error);
        try std.testing.expectEqual(reader_harness.parser.byteOffset(), slice_harness.parser.byteOffset());
    }

    const xml11 = "<?xml version=\"1.1\"?><root>&#x1;</root>";
    var reader_harness: InlineParserHarness = undefined;
    reader_harness.init(xml11);
    try std.testing.expectEqual(@as(?ParseError, null), firstParserError(&reader_harness.parser));

    var slice_harness: InlineSliceParserHarness = undefined;
    slice_harness.init(xml11);
    try std.testing.expectEqual(@as(?ParseError, null), firstParserError(&slice_harness.parser));

    const unsupported = "<?xml version=\"2.0\"?><root/>";
    var unsupported_reader: InlineParserHarness = undefined;
    unsupported_reader.init(unsupported);
    try std.testing.expectEqual(@as(?ParseError, error.UnsupportedXmlVersion), firstParserError(&unsupported_reader.parser));

    var unsupported_slice: InlineSliceParserHarness = undefined;
    unsupported_slice.init(unsupported);
    try std.testing.expectEqual(@as(?ParseError, error.UnsupportedXmlVersion), firstParserError(&unsupported_slice.parser));
    try std.testing.expectEqual(unsupported_reader.parser.byteOffset(), unsupported_slice.parser.byteOffset());
}

test "parser rejects XML 1.1 restricted literal characters" {
    const cases = [_][]const u8{
        "<?xml version=\"1.1\"?><root>\x01</root>",
        "<?xml version=\"1.1\"?><root>\x7F</root>",
    };

    for (cases) |xml| {
        var reader_harness: InlineParserHarness = undefined;
        reader_harness.init(xml);
        const reader_error = firstParserError(&reader_harness.parser);

        var slice_harness: InlineSliceParserHarness = undefined;
        slice_harness.init(xml);
        const slice_error = firstParserError(&slice_harness.parser);

        try std.testing.expectEqual(@as(?ParseError, error.InvalidXmlCharacter), reader_error);
        try std.testing.expectEqual(reader_error, slice_error);
        try std.testing.expectEqual(reader_harness.parser.byteOffset(), slice_harness.parser.byteOffset());
    }
}

test "parser distinguishes escaped markup from forbidden literal sequences" {
    const cases = [_][]const u8{
        "<root attr=\"&lt;\"/>",
        "<root>]]&gt;</root>",
        "<?xml version=\"1.1\"?><root>&#x7F;\xC2\x85</root>",
    };

    for (cases) |xml| {
        var reader_harness: InlineParserHarness = undefined;
        reader_harness.init(xml);

        var slice_harness: InlineSliceParserHarness = undefined;
        slice_harness.init(xml);

        try std.testing.expectEqual(@as(?ParseError, null), firstParserError(&reader_harness.parser));
        try std.testing.expectEqual(@as(?ParseError, null), firstParserError(&slice_harness.parser));
    }
}

test "parser rejects illegal literals in PI comments and CDATA" {
    const cases = [_][]const u8{
        "<?note \x01?><root/>",
        "<root><!--\x01--></root>",
        "<root><![CDATA[\x01]]></root>",
    };

    for (cases) |xml| {
        var reader_harness: InlineParserHarness = undefined;
        reader_harness.init(xml);
        const reader_error = firstParserError(&reader_harness.parser);

        var slice_harness: InlineSliceParserHarness = undefined;
        slice_harness.init(xml);
        const slice_error = firstParserError(&slice_harness.parser);

        try std.testing.expectEqual(@as(?ParseError, error.InvalidXmlCharacter), reader_error);
        try std.testing.expectEqual(reader_error, slice_error);
        try std.testing.expectEqual(reader_harness.parser.byteOffset(), slice_harness.parser.byteOffset());
    }
}

test "parser uses only XML whitespace in markup" {
    const xml = "<root\x0Battr=\"value\"/>";

    var reader_harness: InlineParserHarness = undefined;
    reader_harness.init(xml);
    try std.testing.expectEqual(@as(?ParseError, error.MalformedXml), firstParserError(&reader_harness.parser));

    var slice_harness: InlineSliceParserHarness = undefined;
    slice_harness.init(xml);
    try std.testing.expectEqual(@as(?ParseError, error.MalformedXml), firstParserError(&slice_harness.parser));
    try std.testing.expectEqual(reader_harness.parser.byteOffset(), slice_harness.parser.byteOffset());
}

test "parser rejects forbidden text close across reader refills" {
    const xml = "<root>prefix]]>suffix</root>";

    var slice_harness: InlineSliceParserHarness = undefined;
    slice_harness.init(xml);
    const slice_error = firstParserError(&slice_harness.parser);
    try std.testing.expectEqual(@as(?ParseError, error.MalformedXml), slice_error);

    for (1..8) |chunk_size| {
        var chunked_reader: ChunkedReader = undefined;
        chunked_reader.init(xml, chunk_size);
        var token: [128]u8 = undefined;
        var attributes: [8]Attribute = undefined;
        var namespaces: [8]NamespaceBinding = undefined;
        var namespace_bytes: [128]u8 = undefined;
        var stack: [8]ElementFrame = undefined;
        var element_bytes: [128]u8 = undefined;
        var parser = Parser.init(chunked_reader.readerPtr(), .{
            .token = &token,
            .attributes = &attributes,
            .namespace_bindings = &namespaces,
            .namespace_bytes = &namespace_bytes,
            .element_stack = &stack,
            .element_bytes = &element_bytes,
        });

        try std.testing.expectEqual(@as(?ParseError, error.MalformedXml), firstParserError(&parser));
        try std.testing.expectEqual(slice_harness.parser.byteOffset(), parser.byteOffset());
    }
}

test "parser reports the earliest XML violation with reader and slice parity" {
    const cases = [_]struct {
        xml: []const u8,
        expected: ParseError,
    }{
        .{ .xml = "<root>]]>later\x01</root>", .expected = error.MalformedXml },
        .{ .xml = "<cvParam unitName=\"\x01 later < value\"/>", .expected = error.InvalidXmlCharacter },
        .{ .xml = "<root>\xC2&unknown;</root>", .expected = error.InvalidUtf8 },
    };

    for (cases) |case| {
        var reader_harness: InlineParserHarness = undefined;
        reader_harness.init(case.xml);
        const reader_error = firstParserError(&reader_harness.parser);

        var slice_harness: InlineSliceParserHarness = undefined;
        slice_harness.init(case.xml);
        const slice_error = firstParserError(&slice_harness.parser);

        try std.testing.expectEqual(@as(?ParseError, case.expected), reader_error);
        try std.testing.expectEqual(reader_error, slice_error);
        try std.testing.expectEqual(reader_harness.parser.byteOffset(), slice_harness.parser.byteOffset());
    }
}

test "parser preserves first-failure order around configured limits" {
    const cases = [_]struct {
        xml: []const u8,
        limits: Limits,
        expected: ParseError,
    }{
        .{ .xml = "<root>\x01abcde</root>", .limits = .{ .max_scalar_text_bytes = 4 }, .expected = error.InvalidXmlCharacter },
        .{ .xml = "<root>abcde\x01</root>", .limits = .{ .max_scalar_text_bytes = 4 }, .expected = error.ScalarTextTooLong },
        .{ .xml = "<root><![CDATA[\x01abcde]]></root>", .limits = .{ .max_scalar_text_bytes = 4 }, .expected = error.InvalidXmlCharacter },
        .{ .xml = "<root><![CDATA[abcde\x01]]></root>", .limits = .{ .max_scalar_text_bytes = 4 }, .expected = error.ScalarTextTooLong },
        .{ .xml = "<cvParam unitName=\"\x01abc\"/>", .limits = .{ .max_attribute_bytes = 10 }, .expected = error.InvalidXmlCharacter },
        .{ .xml = "<cvParam unitName=\"abc\x01\"/>", .limits = .{ .max_attribute_bytes = 10 }, .expected = error.AttributeTooLong },
    };

    for (cases) |case| {
        var reader_harness: InlineParserHarness = undefined;
        reader_harness.initWithLimits(case.xml, case.limits);
        const reader_error = firstParserError(&reader_harness.parser);

        var slice_harness: InlineSliceParserHarness = undefined;
        slice_harness.initWithLimits(case.xml, case.limits);
        const slice_error = firstParserError(&slice_harness.parser);

        try std.testing.expectEqual(@as(?ParseError, case.expected), reader_error);
        try std.testing.expectEqual(reader_error, slice_error);
        try std.testing.expectEqual(reader_harness.parser.byteOffset(), slice_harness.parser.byteOffset());
    }
}

test "parser skips utf8 bom and replays partial ef prefix" {
    const plain = "<root></root>";
    const with_bom = "\xEF\xBB\xBF" ++ plain;

    var bom_harness: InlineParserHarness = undefined;
    bom_harness.init(with_bom);
    const bom_root = (try bom_harness.parser.next()).?.start_element;
    try std.testing.expect(bom_root.name.matches(null, "root"));
    const bom_end = (try bom_harness.parser.next()).?.end_element;
    try std.testing.expect(bom_end.name.matches(null, "root"));
    try std.testing.expectEqual(@as(?Event, null), try bom_harness.parser.next());

    const partial = "\xEF\x41\x42<root></root>";
    var token_buffer: [64]u8 = undefined;
    var attrs: [4]Attribute = undefined;
    var ns: [4]NamespaceBinding = undefined;
    var ns_bytes: [64]u8 = undefined;
    var stack: [4]ElementFrame = undefined;
    var elem_bytes: [64]u8 = undefined;
    var slice_parser = Parser.initSlice(partial, .{
        .token = &token_buffer,
        .attributes = &attrs,
        .namespace_bindings = &ns,
        .namespace_bytes = &ns_bytes,
        .element_stack = &stack,
        .element_bytes = &elem_bytes,
    });
    try slice_parser.skipBom();
    try std.testing.expectEqual(@as(usize, 3), slice_parser.input.slice.pos);
    try std.testing.expectEqual(@as(u64, 3), slice_parser.absolute_offset);
    try std.testing.expectEqual(@as(u8, 0xEF), slice_parser.lookahead.?);
    try std.testing.expectEqual(@as(u8, 2), slice_parser.pending_len);
    try std.testing.expectEqual(@as(u8, 0x41), slice_parser.pending[0]);
    try std.testing.expectEqual(@as(u8, 0x42), slice_parser.pending[1]);
}

test "parser emits elements text attributes and namespaces" {
    const xml =
        "<?xml version=\"1.0\"?>" ++
        "<mzML xmlns=\"urn:psi:ms:mzml\">" ++
        "<run id=\"main\">hello &amp; goodbye</run>" ++
        "</mzML>";

    var harness: InlineParserHarness = undefined;
    harness.init(xml);

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

test "slice lazy attributes match eager values around quoted delimiters" {
    const xml = "<cvParam accession=\"MS:1000130\" unitName=\"text > still\"/>";

    var slice_harness: InlineSliceParserHarness = undefined;
    slice_harness.init(xml);
    const slice_start = (try slice_harness.parser.next()).?.start_element;

    var reader_harness: InlineParserHarness = undefined;
    reader_harness.init(xml);
    const reader_start = (try reader_harness.parser.next()).?.start_element;

    try std.testing.expect(slice_start.self_closing);
    try std.testing.expectEqual(@as(usize, 2), slice_start.attributes.len);
    try std.testing.expectEqual(@as(usize, 2), reader_start.attributes.len);
    try std.testing.expectEqualStrings("MS:1000130", slice_start.attr("accession").?);
    try std.testing.expectEqualStrings("text > still", slice_start.attr("unitName").?);
    try std.testing.expectEqualStrings("text > still", reader_start.attr("unitName").?);
}

test "slice lazy attributes use eager decoding for entities and namespaces" {
    const entity_xml = "<cvParam unitName=\"a &quot; b\"/>";
    var entity_harness: InlineSliceParserHarness = undefined;
    entity_harness.init(entity_xml);
    const entity_start = (try entity_harness.parser.next()).?.start_element;
    try std.testing.expectEqual(@as(usize, 1), entity_start.attributes.len);
    try std.testing.expectEqualStrings("a \" b", entity_start.attr("unitName").?);

    const namespace_xml = "<cvParam xmlns=\"urn:test\" accession=\"MS:1000130\"/>";
    var namespace_harness: InlineSliceParserHarness = undefined;
    namespace_harness.init(namespace_xml);
    const namespace_start = (try namespace_harness.parser.next()).?.start_element;
    try std.testing.expect(namespace_start.name.matches("urn:test", "cvParam"));
    try std.testing.expectEqual(@as(usize, 2), namespace_start.attributes.len);
    try std.testing.expectEqualStrings("MS:1000130", namespace_start.attr("accession").?);
}

test "slice and reader raw attribute paths agree on duplicate names" {
    const xml = "<cvParam accession=\"first\" accession=\"second\"/>";

    var slice_harness: InlineSliceParserHarness = undefined;
    slice_harness.init(xml);
    const slice_start = (try slice_harness.parser.next()).?.start_element;

    var reader_harness: InlineParserHarness = undefined;
    reader_harness.init(xml);
    const reader_start = (try reader_harness.parser.next()).?.start_element;

    try std.testing.expectEqualStrings("first", slice_start.attr("accession").?);
    try std.testing.expectEqualStrings("first", reader_start.attr("accession").?);
}

test "lazy raw attribute path preserves invalid UTF8 and unterminated quote errors" {
    const invalid_utf8 = "<cvParam unitName=\"\xc0\"/>";
    var invalid_slice: InlineSliceParserHarness = undefined;
    invalid_slice.init(invalid_utf8);
    try std.testing.expectError(error.InvalidUtf8, invalid_slice.parser.next());

    var invalid_reader: InlineParserHarness = undefined;
    invalid_reader.init(invalid_utf8);
    try std.testing.expectError(error.InvalidUtf8, invalid_reader.parser.next());

    const unterminated = "<cvParam unitName=\"text > still/>";
    var unterminated_slice: InlineSliceParserHarness = undefined;
    unterminated_slice.init(unterminated);
    try std.testing.expectError(error.UnexpectedEof, unterminated_slice.parser.next());

    var unterminated_reader: InlineParserHarness = undefined;
    unterminated_reader.init(unterminated);
    try std.testing.expectError(error.UnexpectedEof, unterminated_reader.parser.next());

    const invalid_entity = "<cvParam unitName=\"\xc0&bogus;\"/>";
    var invalid_entity_slice: InlineSliceParserHarness = undefined;
    invalid_entity_slice.init(invalid_entity);
    try std.testing.expectError(error.InvalidUtf8, invalid_entity_slice.parser.next());

    var invalid_entity_reader: InlineParserHarness = undefined;
    invalid_entity_reader.init(invalid_entity);
    try std.testing.expectError(error.InvalidUtf8, invalid_entity_reader.parser.next());

    const entity_before_invalid = "<cvParam unitName=\"&bogus;\" accession=\"\xc0\"/>";
    var entity_before_invalid_slice: InlineSliceParserHarness = undefined;
    entity_before_invalid_slice.init(entity_before_invalid);
    try std.testing.expectError(error.UnknownEntity, entity_before_invalid_slice.parser.next());

    var entity_before_invalid_reader: InlineParserHarness = undefined;
    entity_before_invalid_reader.init(entity_before_invalid);
    try std.testing.expectError(error.UnknownEntity, entity_before_invalid_reader.parser.next());

    const unquoted_with_quote = "<cvParam unitName=abc\">";
    var unquoted_slice: InlineSliceParserHarness = undefined;
    unquoted_slice.init(unquoted_with_quote);
    try std.testing.expectError(error.MalformedXml, unquoted_slice.parser.next());

    var unquoted_reader: InlineParserHarness = undefined;
    unquoted_reader.init(unquoted_with_quote);
    try std.testing.expectError(error.MalformedXml, unquoted_reader.parser.next());

    const unclosed_unquoted = "<cvParam unitName=abc";
    var unclosed_unquoted_slice: InlineSliceParserHarness = undefined;
    unclosed_unquoted_slice.init(unclosed_unquoted);
    try std.testing.expectError(error.MalformedXml, unclosed_unquoted_slice.parser.next());

    var unclosed_unquoted_reader: InlineParserHarness = undefined;
    unclosed_unquoted_reader.init(unclosed_unquoted);
    try std.testing.expectError(error.MalformedXml, unclosed_unquoted_reader.parser.next());
}

test "initSlice parses identically to init on a fixed reader" {
    const xml = "<root><child>text</child></root>";

    var token_buffer: [4096]u8 = undefined;
    var attributes: [64]Attribute = undefined;
    var namespace_bindings: [32]NamespaceBinding = undefined;
    var namespace_bytes: [256]u8 = undefined;
    var element_stack: [16]ElementFrame = undefined;
    var element_bytes: [256]u8 = undefined;
    const buffers = Buffers{
        .token = &token_buffer,
        .attributes = &attributes,
        .namespace_bindings = &namespace_bindings,
        .namespace_bytes = &namespace_bytes,
        .element_stack = &element_stack,
        .element_bytes = &element_bytes,
    };

    var slice_parser = Parser.initSlice(xml, buffers);
    var reader = std.Io.Reader.fixed(xml);
    var reader_parser = Parser.init(&reader, buffers);

    while (true) {
        const slice_event = try slice_parser.next();
        const reader_event = try reader_parser.next();
        if (slice_event == null and reader_event == null) break;
        try std.testing.expect(slice_event != null);
        try std.testing.expect(reader_event != null);
        try std.testing.expect(eventsSemanticallyEqual(slice_event.?, reader_event.?));
    }
}

test "initSlice assigns mzML element intern ids" {
    const xml =
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">" ++
        "<run id=\"r\" defaultInstrumentConfigurationRef=\"ic\"/>" ++
        "</mzML>";

    var token_buffer: [4096]u8 = undefined;
    var attributes: [64]Attribute = undefined;
    var namespace_bindings: [32]NamespaceBinding = undefined;
    var namespace_bytes: [256]u8 = undefined;
    var element_stack: [16]ElementFrame = undefined;
    var element_bytes: [256]u8 = undefined;
    const buffers = Buffers{
        .token = &token_buffer,
        .attributes = &attributes,
        .namespace_bindings = &namespace_bindings,
        .namespace_bytes = &namespace_bytes,
        .element_stack = &element_stack,
        .element_bytes = &element_bytes,
    };
    var parser = Parser.initSlice(xml, buffers);

    const root = (try parser.next()).?.start_element;
    const run = (try parser.next()).?.start_element;
    const run_end = (try parser.next()).?.end_element;

    try std.testing.expectEqual(elements.ElementId.mzML, root.element_id);
    try std.testing.expectEqual(elements.ElementId.run, run.element_id);
    try std.testing.expectEqual(elements.ElementId.run, run_end.element_id);
}

test "initSlice zero-copies plain text and cdata from input bytes" {
    const xml = "<root>ABCDEF<![CDATA[base64+/=]]></root>";

    var token_buffer: [4096]u8 = undefined;
    var attributes: [64]Attribute = undefined;
    var namespace_bindings: [32]NamespaceBinding = undefined;
    var namespace_bytes: [256]u8 = undefined;
    var element_stack: [16]ElementFrame = undefined;
    var element_bytes: [256]u8 = undefined;
    const buffers = Buffers{
        .token = &token_buffer,
        .attributes = &attributes,
        .namespace_bindings = &namespace_bindings,
        .namespace_bytes = &namespace_bytes,
        .element_stack = &element_stack,
        .element_bytes = &element_bytes,
    };
    var parser = Parser.initSlice(xml, buffers);

    _ = (try parser.next()).?.start_element;
    const plain = (try parser.next()).?.text;
    const cdata = (try parser.next()).?.text;

    try std.testing.expectEqualStrings("ABCDEF", plain.value);
    try std.testing.expect(plain.value.ptr == xml.ptr + 6);
    try std.testing.expect(!plain.from_cdata);
    try std.testing.expectEqualStrings("base64+/=", cdata.value);
    try std.testing.expect(cdata.value.ptr == xml.ptr + 21);
    try std.testing.expect(cdata.from_cdata);
}

test "parser skips comments and processing instructions and emits cdata as text" {
    const xml =
        "<root><?ignored test?><child/><!--comment--><![CDATA[a<b>]]></root>";

    var harness: InlineParserHarness = undefined;
    harness.init(xml);

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

    var harness: InlineParserHarness = undefined;
    harness.init(xml);

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

    var harness: InlineParserHarness = undefined;
    harness.init(xml);

    _ = (try harness.parser.next()).?.start_element;

    try std.testing.expectError(error.InvalidUtf8, harness.parser.next());
}

test "parser rejects mismatched end tags" {
    const xml = "<root><child></root>";

    var harness: InlineParserHarness = undefined;
    harness.init(xml);

    _ = (try harness.parser.next()).?.start_element;
    _ = (try harness.parser.next()).?.start_element;

    try std.testing.expectError(error.MismatchedEndTag, harness.parser.next());
}

test "parser repeated clean inline parses keep event count stable" {
    const xml =
        "<?xml version=\"1.0\"?>" ++
        "<mzML xmlns=\"urn:psi:ms:mzml\"><run id=\"main\">hello &amp; goodbye</run></mzML>";

    for (0..32) |_| {
        var harness: InlineParserHarness = undefined;
        harness.init(xml);
        var event_count: usize = 0;
        while (try harness.parser.next()) |_| {
            event_count += 1;
        }

        try std.testing.expectEqual(@as(usize, 5), event_count);
    }
}

// --- Limit Pressure ---

test "parser emits bounded text chunks" {
    const xml = "<root>abcdefghijklmnopq</root>";

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
    const first = (try parser.next()).?.text;
    try std.testing.expectEqualStrings("abcdefghijkl", first.value);
    try std.testing.expect(!first.is_final);
    const second = (try parser.next()).?.text;
    try std.testing.expectEqualStrings("mnopq", second.value);
    try std.testing.expect(second.is_final);
    _ = (try parser.next()).?.end_element;
    try std.testing.expectEqual(@as(?Event, null), try parser.next());
}

test "parser preserves utf8 and cdata across text chunks" {
    const xml = "<root>abcdefghijk\xF0\x9F\x98\x80xyz<![CDATA[abcdefghijklmnopq]]></root>";

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
    const first = (try parser.next()).?.text;
    try std.testing.expectEqualStrings("abcdefghijk\xF0\x9F\x98\x80", first.value);
    try std.testing.expect(!first.is_final);
    const second = (try parser.next()).?.text;
    try std.testing.expectEqualStrings("xyz", second.value);
    try std.testing.expect(second.is_final);

    const cdata_first = (try parser.next()).?.text;
    try std.testing.expectEqualStrings("abcdefghijkl", cdata_first.value);
    try std.testing.expect(cdata_first.from_cdata);
    try std.testing.expect(!cdata_first.is_final);
    const cdata_second = (try parser.next()).?.text;
    try std.testing.expectEqualStrings("mnopq", cdata_second.value);
    try std.testing.expect(cdata_second.from_cdata);
    try std.testing.expect(cdata_second.is_final);

    _ = (try parser.next()).?.end_element;
    try std.testing.expectEqual(@as(?Event, null), try parser.next());
}

test "parser preserves cdata bracket runs across text chunks" {
    const xml = "<root><![CDATA[abcdefghijkl]]x]>]]></root>";

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
    const first = (try parser.next()).?.text;
    try std.testing.expectEqualStrings("abcdefghijkl]]x", first.value);
    try std.testing.expect(!first.is_final);

    const second = (try parser.next()).?.text;
    try std.testing.expectEqualStrings("]>", second.value);
    try std.testing.expect(second.is_final);
    _ = (try parser.next()).?.end_element;
    try std.testing.expectEqual(@as(?Event, null), try parser.next());
}

test "parser enforces limits by field" {
    const limits = Limits{
        .max_start_tag_bytes = 1 * 1024 * 1024,
        .max_attribute_bytes = 64,
        .max_scalar_text_bytes = 4,
        .max_binary_text_bytes = 12,
    };

    var scalar_reader: InlineParserHarness = undefined;
    scalar_reader.initWithLimits("<root>12345</root>", limits);
    _ = (try scalar_reader.parser.next()).?.start_element;
    try std.testing.expectError(error.ScalarTextTooLong, scalar_reader.parser.next());

    var scalar_slice: InlineSliceParserHarness = undefined;
    scalar_slice.initWithLimits("<root>12345</root>", limits);
    _ = (try scalar_slice.parser.next()).?.start_element;
    try std.testing.expectError(error.ScalarTextTooLong, scalar_slice.parser.next());

    var scalar_exact: InlineSliceParserHarness = undefined;
    scalar_exact.initWithLimits("<root>1234</root>", limits);
    _ = (try scalar_exact.parser.next()).?.start_element;
    try std.testing.expectEqualStrings("1234", (try scalar_exact.parser.next()).?.text.value);

    var cdata_reader: InlineParserHarness = undefined;
    cdata_reader.initWithLimits("<root><![CDATA[12345]]></root>", limits);
    _ = (try cdata_reader.parser.next()).?.start_element;
    try std.testing.expectError(error.ScalarTextTooLong, cdata_reader.parser.next());

    var cdata_slice: InlineSliceParserHarness = undefined;
    cdata_slice.initWithLimits("<root><![CDATA[12345]]></root>", limits);
    _ = (try cdata_slice.parser.next()).?.start_element;
    try std.testing.expectError(error.ScalarTextTooLong, cdata_slice.parser.next());

    const binary_xml = "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\"><binary>123456789012</binary></mzML>";
    var binary_reader: InlineParserHarness = undefined;
    binary_reader.initWithLimits(binary_xml, limits);
    _ = (try binary_reader.parser.next()).?.start_element;
    _ = (try binary_reader.parser.next()).?.start_element;
    const binary_text = (try binary_reader.parser.next()).?.text;
    try std.testing.expectEqualStrings("123456789012", binary_text.value);
    try std.testing.expect(binary_text.is_final);

    const chunk_xml = "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\"><binary>0123456789012345678901234567890123456789012345678901234567890123456789</binary></mzML>";
    var chunk_reader = std.Io.Reader.fixed(chunk_xml);
    var chunk_token: [64]u8 = undefined;
    var chunk_attributes: [4]Attribute = undefined;
    var chunk_namespaces: [4]NamespaceBinding = undefined;
    var chunk_namespace_bytes: [64]u8 = undefined;
    var chunk_stack: [4]ElementFrame = undefined;
    var chunk_element_bytes: [64]u8 = undefined;
    var chunk_parser = Parser.init(&chunk_reader, .{
        .token = &chunk_token,
        .attributes = &chunk_attributes,
        .namespace_bindings = &chunk_namespaces,
        .namespace_bytes = &chunk_namespace_bytes,
        .element_stack = &chunk_stack,
        .element_bytes = &chunk_element_bytes,
        .limits = .{ .max_attribute_bytes = 64, .max_scalar_text_bytes = 4, .max_binary_text_bytes = 70 },
    });
    _ = (try chunk_parser.next()).?.start_element;
    _ = (try chunk_parser.next()).?.start_element;
    const first_chunk = (try chunk_parser.next()).?.text;
    const second_chunk = (try chunk_parser.next()).?.text;
    try std.testing.expectEqual(@as(usize, 60), first_chunk.value.len);
    try std.testing.expect(!first_chunk.is_final);
    try std.testing.expectEqual(@as(usize, 10), second_chunk.value.len);
    try std.testing.expect(second_chunk.is_final);

    var binary_over: InlineParserHarness = undefined;
    binary_over.initWithLimits("<mzML xmlns=\"http://psi.hupo.org/ms/mzml\"><binary>1234567890123</binary></mzML>", limits);
    _ = (try binary_over.parser.next()).?.start_element;
    _ = (try binary_over.parser.next()).?.start_element;
    try std.testing.expectError(error.BinaryTextTooLong, binary_over.parser.next());

    var start_tag: InlineParserHarness = undefined;
    start_tag.initWithLimits("<root a=\"1\"/>", .{ .max_start_tag_bytes = 7, .max_attribute_bytes = 64 });
    try std.testing.expectError(error.StartTagTooLong, start_tag.parser.next());

    var start_tag_exact: InlineParserHarness = undefined;
    start_tag_exact.initWithLimits("<root/>", .{ .max_start_tag_bytes = 7 });
    try std.testing.expect((try start_tag_exact.parser.next()).?.start_element.self_closing);

    var start_tag_slice: InlineSliceParserHarness = undefined;
    start_tag_slice.initWithLimits("<root a=\"1\"/>", .{ .max_start_tag_bytes = 7, .max_attribute_bytes = 64 });
    try std.testing.expectError(error.StartTagTooLong, start_tag_slice.parser.next());

    var lazy_attribute: InlineSliceParserHarness = undefined;
    lazy_attribute.initWithLimits("<cvParam unitName=\"abcde\"/>", .{ .max_attribute_bytes = 12 });
    try std.testing.expectError(error.AttributeTooLong, lazy_attribute.parser.next());

    var eager_attribute: InlineParserHarness = undefined;
    eager_attribute.initWithLimits("<cvParam unitName=\"abcde\"/>", .{ .max_attribute_bytes = 12 });
    try std.testing.expectError(error.AttributeTooLong, eager_attribute.parser.next());
}

test "parser keeps slice and reader parity across refill boundaries" {
    const xml = "<root a=\"value\"><child>hello &amp; goodbye</child><![CDATA[text]]></root>";

    for (1..8) |chunk_size| {
        var slice_token: [128]u8 = undefined;
        var slice_attributes: [8]Attribute = undefined;
        var slice_namespaces: [8]NamespaceBinding = undefined;
        var slice_namespace_bytes: [256]u8 = undefined;
        var slice_stack: [8]ElementFrame = undefined;
        var slice_element_bytes: [256]u8 = undefined;
        var slice_parser = Parser.initSlice(xml, .{
            .token = &slice_token,
            .attributes = &slice_attributes,
            .namespace_bindings = &slice_namespaces,
            .namespace_bytes = &slice_namespace_bytes,
            .element_stack = &slice_stack,
            .element_bytes = &slice_element_bytes,
        });

        var chunked_reader: ChunkedReader = undefined;
        chunked_reader.init(xml, chunk_size);
        var reader_token: [128]u8 = undefined;
        var reader_attributes: [8]Attribute = undefined;
        var reader_namespaces: [8]NamespaceBinding = undefined;
        var reader_namespace_bytes: [256]u8 = undefined;
        var reader_stack: [8]ElementFrame = undefined;
        var reader_element_bytes: [256]u8 = undefined;
        var reader_parser = Parser.init(chunked_reader.readerPtr(), .{
            .token = &reader_token,
            .attributes = &reader_attributes,
            .namespace_bindings = &reader_namespaces,
            .namespace_bytes = &reader_namespace_bytes,
            .element_stack = &reader_stack,
            .element_bytes = &reader_element_bytes,
        });

        while (true) {
            const slice_event = try slice_parser.next();
            const reader_event = try reader_parser.next();
            if (slice_event == null and reader_event == null) break;
            try std.testing.expect(slice_event != null);
            try std.testing.expect(reader_event != null);
            try std.testing.expect(eventsSemanticallyEqual(slice_event.?, reader_event.?));
        }
    }
}

test "parser accepts exact attribute count and rejects one more" {
    const exact_xml = "<root a=\"1\" b=\"2\"/>";
    const overflow_xml = "<root a=\"1\" b=\"2\" c=\"3\"/>";

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

test "Parser start element reports closing tag byte offset" {
    const xml = "<root a=\"1\" >";
    var harness: InlineParserHarness = undefined;
    harness.init(xml);

    const start = (try harness.parser.next()).?.start_element;

    try std.testing.expectEqual(@as(?u64, xml.len - 1), start.end_byte_offset);
}

test "parser accepts exact element name storage and rejects overflow" {
    const exact_xml = "<abcdefgh></abcdefgh>";
    const overflow_xml = "<abcdefghi></abcdefghi>";

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

test "parser repeats bounded text chunks without changing event count" {
    const xml = "<root>abcdefghijklmnopq</root>";

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

        const first = (try parser.next()).?.text;
        const second = (try parser.next()).?.text;
        try std.testing.expect(!first.is_final);
        try std.testing.expect(second.is_final);
        _ = (try parser.next()).?.end_element;
        try std.testing.expectEqual(@as(?Event, null), try parser.next());
    }
}

// --- Fixture Corpus ---

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

// --- Fixture Sweep ---

test "parser accepts valid xml fixtures" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    try expectFixtureParses(allocator, io, "fixtures/xml/valid/namespaces-and-entities.xml");
    try expectFixtureParses(allocator, io, "fixtures/xml/valid/comments-cdata.xml");
    try expectFixtureParses(allocator, io, "fixtures/xml/valid/xml10-declaration-basic.xml");
    try expectFixtureParses(allocator, io, "fixtures/xml/valid/xml11-declaration-basic.xml");
    try expectFixtureParses(allocator, io, "fixtures/xml/valid/quoted-greater-than-attribute.xml");
}

test "parser rejects invalid xml fixtures" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    try expectFixtureError(allocator, io, "fixtures/xml/invalid/mismatched-end-tag.xml", error.MismatchedEndTag);
    try expectFixtureError(allocator, io, "fixtures/xml/invalid/unknown-entity.xml", error.UnknownEntity);
    try expectFixtureError(allocator, io, "fixtures/xml/invalid/unsupported-doctype.xml", error.UnsupportedMarkup);
    try expectFixtureError(allocator, io, "fixtures/xml/invalid/external-entity.xml", error.UnsupportedMarkup);
    try expectFixtureError(allocator, io, "fixtures/xml/invalid/namespace-empty-prefix-declaration.xml", error.MalformedXml);
    try expectFixtureError(allocator, io, "fixtures/xml/invalid/malformed-processing-instruction.xml", error.UnexpectedEof);
    try expectFixtureError(allocator, io, "fixtures/xml/invalid/xml11-unclosed-declaration.xml", error.UnexpectedEof);
    try expectFixtureError(allocator, io, "fixtures/xml/invalid/invalid-name-start.xml", error.MalformedXml);
    try expectFixtureError(allocator, io, "fixtures/xml/invalid/invalid-attribute-value.xml", error.InvalidXmlCharacter);
    try expectFixtureError(allocator, io, "fixtures/xml/invalid/invalid-character-reference.xml", error.InvalidCharacterReference);
    try expectFixtureError(allocator, io, "fixtures/xml/invalid/forbidden-text-close.xml", error.MalformedXml);
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
