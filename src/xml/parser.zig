//! Pull parser for XML input, backed by zmz's event stream.
//!
//! Emits the borrowed events mzValidate's validators consume. zmz checks
//! well-formedness, resolves namespaces, and bounds nesting at
//! `zmz.MAX_DEPTH`; this layer converts its events, skips whitespace-only
//! text, and applies mzValidate's text, attribute, and namespace limits. zmz
//! allocates its buffers from the caller's allocator on the first read; call
//! `deinit` to release them.

const std = @import("std");
const zmz = @import("zmz").mzml;
const elements = @import("../mzml/elements.zig");
const events = @import("events.zig");

const Attribute = events.Attribute;
const Event = events.Event;
const QName = events.QName;

pub const ParseError = error{
    UnexpectedEof,
    MalformedXml,
    InvalidUtf8,
    StartTagTooLong,
    AttributeTooLong,
    ScalarTextTooLong,
    BinaryTextTooLong,
    TooManyAttributes,
    TooManyNamespaces,
    ElementNestingTooDeep,
    UnknownEntity,
    InvalidCharacterReference,
    InvalidXmlCharacter,
    UnsupportedXmlVersion,
    UnsupportedMarkup,
    MismatchedEndTag,
    OutOfMemory,
} || error{ReadFailed};

/// Caller-owned scratch. `attributes` bounds attributes per element and receives
/// each event's attributes.
pub const Buffers = struct {
    attributes: []Attribute,
    limits: Limits = .{},
};

pub const Limits = struct {
    /// Namespace bindings in scope at once.
    max_namespaces: usize = 32,
    max_start_tag_bytes: usize = 1024 * 1024,
    max_attribute_bytes: usize = 64 * 1024,
    max_scalar_text_bytes: usize = 64 * 1024,
    max_binary_text_bytes: usize = 256 * 1024 * 1024,
};

pub const Input = union(enum) {
    reader: *std.Io.Reader,
    slice: []const u8,
};

/// Streaming pull parser. Emits borrowed events; call `next()` until `null`.
pub const Parser = struct {
    allocator: std.mem.Allocator,
    input: Input,
    slice_reader: std.Io.Reader = undefined,
    zmz_events: ?zmz.Events = null,
    attributes: []Attribute,
    limits: Limits,
    /// Depth of the open binary element, to choose the text limit.
    binary_depth: ?usize = null,
    depth: usize = 0,
    root_seen: bool = false,
    last_byte_offset: u64 = 0,
    /// The text node being read: its first byte, whether it has shown non-whitespace, and size.
    text_start: ?u64 = null,
    text_significant: bool = false,
    text_bytes: usize = 0,

    pub fn init(allocator: std.mem.Allocator, reader: *std.Io.Reader, buffers: Buffers) Parser {
        return .{ .allocator = allocator, .input = .{ .reader = reader }, .attributes = buffers.attributes, .limits = buffers.limits };
    }

    pub fn initSlice(allocator: std.mem.Allocator, bytes: []const u8, buffers: Buffers) Parser {
        return .{ .allocator = allocator, .input = .{ .slice = bytes }, .attributes = buffers.attributes, .limits = buffers.limits };
    }

    pub fn deinit(parser: *Parser) void {
        if (parser.zmz_events) |*events_stream| events_stream.deinit();
        parser.* = undefined;
    }

    /// Offset of the last byte consumed.
    pub fn byteOffset(parser: *const Parser) u64 {
        return parser.last_byte_offset;
    }

    /// Returns the next event, `null` at EOF, or a parse error.
    pub fn next(parser: *Parser) ParseError!?Event {
        const source = try parser.eventStream();
        while (true) {
            const event = source.next() catch |err| return parser.failure(err);
            const value = event orelse return null;
            parser.last_byte_offset = value.span.end -| 1;
            switch (value.data) {
                .start_element => |start| {
                    parser.text_start = null;
                    return try parser.startEvent(value.span.start, value.span.end, start);
                },
                .end_element => |end| {
                    parser.text_start = null;
                    if (parser.binary_depth == parser.depth) parser.binary_depth = null;
                    parser.depth -= 1;
                    // An empty element's end sits at its "/>" slash.
                    const offset = if (value.span.start == value.span.end) value.span.start -| 2 else value.span.start;
                    return .{ .end_element = .{
                        .byte_offset = offset,
                        .name = qname(end.name),
                        .element_id = elements.resolveId(.unknown, end.name.expanded.local, end.name.expanded.namespace_uri),
                    } };
                },
                .text => |text| {
                    if (parser.text_start == null) {
                        parser.text_start = value.span.start;
                        parser.text_significant = false;
                        parser.text_bytes = 0;
                    }
                    parser.text_bytes = std.math.add(usize, parser.text_bytes, text.bytes.len) catch return parser.textLimit();
                    const binary = parser.binary_depth != null and parser.binary_depth.? == parser.depth;
                    if (parser.text_bytes > if (binary) parser.limits.max_binary_text_bytes else parser.limits.max_scalar_text_bytes) return parser.textLimit();
                    if (!parser.text_significant and isWhitespaceOnly(text.bytes)) continue;
                    parser.text_significant = true;
                    return .{ .text = .{ .byte_offset = parser.text_start.?, .value = text.bytes } };
                },
            }
        }
    }

    fn eventStream(parser: *Parser) ParseError!*zmz.Events {
        if (parser.zmz_events) |*existing| return existing;
        const reader = switch (parser.input) {
            .reader => |reader| reader,
            .slice => |bytes| blk: {
                if (bytes.len == 0) return error.MalformedXml;
                parser.slice_reader = std.Io.Reader.fixed(bytes);
                break :blk &parser.slice_reader;
            },
        };
        parser.zmz_events = zmz.Events.init(parser.allocator, reader, .{
            .attributes = @max(parser.attributes.len, 1),
            .attribute_bytes = parser.limits.max_start_tag_bytes,
        }) catch return error.MalformedXml;
        return &parser.zmz_events.?;
    }

    fn startEvent(parser: *Parser, start_offset: u64, end_offset: u64, start: zmz.Events.StartElement) ParseError!Event {
        if (start.attributes.len > parser.attributes.len) return error.TooManyAttributes;
        var position: usize = 0;
        var bindings: usize = 0;
        while (parser.zmz_events.?.namespaceAt(&position)) |_| bindings += 1;
        if (bindings > parser.limits.max_namespaces) return error.TooManyNamespaces;
        for (start.attributes, 0..) |attribute, i| {
            if (attribute.value.len > parser.limits.max_attribute_bytes) return error.AttributeTooLong;
            parser.attributes[i] = .{ .byte_offset = attribute.offset, .name = qname(attribute.name), .value = attribute.value };
        }
        parser.root_seen = true;
        parser.depth += 1;
        const local = start.name.expanded.local;
        const element_id = elements.resolveId(.unknown, local, start.name.expanded.namespace_uri);
        if (element_id == .binary) parser.binary_depth = parser.depth;
        return .{ .start_element = .{
            .byte_offset = start_offset,
            .end_byte_offset = end_offset -| 1,
            .name = qname(start.name),
            .element_id = element_id,
            .attributes = parser.attributes[0..start.attributes.len],
            .self_closing = start.empty_element_syntax,
        } };
    }

    fn textLimit(parser: *const Parser) ParseError {
        const binary = parser.binary_depth != null and parser.binary_depth.? == parser.depth;
        return if (binary) error.BinaryTextTooLong else error.ScalarTextTooLong;
    }

    fn failure(parser: *Parser, err: zmz.Events.Error) ParseError {
        const report = parser.zmz_events.?.diagnostic();
        if (report) |found| if (found.location) |location| switch (location) {
            // zmz reports the offending byte of broken XML and encodings (the end of input for
            // a truncation), otherwise the next unread byte; mzValidate reports the last byte read.
            .input_event => |offset| parser.last_byte_offset = switch (err) {
                error.InvalidEncoding => offset,
                error.InvalidXml => if (found.detail == .xml and found.detail.xml == .unexpected_end) offset -| 1 else offset,
                else => offset -| 1,
            },
            else => {},
        };
        const detail = if (report) |found| found.detail else .none;
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.ReadFailed => error.ReadFailed,
            error.InvalidEncoding => error.InvalidUtf8,
            error.UnsupportedVersion => error.UnsupportedXmlVersion,
            error.DtdForbidden => error.UnsupportedMarkup,
            error.LimitExceeded => switch (detail) {
                .limit => |limit| switch (limit.name) {
                    .attributes => error.TooManyAttributes,
                    .attribute_bytes => error.StartTagTooLong,
                    .depth => error.ElementNestingTooDeep,
                    else => error.MalformedXml,
                },
                else => error.MalformedXml,
            },
            error.InvalidXml => switch (detail) {
                .xml => |rule| switch (rule) {
                    .unexpected_end => if (parser.root_seen) error.UnexpectedEof else error.MalformedXml,
                    .mismatched_end_tag => error.MismatchedEndTag,
                    .unknown_entity => error.UnknownEntity,
                    .invalid_character_reference => error.InvalidCharacterReference,
                    .invalid_character, .less_than_in_attribute => error.InvalidXmlCharacter,
                    else => error.MalformedXml,
                },
                else => error.MalformedXml,
            },
            else => error.MalformedXml,
        };
    }
};

fn qname(name: zmz.Events.Name) QName {
    return .{ .prefix = name.expanded.prefix, .local_name = name.expanded.local, .namespace_uri = name.expanded.namespace_uri };
}

fn isWhitespaceOnly(bytes: []const u8) bool {
    for (bytes) |byte| switch (byte) {
        ' ', '\t', '\r', '\n' => {},
        else => return false,
    };
    return true;
}
