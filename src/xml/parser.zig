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

// --- Unit Tests ---

const mzml_namespace = "http://psi.hupo.org/ms/mzml";

/// Drains `xml` from a slice and returns the first parse error, or null.
fn firstSliceError(xml: []const u8, attribute_capacity: usize, limits: Limits) !?ParseError {
    var attributes: [8]Attribute = undefined;
    var parser = Parser.initSlice(std.testing.allocator, xml, .{
        .attributes = attributes[0..attribute_capacity],
        .limits = limits,
    });
    defer parser.deinit();
    while (true) {
        const event = parser.next() catch |err| return @as(?ParseError, err);
        if (event == null) return null;
    }
}

/// Drains one file through a small-buffer file reader and through a slice in
/// lockstep, expecting identical events and the same outcome from both.
fn expectReaderSliceParity(io: std.Io, path: []const u8) !?ParseError {
    const allocator = std.testing.allocator;
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1024 * 1024));
    defer allocator.free(bytes);
    var file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var read_buffer: [256]u8 = undefined;
    var file_reader = file.reader(io, &read_buffer);

    var reader_attributes: [64]Attribute = undefined;
    var slice_attributes: [64]Attribute = undefined;
    var from_reader = Parser.init(allocator, &file_reader.interface, .{ .attributes = &reader_attributes });
    defer from_reader.deinit();
    var from_slice = Parser.initSlice(allocator, bytes, .{ .attributes = &slice_attributes });
    defer from_slice.deinit();

    while (true) {
        const reader_event = from_reader.next() catch |reader_err| {
            try std.testing.expectError(reader_err, from_slice.next());
            try std.testing.expectEqual(from_slice.byteOffset(), from_reader.byteOffset());
            return @as(?ParseError, reader_err);
        };
        const slice_event = try from_slice.next();
        const left = reader_event orelse {
            try std.testing.expect(slice_event == null);
            return null;
        };
        const right = slice_event orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(std.meta.activeTag(left), std.meta.activeTag(right));
        switch (left) {
            .start_element => |start| {
                try std.testing.expectEqual(start.byte_offset, right.start_element.byte_offset);
                try std.testing.expectEqual(start.end_byte_offset, right.start_element.end_byte_offset);
                try std.testing.expectEqualStrings(start.name.local_name, right.start_element.name.local_name);
                try std.testing.expectEqual(start.attributes.len, right.start_element.attributes.len);
                for (start.attributes, right.start_element.attributes) |a, b| {
                    try std.testing.expectEqualStrings(a.name.local_name, b.name.local_name);
                    try std.testing.expectEqualStrings(a.value, b.value);
                }
            },
            .end_element => |end| {
                try std.testing.expectEqual(end.byte_offset, right.end_element.byte_offset);
                try std.testing.expectEqualStrings(end.name.local_name, right.end_element.name.local_name);
            },
            // Reader text can arrive in more pieces than slice text, so only the start must agree.
            .text => |text| try std.testing.expectEqual(text.byte_offset, right.text.byte_offset),
        }
    }
}

fn fixturePaths(io: std.Io, root: []const u8) !std.ArrayList([]u8) {
    const allocator = std.testing.allocator;
    var paths: std.ArrayList([]u8) = .empty;
    errdefer {
        for (paths.items) |path| allocator.free(path);
        paths.deinit(allocator);
    }
    var dir = try std.Io.Dir.cwd().openDir(io, root, .{ .iterate = true });
    defer dir.close(io);
    var walker = try dir.walk(allocator);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.path, ".xml")) continue;
        const path = try std.fs.path.join(allocator, &.{ root, entry.path });
        paths.append(allocator, path) catch |err| {
            allocator.free(path);
            return err;
        };
    }
    try std.testing.expect(paths.items.len > 0);
    return paths;
}

fn freePaths(paths: *std.ArrayList([]u8)) void {
    for (paths.items) |path| std.testing.allocator.free(path);
    paths.deinit(std.testing.allocator);
}

test "parser accepts the valid and corpus XML fixtures from reader and slice" {
    const io = std.testing.io;
    for ([_][]const u8{ "fixtures/xml/valid", "fixtures/xml/corpus" }) |root| {
        var paths = try fixturePaths(io, root);
        defer freePaths(&paths);
        for (paths.items) |path| {
            if (try expectReaderSliceParity(io, path)) |err| {
                std.debug.print("{s}: {t}\n", .{ path, err });
                return error.TestUnexpectedResult;
            }
        }
    }
}

test "parser rejects every invalid XML fixture the same way from reader and slice" {
    const io = std.testing.io;
    var paths = try fixturePaths(io, "fixtures/xml/invalid");
    defer freePaths(&paths);
    for (paths.items) |path| {
        if (try expectReaderSliceParity(io, path) == null) {
            std.debug.print("{s}: accepted\n", .{path});
            return error.TestUnexpectedResult;
        }
    }
}

test "parser reader and slice agree on an mzML file across buffer refills" {
    try std.testing.expectEqual(null, try expectReaderSliceParity(std.testing.io, "fixtures/mzml/valid/tiny.pwiz.1.1.mzML"));
}

test "parser applies attribute and text limits at their exact boundaries" {
    const limits: Limits = .{ .max_attribute_bytes = 4, .max_scalar_text_bytes = 4, .max_binary_text_bytes = 8 };
    try std.testing.expectEqual(null, try firstSliceError("<a x=\"1234\"/>", 8, limits));
    try std.testing.expectEqual(@as(?ParseError, error.AttributeTooLong), try firstSliceError("<a x=\"12345\"/>", 8, limits));
    try std.testing.expectEqual(null, try firstSliceError("<a>1234</a>", 8, limits));
    try std.testing.expectEqual(@as(?ParseError, error.ScalarTextTooLong), try firstSliceError("<a>12345</a>", 8, limits));
    // Binary text has its own, larger limit.
    try std.testing.expectEqual(null, try firstSliceError("<binary xmlns=\"" ++ mzml_namespace ++ "\">12345678</binary>", 8, limits));
    try std.testing.expectEqual(@as(?ParseError, error.BinaryTextTooLong), try firstSliceError("<binary xmlns=\"" ++ mzml_namespace ++ "\">123456789</binary>", 8, limits));
}

test "parser applies attribute and namespace counts at their exact boundaries" {
    try std.testing.expectEqual(null, try firstSliceError("<a x=\"1\" y=\"2\"/>", 2, .{}));
    try std.testing.expectEqual(@as(?ParseError, error.TooManyAttributes), try firstSliceError("<a x=\"1\" y=\"2\" z=\"3\"/>", 2, .{}));
    const two = "<a xmlns:p=\"urn:p\" xmlns:q=\"urn:q\"/>";
    const three = "<a xmlns:p=\"urn:p\" xmlns:q=\"urn:q\" xmlns:r=\"urn:r\"/>";
    try std.testing.expectEqual(null, try firstSliceError(two, 8, .{ .max_namespaces = 2 }));
    try std.testing.expectEqual(@as(?ParseError, error.TooManyNamespaces), try firstSliceError(three, 8, .{ .max_namespaces = 2 }));
}

test "parser accepts nesting up to zmz.MAX_DEPTH and rejects one more" {
    const allocator = std.testing.allocator;
    for ([_]usize{ zmz.MAX_DEPTH, zmz.MAX_DEPTH + 1 }) |depth| {
        var xml: std.ArrayList(u8) = .empty;
        defer xml.deinit(allocator);
        for (0..depth) |_| try xml.appendSlice(allocator, "<a>");
        for (0..depth) |_| try xml.appendSlice(allocator, "</a>");
        const expected: ?ParseError = if (depth > zmz.MAX_DEPTH) error.ElementNestingTooDeep else null;
        try std.testing.expectEqual(expected, try firstSliceError(xml.items, 8, .{}));
    }
}

test "parser skips whitespace-only text and reports text and tag offsets" {
    const xml = "<a>\n  <b> x </b>\n</a>";
    var attributes: [8]Attribute = undefined;
    var parser = Parser.initSlice(std.testing.allocator, xml, .{ .attributes = &attributes });
    defer parser.deinit();

    const a = (try parser.next()).?.start_element;
    try std.testing.expectEqual(@as(u64, 0), a.byte_offset);
    try std.testing.expectEqual(@as(?u64, 2), a.end_byte_offset);
    const b = (try parser.next()).?.start_element;
    try std.testing.expectEqualStrings("b", b.name.local_name);
    try std.testing.expectEqual(@as(u64, 6), b.byte_offset);
    const text = (try parser.next()).?.text;
    try std.testing.expectEqualStrings(" x ", text.value);
    try std.testing.expectEqual(@as(u64, 9), text.byte_offset);
    try std.testing.expectEqualStrings("b", (try parser.next()).?.end_element.name.local_name);
    try std.testing.expectEqualStrings("a", (try parser.next()).?.end_element.name.local_name);
    try std.testing.expectEqual(null, try parser.next());
}
