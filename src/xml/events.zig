//! Borrowed event values emitted by the streaming XML parser.
//!
//! Slice fields reference parser input or caller scratch and remain valid only
//! until the next `Parser.next()` call. Reader text may span multiple events;
//! slice text may point directly into caller-provided bytes.

const std = @import("std");
const elements = @import("../mzml/elements.zig");

pub const ElementId = elements.ElementId;

pub const QName = struct {
    prefix: ?[]const u8 = null,
    local_name: []const u8,
    namespace_uri: ?[]const u8 = null,

    /// Compares a resolved name against the namespace and local name expected by rules.
    pub fn matches(name: QName, namespace_uri: ?[]const u8, local_name: []const u8) bool {
        if (!std.mem.eql(u8, name.local_name, local_name)) return false;
        if (name.namespace_uri) |actual| {
            if (namespace_uri) |expected| {
                return std.mem.eql(u8, actual, expected);
            }
            return false;
        }
        return namespace_uri == null;
    }
};

pub const Attribute = struct {
    byte_offset: u64,
    name: QName,
    value: []const u8,
    is_namespace_declaration: bool = false,
};

/// Looks up an unqualified mzML attribute by local name.
pub fn attributeByLocalName(attributes: []const Attribute, local_name: []const u8) ?[]const u8 {
    for (attributes) |attribute| {
        if (attribute.is_namespace_declaration or attribute.name.prefix != null or attribute.name.namespace_uri != null) continue;
        if (std.mem.eql(u8, attribute.name.local_name, local_name)) return attribute.value;
    }
    return null;
}

/// Opening-tag event whose slice fields expire at the next `Parser.next()` call.
pub const StartElement = struct {
    byte_offset: u64,
    /// Byte offset of the opening tag's closing `>` when emitted by Parser.
    end_byte_offset: ?u64 = null,
    name: QName,
    element_id: ElementId = .unknown,
    attributes: []const Attribute,
    self_closing: bool,

    /// Intern ID from the parser when set; otherwise derived from the QName.
    pub fn resolvedId(self: StartElement) ElementId {
        return elements.resolveId(
            self.element_id,
            self.name.local_name,
            self.name.namespace_uri,
        );
    }

    /// Looks up an unqualified attribute by local name.
    pub fn attr(self: StartElement, local_name: []const u8) ?[]const u8 {
        return attributeByLocalName(self.attributes, local_name);
    }
};

pub const EndElement = struct {
    byte_offset: u64,
    name: QName,
    element_id: ElementId = .unknown,

    /// Intern ID from the parser when set; otherwise derived from the QName.
    pub fn resolvedId(self: EndElement) ElementId {
        return elements.resolveId(
            self.element_id,
            self.name.local_name,
            self.name.namespace_uri,
        );
    }
};

/// `from_cdata` distinguishes CDATA from normal text. Reader-backed text can
/// span events; `is_final` marks the last chunk of that logical text node.
pub const Text = struct {
    byte_offset: u64,
    value: []const u8,
    from_cdata: bool = false,
    is_final: bool = true,
};

pub const EventKind = enum {
    start_element,
    end_element,
    text,
};

/// All slices remain valid until the next `Parser.next()` call.
pub const Event = union(EventKind) {
    start_element: StartElement,
    end_element: EndElement,
    text: Text,
};

// --- Unit Tests ---

test "StartElement.resolvedId prefers parser intern id" {
    const start = StartElement{
        .byte_offset = 0,
        .name = .{ .local_name = "spectrum", .namespace_uri = diagnostic.mzml_namespace },
        .element_id = .chromatogram,
        .attributes = &.{},
        .self_closing = false,
    };

    try std.testing.expectEqual(ElementId.chromatogram, start.resolvedId());
}

test "StartElement.resolvedId falls back to element name" {
    const start = StartElement{
        .byte_offset = 0,
        .name = .{ .local_name = "cvParam", .namespace_uri = diagnostic.mzml_namespace },
        .attributes = &.{},
        .self_closing = false,
    };

    try std.testing.expectEqual(ElementId.cvParam, start.resolvedId());
}

test "EndElement.resolvedId matches start for same local name" {
    const name = QName{ .local_name = "source", .namespace_uri = diagnostic.mzml_namespace };
    const start = StartElement{
        .byte_offset = 0,
        .name = name,
        .element_id = .source,
        .attributes = &.{},
        .self_closing = false,
    };
    const end = EndElement{ .byte_offset = 10, .name = name, .element_id = .unknown };

    try std.testing.expectEqual(start.resolvedId(), end.resolvedId());
}

test "StartElement.attr accepts only unqualified attributes" {
    const attributes = [_]Attribute{
        .{ .byte_offset = 2, .name = .{ .prefix = "p", .local_name = "id", .namespace_uri = "urn:test" }, .value = "foreign" },
        .{ .byte_offset = 1, .name = .{ .local_name = "id" }, .value = "plain" },
    };
    const start = StartElement{
        .byte_offset = 0,
        .name = .{ .local_name = "cvParam" },
        .attributes = &attributes,
        .self_closing = true,
    };

    try std.testing.expectEqualStrings("plain", start.attr("id").?);
}

const diagnostic = @import("../diagnostic.zig");
