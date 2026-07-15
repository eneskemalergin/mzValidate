//! Event types the streaming parser emits.
//!
//! Every slice field borrows from the parser input or caller-supplied
//! buffers. Text values on the mmap slice path point into the mapped
//! bytes. Other fields use the token buffer. All slices are only valid
//! until the next `Parser.next()` call. Copy anything you need to keep.
//!
//! Types:
//!   StartElement: opening tag with name, attributes, self-closing flag
//!   EndElement:   closing tag
//!   Text:         character data or CDATA (distinguished by `from_cdata`)
//!   Attribute:    one attribute within a start event
//!   QName:        namespace-expanded element or attribute name
//!   Event:        union of the three event kinds
//!   EventKind:    enum discriminators for the union

const std = @import("std");
const elements = @import("../mzml/elements.zig");

pub const ElementId = elements.ElementId;

// --- Types ---

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

// Scans a raw tag byte slice for an attribute value by local name.
// Used when eager attribute parsing was skipped (cvParam/userParam).
fn rawTagAttributeValue(tag_bytes: []const u8, local_name: []const u8) ?[]const u8 {
    var pos: usize = 0;
    while (pos < tag_bytes.len) {
        while (pos < tag_bytes.len and switch (tag_bytes[pos]) {
            ' ', '\t', '\r', '\n' => true,
            else => false,
        }) : (pos += 1) {}
        if (pos >= tag_bytes.len) return null;

        const name_start = pos;
        while (pos < tag_bytes.len and tag_bytes[pos] != '=' and !std.ascii.isWhitespace(tag_bytes[pos])) : (pos += 1) {}
        if (pos >= tag_bytes.len or tag_bytes[pos] != '=') return null;
        if (!std.mem.eql(u8, tag_bytes[name_start..pos], local_name)) {
            pos += 1;
            if (pos >= tag_bytes.len) return null;
            const q = tag_bytes[pos];
            if (q != '"' and q != '\'') return null;
            pos += 1;
            while (pos < tag_bytes.len and tag_bytes[pos] != q) : (pos += 1) {}
            if (pos >= tag_bytes.len) return null;
            pos += 1;
            continue;
        }
        pos += 1;
        if (pos >= tag_bytes.len) return null;
        const q = tag_bytes[pos];
        if (q != '"' and q != '\'') return null;
        pos += 1;
        const val_start = pos;
        while (pos < tag_bytes.len and tag_bytes[pos] != q) : (pos += 1) {}
        return tag_bytes[val_start..pos];
    }
    return null;
}

/// Looks up mzML attributes by local name, ignoring `xmlns*` declarations.
pub fn attributeByLocalName(attributes: []const Attribute, local_name: []const u8) ?[]const u8 {
    for (attributes) |attr| {
        if (attr.is_namespace_declaration) continue;
        if (std.mem.eql(u8, attr.name.local_name, local_name)) return attr.value;
    }
    return null;
}

/// Borrowed attribute views. Valid until the next `Parser.next()` call.
pub const StartElement = struct {
    byte_offset: u64,
    name: QName,
    element_id: ElementId = .unknown,
    attributes: []const Attribute,
    self_closing: bool,
    /// When eager attribute parsing was skipped, raw_tag holds the raw bytes
    /// from the start of the tag name to `>` (exclusive), used by
    /// `rawTagAttributeValue`. Borrows from the parser buffer.
    raw_tag: []const u8 = "",

    /// Intern ID from the parser when set; otherwise derived from the QName.
    pub fn resolvedId(self: StartElement) ElementId {
        return elements.resolveId(
            self.element_id,
            self.name.local_name,
            self.name.namespace_uri,
        );
    }

    /// Looks up an attribute by local name, checking eagerly-parsed attributes
    /// first, then falling back to raw_tag scanning (cvParam/userParam path).
    pub fn attr(self: StartElement, name: []const u8) ?[]const u8 {
        for (self.attributes) |a| {
            if (a.is_namespace_declaration) continue;
            if (std.mem.eql(u8, a.name.local_name, name)) return a.value;
        }
        if (self.raw_tag.len > 0) return rawTagAttributeValue(self.raw_tag, name);
        return null;
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

// --- Tests ---

const diagnostic = @import("../diagnostic.zig");

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
