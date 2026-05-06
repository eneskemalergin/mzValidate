//! Streaming XML event types shared by the tokenizer and future validators.

const std = @import("std");

/// Identifies the namespace-expanded name of an element or attribute.
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

/// View of one attribute within a start-element event.
pub const Attribute = struct {
    byte_offset: u64,
    name: QName,
    value: []const u8,
    is_namespace_declaration: bool = false,
};

/// Start tag plus borrowed attribute views.
pub const StartElement = struct {
    byte_offset: u64,
    name: QName,
    attributes: []const Attribute,
    self_closing: bool,
};

/// End tag after namespace expansion.
pub const EndElement = struct {
    byte_offset: u64,
    name: QName,
};

/// Text node payload. CDATA is normalized into the same event kind.
pub const Text = struct {
    byte_offset: u64,
    value: []const u8,
    from_cdata: bool = false,
};

/// Kinds emitted by the streaming parser.
pub const EventKind = enum {
    start_element,
    end_element,
    text,
};

/// One parser event. All slices remain valid until the next `Parser.next` call.
pub const Event = union(EventKind) {
    start_element: StartElement,
    end_element: EndElement,
    text: Text,
};
