//! XML event types produced by the streaming parser.
//!
//! All slice fields borrow from the parser's caller-supplied buffers and
//! are only valid until the next `Parser.next()` call. Consumers that need
//! to retain a value across calls must copy it.

const std = @import("std");

// --- Types ---

/// Namespace-expanded element or attribute name.
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

/// Start tag with borrowed attribute views. Valid until the next `Parser.next()` call.
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

/// Text node or decoded CDATA section. Both surfaces as the same event kind.
/// `from_cdata` lets validators warn about CDATA if the schema prohibits it.
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
