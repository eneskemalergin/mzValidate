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

/// Borrowed attribute views. Valid until the next `Parser.next()` call.
pub const StartElement = struct {
    byte_offset: u64,
    name: QName,
    attributes: []const Attribute,
    self_closing: bool,
};

pub const EndElement = struct {
    byte_offset: u64,
    name: QName,
};

/// `from_cdata` distinguishes CDATA from normal text, so validators can
/// warn about CDATA usage if the schema prohibits it.
pub const Text = struct {
    byte_offset: u64,
    value: []const u8,
    from_cdata: bool = false,
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
