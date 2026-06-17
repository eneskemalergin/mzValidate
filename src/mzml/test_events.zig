//! Hand-built XML events for inline unit tests in sibling mzML validators.
//!
//! Default `element_id` is `.unknown` so tests hit `resolvedId()` name
//! fallback like hand-built events in the wild. Use `.interned` when the
//! parser-filled id is the point of the test.

const diagnostic = @import("../diagnostic.zig");
const elements = @import("elements.zig");
const xml_events = @import("../xml/events.zig");

pub const mzml_namespace = diagnostic.mzml_namespace;
pub const Attribute = xml_events.Attribute;
pub const ElementId = xml_events.ElementId;
pub const EndElement = xml_events.EndElement;
pub const StartElement = xml_events.StartElement;
pub const Text = xml_events.Text;

pub const IdMode = enum {
    unknown,
    interned,
};

fn resolveElementId(local_name: []const u8, id_mode: IdMode) ElementId {
    return switch (id_mode) {
        .unknown => .unknown,
        .interned => elements.idFromParts(local_name, mzml_namespace),
    };
}

pub fn attr(name: []const u8, value: []const u8) Attribute {
    return .{ .byte_offset = 0, .name = .{ .local_name = name }, .value = value };
}

pub fn text(value: []const u8) Text {
    return .{ .byte_offset = 0, .value = value, .from_cdata = false };
}

pub fn start(
    local_name: []const u8,
    attributes: []const Attribute,
    byte_offset: u64,
    id_mode: IdMode,
) StartElement {
    return .{
        .byte_offset = byte_offset,
        .name = .{ .local_name = local_name, .namespace_uri = mzml_namespace },
        .element_id = resolveElementId(local_name, id_mode),
        .attributes = attributes,
        .self_closing = false,
    };
}

pub fn end(local_name: []const u8, byte_offset: u64, id_mode: IdMode) EndElement {
    return .{
        .byte_offset = byte_offset,
        .name = .{ .local_name = local_name, .namespace_uri = mzml_namespace },
        .element_id = resolveElementId(local_name, id_mode),
    };
}

pub fn startUnknown(local_name: []const u8, attributes: []const Attribute, byte_offset: u64) StartElement {
    return start(local_name, attributes, byte_offset, .unknown);
}

pub fn endUnknown(local_name: []const u8) EndElement {
    return end(local_name, 0, .unknown);
}

pub fn startInterned(local_name: []const u8, attributes: []const Attribute, byte_offset: u64) StartElement {
    return start(local_name, attributes, byte_offset, .interned);
}

pub fn endInterned(local_name: []const u8, byte_offset: u64) EndElement {
    return end(local_name, byte_offset, .interned);
}
