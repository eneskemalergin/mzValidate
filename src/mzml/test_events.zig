//! Hand-built XML events for inline unit tests in sibling mzML validators.
//!
//! Default `element_id` is `.unknown` so tests hit `resolvedId()` name
//! fallback like hand-built events in the wild. Use `.interned` when the
//! parser-filled id is the point of the test.

const std = @import("std");
const diagnostic = @import("../diagnostic.zig");
const xml_events = @import("../xml/events.zig");
const elements = @import("elements.zig");

pub fn attr(name: []const u8, value: []const u8) xml_events.Attribute {
    return .{ .byte_offset = 0, .name = .{ .local_name = name }, .value = value };
}

pub fn text(value: []const u8) xml_events.Text {
    return .{ .byte_offset = 0, .value = value, .from_cdata = false };
}

pub fn startUnknown(local_name: []const u8, attributes: []const xml_events.Attribute, byte_offset: u64) xml_events.StartElement {
    return start(local_name, attributes, byte_offset, .unknown);
}

pub fn endUnknown(local_name: []const u8) xml_events.EndElement {
    return end(local_name, 0, .unknown);
}

pub fn startInterned(local_name: []const u8, attributes: []const xml_events.Attribute, byte_offset: u64) xml_events.StartElement {
    return start(local_name, attributes, byte_offset, .interned);
}

pub fn endInterned(local_name: []const u8, byte_offset: u64) xml_events.EndElement {
    return end(local_name, byte_offset, .interned);
}

const mzml_namespace = diagnostic.mzml_namespace;

const IdMode = enum {
    unknown,
    interned,
};

fn resolveElementId(local_name: []const u8, id_mode: IdMode) xml_events.ElementId {
    return switch (id_mode) {
        .unknown => .unknown,
        .interned => elements.idFromParts(local_name, mzml_namespace),
    };
}

fn start(
    local_name: []const u8,
    attributes: []const xml_events.Attribute,
    byte_offset: u64,
    id_mode: IdMode,
) xml_events.StartElement {
    return .{
        .byte_offset = byte_offset,
        .name = .{ .local_name = local_name, .namespace_uri = mzml_namespace },
        .element_id = resolveElementId(local_name, id_mode),
        .attributes = attributes,
        .self_closing = false,
    };
}

fn end(local_name: []const u8, byte_offset: u64, id_mode: IdMode) xml_events.EndElement {
    return .{
        .byte_offset = byte_offset,
        .name = .{ .local_name = local_name, .namespace_uri = mzml_namespace },
        .element_id = resolveElementId(local_name, id_mode),
    };
}
