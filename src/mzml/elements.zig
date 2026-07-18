//! mzML 1.1.0 element intern IDs and comptime validation dispatch masks.
//!
//! `unknown` covers non-mzML XML and unrecognized local names.

const std = @import("std");
const diagnostic = @import("../diagnostic.zig");

const mzml_namespace = diagnostic.mzml_namespace;

/// Fits in `u7`; one ID per mzML 1.1.0 schema element name.
pub const ElementId = enum(u7) {
    unknown = 0,
    activation,
    analyzer,
    binary,
    binaryDataArray,
    binaryDataArrayList,
    chromatogram,
    chromatogramList,
    componentList,
    contact,
    cv,
    cvList,
    cvParam,
    dataProcessing,
    dataProcessingList,
    detector,
    fileChecksum,
    fileContent,
    fileDescription,
    index,
    indexList,
    indexListOffset,
    indexedmzML,
    instrumentConfiguration,
    instrumentConfigurationList,
    isolationWindow,
    mzML,
    offset,
    paramGroupRef,
    precursor,
    precursorList,
    processingMethod,
    product,
    productList,
    referenceableParamGroup,
    referenceableParamGroupList,
    referenceableParamGroupRef,
    run,
    sample,
    sampleList,
    scan,
    scanList,
    scanSettings,
    scanSettingsList,
    scanWindow,
    scanWindowList,
    selectedIon,
    selectedIonList,
    software,
    softwareList,
    softwareRef,
    source,
    sourceFile,
    sourceFileList,
    sourceFileRef,
    sourceFileRefList,
    spectrum,
    spectrumList,
    target,
    targetList,
    userParam,
};

const element_map = blk: {
    const fields = std.meta.fields(ElementId);
    var kv: [fields.len]struct { []const u8, ElementId } = undefined;
    var i: usize = 0;
    for (fields) |f| {
        if (std.mem.eql(u8, f.name, "unknown")) continue;
        kv[i] = .{ f.name, @field(ElementId, f.name) };
        i += 1;
    }
    break :blk std.StaticStringMap(ElementId).initComptime(kv[0..i]);
};

/// Maps a local name to an intern ID, or `.unknown` when unrecognized.
pub fn idFromLocalName(local_name: []const u8) ElementId {
    return element_map.get(local_name) orelse .unknown;
}

/// Rejects an explicitly foreign namespace; an absent URI preserves local-name lookup.
pub fn idFromParts(local_name: []const u8, namespace_uri: ?[]const u8) ElementId {
    if (namespace_uri) |ns| {
        if (!std.mem.eql(u8, ns, mzml_namespace)) return .unknown;
    }
    return idFromLocalName(local_name);
}

/// Parser intern ID when known; otherwise falls back to QName lookup.
pub fn resolveId(id: ElementId, local_name: []const u8, namespace_uri: ?[]const u8) ElementId {
    if (id != .unknown) return id;
    return idFromParts(local_name, namespace_uri);
}

pub fn isKnownMzmlLocalName(local_name: []const u8) bool {
    return idFromLocalName(local_name) != .unknown;
}

/// Per-tag fusion mask for index and semantic validators in `runValidation`.
/// Structural and binary validators are always invoked on the hot path; only
/// these bits gate `IndexValidator` / `SemanticValidator` calls.
pub const IndexSemanticMask = packed struct(u2) {
    index: bool = false,
    semantic: bool = false,

    pub const none = IndexSemanticMask{};

    pub fn any(self: IndexSemanticMask) bool {
        return @as(u2, @bitCast(self)) != 0;
    }

    pub fn intersect(self: IndexSemanticMask, other: IndexSemanticMask) IndexSemanticMask {
        return @bitCast(@as(u2, @bitCast(self)) & @as(u2, @bitCast(other)));
    }
};

pub const mask_table_len = 128;

fn comptimeMask(index: bool, semantic: bool) IndexSemanticMask {
    return .{ .index = index, .semantic = semantic };
}

// Hand-traced from index/semantic `switch (tag)` prongs. A false bit means
// that validator is a no-op for the event and may be skipped.
fn startMaskFor(comptime tag: ElementId) IndexSemanticMask {
    return switch (tag) {
        .unknown => .none,
        .activation, .contact, .isolationWindow, .paramGroupRef, .sourceFileRef, .sourceFileRefList, .target, .targetList => comptimeMask(false, true),
        .cvParam, .userParam, .binary => comptimeMask(false, true),
        .indexedmzML, .mzML, .spectrumList, .chromatogramList, .spectrum, .chromatogram => comptimeMask(true, true),
        .indexList, .indexListOffset, .fileChecksum, .index, .offset => comptimeMask(true, true),
        .binaryDataArray => comptimeMask(false, true),
        else => comptimeMask(false, true),
    };
}

fn endMaskFor(comptime tag: ElementId) IndexSemanticMask {
    return switch (tag) {
        .unknown, .cv, .cvParam, .userParam => .none,
        .index, .offset, .indexList, .indexListOffset, .fileChecksum => comptimeMask(true, true),
        else => comptimeMask(false, true),
    };
}

/// Comptime tables: which index/semantic handlers may run per start tag.
pub const start_masks: [mask_table_len]IndexSemanticMask = buildMaskTable(startMaskFor);
/// Comptime tables: which index/semantic handlers may run per end tag.
pub const end_masks: [mask_table_len]IndexSemanticMask = buildMaskTable(endMaskFor);

fn buildMaskTable(comptime mask_fn: anytype) [mask_table_len]IndexSemanticMask {
    var table: [mask_table_len]IndexSemanticMask = @splat(.none);
    inline for (std.meta.fields(ElementId)) |field| {
        const tag = @field(ElementId, field.name);
        table[@intFromEnum(tag)] = mask_fn(tag);
    }
    return table;
}

pub fn startMask(id: ElementId) IndexSemanticMask {
    return start_masks[@intFromEnum(id)];
}

pub fn endMask(id: ElementId) IndexSemanticMask {
    return end_masks[@intFromEnum(id)];
}

/// Applies CLI skip flags to the fusion mask (`skip_binary` is handled separately).
pub fn activeMask(_skip_binary: bool, skip_index: bool, skip_semantic: bool) IndexSemanticMask {
    _ = _skip_binary;
    return .{
        .index = !skip_index,
        .semantic = !skip_semantic,
    };
}

// --- Unit Tests ---

test "idFromLocalName maps schema element names" {
    try std.testing.expectEqual(ElementId.spectrum, idFromLocalName("spectrum"));
    try std.testing.expectEqual(ElementId.indexedmzML, idFromLocalName("indexedmzML"));
    try std.testing.expectEqual(ElementId.unknown, idFromLocalName("notAnElement"));
}

test "every ElementId tag maps back from its local name" {
    inline for (std.meta.fields(ElementId)) |field| {
        if (!std.mem.eql(u8, field.name, "unknown")) {
            try std.testing.expectEqual(
                @field(ElementId, field.name),
                idFromLocalName(field.name),
            );
        }
    }
}

test "idFromParts rejects foreign namespaces" {
    try std.testing.expectEqual(ElementId.unknown, idFromParts("spectrum", "urn:other"));
}

test "every non-unknown ElementId has a dispatch mask" {
    inline for (std.meta.fields(ElementId)) |field| {
        if (comptime std.mem.eql(u8, field.name, "unknown")) continue;
        const tag = @field(ElementId, field.name);
        const start = start_masks[@intFromEnum(tag)];
        const end = end_masks[@intFromEnum(tag)];
        try std.testing.expect(start.any() or end.any());
    }
}

test "dispatch mask tables match comptime tracers" {
    inline for (std.meta.fields(ElementId)) |field| {
        const tag = @field(ElementId, field.name);
        try std.testing.expectEqual(startMaskFor(tag), start_masks[@intFromEnum(tag)]);
        try std.testing.expectEqual(endMaskFor(tag), end_masks[@intFromEnum(tag)]);
    }
}

test "dispatch masks hand-traced spot checks" {
    const index_and_semantic = comptimeMask(true, true);
    const sem_only = comptimeMask(false, true);

    try std.testing.expectEqual(index_and_semantic, startMask(.spectrum));
    try std.testing.expectEqual(index_and_semantic, startMask(.chromatogram));
    try std.testing.expectEqual(index_and_semantic, startMask(.spectrumList));
    try std.testing.expectEqual(index_and_semantic, startMask(.chromatogramList));
    try std.testing.expectEqual(sem_only, startMask(.cvParam));
    try std.testing.expectEqual(sem_only, startMask(.activation));
    try std.testing.expectEqual(IndexSemanticMask.none, startMask(.unknown));
    try std.testing.expectEqual(index_and_semantic, startMask(.indexList));
    try std.testing.expectEqual(sem_only, endMask(.spectrum));
    try std.testing.expectEqual(IndexSemanticMask.none, endMask(.cvParam));
    try std.testing.expectEqual(index_and_semantic, endMask(.offset));
}

test "activeMask respects skip flags" {
    try std.testing.expectEqual(comptimeMask(true, true), activeMask(false, false, false));
    try std.testing.expectEqual(comptimeMask(true, false), activeMask(true, false, true));
    try std.testing.expectEqual(IndexSemanticMask.none, activeMask(true, true, true));
}

test "dispatch masks align with tiny mzML fixture tags" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const xml = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/valid/tiny.pwiz.1.1.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(xml);
    const token_buffer = try allocator.alloc(u8, 1024 * 1024);
    defer allocator.free(token_buffer);
    var attributes: [64]xml_events.Attribute = undefined;
    var namespace_bindings: [32]xml_parser.NamespaceBinding = undefined;
    var namespace_bytes: [2048]u8 = undefined;
    var element_stack: [128]xml_parser.ElementFrame = undefined;
    var element_bytes: [4096]u8 = undefined;

    var parser = xml_parser.Parser.initSlice(xml, .{
        .token = token_buffer,
        .attributes = &attributes,
        .namespace_bindings = &namespace_bindings,
        .namespace_bytes = &namespace_bytes,
        .element_stack = &element_stack,
        .element_bytes = &element_bytes,
    });

    while (try parser.next()) |event| {
        switch (event) {
            .start_element => |start| {
                const tag = start.resolvedId();
                const mask = startMask(tag);
                try std.testing.expect(mask.any());
            },
            .end_element => |end| {
                const tag = end.resolvedId();
                const mask = endMask(tag);
                if (tag != .cv and tag != .cvParam and tag != .userParam) {
                    try std.testing.expect(mask.semantic);
                }
            },
            .text => {},
        }
    }
}

const xml_parser = @import("../xml/parser.zig");
const xml_events = @import("../xml/events.zig");
