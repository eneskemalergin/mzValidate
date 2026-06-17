//! mzML 1.1.0 element intern IDs for hot-path dispatch.
//!
//! `unknown` covers non-mzML XML and unrecognized local names.
//! Validators call `StartElement.resolvedId` / `EndElement.resolvedId`.

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

pub fn idFromLocalName(local_name: []const u8) ElementId {
    inline for (std.meta.fields(ElementId)) |field| {
        if (!std.mem.eql(u8, field.name, "unknown") and
            std.mem.eql(u8, local_name, field.name))
        {
            return @field(ElementId, field.name);
        }
    }
    return .unknown;
}

pub fn idFromParts(local_name: []const u8, namespace_uri: ?[]const u8) ElementId {
    if (namespace_uri) |ns| {
        if (!std.mem.eql(u8, ns, mzml_namespace)) return .unknown;
    }
    return idFromLocalName(local_name);
}

pub fn resolveId(id: ElementId, local_name: []const u8, namespace_uri: ?[]const u8) ElementId {
    if (id != .unknown) return id;
    return idFromParts(local_name, namespace_uri);
}

pub fn isKnownMzmlLocalName(local_name: []const u8) bool {
    return idFromLocalName(local_name) != .unknown;
}

/// Which validators may do work on a given element tag (start or end event).
/// Used by `runValidation` outer fusion (Slice B.6). Bits are ANDed with the
/// active mask from `CheckOptions` skip flags.
pub const ValidatorMask = packed struct(u4) {
    structural: bool = false,
    binary: bool = false,
    index: bool = false,
    semantic: bool = false,

    pub const none = ValidatorMask{};

    pub fn any(self: ValidatorMask) bool {
        return @as(u4, @bitCast(self)) != 0;
    }

    pub fn intersect(self: ValidatorMask, other: ValidatorMask) ValidatorMask {
        return @bitCast(@as(u4, @bitCast(self)) & @as(u4, @bitCast(other)));
    }
};

pub const mask_table_len = 128;

fn comptimeMask(structural: bool, binary: bool, index: bool, semantic: bool) ValidatorMask {
    return .{
        .structural = structural,
        .binary = binary,
        .index = index,
        .semantic = semantic,
    };
}

/// Hand-traced from structural/binary/index/semantic `switch (tag)` prongs.
/// `false` means the validator is a no-op for that event and may be skipped.
fn startMaskFor(comptime tag: ElementId) ValidatorMask {
    return switch (tag) {
        .unknown => comptimeMask(true, false, false, false),
        .activation, .contact, .isolationWindow, .paramGroupRef, .sourceFileRef, .sourceFileRefList, .target, .targetList =>
            comptimeMask(false, false, false, true),
        .cvParam => comptimeMask(false, true, false, true),
        .userParam => comptimeMask(false, false, false, true),
        .binary => comptimeMask(false, true, false, true),
        .indexedmzML, .mzML, .spectrum, .chromatogram =>
            comptimeMask(true, true, true, true),
        .indexList, .indexListOffset, .fileChecksum =>
            comptimeMask(true, false, true, true),
        .index, .offset => comptimeMask(false, false, true, true),
        .binaryDataArray => comptimeMask(true, true, false, true),
        else => comptimeMask(true, false, false, true),
    };
}

fn endMaskFor(comptime tag: ElementId) ValidatorMask {
    return switch (tag) {
        .unknown, .cv, .cvParam, .userParam => .none,
        .binary, .binaryDataArray, .spectrum, .chromatogram, .mzML =>
            comptimeMask(true, true, false, true),
        .index, .offset, .indexList, .indexListOffset, .fileChecksum =>
            comptimeMask(false, false, true, true),
        .run, .fileDescription, .cvList, .sourceFileList, .referenceableParamGroupList,
        .sampleList, .softwareList, .scanSettingsList, .instrumentConfigurationList,
        .componentList, .instrumentConfiguration, .dataProcessingList, .dataProcessing,
        .spectrumList, .chromatogramList, .scanList, .binaryDataArrayList, .precursorList,
        .productList, .scanWindowList, .selectedIonList =>
            comptimeMask(true, false, false, true),
        else => comptimeMask(false, false, false, true),
    };
}

pub const start_masks: [mask_table_len]ValidatorMask = buildMaskTable(startMaskFor);
pub const end_masks: [mask_table_len]ValidatorMask = buildMaskTable(endMaskFor);

fn buildMaskTable(comptime mask_fn: anytype) [mask_table_len]ValidatorMask {
    var table: [mask_table_len]ValidatorMask = @splat(.none);
    inline for (std.meta.fields(ElementId)) |field| {
        const tag = @field(ElementId, field.name);
        table[@intFromEnum(tag)] = mask_fn(tag);
    }
    return table;
}

pub fn startMask(id: ElementId) ValidatorMask {
    return start_masks[@intFromEnum(id)];
}

pub fn endMask(id: ElementId) ValidatorMask {
    return end_masks[@intFromEnum(id)];
}

pub fn activeMask(skip_binary: bool, skip_index: bool, skip_semantic: bool) ValidatorMask {
    return .{
        .structural = true,
        .binary = !skip_binary,
        .index = !skip_index,
        .semantic = !skip_semantic,
    };
}

// --- Tests ---

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
    const all = comptimeMask(true, true, true, true);
    const sem_only = comptimeMask(false, false, false, true);
    const bin_cv = comptimeMask(false, true, false, true);
    const idx_wrap = comptimeMask(true, false, true, true);

    try std.testing.expectEqual(all, startMask(.spectrum));
    try std.testing.expectEqual(all, startMask(.chromatogram));
    try std.testing.expectEqual(bin_cv, startMask(.cvParam));
    try std.testing.expectEqual(sem_only, startMask(.activation));
    try std.testing.expectEqual(comptimeMask(true, false, false, false), startMask(.unknown));
    try std.testing.expectEqual(idx_wrap, startMask(.indexList));
    try std.testing.expectEqual(comptimeMask(true, true, false, true), endMask(.spectrum));
    try std.testing.expectEqual(ValidatorMask.none, endMask(.cvParam));
    try std.testing.expectEqual(comptimeMask(false, false, true, true), endMask(.offset));
}

test "activeMask respects skip flags" {
    const full = comptimeMask(true, true, true, true);
    const l1 = activeMask(true, false, true);
    try std.testing.expectEqual(comptimeMask(true, false, true, false), l1);
    try std.testing.expectEqual(full, activeMask(false, false, false));
    try std.testing.expectEqual(comptimeMask(true, false, false, false), activeMask(true, true, true));
}

test "dispatch masks align with tiny mzML fixture tags" {
    const xml_parser = @import("../xml/parser.zig");
    const xml_events = @import("../xml/events.zig");

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
