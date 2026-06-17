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
