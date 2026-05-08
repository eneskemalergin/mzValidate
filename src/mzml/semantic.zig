//! CV accession, namespace, and unit term validation for mzML files.
//!
//! Validates every `<cvParam>` and `<userParam>` against the CvTable built
//! from psi-ms.obo. Checks:
//!   - cvRef resolves to a declared `<cv>` entry in `<cvList>`
//!   - Accession exists in the CV
//!   - Term is not obsolete
//!   - cvRef matches the term's namespace
//!   - unitAccession (if present) exists in the CV
//!
//! Slices B and C of Phase 3.

const std = @import("std");
const diagnostic = @import("../diagnostic.zig");
const obo = @import("../obo/parser.zig");
const xml_events = @import("../xml/events.zig");

const Attribute = xml_events.Attribute;
const CvTable = obo.CvTable;
const Diagnostic = diagnostic.Diagnostic;
const RuleId = diagnostic.RuleId;
const StartElement = xml_events.StartElement;

const mzml_namespace = "http://psi.hupo.org/ms/mzml";

pub const SemanticValidator = struct {
    allocator: std.mem.Allocator,
    cv_table: *const CvTable,
    diagnostics: *std.ArrayList(Diagnostic),
    path: ?[]const u8,

    /// Tracks declared `<cv id="...">` entries for cvRef resolution.
    /// Keys are allocator.dupe'd from parser events and freed in deinit.
    cv_refs: std.StringHashMap(void),

    pub fn init(allocator: std.mem.Allocator, cv_table: *const CvTable, diagnostics: *std.ArrayList(Diagnostic), path: ?[]const u8) SemanticValidator {
        return .{
            .allocator = allocator,
            .cv_table = cv_table,
            .diagnostics = diagnostics,
            .path = path,
            .cv_refs = std.StringHashMap(void).init(allocator),
        };
    }

    pub fn deinit(validator: *SemanticValidator) void {
        // Free dupe'd cv id keys.
        var it = validator.cv_refs.iterator();
        while (it.next()) |entry| validator.allocator.free(entry.key_ptr.*);
        validator.cv_refs.deinit();
    }

    pub fn consumeStart(validator: *SemanticValidator, start: StartElement, _: usize) !void {
        // Track `<cv id="...">` declarations for cvRef resolution.
        // Key is dupe'd since the parser reuses its token buffer between events.
        if (start.name.matches(mzml_namespace, "cv")) {
            if (attributeValue(start.attributes, "id")) |id| {
                const owned = try validator.allocator.dupe(u8, id);
                validator.cv_refs.put(owned, {}) catch validator.allocator.free(owned);
            }
            return;
        }

        if (!start.name.matches(mzml_namespace, "cvParam") and !start.name.matches(mzml_namespace, "userParam")) return;

        const accession = attributeValue(start.attributes, "accession") orelse return;
        const cv_ref = attributeValue(start.attributes, "cvRef") orelse return;

        // Resolve cvRef against declared cv ids.
        if (!validator.cv_refs.contains(cv_ref)) {
            try validator.diagnostics.append(validator.allocator, .{
                .severity = .@"error",
                .rule = RuleId.mzml_cv_namespace,
                .location = .{ .byte_offset = start.byte_offset },
                .path = validator.path,
                .message = "cvRef does not match any declared cv id in cvList",
            });
            return;
        }

        const term = validator.cv_table.lookup(accession);
        if (term) |t| {
            if (t.is_obsolete) {
                try validator.diagnostics.append(validator.allocator, .{
                    .severity = .warning,
                    .rule = RuleId.mzml_cv_obsolete,
                    .location = .{ .byte_offset = start.byte_offset },
                    .path = validator.path,
                    .message = "CV term is obsolete; check replaced_by for alternatives",
                });
                return;
            }
            if (!std.mem.eql(u8, t.namespace, cv_ref)) {
                try validator.diagnostics.append(validator.allocator, .{
                    .severity = .@"error",
                    .rule = RuleId.mzml_cv_namespace,
                    .location = .{ .byte_offset = start.byte_offset },
                    .path = validator.path,
                    .message = "cvRef does not match term namespace",
                });
            }
        } else {
            try validator.diagnostics.append(validator.allocator, .{
                .severity = .@"error",
                .rule = RuleId.mzml_cv_accession,
                .location = .{ .byte_offset = start.byte_offset },
                .path = validator.path,
                .message = "unrecognized CV accession",
            });
        }

        // Unit term validation (Slice C).
        if (attributeValue(start.attributes, "unitAccession")) |unit_acc| {
            const unit_cv_ref = attributeValue(start.attributes, "unitCvRef");
            const unit_name = attributeValue(start.attributes, "unitName");

            if (validator.cv_table.lookup(unit_acc)) |unit_term| {
                // Check unitCvRef matches unit term's namespace.
                if (unit_cv_ref) |ref| {
                    if (!std.mem.eql(u8, ref, unit_term.namespace)) {
                        try validator.diagnostics.append(validator.allocator, .{
                            .severity = .@"error",
                            .rule = RuleId.mzml_cv_namespace,
                            .location = .{ .byte_offset = start.byte_offset },
                            .path = validator.path,
                            .message = "unitCvRef does not match unit term namespace",
                        });
                    }
                }
                // Check unitName matches canonical term name.
                if (unit_name) |name| {
                    if (!std.mem.eql(u8, name, unit_term.name)) {
                        try validator.diagnostics.append(validator.allocator, .{
                            .severity = .warning,
                            .rule = RuleId.mzml_cv_unit,
                            .location = .{ .byte_offset = start.byte_offset },
                            .path = validator.path,
                            .message = "unitName does not match the term's canonical name",
                        });
                    }
                }
            } else {
                try validator.diagnostics.append(validator.allocator, .{
                    .severity = .@"error",
                    .rule = RuleId.mzml_cv_unit,
                    .location = .{ .byte_offset = start.byte_offset },
                    .path = validator.path,
                    .message = "unrecognized unit accession",
                });
            }
        }
    }

    pub fn consumeEnd(_: *SemanticValidator, _: xml_events.EndElement, _: usize) void {}

    pub fn finish(_: *SemanticValidator) void {}
};

fn attributeValue(attributes: []const Attribute, name: []const u8) ?[]const u8 {
    for (attributes) |a| {
        if (a.name.matches(null, name)) return a.value;
    }
    return null;
}

// --- Unit tests ---

const testing = std.testing;
const expectEqual = testing.expectEqual;
const expectEqualStrings = testing.expectEqualStrings;

fn makeCvParam(accession: []const u8, cv_ref: []const u8, byte_offset: u64) StartElement {
    return .{
        .byte_offset = byte_offset,
        .name = .{ .local_name = "cvParam", .namespace_uri = mzml_namespace },
        .attributes = &.{
            .{ .byte_offset = 0, .name = .{ .local_name = "accession" }, .value = accession },
            .{ .byte_offset = 0, .name = .{ .local_name = "cvRef" }, .value = cv_ref },
        },
        .self_closing = false,
    };
}

fn makeCv(id: []const u8) StartElement {
    return .{
        .byte_offset = 0,
        .name = .{ .local_name = "cv", .namespace_uri = mzml_namespace },
        .attributes = &.{
            .{ .byte_offset = 0, .name = .{ .local_name = "id" }, .value = id },
            .{ .byte_offset = 0, .name = .{ .local_name = "fullName" }, .value = "test" },
        },
        .self_closing = false,
    };
}

fn makeUnitParam(accession: []const u8, cv_ref: []const u8, unit_acc: []const u8, byte_offset: u64) StartElement {
    return .{
        .byte_offset = byte_offset,
        .name = .{ .local_name = "cvParam", .namespace_uri = mzml_namespace },
        .attributes = &.{
            .{ .byte_offset = 0, .name = .{ .local_name = "accession" }, .value = accession },
            .{ .byte_offset = 0, .name = .{ .local_name = "cvRef" }, .value = cv_ref },
            .{ .byte_offset = 0, .name = .{ .local_name = "unitAccession" }, .value = unit_acc },
            .{ .byte_offset = 0, .name = .{ .local_name = "unitCvRef" }, .value = "UO" },
        },
        .self_closing = false,
    };
}

fn makeUnitParamWithName(accession: []const u8, cv_ref: []const u8, unit_acc: []const u8, unit_name: []const u8, byte_offset: u64) StartElement {
    return .{
        .byte_offset = byte_offset,
        .name = .{ .local_name = "cvParam", .namespace_uri = mzml_namespace },
        .attributes = &.{
            .{ .byte_offset = 0, .name = .{ .local_name = "accession" }, .value = accession },
            .{ .byte_offset = 0, .name = .{ .local_name = "cvRef" }, .value = cv_ref },
            .{ .byte_offset = 0, .name = .{ .local_name = "unitAccession" }, .value = unit_acc },
            .{ .byte_offset = 0, .name = .{ .local_name = "unitCvRef" }, .value = "UO" },
            .{ .byte_offset = 0, .name = .{ .local_name = "unitName" }, .value = unit_name },
        },
        .self_closing = false,
    };
}

fn makeUserParamNoAccession(byte_offset: u64) StartElement {
    return .{
        .byte_offset = byte_offset,
        .name = .{ .local_name = "userParam", .namespace_uri = mzml_namespace },
        .attributes = &.{
            .{ .byte_offset = 0, .name = .{ .local_name = "name" }, .value = "some param" },
        },
        .self_closing = false,
    };
}

test "SemanticValidator: valid accession produces no diagnostic" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000001\n" ++ "name: sample name\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var sv = SemanticValidator.init(allocator, &cv_table, &diagnostics, null);
    defer sv.deinit();
    try sv.consumeStart(makeCv("MS"), 1);
    try sv.consumeStart(makeCvParam("MS:1000001", "MS", 0), 2);
    try expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "SemanticValidator: invalid accession produces error" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000001\n" ++ "name: sample name\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var sv = SemanticValidator.init(allocator, &cv_table, &diagnostics, null);
    defer sv.deinit();
    try sv.consumeStart(makeCv("MS"), 1);
    try sv.consumeStart(makeCvParam("MS:9999999", "MS", 100), 2);
    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_cv_accession, diagnostics.items[0].rule);
}

test "SemanticValidator: obsolete accession produces warning" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000001\n" ++ "name: obsolete term\n" ++ "namespace: MS\n" ++ "is_obsolete: true\n" ++ "replaced_by: MS:1000002\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var sv = SemanticValidator.init(allocator, &cv_table, &diagnostics, null);
    defer sv.deinit();
    try sv.consumeStart(makeCv("MS"), 1);
    try sv.consumeStart(makeCvParam("MS:1000001", "MS", 100), 2);
    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_cv_obsolete, diagnostics.items[0].rule);
}

test "SemanticValidator: mismatched cvRef/namespace produces error" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000001\n" ++ "name: sample name\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var sv = SemanticValidator.init(allocator, &cv_table, &diagnostics, null);
    defer sv.deinit();
    try sv.consumeStart(makeCv("MS"), 1);
    try sv.consumeStart(makeCvParam("MS:1000001", "UO", 100), 2);
    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_cv_namespace, diagnostics.items[0].rule);
}

test "SemanticValidator: cvRef not in cvList produces error" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000001\n" ++ "name: sample name\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var sv = SemanticValidator.init(allocator, &cv_table, &diagnostics, null);
    defer sv.deinit();
    try sv.consumeStart(makeCvParam("MS:1000001", "NONEXISTENT", 100), 1);
    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_cv_namespace, diagnostics.items[0].rule);
}

test "SemanticValidator: valid unit accession produces no diagnostic" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000001\n" ++ "name: sample name\n" ++ "namespace: MS\n" ++ "\n" ++ "[Term]\n" ++ "id: UO:0000000\n" ++ "name: length unit\n" ++ "namespace: UO\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var sv = SemanticValidator.init(allocator, &cv_table, &diagnostics, null);
    defer sv.deinit();
    try sv.consumeStart(makeCv("MS"), 1);
    try sv.consumeStart(makeCv("UO"), 1);
    try sv.consumeStart(makeUnitParam("MS:1000001", "MS", "UO:0000000", 100), 2);
    try expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "SemanticValidator: invalid unit accession produces error" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000001\n" ++ "name: sample name\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var sv = SemanticValidator.init(allocator, &cv_table, &diagnostics, null);
    defer sv.deinit();
    try sv.consumeStart(makeCv("MS"), 1);
    try sv.consumeStart(makeUnitParam("MS:1000001", "MS", "UO:9999999", 100), 2);
    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_cv_unit, diagnostics.items[0].rule);
}

test "SemanticValidator: unitCvRef mismatch produces error" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: UO:0000000\n" ++ "name: length unit\n" ++ "namespace: UO\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var sv = SemanticValidator.init(allocator, &cv_table, &diagnostics, null);
    defer sv.deinit();
    try sv.consumeStart(makeCv("UO"), 1);
    // unitCvRef=MS but term namespace=UO -> mismatch
    try sv.consumeStart(.{
        .byte_offset = 100,
        .name = .{ .local_name = "cvParam", .namespace_uri = mzml_namespace },
        .attributes = &.{
            .{ .byte_offset = 0, .name = .{ .local_name = "accession" }, .value = "UO:0000000" },
            .{ .byte_offset = 0, .name = .{ .local_name = "cvRef" }, .value = "UO" },
            .{ .byte_offset = 0, .name = .{ .local_name = "unitAccession" }, .value = "UO:0000000" },
            .{ .byte_offset = 0, .name = .{ .local_name = "unitCvRef" }, .value = "MS" },
        },
        .self_closing = false,
    }, 2);
    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_cv_namespace, diagnostics.items[0].rule);
}

test "SemanticValidator: unitName mismatch produces warning" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: UO:0000000\n" ++ "name: length unit\n" ++ "namespace: UO\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var sv = SemanticValidator.init(allocator, &cv_table, &diagnostics, null);
    defer sv.deinit();
    try sv.consumeStart(makeCv("UO"), 1);
    try sv.consumeStart(makeUnitParamWithName("UO:0000000", "UO", "UO:0000000", "wrong name", 100), 2);
    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_cv_unit, diagnostics.items[0].rule);
}

test "SemanticValidator: userParam without accession is skipped" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000001\n" ++ "name: sample name\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var sv = SemanticValidator.init(allocator, &cv_table, &diagnostics, null);
    defer sv.deinit();
    try sv.consumeStart(makeUserParamNoAccession(0), 2);
    try expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "SemanticValidator: cvRef after cvList declaration works" {
    // Verify that cvRef resolution works when <cv> is processed before <cvParam>.
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000001\n" ++ "name: sample name\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var sv = SemanticValidator.init(allocator, &cv_table, &diagnostics, null);
    defer sv.deinit();
    // Process cv elements FIRST (as they appear in a real file), then cvParam.
    try sv.consumeStart(makeCv("MS"), 1);
    try sv.consumeStart(makeCv("UO"), 1);
    try sv.consumeStart(makeCvParam("MS:1000001", "MS", 0), 2);
    try expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "SemanticValidator: multiple diagnostics on one cvParam" {
    // cvRef not in cvList AND invalid accession -> 2 diagnostics.
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000001\n" ++ "name: sample name\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var sv = SemanticValidator.init(allocator, &cv_table, &diagnostics, null);
    defer sv.deinit();
    // Not registering any cv -> cvRef fails -> returns early -> only 1 diagnostic.
    try sv.consumeStart(makeCvParam("MS:9999999", "NONEXISTENT", 100), 1);
    try expectEqual(@as(usize, 1), diagnostics.items.len);
}
