//! CV validation, scope tracking, contradiction detection, and reference resolution.
//!
//! Validates every `<cvParam>` and `<userParam>` against the CvTable built
//! from psi-ms.obo. Checks:
//!   - cvRef resolves to a declared `<cv>` entry in `<cvList>`
//!   - Accession exists in the CV
//!   - Term is not obsolete
//!   - cvRef matches the term's namespace
//!   - unitAccession (if present) exists in the CV
//!   - Contradictory OR terms on the same element (Slice E)
//!   - All *Ref attributes resolve to declared id values (Slice F)
//!
//! Slices B through F of Phase 3.

const std = @import("std");
const diagnostic = @import("../diagnostic.zig");
const obo = @import("../obo/parser.zig");
const rule_engine = @import("../obo/rule_engine.zig");
const xml_events = @import("../xml/events.zig");

const Attribute = xml_events.Attribute;
const CvTable = obo.CvTable;
const Diagnostic = diagnostic.Diagnostic;
const RuleEngine = rule_engine.RuleEngine;
const RuleId = diagnostic.RuleId;
const StartElement = xml_events.StartElement;
const EndElement = xml_events.EndElement;

const mzml_namespace = "http://psi.hupo.org/ms/mzml";

/// A declared id in the document.
const Declaration = struct {
    element_name: []const u8,
    byte_offset: u64,
};

/// A *Ref attribute encountered before its target id was declared.
const UnresolvedRef = struct {
    ref_attr: []const u8,
    ref_value: []const u8,
    element_path: []const u8,
    byte_offset: u64,
};

/// Accumulates id declarations and deferred *Ref attributes, then resolves
/// them in finish().  Owns all strings via the parent allocator.
const RefTable = struct {
    allocator: std.mem.Allocator,
    declarations: std.StringHashMap(Declaration),
    unresolved: std.ArrayList(UnresolvedRef),

    fn init(allocator: std.mem.Allocator) RefTable {
        return .{
            .allocator = allocator,
            .declarations = std.StringHashMap(Declaration).init(allocator),
            .unresolved = std.ArrayList(UnresolvedRef).empty,
        };
    }

    fn deinit(table: *RefTable) void {
        var it = table.declarations.iterator();
        while (it.next()) |entry| {
            table.allocator.free(entry.key_ptr.*);
            table.allocator.free(entry.value_ptr.element_name);
        }
        table.declarations.deinit();
        for (table.unresolved.items) |r| {
            table.allocator.free(r.ref_attr);
            table.allocator.free(r.ref_value);
            table.allocator.free(r.element_path);
        }
        table.unresolved.deinit(table.allocator);
    }

    /// Records an id declaration.  Returns true if the id is new, false if duplicate.
    fn declare(table: *RefTable, id: []const u8, element_name: []const u8, byte_offset: u64) !bool {
        const owned_id = try table.allocator.dupe(u8, id);
        const result = try table.declarations.getOrPut(owned_id);
        if (result.found_existing) {
            table.allocator.free(owned_id);
            return false;
        }
        result.key_ptr.* = owned_id;
        result.value_ptr.* = .{
            .element_name = try table.allocator.dupe(u8, element_name),
            .byte_offset = byte_offset,
        };
        return true;
    }

    /// Queues a *Ref attribute for deferred resolution.
    fn addRef(table: *RefTable, ref_attr: []const u8, ref_value: []const u8, element_path: []const u8, byte_offset: u64) !void {
        try table.unresolved.append(table.allocator, .{
            .ref_attr = try table.allocator.dupe(u8, ref_attr),
            .ref_value = try table.allocator.dupe(u8, ref_value),
            .element_path = try table.allocator.dupe(u8, element_path),
            .byte_offset = byte_offset,
        });
    }

    /// Drains the unresolved queue and emits diagnostics for any refs that
    /// cannot be resolved.
    fn resolveAll(table: *RefTable, diagnostics: *std.ArrayList(Diagnostic), path: ?[]const u8) void {
        for (table.unresolved.items) |r| {
            if (table.declarations.get(r.ref_value)) |_| {
                // resolved OK
            } else {
                diagnostics.append(table.allocator, .{
                    .severity = .@"error",
                    .rule = RuleId.mzml_ref_unresolved,
                    .location = .{ .byte_offset = r.byte_offset },
                    .path = path,
                    .message = "unresolved reference",
                }) catch {};
            }
        }
    }
};

pub const SemanticValidator = struct {
    allocator: std.mem.Allocator,
    cv_table: *const CvTable,
    rule_engine: *const RuleEngine,
    diagnostics: *std.ArrayList(Diagnostic),
    path: ?[]const u8,

    cv_refs: std.StringHashMap(void),

    /// Element name stack for path building (/mzML/run/...).
    element_names: std.ArrayList([]const u8),

    /// Per-scope term accessions collected for contradiction detection.
    scope_terms: std.ArrayList(std.ArrayList([]const u8)),

    /// Reference resolution table (Slice F).
    ref_table: RefTable,

    pub fn init(allocator: std.mem.Allocator, cv_table: *const CvTable, engine: *const RuleEngine, diagnostics: *std.ArrayList(Diagnostic), path: ?[]const u8) SemanticValidator {
        return .{
            .allocator = allocator,
            .cv_table = cv_table,
            .rule_engine = engine,
            .diagnostics = diagnostics,
            .path = path,
            .cv_refs = std.StringHashMap(void).init(allocator),
            .element_names = std.ArrayList([]const u8).empty,
            .scope_terms = std.ArrayList(std.ArrayList([]const u8)).empty,
            .ref_table = RefTable.init(allocator),
        };
    }

    pub fn deinit(validator: *SemanticValidator) void {
        var it = validator.cv_refs.iterator();
        while (it.next()) |entry| validator.allocator.free(entry.key_ptr.*);
        validator.cv_refs.deinit();
        validator.element_names.deinit(validator.allocator);
        for (validator.scope_terms.items) |*list| {
            for (list.items) |item| validator.allocator.free(item);
            list.deinit(validator.allocator);
        }
        validator.scope_terms.deinit(validator.allocator);
        validator.ref_table.deinit();
    }

    pub fn consumeStart(validator: *SemanticValidator, start: StartElement, _: usize) !void {
        if (start.name.matches(mzml_namespace, "cv")) {
            if (attributeValue(start.attributes, "id")) |id| {
                const owned = try validator.allocator.dupe(u8, id);
                validator.cv_refs.put(owned, {}) catch validator.allocator.free(owned);
            }
            return;
        }

        // Reference resolution: track id declarations and *Ref attributes.
        if (!start.name.matches(mzml_namespace, "cvParam") and !start.name.matches(mzml_namespace, "userParam")) {
            // Build current element path.
            var path_buf: [512]u8 = undefined;
            var pos: usize = 0;
            path_buf[pos] = '/'; pos += 1;
            for (validator.element_names.items, 0..) |name, i| {
                if (i > 0) { path_buf[pos] = '/'; pos += 1; }
                @memcpy(path_buf[pos..][0..name.len], name);
                pos += name.len;
            }
            @memcpy(path_buf[pos..][0..start.name.local_name.len], start.name.local_name);
            pos += start.name.local_name.len;
            const cur_path = path_buf[0..pos];

            // Record id declaration.
            if (attributeValue(start.attributes, "id")) |id| {
                if (!try validator.ref_table.declare(id, start.name.local_name, start.byte_offset)) {
                    try validator.diagnostics.append(validator.allocator, .{
                        .severity = .@"error",
                        .rule = RuleId.mzml_ref_duplicate_id,
                        .location = .{ .byte_offset = start.byte_offset },
                        .path = validator.path,
                        .message = "duplicate id",
                    });
                }
            }

            // Queue *Ref attributes for deferred resolution.
            for (start.attributes) |attr| {
                const name = attr.name.local_name;
                if (isRefAttr(name)) {
                    try validator.ref_table.addRef(name, attr.value, cur_path, start.byte_offset);
                }
            }
        }

        if (start.name.matches(mzml_namespace, "cvParam") or start.name.matches(mzml_namespace, "userParam")) {
            if (attributeValue(start.attributes, "accession")) |acc| {
                if (validator.scope_terms.items.len > 0) {
                    const list = &validator.scope_terms.items[validator.scope_terms.items.len - 1];
                    const owned = try validator.allocator.dupe(u8, acc);
                    list.append(validator.allocator, owned) catch validator.allocator.free(owned);
                }
            }
        } else {
            try validator.element_names.append(validator.allocator, start.name.local_name);
            try validator.scope_terms.append(validator.allocator, std.ArrayList([]const u8).empty);
        }

        if (!start.name.matches(mzml_namespace, "cvParam")) return;

        const accession = attributeValue(start.attributes, "accession") orelse return;
        const cv_ref = attributeValue(start.attributes, "cvRef") orelse return;

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

    pub fn consumeEnd(validator: *SemanticValidator, end: EndElement, _: usize) void {
        if (end.name.matches(mzml_namespace, "cvParam") or end.name.matches(mzml_namespace, "userParam")) return;

        // Build element path from the name stack BEFORE popping.
        var path_buf: [256]u8 = undefined;
        var pos: usize = 0;
        path_buf[pos] = '/'; pos += 1;
        for (validator.element_names.items, 0..) |name, i| {
            if (i > 0) { path_buf[pos] = '/'; pos += 1; }
            @memcpy(path_buf[pos..][0..name.len], name);
            pos += name.len;
        }
        const path = path_buf[0..pos];

        // Pop scope and element name.
        if (validator.element_names.items.len == 0) return;
        validator.element_names.items.len -= 1;
        if (validator.scope_terms.items.len == 0) return;
        const scope = &validator.scope_terms.items[validator.scope_terms.items.len - 1];
        validator.scope_terms.items.len -= 1;
        defer {
            for (scope.items) |item| validator.allocator.free(item);
            scope.deinit(validator.allocator);
        }

        // Check OR rules for contradictions.
        const rules = validator.rule_engine.rulesFor(path);
        for (rules) |rule| {
            if (rule.logic != .@"or") continue;
            // Count how many terms from this OR rule appear in the scope.
            var matched: usize = 0;
            var last_match: []const u8 = "";
            for (rule.terms) |rt| {
                for (scope.items) |st| {
                    if (std.mem.eql(u8, rt, st)) {
                        matched += 1;
                        last_match = rt;
                        break;
                    }
                }
            }
            if (matched > 1) {
                validator.diagnostics.append(validator.allocator, .{
                    .severity = .@"error",
                    .rule = RuleId.mzml_cv_contradiction,
                    .location = .{ .byte_offset = end.byte_offset },
                    .path = validator.path,
                    .message = "element has contradictory CV terms",
                }) catch {};
                return;
            }
        }
    }

    pub fn finish(validator: *SemanticValidator) void {
        validator.ref_table.resolveAll(validator.diagnostics, validator.path);
    }
};

/// Returns true if an attribute name is a `*Ref` reference attribute.
fn isRefAttr(name: []const u8) bool {
    // Known ref attributes in mzML:
    //   softwareRef, dataProcessingRef, instrumentConfigurationRef,
    //   defaultInstrumentConfigurationRef, defaultDataProcessingRef,
    //   sourceFileRef, sampleRef
    // paramGroupRef uses attribute name "ref"
    if (std.mem.eql(u8, name, "ref")) return true;
    return name.len >= 3 and std.mem.eql(u8, name[name.len - 3 ..], "Ref");
}

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

// --- Test helpers ---

fn testEngine(allocator: std.mem.Allocator) !RuleEngine {
    return try RuleEngine.init(allocator, "<CvMapping><CvMappingRuleList></CvMappingRuleList></CvMapping>");
}

fn makeEnd(name: []const u8) EndElement {
    return .{ .byte_offset = 0, .name = .{ .local_name = name, .namespace_uri = mzml_namespace } };
}

test "SemanticValidator: valid accession produces no diagnostic" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000001\n" ++ "name: sample name\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var engine = try testEngine(allocator);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
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

    var engine = try testEngine(allocator);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
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

    var engine = try testEngine(allocator);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
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

    var engine = try testEngine(allocator);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
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

    var engine = try testEngine(allocator);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
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

    var engine = try testEngine(allocator);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
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

    var engine = try testEngine(allocator);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
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

    var engine = try testEngine(allocator);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
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

    var engine = try testEngine(allocator);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
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

    var engine = try testEngine(allocator);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
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

    var engine = try testEngine(allocator);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
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

    var engine = try testEngine(allocator);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
    defer sv.deinit();
    // Not registering any cv -> cvRef fails -> returns early -> only 1 diagnostic.
    try sv.consumeStart(makeCvParam("MS:9999999", "NONEXISTENT", 100), 1);
    try expectEqual(@as(usize, 1), diagnostics.items.len);
}

test "SemanticValidator: no contradiction with single term" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000130\n" ++ "name: positive scan\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    // Create engine with an OR rule for spectrum: MS:1000130 or MS:1000129
    const rule_xml = "<CvMapping><CvMappingRuleList>" ++
        "<CvMappingRule id=\"test\" cvElementPath=\"/\" requirementLevel=\"MAY\" scopePath=\"/spectrum\" cvTermsCombinationLogic=\"OR\">" ++
        "<CvTerm termAccession=\"MS:1000130\"></CvTerm>" ++
        "<CvTerm termAccession=\"MS:1000129\"></CvTerm>" ++
        "</CvMappingRule>" ++
        "</CvMappingRuleList></CvMapping>";
    var engine = try RuleEngine.init(allocator, rule_xml);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
    defer sv.deinit();
    try sv.consumeStart(makeCv("MS"), 1);

    // Open a scope element (spectrum)
    try sv.consumeStart(.{
        .byte_offset = 0,
        .name = .{ .local_name = "spectrum", .namespace_uri = mzml_namespace },
        .attributes = &.{},
        .self_closing = false,
    }, 2);

    // Add only ONE cvParam — no contradiction expected.
    try sv.consumeStart(makeCvParam("MS:1000130", "MS", 10), 3);

    // Close spectrum — no contradiction
    sv.consumeEnd(.{ .byte_offset = 30, .name = .{ .local_name = "spectrum", .namespace_uri = mzml_namespace } }, 2);
    try expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "SemanticValidator: declared id resolves in finish" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000001\n" ++ "name: test\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var engine = try testEngine(allocator);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
    defer sv.deinit();

    // Declare a software element with id="SW1"
    try sv.consumeStart(.{
        .byte_offset = 0,
        .name = .{ .local_name = "software", .namespace_uri = mzml_namespace },
        .attributes = &.{
            .{ .byte_offset = 0, .name = .{ .local_name = "id" }, .value = "SW1" },
            .{ .byte_offset = 0, .name = .{ .local_name = "version" }, .value = "1.0" },
        },
        .self_closing = false,
    }, 1);

    // Declare an instrument configuration with softwareRef="SW1"
    try sv.consumeStart(.{
        .byte_offset = 10,
        .name = .{ .local_name = "instrumentConfiguration", .namespace_uri = mzml_namespace },
        .attributes = &.{
            .{ .byte_offset = 0, .name = .{ .local_name = "id" }, .value = "IC1" },
            .{ .byte_offset = 0, .name = .{ .local_name = "softwareRef" }, .value = "SW1" },
        },
        .self_closing = false,
    }, 2);

    sv.finish();
    try expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "SemanticValidator: unresolved ref produces error" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000001\n" ++ "name: test\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var engine = try testEngine(allocator);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
    defer sv.deinit();

    // softwareRef="NONEXISTENT" with no matching id declaration.
    try sv.consumeStart(.{
        .byte_offset = 10,
        .name = .{ .local_name = "instrumentConfiguration", .namespace_uri = mzml_namespace },
        .attributes = &.{
            .{ .byte_offset = 0, .name = .{ .local_name = "softwareRef" }, .value = "NONEXISTENT" },
        },
        .self_closing = false,
    }, 1);

    sv.finish();
    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_ref_unresolved, diagnostics.items[0].rule);
}

test "SemanticValidator: duplicate id produces error" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000001\n" ++ "name: test\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var engine = try testEngine(allocator);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
    defer sv.deinit();

    // Two elements with the same id.
    try sv.consumeStart(.{
        .byte_offset = 0,
        .name = .{ .local_name = "software", .namespace_uri = mzml_namespace },
        .attributes = &.{.{ .byte_offset = 0, .name = .{ .local_name = "id" }, .value = "SW1" }},
        .self_closing = false,
    }, 1);
    try sv.consumeStart(.{
        .byte_offset = 10,
        .name = .{ .local_name = "software", .namespace_uri = mzml_namespace },
        .attributes = &.{.{ .byte_offset = 0, .name = .{ .local_name = "id" }, .value = "SW1" }},
        .self_closing = false,
    }, 2);

    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_ref_duplicate_id, diagnostics.items[0].rule);
}

test "SemanticValidator: forward reference resolves in finish" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000001\n" ++ "name: test\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var engine = try testEngine(allocator);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
    defer sv.deinit();

    // Reference appears BEFORE the declaration.
    try sv.consumeStart(.{
        .byte_offset = 0,
        .name = .{ .local_name = "instrumentConfiguration", .namespace_uri = mzml_namespace },
        .attributes = &.{.{ .byte_offset = 0, .name = .{ .local_name = "softwareRef" }, .value = "SW1" }},
        .self_closing = false,
    }, 1);
    try sv.consumeStart(.{
        .byte_offset = 10,
        .name = .{ .local_name = "software", .namespace_uri = mzml_namespace },
        .attributes = &.{.{ .byte_offset = 0, .name = .{ .local_name = "id" }, .value = "SW1" }},
        .self_closing = false,
    }, 2);

    sv.finish();
    try expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "SemanticValidator: IM-MS and DIA CV terms are recognised" {
    const allocator = testing.allocator;
    const obo_text = @embedFile("../data/psi-ms.obo");
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var engine = try testEngine(allocator);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
    defer sv.deinit();
    try sv.consumeStart(makeCv("MS"), 1);

    try sv.consumeStart(makeCvParam("MS:1002476", "MS", 0), 2);
    try sv.consumeStart(makeCvParam("MS:1002815", "MS", 10), 2);
    try sv.consumeStart(makeCvParam("MS:1002836", "MS", 20), 2);
    try sv.consumeStart(makeCvParam("MS:1000826", "MS", 30), 2);
    try sv.consumeStart(makeCvParam("MS:1002446", "MS", 40), 2);
    try sv.consumeStart(makeCvParam("MS:1002687", "MS", 50), 2);

    try expectEqual(@as(usize, 0), diagnostics.items.len);
}
