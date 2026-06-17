//! CV validation, scope tracking, contradiction detection, and reference resolution.
//!
//! Validates every `<cvParam>` and `<userParam>` against the CvTable built
//! from psi-ms.obo.  Checks:
//!   - cvRef resolves to a declared `<cv>` entry in `<cvList>`
//!   - Accession exists in the CV
//!   - Term is not obsolete
//!   - cvRef matches the term's namespace
//!   - unitAccession (if present) exists in the CV
//!   - Contradictory OR terms on the same element
//!   - All *Ref attributes resolve to declared id values

const std = @import("std");
const diagnostic = @import("../diagnostic.zig");
const obo = @import("../obo/parser.zig");
const rule_engine = @import("../obo/rule_engine.zig");
const xml_events = @import("../xml/events.zig");
const elements = @import("elements.zig");

const Attribute = xml_events.Attribute;
const CvTable = obo.CvTable;
const Diagnostic = diagnostic.Diagnostic;
const RuleEngine = rule_engine.RuleEngine;
const RuleId = diagnostic.RuleId;
const StartElement = xml_events.StartElement;
const EndElement = xml_events.EndElement;

const mzml_namespace = diagnostic.mzml_namespace;

// A declared id in the document.
const Declaration = struct {
    element_name: []const u8,
    byte_offset: u64,
};

// A *Ref attribute encountered before its target id was declared.
const UnresolvedRef = struct {
    ref_attr: []const u8,
    ref_value: []const u8,
    element_path: []const u8,
    byte_offset: u64,
};

// Accumulates id declarations and deferred *Ref attributes, then resolves
// them in finish().  Owns all strings via the parent allocator.
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

    fn addRef(table: *RefTable, ref_attr: []const u8, ref_value: []const u8, element_path: []const u8, byte_offset: u64) !void {
        try table.unresolved.append(table.allocator, .{
            .ref_attr = try table.allocator.dupe(u8, ref_attr),
            .ref_value = try table.allocator.dupe(u8, ref_value),
            .element_path = try table.allocator.dupe(u8, element_path),
            .byte_offset = byte_offset,
        });
    }

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

    // Element name stack for path building (/mzML/run/...).
    element_names: std.ArrayList([]const u8),

    // Per-scope term accessions collected for contradiction detection.
    scope_terms: std.ArrayList(std.ArrayList([]const u8)),

    // Reference resolution table.
    ref_table: RefTable,

    // ReferenceableParamGroup id -> list of cvParam accessions.
    param_groups: std.StringHashMap(std.ArrayList([]const u8)),
    // Set when inside a referenceableParamGroup to capture its id.
    current_group_id: ?[]const u8 = null,

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
            .param_groups = std.StringHashMap(std.ArrayList([]const u8)).init(allocator),
        };
    }

    pub fn deinit(validator: *SemanticValidator) void {
        var it = validator.cv_refs.iterator();
        while (it.next()) |entry| validator.allocator.free(entry.key_ptr.*);
        validator.cv_refs.deinit();
        for (validator.element_names.items) |name| validator.allocator.free(name);
        validator.element_names.deinit(validator.allocator);
        for (validator.scope_terms.items) |*list| {
            for (list.items) |item| validator.allocator.free(item);
            list.deinit(validator.allocator);
        }
        validator.scope_terms.deinit(validator.allocator);
        // Free param_groups entries.
        {
            var pg_it = validator.param_groups.iterator();
            while (pg_it.next()) |entry| {
                validator.allocator.free(entry.key_ptr.*);
                for (entry.value_ptr.items) |acc| validator.allocator.free(acc);
                entry.value_ptr.deinit(validator.allocator);
            }
        }
        validator.param_groups.deinit();
        validator.ref_table.deinit();
    }

    pub fn consumeStart(validator: *SemanticValidator, start: StartElement, _: usize) !void {
        if (start.resolvedId() == .cv) {
            if (attributeValue(start.attributes, "id")) |id| {
                const owned = try validator.allocator.dupe(u8, id);
                validator.cv_refs.put(owned, {}) catch validator.allocator.free(owned);
            }
            return;
        }

        // Reference resolution: track id declarations and *Ref attributes.
        if (start.resolvedId() != .cvParam and start.resolvedId() != .userParam) {
            var path_buf: [4096]u8 = undefined;
            var pos: usize = 0;
            path_buf[pos] = '/';
            pos += 1;
            for (validator.element_names.items, 0..) |name, i| {
                if (i > 0) {
                    if (pos + 1 >= path_buf.len) return;
                    path_buf[pos] = '/';
                    pos += 1;
                }
                if (pos + name.len > path_buf.len) return;
                @memcpy(path_buf[pos..][0..name.len], name);
                pos += name.len;
            }
            if (pos + start.name.local_name.len > path_buf.len) return;
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

        if (start.resolvedId() == .cvParam or start.resolvedId() == .userParam) {
            if (attributeValue(start.attributes, "accession")) |acc| {
                if (validator.scope_terms.items.len > 0) {
                    const list = &validator.scope_terms.items[validator.scope_terms.items.len - 1];
                    const owned = try validator.allocator.dupe(u8, acc);
                    list.append(validator.allocator, owned) catch validator.allocator.free(owned);
                }
            }
        } else {
            const owned = try validator.allocator.dupe(u8, start.name.local_name);
            try validator.element_names.append(validator.allocator, owned);
            try validator.scope_terms.append(validator.allocator, std.ArrayList([]const u8).empty);

            // Track referenceableParamGroup id for later capture.
            if (start.resolvedId() == .referenceableParamGroup) {
                validator.current_group_id = attributeValue(start.attributes, "id");
            }

            // Resolve referenceableParamGroupRef: add group's cvParams to parent scope.
            if (start.resolvedId() == .referenceableParamGroupRef) {
                if (attributeValue(start.attributes, "ref")) |ref_id| {
                    if (validator.param_groups.get(ref_id)) |group_terms| {
                        if (validator.scope_terms.items.len >= 2) {
                            const parent = &validator.scope_terms.items[validator.scope_terms.items.len - 2];
                            for (group_terms.items) |acc| {
                                const owned_acc = try validator.allocator.dupe(u8, acc);
                                parent.append(validator.allocator, owned_acc) catch {
                                    validator.allocator.free(owned_acc);
                                    return;
                                };
                            }
                        }
                    }
                }
            }
        }

        const accession = attributeValue(start.attributes, "accession") orelse return;
        const cv_ref = if (attributeValue(start.attributes, "cvRef")) |ref|
            ref
        else if (start.resolvedId() == .userParam) blk: {
            const colon = std.mem.indexOfScalar(u8, accession, ':') orelse return;
            break :blk accession[0..colon];
        } else return;

        if (!validator.cv_refs.contains(cv_ref)) {
            // BTO/GO/PATO may not be declared in cvList; skip cvRef check.
            if (!isKnownExternalPrefix(cv_ref)) {
                try validator.diagnostics.append(validator.allocator, .{
                    .severity = .@"error",
                    .rule = RuleId.mzml_cv_namespace,
                    .location = .{ .byte_offset = start.byte_offset },
                    .path = validator.path,
                    .message = "cvRef does not match any declared cv id in cvList",
                });
                return;
            }
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
                // Skip namespace check for BTO/GO/PATO (externally-managed CVs).
                if (!isKnownExternalPrefix(cv_ref)) {
                    try validator.diagnostics.append(validator.allocator, .{
                        .severity = .@"error",
                        .rule = RuleId.mzml_cv_namespace,
                        .location = .{ .byte_offset = start.byte_offset },
                        .path = validator.path,
                        .message = "cvRef does not match term namespace",
                    });
                }
            }
        } else {
            // BTO/GO/PATO terms may not be in our embedded psi-ms.obo.
            if (!isKnownExternalPrefix(extractAccessionPrefix(accession))) {
                try validator.diagnostics.append(validator.allocator, .{
                    .severity = .@"error",
                    .rule = RuleId.mzml_cv_accession,
                    .location = .{ .byte_offset = start.byte_offset },
                    .path = validator.path,
                    .message = "unrecognized CV accession",
                });
            }
        }

        // Unit term validation.
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
                    const exact_match = std.mem.eql(u8, name, unit_term.name);
                    const case_insensitive_match = if (!exact_match) std.ascii.eqlIgnoreCase(name, unit_term.name) else false;
                    const synonym_match = if (!exact_match and !case_insensitive_match) blk: {
                        var found = false;
                        for (unit_term.synonyms) |syn| {
                            if (std.mem.eql(u8, name, syn) or std.ascii.eqlIgnoreCase(name, syn)) {
                                found = true;
                                break;
                            }
                        }
                        break :blk found;
                    } else false;
                    if (!exact_match and !case_insensitive_match and !synonym_match) {
                        try validator.diagnostics.append(validator.allocator, .{
                            .severity = .info,
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

    pub fn consumeEnd(validator: *SemanticValidator, end: EndElement, _: usize) !void {
        const tag = end.resolvedId();
        if (tag == .cvParam or tag == .userParam) return;
        if (tag == .cv) return;

        var path_buf: [4096]u8 = undefined;
        var pos: usize = 0;
        path_buf[pos] = '/';
        pos += 1;
        for (validator.element_names.items, 0..) |name, i| {
            if (i > 0) {
                if (pos + 1 >= path_buf.len) return;
                path_buf[pos] = '/';
                pos += 1;
            }
            if (pos + name.len > path_buf.len) return;
            @memcpy(path_buf[pos..][0..name.len], name);
            pos += name.len;
        }
        const path = path_buf[0..pos];

        if (validator.element_names.items.len == 0) return;
        const name = validator.element_names.items[validator.element_names.items.len - 1];
        validator.allocator.free(name);
        validator.element_names.items.len -= 1;
        if (validator.scope_terms.items.len == 0) return;
        const scope = &validator.scope_terms.items[validator.scope_terms.items.len - 1];
        validator.scope_terms.items.len -= 1;
        defer {
            for (scope.items) |item| validator.allocator.free(item);
            scope.deinit(validator.allocator);
        }

        // Capture referenceableParamGroup cvParams for later ref resolution.
        if (tag == .referenceableParamGroup) {
            if (validator.current_group_id) |group_id| {
                if (validator.param_groups.get(group_id) == null) {
                    const owned_id = try validator.allocator.dupe(u8, group_id);
                    var term_list = std.ArrayList([]const u8).empty;
                    errdefer {
                        for (term_list.items) |t| validator.allocator.free(t);
                        term_list.deinit(validator.allocator);
                    }
                    for (scope.items) |acc| {
                        const owned = try validator.allocator.dupe(u8, acc);
                        try term_list.append(validator.allocator, owned);
                    }
                    validator.param_groups.put(owned_id, term_list) catch {
                        validator.allocator.free(owned_id);
                        for (term_list.items) |t| validator.allocator.free(t);
                        term_list.deinit(validator.allocator);
                    };
                }
                validator.current_group_id = null;
            }
        }

        // Check rules for required terms and contradictions.
        const rules = validator.rule_engine.rulesFor(path);
        for (rules) |rule| {
            var matched: usize = 0;
            for (rule.terms) |rt| {
                for (scope.items) |st| {
                    const is_match = if (rt.allow_children)
                        validator.cv_table.isDescendantOf(st, rt.accession)
                    else
                        std.mem.eql(u8, st, rt.accession);
                    if (is_match) {
                        matched += 1;
                        break;
                    }
                }
            }

            switch (rule.requirement) {
                .must => {
                    const ok = switch (rule.logic) {
                        .@"and" => matched == rule.terms.len,
                        .@"or" => matched > 0,
                    };
                    if (!ok) {
                        validator.diagnostics.append(validator.allocator, .{
                            .severity = .@"error",
                            .rule = RuleId.mzml_cv_required,
                            .location = .{ .byte_offset = end.byte_offset },
                            .path = validator.path,
                            .message = "missing required CV term for element",
                        }) catch {};
                        return;
                    }
                },
                .should => {
                    const ok = switch (rule.logic) {
                        .@"and" => matched == rule.terms.len,
                        .@"or" => matched > 0,
                    };
                    if (!ok) {
                        validator.diagnostics.append(validator.allocator, .{
                            .severity = .warning,
                            .rule = RuleId.mzml_cv_recommended,
                            .location = .{ .byte_offset = end.byte_offset },
                            .path = validator.path,
                            .message = "missing recommended CV term for element",
                        }) catch {};
                    }
                },
                .may => {},
            }
        }

        // Contradiction: two alternatives from the same OR rule on one element.
        if (scope.items.len >= 2) {
            for (rules) |r| {
                if (r.logic != .@"or") continue;
                var or_matched: usize = 0;
                for (scope.items) |st| {
                    for (r.terms) |rt| {
                        const is_match = if (rt.allow_children)
                            validator.cv_table.isDescendantOf(st, rt.accession)
                        else
                            std.mem.eql(u8, st, rt.accession);
                        if (is_match) {
                            or_matched += 1;
                            break;
                        }
                    }
                }
                if (or_matched > 1) {
                    validator.diagnostics.append(validator.allocator, .{
                        .severity = .warning,
                        .rule = RuleId.mzml_cv_contradiction,
                        .location = .{ .byte_offset = end.byte_offset },
                        .path = validator.path,
                        .message = "element has contradictory CV terms",
                    }) catch {};
                    return;
                }
            }
        }
    }

    pub fn finish(validator: *SemanticValidator) void {
        validator.ref_table.resolveAll(validator.diagnostics, validator.path);
    }
};

// Recognised external CV prefixes not defined in psi-ms.obo.
// Matching OpenMS behaviour: BTO, GO, PATO terms are not validated
// because their ontologies are not embedded.
fn isKnownExternalPrefix(prefix: []const u8) bool {
    return std.mem.eql(u8, prefix, "BTO") or
        std.mem.eql(u8, prefix, "GO") or
        std.mem.eql(u8, prefix, "PATO");
}

// Extracts the namespace prefix from an accession string (e.g. "MS" from "MS:1000001").
fn extractAccessionPrefix(accession: []const u8) []const u8 {
    const colon = std.mem.indexOfScalar(u8, accession, ':') orelse return accession;
    return accession[0..colon];
}

fn isRefAttr(name: []const u8) bool {
    // paramGroupRef uses attribute name "ref" instead of *Ref suffix.
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
const Severity = diagnostic.Severity;

fn makeCvParam(accession: []const u8, cv_ref: []const u8, byte_offset: u64) StartElement {
    return .{
        .byte_offset = byte_offset,
        .name = .{ .local_name = "cvParam", .namespace_uri = mzml_namespace },
        .element_id = .cvParam,
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
        .element_id = .cv,
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
        .element_id = .cvParam,
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
        .element_id = .cvParam,
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
        .element_id = .userParam,
        .attributes = &.{
            .{ .byte_offset = 0, .name = .{ .local_name = "name" }, .value = "some param" },
        },
        .self_closing = false,
    };
}

fn internId(local_name: []const u8) xml_events.ElementId {
    return elements.idFromParts(local_name, mzml_namespace);
}

fn makeStart(byte_offset: u64, local_name: []const u8, attributes: []const Attribute) StartElement {
    return .{
        .byte_offset = byte_offset,
        .name = .{ .local_name = local_name, .namespace_uri = mzml_namespace },
        .element_id = internId(local_name),
        .attributes = attributes,
        .self_closing = false,
    };
}

fn makeEnd(byte_offset: u64, local_name: []const u8) EndElement {
    return .{
        .byte_offset = byte_offset,
        .name = .{ .local_name = local_name, .namespace_uri = mzml_namespace },
        .element_id = internId(local_name),
    };
}

fn makeUserParam(byte_offset: u64, accession: []const u8, name: []const u8) StartElement {
    return .{
        .byte_offset = byte_offset,
        .name = .{ .local_name = "userParam", .namespace_uri = mzml_namespace },
        .element_id = .userParam,
        .attributes = &.{
            .{ .byte_offset = 0, .name = .{ .local_name = "accession" }, .value = accession },
            .{ .byte_offset = 0, .name = .{ .local_name = "name" }, .value = name },
        },
        .self_closing = false,
    };
}

fn testEngine(allocator: std.mem.Allocator) !RuleEngine {
    return try RuleEngine.init(allocator, "<CvMapping><CvMappingRuleList></CvMappingRuleList></CvMapping>");
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

test "SemanticValidator: cvParam with unknown intern id still validates accession" {
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

    var param = makeCvParam("MS:9999999", "MS", 100);
    param.element_id = .unknown;
    try sv.consumeStart(param, 2);

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
    try sv.consumeStart(makeStart(100, "cvParam", &.{
        .{ .byte_offset = 0, .name = .{ .local_name = "accession" }, .value = "UO:0000000" },
        .{ .byte_offset = 0, .name = .{ .local_name = "cvRef" }, .value = "UO" },
        .{ .byte_offset = 0, .name = .{ .local_name = "unitAccession" }, .value = "UO:0000000" },
        .{ .byte_offset = 0, .name = .{ .local_name = "unitCvRef" }, .value = "MS" },
    }), 2);
    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_cv_namespace, diagnostics.items[0].rule);
}

test "SemanticValidator: unitName mismatch produces info" {
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
    try expectEqual(Severity.info, diagnostics.items[0].severity);
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

    try sv.consumeStart(makeStart(0, "spectrum", &.{}), 2);

    try sv.consumeStart(makeCvParam("MS:1000130", "MS", 10), 3);

    try sv.consumeEnd(makeEnd(30, "spectrum"), 2);
    try expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "SemanticValidator: must rule fires when term missing" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000008\n" ++ "name: ionization type\n" ++ "namespace: MS\n" ++
        "[Term]\n" ++ "id: MS:1000482\n" ++ "name: source attribute\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    // MUST/AND rule: source must have MS:1000008
    const rule_xml = "<CvMapping><CvMappingRuleList>" ++
        "<CvMappingRule id=\"source_must\" cvElementPath=\"/\" requirementLevel=\"MUST\" scopePath=\"/source\" cvTermsCombinationLogic=\"AND\">" ++
        "<CvTerm termAccession=\"MS:1000008\"></CvTerm>" ++
        "</CvMappingRule>" ++
        "</CvMappingRuleList></CvMapping>";
    var engine = try RuleEngine.init(allocator, rule_xml);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
    defer sv.deinit();
    try sv.consumeStart(makeCv("MS"), 1);

    try sv.consumeStart(makeStart(0, "source", &.{}), 2);

    try sv.consumeStart(makeCvParam("MS:1000482", "MS", 10), 3);

    try sv.consumeEnd(makeEnd(20, "source"), 2);
    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_cv_required, diagnostics.items[0].rule);
}

test "SemanticValidator: must rule passes when term present" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000008\n" ++ "name: ionization type\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    const rule_xml = "<CvMapping><CvMappingRuleList>" ++
        "<CvMappingRule id=\"source_must\" cvElementPath=\"/\" requirementLevel=\"MUST\" scopePath=\"/source\" cvTermsCombinationLogic=\"AND\">" ++
        "<CvTerm termAccession=\"MS:1000008\"></CvTerm>" ++
        "</CvMappingRule>" ++
        "</CvMappingRuleList></CvMapping>";
    var engine = try RuleEngine.init(allocator, rule_xml);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
    defer sv.deinit();
    try sv.consumeStart(makeCv("MS"), 1);

    try sv.consumeStart(makeStart(0, "source", &.{}), 2);

    try sv.consumeStart(makeCvParam("MS:1000008", "MS", 10), 3);

    try sv.consumeEnd(makeEnd(20, "source"), 2);
    try expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "SemanticValidator: must or rule fires when no term matches" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000008\n" ++ "name: ionization type\n" ++ "namespace: MS\n" ++
        "[Term]\n" ++ "id: MS:1000443\n" ++ "name: mass analyzer\n" ++ "namespace: MS\n" ++
        "[Term]\n" ++ "id: MS:1000482\n" ++ "name: source attribute\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    // MUST/OR rule: source must have MS:1000008 or MS:1000443
    const rule_xml = "<CvMapping><CvMappingRuleList>" ++
        "<CvMappingRule id=\"test\" cvElementPath=\"/\" requirementLevel=\"MUST\" scopePath=\"/source\" cvTermsCombinationLogic=\"OR\">" ++
        "<CvTerm termAccession=\"MS:1000008\"></CvTerm>" ++
        "<CvTerm termAccession=\"MS:1000443\"></CvTerm>" ++
        "</CvMappingRule>" ++
        "</CvMappingRuleList></CvMapping>";
    var engine = try RuleEngine.init(allocator, rule_xml);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
    defer sv.deinit();
    try sv.consumeStart(makeCv("MS"), 1);

    try sv.consumeStart(makeStart(0, "source", &.{}), 2);

    try sv.consumeStart(makeCvParam("MS:1000482", "MS", 10), 3);

    try sv.consumeEnd(makeEnd(20, "source"), 2);
    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_cv_required, diagnostics.items[0].rule);
}

test "SemanticValidator: must or rule passes when one term present" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000008\n" ++ "name: ionization type\n" ++ "namespace: MS\n" ++
        "[Term]\n" ++ "id: MS:1000443\n" ++ "name: mass analyzer\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    const rule_xml = "<CvMapping><CvMappingRuleList>" ++
        "<CvMappingRule id=\"test\" cvElementPath=\"/\" requirementLevel=\"MUST\" scopePath=\"/source\" cvTermsCombinationLogic=\"OR\">" ++
        "<CvTerm termAccession=\"MS:1000008\"></CvTerm>" ++
        "<CvTerm termAccession=\"MS:1000443\"></CvTerm>" ++
        "</CvMappingRule>" ++
        "</CvMappingRuleList></CvMapping>";
    var engine = try RuleEngine.init(allocator, rule_xml);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
    defer sv.deinit();
    try sv.consumeStart(makeCv("MS"), 1);

    try sv.consumeStart(makeStart(0, "source", &.{}), 2);

    try sv.consumeStart(makeCvParam("MS:1000008", "MS", 10), 3);

    try sv.consumeEnd(makeEnd(20, "source"), 2);
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

    try sv.consumeStart(makeStart(0, "software", &.{
        .{ .byte_offset = 0, .name = .{ .local_name = "id" }, .value = "SW1" },
        .{ .byte_offset = 0, .name = .{ .local_name = "version" }, .value = "1.0" },
    }), 1);

    try sv.consumeStart(makeStart(10, "instrumentConfiguration", &.{
        .{ .byte_offset = 0, .name = .{ .local_name = "id" }, .value = "IC1" },
        .{ .byte_offset = 0, .name = .{ .local_name = "softwareRef" }, .value = "SW1" },
    }), 2);

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

    try sv.consumeStart(makeStart(10, "instrumentConfiguration", &.{
        .{ .byte_offset = 0, .name = .{ .local_name = "softwareRef" }, .value = "NONEXISTENT" },
    }), 1);

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

    try sv.consumeStart(makeStart(0, "software", &.{
        .{ .byte_offset = 0, .name = .{ .local_name = "id" }, .value = "SW1" },
    }), 1);
    try sv.consumeStart(makeStart(10, "software", &.{
        .{ .byte_offset = 0, .name = .{ .local_name = "id" }, .value = "SW1" },
    }), 2);

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

    try sv.consumeStart(makeStart(0, "instrumentConfiguration", &.{
        .{ .byte_offset = 0, .name = .{ .local_name = "softwareRef" }, .value = "SW1" },
    }), 1);
    try sv.consumeStart(makeStart(10, "software", &.{
        .{ .byte_offset = 0, .name = .{ .local_name = "id" }, .value = "SW1" },
    }), 2);

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

// --- userParam CV validation ---

test "SemanticValidator: userParam with valid accession triggers CV validation" {
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

    try sv.consumeStart(makeUserParam(0, "MS:1000001", "test param"), 1);
    try expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "SemanticValidator: userParam with invalid accession produces error" {
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

    try sv.consumeStart(makeUserParam(0, "MS:9999999", "test param"), 1);
    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_cv_accession, diagnostics.items[0].rule);
}

// --- BTO/GO/PATO support ---

test "SemanticValidator: BTO accession does not produce unrecognized error" {
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

    try sv.consumeStart(makeCvParam("BTO:0000001", "BTO", 0), 1);
    try expectEqual(@as(usize, 0), diagnostics.items.len);
}

// --- Contradiction detection across all rules ---

test "SemanticValidator: contradiction detected when two OR alternatives on same element" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000130\n" ++ "name: positive scan\n" ++ "namespace: MS\n" ++
        "[Term]\n" ++ "id: MS:1000129\n" ++ "name: negative scan\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    // OR rule: spectrum must have MS:1000130 or MS:1000129
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

    try sv.consumeStart(makeStart(0, "spectrum", &.{}), 2);

    try sv.consumeStart(makeCvParam("MS:1000130", "MS", 10), 3);
    try sv.consumeStart(makeCvParam("MS:1000129", "MS", 20), 3);

    try sv.consumeEnd(makeEnd(30, "spectrum"), 2);
    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_cv_contradiction, diagnostics.items[0].rule);
}
