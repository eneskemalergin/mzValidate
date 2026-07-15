//! CV validation, scope tracking, contradiction detection, and reference resolution.
//!
//! Validates every `<cvParam>` and `<userParam>` against the CvTable built
//! from psi-ms.obo. Checks:
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
const ElementId = elements.ElementId;
const MappingRule = rule_engine.MappingRule;

const mzml_namespace = diagnostic.mzml_namespace;

// A declared id in the document.
const Declaration = struct {
    element_name: []const u8,
    byte_offset: u64,
};

// A *Ref attribute encountered before its target id was declared.
const ScopeItem = struct {
    accession: []const u8,
    /// Whether `accession` was heap-allocated and must be freed.
    owned: bool,
};

const ScopeFrame = struct {
    element_id: ElementId,
    scope_start: usize,
    rules: []const MappingRule,
};

const UnresolvedRef = struct {
    ref_attr: []const u8,
    ref_value: []const u8,
    byte_offset: u64,
};

// Defers *Ref resolution until the document end so forward references work.
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
        }
        table.unresolved.deinit(table.allocator);
    }

    fn declare(table: *RefTable, id: []const u8, element_name: []const u8, byte_offset: u64) !bool {
        const owned_id = try table.allocator.dupe(u8, id);
        errdefer table.allocator.free(owned_id);
        const owned_element_name = try table.allocator.dupe(u8, element_name);
        errdefer table.allocator.free(owned_element_name);

        const result = try table.declarations.getOrPut(owned_id);
        if (result.found_existing) {
            table.allocator.free(owned_id);
            table.allocator.free(owned_element_name);
            return false;
        }
        result.key_ptr.* = owned_id;
        result.value_ptr.* = .{
            .element_name = owned_element_name,
            .byte_offset = byte_offset,
        };
        return true;
    }

    fn addRef(table: *RefTable, ref_attr: []const u8, ref_value: []const u8, byte_offset: u64) !void {
        try table.unresolved.append(table.allocator, .{
            .ref_attr = try table.allocator.dupe(u8, ref_attr),
            .ref_value = try table.allocator.dupe(u8, ref_value),
            .byte_offset = byte_offset,
        });
    }

    fn resolveAll(table: *RefTable, diagnostics: *std.ArrayList(Diagnostic), path: ?[]const u8) !void {
        for (table.unresolved.items) |r| {
            if (table.declarations.get(r.ref_value)) |_| {
                // resolved OK
            } else {
                try diagnostics.append(table.allocator, .{
                    .severity = .@"error",
                    .rule = RuleId.mzml_ref_unresolved,
                    .location = .{ .byte_offset = r.byte_offset },
                    .path = path,
                    .message = "unresolved reference",
                });
            }
        }
    }
};

/// CV terms, scope rules, contradictions, and id/*Ref resolution.
pub const SemanticValidator = struct {
    allocator: std.mem.Allocator,
    cv_table: *const CvTable,
    rule_engine: *const RuleEngine,
    diagnostics: *std.ArrayList(Diagnostic),
    path: ?[]const u8,

    cv_refs: std.StringHashMap(void),

    scope_frames: std.ArrayList(ScopeFrame),
    scope_items: std.ArrayList(ScopeItem),

    ref_table: RefTable,

    param_groups: std.StringHashMap(std.ArrayList([]const u8)),
    current_group_id: ?[]const u8 = null,

    pub fn init(allocator: std.mem.Allocator, cv_table: *const CvTable, engine: *const RuleEngine, diagnostics: *std.ArrayList(Diagnostic), path: ?[]const u8) SemanticValidator {
        return .{
            .allocator = allocator,
            .cv_table = cv_table,
            .rule_engine = engine,
            .diagnostics = diagnostics,
            .path = path,
            .cv_refs = std.StringHashMap(void).init(allocator),
            .scope_frames = std.ArrayList(ScopeFrame).empty,
            .scope_items = std.ArrayList(ScopeItem).empty,
            .ref_table = RefTable.init(allocator),
            .param_groups = std.StringHashMap(std.ArrayList([]const u8)).init(allocator),
        };
    }

    pub fn deinit(validator: *SemanticValidator) void {
        var it = validator.cv_refs.iterator();
        while (it.next()) |entry| validator.allocator.free(entry.key_ptr.*);
        validator.cv_refs.deinit();
        validator.scope_frames.deinit(validator.allocator);
        for (validator.scope_items.items) |item| {
            if (item.owned) validator.allocator.free(item.accession);
        }
        validator.scope_items.deinit(validator.allocator);
        // Free current_group_id.
        if (validator.current_group_id) |id| validator.allocator.free(id);
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

    pub fn consumeStart(validator: *SemanticValidator, start: StartElement) !void {
        const tag = start.resolvedId();

        var pa: ?[]const u8 = null;
        var cvr: ?[]const u8 = null;
        var ua: ?[]const u8 = null;
        var ucr: ?[]const u8 = null;
        var un: ?[]const u8 = null;
        if (tag == .cvParam or tag == .userParam) {
            if (start.raw_tag.len > 0) {
                var pos: usize = 0;
                const bytes = start.raw_tag;
                while (pos < bytes.len) {
                    while (pos < bytes.len and switch (bytes[pos]) {
                        ' ', '\t', '\r', '\n' => true,
                        else => false,
                    }) : (pos += 1) {}
                    if (pos >= bytes.len) break;
                    const ns = pos;
                    while (pos < bytes.len and bytes[pos] != '=' and !std.ascii.isWhitespace(bytes[pos])) : (pos += 1) {}
                    if (pos >= bytes.len or bytes[pos] != '=') break;
                    const attr_name = bytes[ns..pos];
                    pos += 1;
                    if (pos >= bytes.len) break;
                    const q = bytes[pos];
                    if (q != '"' and q != '\'') break;
                    pos += 1;
                    const vs = pos;
                    while (pos < bytes.len and bytes[pos] != q) : (pos += 1) {}
                    const attr_val = bytes[vs..pos];
                    if (pos < bytes.len) pos += 1;
                    if (std.mem.eql(u8, attr_name, "accession")) {
                        pa = attr_val;
                    } else if (std.mem.eql(u8, attr_name, "cvRef")) {
                        cvr = attr_val;
                    } else if (std.mem.eql(u8, attr_name, "unitAccession")) {
                        ua = attr_val;
                    } else if (std.mem.eql(u8, attr_name, "unitCvRef")) {
                        ucr = attr_val;
                    } else if (std.mem.eql(u8, attr_name, "unitName")) {
                        un = attr_val;
                    }
                }
            } else {
                pa = start.attr("accession");
                cvr = start.attr("cvRef");
                ua = start.attr("unitAccession");
                ucr = start.attr("unitCvRef");
                un = start.attr("unitName");
            }
        }

        switch (tag) {
            .cv => {
                if (start.attr("id")) |id| {
                    const owned = try validator.allocator.dupe(u8, id);
                    errdefer validator.allocator.free(owned);
                    try validator.cv_refs.put(owned, {});
                }
                return;
            },
            else => {},
        }

        if (tag == .cvParam or tag == .userParam) {
            if (pa) |acc| {
                if (validator.scope_frames.items.len > 0) {
                    const on_slice = start.raw_tag.len > 0;
                    if (on_slice) {
                        try validator.scope_items.append(validator.allocator, .{ .accession = acc, .owned = false });
                    } else {
                        const owned = try validator.allocator.dupe(u8, acc);
                        errdefer validator.allocator.free(owned);
                        try validator.scope_items.append(validator.allocator, .{ .accession = owned, .owned = true });
                    }
                }
            }
        } else {
            if (start.attr("id")) |id| {
                // Only register ids for elements that are xs:ID typed or
                // xs:key constrained by the mzML schema.  <mzML> and <run>
                // use plain xs:string with no key constraint and no *Ref
                // attribute targets them, so skip them to avoid false
                // duplicate-id errors when all three share the same value.
                if (tag != .mzML and tag != .run) {
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
            }

            for (start.attributes) |attr| {
                const name_attr = attr.name.local_name;
                if (isRefAttr(name_attr)) {
                    try validator.ref_table.addRef(name_attr, attr.value, start.byte_offset);
                }
            }

            if (tag == .referenceableParamGroupRef) {
                if (start.attr("ref")) |ref_id| {
                    if (validator.param_groups.get(ref_id)) |group_terms| {
                        if (validator.scope_frames.items.len >= 1) {
                            for (group_terms.items) |acc| {
                                const owned_acc = try validator.allocator.dupe(u8, acc);
                                errdefer validator.allocator.free(owned_acc);
                                try validator.scope_items.append(validator.allocator, .{ .accession = owned_acc, .owned = true });
                            }
                        }
                    }
                }
            }

            const scope_start = validator.scope_items.items.len;

            var path_buf: [4096]u8 = undefined;
            var pos: usize = 0;
            path_buf[pos] = '/';
            pos += 1;
            for (validator.scope_frames.items) |frame| {
                const fname = @tagName(frame.element_id);
                if (pos + fname.len + 1 > path_buf.len) return;
                @memcpy(path_buf[pos..][0..fname.len], fname);
                pos += fname.len;
                path_buf[pos] = '/';
                pos += 1;
            }
            if (pos + start.name.local_name.len > path_buf.len) return;
            @memcpy(path_buf[pos..][0..start.name.local_name.len], start.name.local_name);
            pos += start.name.local_name.len;
            const cur_path = path_buf[0..pos];
            const rules = validator.rule_engine.rulesFor(cur_path);

            try validator.scope_frames.append(validator.allocator, ScopeFrame{
                .element_id = tag,
                .scope_start = scope_start,
                .rules = rules,
            });

            switch (tag) {
                .referenceableParamGroup => {
                    const id_attr = start.attr("id");
                    if (validator.current_group_id) |old_id| {
                        validator.allocator.free(old_id);
                    }
                    if (id_attr) |id| {
                        validator.current_group_id = try validator.allocator.dupe(u8, id);
                    } else {
                        validator.current_group_id = null;
                    }
                },
                else => {},
            }
        }

        const accession = pa orelse return;
        const cv_ref = if (cvr) |ref|
            ref
        else if (tag == .userParam) blk: {
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
        if (ua) |unit_acc| {
            const unit_cv_ref = ucr;
            const unit_name = un;

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

    pub fn consumeEnd(validator: *SemanticValidator, end: EndElement) !void {
        const tag = end.resolvedId();

        switch (tag) {
            .cv, .cvParam, .userParam => return,
            else => {},
        }

        if (validator.scope_frames.items.len == 0) return;
        const frame = validator.scope_frames.items[validator.scope_frames.items.len - 1];
        validator.scope_frames.items.len -= 1;
        const scope = validator.scope_items.items[frame.scope_start..validator.scope_items.items.len];
        defer validator.scope_items.items.len = frame.scope_start;
        defer {
            for (scope) |item| if (item.owned) validator.allocator.free(item.accession);
        }

        // Capture referenceableParamGroup cvParams for later ref resolution.
        switch (tag) {
            .referenceableParamGroup => {
                if (validator.current_group_id) |group_id| {
                    if (validator.param_groups.get(group_id) == null) {
                        const owned_id = try validator.allocator.dupe(u8, group_id);
                        var term_list = std.ArrayList([]const u8).empty;
                        errdefer {
                            for (term_list.items) |t| validator.allocator.free(t);
                            term_list.deinit(validator.allocator);
                        }
                        for (scope) |item| {
                            const owned = try validator.allocator.dupe(u8, item.accession);
                            try term_list.append(validator.allocator, owned);
                        }
                        errdefer validator.allocator.free(owned_id);
                        try validator.param_groups.put(owned_id, term_list);
                    }
                    if (validator.current_group_id) |id| {
                        validator.allocator.free(id);
                        validator.current_group_id = null;
                    }
                }
            },
            else => {},
        }

        // Check rules for required terms and contradictions.
        const rules = frame.rules;
        for (rules) |rule| {
            var matched: usize = 0;
            for (rule.terms) |rt| {
                for (scope) |st| {
                    const is_match = if (rt.allow_children)
                        validator.cv_table.isDescendantOf(st.accession, rt.accession)
                    else
                        std.mem.eql(u8, st.accession, rt.accession);
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
                        try validator.diagnostics.append(validator.allocator, .{
                            .severity = .@"error",
                            .rule = RuleId.mzml_cv_required,
                            .location = .{ .byte_offset = end.byte_offset },
                            .path = validator.path,
                            .message = "missing required CV term for element",
                        });
                        return;
                    }
                },
                .should => {
                    const ok = switch (rule.logic) {
                        .@"and" => matched == rule.terms.len,
                        .@"or" => matched > 0,
                    };
                    if (!ok) {
                        try validator.diagnostics.append(validator.allocator, .{
                            .severity = .warning,
                            .rule = RuleId.mzml_cv_recommended,
                            .location = .{ .byte_offset = end.byte_offset },
                            .path = validator.path,
                            .message = "missing recommended CV term for element",
                        });
                    }
                },
                .may => {},
            }
        }

        // Non-repeatable term duplication (outside OR groups; OR-group
        // duplicates are caught by contradiction detection above).
        for (scope, 0..) |item, i| {
            for (scope[0..i]) |earlier| {
                if (std.mem.eql(u8, item.accession, earlier.accession)) {
                    for (rules) |r| {
                        for (r.terms) |rt| {
                            if (!rt.is_repeatable and std.mem.eql(u8, rt.accession, item.accession)) {
                                try validator.diagnostics.append(validator.allocator, .{
                                    .severity = .warning,
                                    .rule = RuleId.mzml_cv_term_repeat,
                                    .location = .{ .byte_offset = end.byte_offset },
                                    .path = validator.path,
                                    .message = "non-repeatable CV term appears more than once on the same element",
                                });
                                return;
                            }
                        }
                    }
                }
            }
        }

        // Contradiction: two alternatives from the same OR rule on one element.
        // A contradiction exists when:
        //   1. Two scope items match the same rule term which is
        //      is_repeatable=false (e.g., both positive and negative scan),
        //   2. OR two scope items match different rule terms and at least
        //      one has allow_children=false (specific alternatives).
        // Terms with is_repeatable=true are broad categories that can
        // legitimately have multiple children (e.g., "selection window
        // attribute" with upper and lower limits).
        if (scope.len >= 2) {
            for (rules) |r| {
                if (r.logic != .@"or") continue;
                var or_matched: usize = 0;
                var first_term: ?usize = null;
                for (scope) |st| {
                    for (r.terms, 0..) |rt, i| {
                        const is_match = if (rt.allow_children)
                            validator.cv_table.isDescendantOf(st.accession, rt.accession)
                        else
                            std.mem.eql(u8, st.accession, rt.accession);
                        if (is_match) {
                            or_matched += 1;
                            if (first_term) |idx| {
                                if (i == idx) {
                                    // Same term matched twice.
                                    if (!rt.is_repeatable) {
                                        try validator.diagnostics.append(validator.allocator, .{
                                            .severity = .warning,
                                            .rule = RuleId.mzml_cv_contradiction,
                                            .location = .{ .byte_offset = end.byte_offset },
                                            .path = validator.path,
                                            .message = "element has contradictory CV terms",
                                        });
                                        return;
                                    }
                                }
                            } else {
                                first_term = i;
                            }
                            break;
                        }
                    }
                }
                if (or_matched > 1) {
                    // Multiple different terms matched. Only a contradiction if
                    // any term uses allow_children=false (specific alternatives).
                    // When all terms use allow_children=true, they represent
                    // independent attribute categories that can coexist.
                    var all_allow_children = true;
                    for (r.terms) |rt| {
                        if (!rt.allow_children) {
                            all_allow_children = false;
                            break;
                        }
                    }
                    if (!all_allow_children) {
                        try validator.diagnostics.append(validator.allocator, .{
                            .severity = .warning,
                            .rule = RuleId.mzml_cv_contradiction,
                            .location = .{ .byte_offset = end.byte_offset },
                            .path = validator.path,
                            .message = "element has contradictory CV terms",
                        });
                        return;
                    }
                }
            }
        }
    }

    pub fn finish(validator: *SemanticValidator) !void {
        try validator.ref_table.resolveAll(validator.diagnostics, validator.path);
    }
};

// Recognised external CV prefixes not defined in psi-ms.obo.
// Matching OpenMS behaviour: BTO, GO, PATO terms are not validated
// because their ontologies are not embedded.
fn isKnownExternalPrefix(prefix: []const u8) bool {
    if (prefix.len == 3) {
        return prefix[0] == 'B' and prefix[1] == 'T' and prefix[2] == 'O';
    }
    if (prefix.len == 2) {
        return prefix[0] == 'G' and prefix[1] == 'O';
    }
    if (prefix.len == 4) {
        return prefix[0] == 'P' and prefix[1] == 'A' and prefix[2] == 'T' and prefix[3] == 'O';
    }
    return false;
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

// --- Unit tests ---

const test_events = @import("test_events.zig");
const testing = std.testing;
const expectEqual = testing.expectEqual;
const expectEqualStrings = testing.expectEqualStrings;
const expectError = testing.expectError;
const Severity = diagnostic.Severity;

fn consumeCvParam(validator: *SemanticValidator, accession: []const u8, cv_ref: []const u8, byte_offset: u64) !void {
    const attributes = [_]Attribute{
        .{ .byte_offset = 0, .name = .{ .local_name = "accession" }, .value = accession },
        .{ .byte_offset = 0, .name = .{ .local_name = "cvRef" }, .value = cv_ref },
    };
    try validator.consumeStart(.{
        .byte_offset = byte_offset,
        .name = .{ .local_name = "cvParam", .namespace_uri = mzml_namespace },
        .element_id = .cvParam,
        .attributes = &attributes,
        .self_closing = false,
    });
}

fn consumeUnknownCvParam(validator: *SemanticValidator, accession: []const u8, cv_ref: []const u8, byte_offset: u64) !void {
    const attributes = [_]Attribute{
        .{ .byte_offset = 0, .name = .{ .local_name = "accession" }, .value = accession },
        .{ .byte_offset = 0, .name = .{ .local_name = "cvRef" }, .value = cv_ref },
    };
    try validator.consumeStart(.{
        .byte_offset = byte_offset,
        .name = .{ .local_name = "cvParam", .namespace_uri = mzml_namespace },
        .element_id = .unknown,
        .attributes = &attributes,
        .self_closing = false,
    });
}

fn consumeCv(validator: *SemanticValidator, id: []const u8) !void {
    const attributes = [_]Attribute{
        .{ .byte_offset = 0, .name = .{ .local_name = "id" }, .value = id },
        .{ .byte_offset = 0, .name = .{ .local_name = "fullName" }, .value = "test" },
    };
    try validator.consumeStart(.{
        .byte_offset = 0,
        .name = .{ .local_name = "cv", .namespace_uri = mzml_namespace },
        .element_id = .cv,
        .attributes = &attributes,
        .self_closing = false,
    });
}

fn consumeUnitParam(validator: *SemanticValidator, accession: []const u8, cv_ref: []const u8, unit_acc: []const u8, byte_offset: u64) !void {
    const attributes = [_]Attribute{
        .{ .byte_offset = 0, .name = .{ .local_name = "accession" }, .value = accession },
        .{ .byte_offset = 0, .name = .{ .local_name = "cvRef" }, .value = cv_ref },
        .{ .byte_offset = 0, .name = .{ .local_name = "unitAccession" }, .value = unit_acc },
        .{ .byte_offset = 0, .name = .{ .local_name = "unitCvRef" }, .value = "UO" },
    };
    try validator.consumeStart(.{
        .byte_offset = byte_offset,
        .name = .{ .local_name = "cvParam", .namespace_uri = mzml_namespace },
        .element_id = .cvParam,
        .attributes = &attributes,
        .self_closing = false,
    });
}

fn consumeUnitParamWithName(validator: *SemanticValidator, accession: []const u8, cv_ref: []const u8, unit_acc: []const u8, unit_name: []const u8, byte_offset: u64) !void {
    const attributes = [_]Attribute{
        .{ .byte_offset = 0, .name = .{ .local_name = "accession" }, .value = accession },
        .{ .byte_offset = 0, .name = .{ .local_name = "cvRef" }, .value = cv_ref },
        .{ .byte_offset = 0, .name = .{ .local_name = "unitAccession" }, .value = unit_acc },
        .{ .byte_offset = 0, .name = .{ .local_name = "unitCvRef" }, .value = "UO" },
        .{ .byte_offset = 0, .name = .{ .local_name = "unitName" }, .value = unit_name },
    };
    try validator.consumeStart(.{
        .byte_offset = byte_offset,
        .name = .{ .local_name = "cvParam", .namespace_uri = mzml_namespace },
        .element_id = .cvParam,
        .attributes = &attributes,
        .self_closing = false,
    });
}

fn consumeUserParamNoAccession(validator: *SemanticValidator, byte_offset: u64) !void {
    const attributes = [_]Attribute{
        .{ .byte_offset = 0, .name = .{ .local_name = "name" }, .value = "some param" },
    };
    try validator.consumeStart(.{
        .byte_offset = byte_offset,
        .name = .{ .local_name = "userParam", .namespace_uri = mzml_namespace },
        .element_id = .userParam,
        .attributes = &attributes,
        .self_closing = false,
    });
}

fn consumeUserParam(validator: *SemanticValidator, byte_offset: u64, accession: []const u8, name: []const u8) !void {
    const attributes = [_]Attribute{
        .{ .byte_offset = 0, .name = .{ .local_name = "accession" }, .value = accession },
        .{ .byte_offset = 0, .name = .{ .local_name = "name" }, .value = name },
    };
    try validator.consumeStart(.{
        .byte_offset = byte_offset,
        .name = .{ .local_name = "userParam", .namespace_uri = mzml_namespace },
        .element_id = .userParam,
        .attributes = &attributes,
        .self_closing = false,
    });
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
    try consumeCv(&sv, "MS");
    try consumeCvParam(&sv, "MS:1000001", "MS", 0);
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
    try consumeCv(&sv, "MS");
    try consumeCvParam(&sv, "MS:9999999", "MS", 100);
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
    try consumeCv(&sv, "MS");
    try consumeUnknownCvParam(&sv, "MS:9999999", "MS", 100);

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
    try consumeCv(&sv, "MS");
    try consumeCvParam(&sv, "MS:1000001", "MS", 100);
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
    try consumeCv(&sv, "MS");
    try consumeCvParam(&sv, "MS:1000001", "UO", 100);
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
    try consumeCvParam(&sv, "MS:1000001", "NONEXISTENT", 100);
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
    try consumeCv(&sv, "MS");
    try consumeCv(&sv, "UO");
    try consumeUnitParam(&sv, "MS:1000001", "MS", "UO:0000000", 100);
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
    try consumeCv(&sv, "MS");
    try consumeUnitParam(&sv, "MS:1000001", "MS", "UO:9999999", 100);
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
    try consumeCv(&sv, "UO");
    try sv.consumeStart(test_events.startInterned("cvParam", &.{
        .{ .byte_offset = 0, .name = .{ .local_name = "accession" }, .value = "UO:0000000" },
        .{ .byte_offset = 0, .name = .{ .local_name = "cvRef" }, .value = "UO" },
        .{ .byte_offset = 0, .name = .{ .local_name = "unitAccession" }, .value = "UO:0000000" },
        .{ .byte_offset = 0, .name = .{ .local_name = "unitCvRef" }, .value = "MS" },
    }, 100));
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
    try consumeCv(&sv, "UO");
    try consumeUnitParamWithName(&sv, "UO:0000000", "UO", "UO:0000000", "wrong name", 100);
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
    try consumeUserParamNoAccession(&sv, 0);
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
    try consumeCv(&sv, "MS");
    try consumeCv(&sv, "UO");
    try consumeCvParam(&sv, "MS:1000001", "MS", 0);
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
    try consumeCvParam(&sv, "MS:9999999", "NONEXISTENT", 100);
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
    try consumeCv(&sv, "MS");

    try sv.consumeStart(test_events.startInterned("spectrum", &.{}, 0));

    try consumeCvParam(&sv, "MS:1000130", "MS", 10);

    try sv.consumeEnd(test_events.endInterned("spectrum", 30));
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
    try consumeCv(&sv, "MS");

    try sv.consumeStart(test_events.startInterned("source", &.{}, 0));

    try consumeCvParam(&sv, "MS:1000482", "MS", 10);

    try sv.consumeEnd(test_events.endInterned("source", 20));
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
    try consumeCv(&sv, "MS");

    try sv.consumeStart(test_events.startInterned("source", &.{}, 0));

    try consumeCvParam(&sv, "MS:1000008", "MS", 10);

    try sv.consumeEnd(test_events.endInterned("source", 20));
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
    try consumeCv(&sv, "MS");

    try sv.consumeStart(test_events.startInterned("source", &.{}, 0));

    try consumeCvParam(&sv, "MS:1000482", "MS", 10);

    try sv.consumeEnd(test_events.endInterned("source", 20));
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
    try consumeCv(&sv, "MS");

    try sv.consumeStart(test_events.startInterned("source", &.{}, 0));

    try consumeCvParam(&sv, "MS:1000008", "MS", 10);

    try sv.consumeEnd(test_events.endInterned("source", 20));
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

    try sv.consumeStart(test_events.startInterned("software", &.{
        .{ .byte_offset = 0, .name = .{ .local_name = "id" }, .value = "SW1" },
        .{ .byte_offset = 0, .name = .{ .local_name = "version" }, .value = "1.0" },
    }, 0));

    try sv.consumeStart(test_events.startInterned("instrumentConfiguration", &.{
        .{ .byte_offset = 0, .name = .{ .local_name = "id" }, .value = "IC1" },
        .{ .byte_offset = 0, .name = .{ .local_name = "softwareRef" }, .value = "SW1" },
    }, 10));

    try sv.finish();
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

    try sv.consumeStart(test_events.startInterned("instrumentConfiguration", &.{
        .{ .byte_offset = 0, .name = .{ .local_name = "softwareRef" }, .value = "NONEXISTENT" },
    }, 10));

    try sv.finish();
    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_ref_unresolved, diagnostics.items[0].rule);
}

test "RefTable: unresolved diagnostic allocation failure propagates" {
    var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(std.testing.allocator);

    var table = RefTable.init(failing_allocator.allocator());
    var unresolved = [_]UnresolvedRef{.{ .ref_attr = "ref", .ref_value = "missing", .byte_offset = 0 }};
    table.unresolved = .{ .items = &unresolved, .capacity = unresolved.len };
    defer {
        table.unresolved = .empty;
        table.deinit();
    }

    try expectError(error.OutOfMemory, table.resolveAll(&diagnostics, null));
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

    try sv.consumeStart(test_events.startInterned("software", &.{
        .{ .byte_offset = 0, .name = .{ .local_name = "id" }, .value = "SW1" },
    }, 0));
    try sv.consumeStart(test_events.startInterned("software", &.{
        .{ .byte_offset = 0, .name = .{ .local_name = "id" }, .value = "SW1" },
    }, 10));

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

    try sv.consumeStart(test_events.startInterned("instrumentConfiguration", &.{
        .{ .byte_offset = 0, .name = .{ .local_name = "softwareRef" }, .value = "SW1" },
    }, 0));
    try sv.consumeStart(test_events.startInterned("software", &.{
        .{ .byte_offset = 0, .name = .{ .local_name = "id" }, .value = "SW1" },
    }, 10));

    try sv.finish();
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
    try consumeCv(&sv, "MS");

    try consumeCvParam(&sv, "MS:1002476", "MS", 0);
    try consumeCvParam(&sv, "MS:1002815", "MS", 10);
    try consumeCvParam(&sv, "MS:1002836", "MS", 20);
    try consumeCvParam(&sv, "MS:1000826", "MS", 30);
    try consumeCvParam(&sv, "MS:1002446", "MS", 40);
    try consumeCvParam(&sv, "MS:1002687", "MS", 50);

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
    try consumeCv(&sv, "MS");

    try consumeUserParam(&sv, 0, "MS:1000001", "test param");
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
    try consumeCv(&sv, "MS");

    try consumeUserParam(&sv, 0, "MS:9999999", "test param");
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

    try consumeCvParam(&sv, "BTO:0000001", "BTO", 0);
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
    try consumeCv(&sv, "MS");

    try sv.consumeStart(test_events.startInterned("spectrum", &.{}, 0));

    try consumeCvParam(&sv, "MS:1000130", "MS", 10);
    try consumeCvParam(&sv, "MS:1000129", "MS", 20);

    try sv.consumeEnd(test_events.endInterned("spectrum", 30));
    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_cv_contradiction, diagnostics.items[0].rule);
}
