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
const xml_scan = @import("../xml/scan.zig");
const elements = @import("elements.zig");

const Attribute = xml_events.Attribute;
const CvTable = obo.CvTable;
const Diagnostic = diagnostic.Diagnostic;
const DiagnosticSink = diagnostic.DiagnosticSink;
const RuleEngine = rule_engine.RuleEngine;
const RuleId = diagnostic.RuleId;
const StartElement = xml_events.StartElement;
const EndElement = xml_events.EndElement;
const ElementId = elements.ElementId;
const MappingRule = rule_engine.MappingRule;
const MappingTerm = rule_engine.MappingTerm;

const mzml_namespace = diagnostic.mzml_namespace;

const SemanticOwner = enum {
    declaration,
    unresolved,
    scope,
    param_group,
};

const SemanticBudget = struct {
    allocator: std.mem.Allocator,
    diagnostics: *DiagnosticSink,
    path: ?[]const u8,
    limit: usize,
    current_bytes: usize = 0,
    peak_bytes: usize = 0,
    declaration_bytes: usize = 0,
    unresolved_bytes: usize = 0,
    scope_bytes: usize = 0,
    param_group_bytes: usize = 0,
    declaration_peak_bytes: usize = 0,
    unresolved_peak_bytes: usize = 0,
    scope_peak_bytes: usize = 0,
    param_group_peak_bytes: usize = 0,

    fn init(
        allocator: std.mem.Allocator,
        diagnostics: *DiagnosticSink,
        path: ?[]const u8,
        limits: diagnostic.ResourceLimits,
    ) SemanticBudget {
        return .{
            .allocator = allocator,
            .diagnostics = diagnostics,
            .path = path,
            .limit = limits.max_semantic_bytes,
        };
    }

    fn reserve(self: *SemanticBudget, owner: SemanticOwner, bytes: usize, byte_offset: u64) !void {
        const next = std.math.add(usize, self.current_bytes, bytes) catch {
            try self.limitDiagnostic(byte_offset);
            return error.ResourceLimitExceeded;
        };
        if (next > self.limit) {
            try self.limitDiagnostic(byte_offset);
            return error.ResourceLimitExceeded;
        }

        const owner_bytes = self.ownerBytes(owner);
        owner_bytes.* = std.math.add(usize, owner_bytes.*, bytes) catch {
            try self.limitDiagnostic(byte_offset);
            return error.ResourceLimitExceeded;
        };
        const owner_peak_bytes = self.ownerPeakBytes(owner);
        owner_peak_bytes.* = @max(owner_peak_bytes.*, owner_bytes.*);
        self.current_bytes = next;
        self.peak_bytes = @max(self.peak_bytes, next);
    }

    fn release(self: *SemanticBudget, owner: SemanticOwner, bytes: usize) void {
        self.ownerBytes(owner).* -= bytes;
        self.current_bytes -= bytes;
    }

    fn ownerBytes(self: *SemanticBudget, owner: SemanticOwner) *usize {
        return switch (owner) {
            .declaration => &self.declaration_bytes,
            .unresolved => &self.unresolved_bytes,
            .scope => &self.scope_bytes,
            .param_group => &self.param_group_bytes,
        };
    }

    fn ownerPeakBytes(self: *SemanticBudget, owner: SemanticOwner) *usize {
        return switch (owner) {
            .declaration => &self.declaration_peak_bytes,
            .unresolved => &self.unresolved_peak_bytes,
            .scope => &self.scope_peak_bytes,
            .param_group => &self.param_group_peak_bytes,
        };
    }

    fn limitDiagnostic(self: *SemanticBudget, byte_offset: u64) !void {
        _ = try self.diagnostics.append(self.allocator, .{
            .severity = .@"error",
            .rule = RuleId.runtime_semantic_limit,
            .location = .{ .byte_offset = byte_offset },
            .path = self.path,
            .message = "semantic state exceeds the configured limit",
        });
    }
};

fn ensureListCapacity(
    list: anytype,
    budget: *SemanticBudget,
    owner: SemanticOwner,
    required: usize,
    byte_offset: u64,
) !void {
    if (required <= list.capacity) return;
    const item_type = @typeInfo(@TypeOf(list.items)).pointer.child;
    const extra_items = required - list.capacity;
    const extra_bytes = std.math.mul(usize, extra_items, @sizeOf(item_type)) catch {
        try budget.limitDiagnostic(byte_offset);
        return error.ResourceLimitExceeded;
    };
    try budget.reserve(owner, extra_bytes, byte_offset);
    errdefer budget.release(owner, extra_bytes);
    try list.ensureTotalCapacityPrecise(budget.allocator, required);
}

fn ensureListAppendCapacity(
    list: anytype,
    budget: *SemanticBudget,
    owner: SemanticOwner,
    byte_offset: u64,
) !void {
    const required = std.math.add(usize, list.items.len, 1) catch {
        try budget.limitDiagnostic(byte_offset);
        return error.ResourceLimitExceeded;
    };
    try ensureListCapacity(list, budget, owner, required, byte_offset);
}

// A declared id in the document.
const Declaration = struct {
    element_id: ElementId,
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
    ref_value: []const u8,
    expected_element: ?ElementId = null,
    byte_offset: u64,
};

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
        }
        table.declarations.deinit();
        for (table.unresolved.items) |r| {
            table.allocator.free(r.ref_value);
        }
        table.unresolved.deinit(table.allocator);
    }

    fn declare(
        table: *RefTable,
        budget: *SemanticBudget,
        diagnostics: *DiagnosticSink,
        path: ?[]const u8,
        id: []const u8,
        element_id: ElementId,
        byte_offset: u64,
    ) !bool {
        if (table.declarations.contains(id)) return false;

        const bytes = std.math.add(usize, @sizeOf(Declaration), id.len) catch {
            try budget.limitDiagnostic(byte_offset);
            return error.ResourceLimitExceeded;
        };
        try budget.reserve(.declaration, bytes, byte_offset);
        var budget_owned = true;
        defer if (budget_owned) budget.release(.declaration, bytes);
        const owned_id = try table.allocator.dupe(u8, id);
        var id_owned = true;
        defer if (id_owned) table.allocator.free(owned_id);

        const result = try table.declarations.getOrPut(owned_id);
        if (result.found_existing) {
            return false;
        }
        result.key_ptr.* = owned_id;
        id_owned = false;
        budget_owned = false;
        result.value_ptr.* = .{
            .element_id = element_id,
        };
        try table.resolveDeclared(budget, diagnostics, path, id, element_id);
        return true;
    }

    fn addRef(
        table: *RefTable,
        budget: *SemanticBudget,
        diagnostics: *DiagnosticSink,
        path: ?[]const u8,
        ref_value: []const u8,
        expected_element: ?ElementId,
        byte_offset: u64,
    ) !void {
        if (ref_value.len == 0) {
            _ = try diagnostics.append(table.allocator, .{
                .severity = .@"error",
                .rule = RuleId.mzml_ref_empty,
                .location = .{ .byte_offset = byte_offset },
                .path = path,
                .message = "reference value is empty",
            });
            return;
        }

        if (table.declarations.get(ref_value)) |declaration| {
            try table.checkResolved(diagnostics, path, expected_element, declaration, byte_offset);
            return;
        }

        try budget.reserve(.unresolved, ref_value.len, byte_offset);
        errdefer budget.release(.unresolved, ref_value.len);

        const owned_value = try table.allocator.dupe(u8, ref_value);
        errdefer table.allocator.free(owned_value);
        try ensureListAppendCapacity(&table.unresolved, budget, .unresolved, byte_offset);
        try table.unresolved.append(table.allocator, .{
            .ref_value = owned_value,
            .expected_element = expected_element,
            .byte_offset = byte_offset,
        });
    }

    fn resolveAll(table: *RefTable, diagnostics: *DiagnosticSink, path: ?[]const u8) !void {
        for (table.unresolved.items) |r| {
            const declaration = table.declarations.get(r.ref_value) orelse {
                _ = try diagnostics.append(table.allocator, .{
                    .severity = .@"error",
                    .rule = RuleId.mzml_ref_unresolved,
                    .location = .{ .byte_offset = r.byte_offset },
                    .path = path,
                    .message = "unresolved reference",
                });
                continue;
            };
            try table.checkResolved(diagnostics, path, r.expected_element, declaration, r.byte_offset);
        }
    }

    fn resolveDeclared(
        table: *RefTable,
        budget: *SemanticBudget,
        diagnostics: *DiagnosticSink,
        path: ?[]const u8,
        id: []const u8,
        element_id: ElementId,
    ) !void {
        var i: usize = 0;
        while (i < table.unresolved.items.len) {
            if (!std.mem.eql(u8, table.unresolved.items[i].ref_value, id)) {
                i += 1;
                continue;
            }
            const reference = table.unresolved.orderedRemove(i);
            defer {
                budget.release(.unresolved, reference.ref_value.len);
                table.allocator.free(reference.ref_value);
            }
            try table.checkResolved(
                diagnostics,
                path,
                reference.expected_element,
                .{ .element_id = element_id },
                reference.byte_offset,
            );
        }
    }

    fn checkResolved(
        table: *RefTable,
        diagnostics: *DiagnosticSink,
        path: ?[]const u8,
        expected_element: ?ElementId,
        declaration: Declaration,
        byte_offset: u64,
    ) !void {
        if (expected_element) |expected| {
            if (declaration.element_id != expected) {
                _ = try diagnostics.append(table.allocator, .{
                    .severity = .@"error",
                    .rule = RuleId.mzml_ref_wrong_target,
                    .location = .{ .byte_offset = byte_offset },
                    .path = path,
                    .message = "reference target has the wrong element type",
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
    diagnostics: *DiagnosticSink,
    path: ?[]const u8,
    budget: SemanticBudget,

    cv_refs: std.StringHashMap(void),

    scope_frames: std.ArrayList(ScopeFrame),
    scope_items: std.ArrayList(ScopeItem),

    ref_table: RefTable,

    param_groups: std.StringHashMap(std.ArrayList([]const u8)),
    current_group_id: ?[]const u8 = null,
    ancestry_limit_reported: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        cv_table: *const CvTable,
        engine: *const RuleEngine,
        diagnostics: *DiagnosticSink,
        path: ?[]const u8,
    ) SemanticValidator {
        return initWithLimits(allocator, cv_table, engine, diagnostics, path, .{});
    }

    pub fn initWithLimits(
        allocator: std.mem.Allocator,
        cv_table: *const CvTable,
        engine: *const RuleEngine,
        diagnostics: *DiagnosticSink,
        path: ?[]const u8,
        limits: diagnostic.ResourceLimits,
    ) SemanticValidator {
        return .{
            .allocator = allocator,
            .cv_table = cv_table,
            .rule_engine = engine,
            .diagnostics = diagnostics,
            .path = path,
            .budget = SemanticBudget.init(allocator, diagnostics, path, limits),
            .cv_refs = std.StringHashMap(void).init(allocator),
            .scope_frames = std.ArrayList(ScopeFrame).empty,
            .scope_items = std.ArrayList(ScopeItem).empty,
            .ref_table = RefTable.init(allocator),
            .param_groups = std.StringHashMap(std.ArrayList([]const u8)).init(allocator),
        };
    }

    pub fn resourceUsage(validator: *const SemanticValidator) diagnostic.ResourceUsage {
        return .{
            .semantic_current_bytes = validator.budget.current_bytes,
            .semantic_peak_bytes = validator.budget.peak_bytes,
            .semantic_declaration_bytes = validator.budget.declaration_bytes,
            .semantic_unresolved_bytes = validator.budget.unresolved_bytes,
            .semantic_scope_bytes = validator.budget.scope_bytes,
            .semantic_param_group_bytes = validator.budget.param_group_bytes,
            .semantic_declaration_peak_bytes = validator.budget.declaration_peak_bytes,
            .semantic_unresolved_peak_bytes = validator.budget.unresolved_peak_bytes,
            .semantic_scope_peak_bytes = validator.budget.scope_peak_bytes,
            .semantic_param_group_peak_bytes = validator.budget.param_group_peak_bytes,
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
        if (validator.current_group_id) |id| validator.allocator.free(id);
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

    fn appendScopeItem(validator: *SemanticValidator, accession: []const u8, owned: bool, byte_offset: u64) !void {
        try ensureListAppendCapacity(&validator.scope_items, &validator.budget, .scope, byte_offset);
        if (!owned) {
            try validator.scope_items.append(validator.allocator, .{ .accession = accession, .owned = false });
            return;
        }

        try validator.budget.reserve(.scope, accession.len, byte_offset);
        errdefer validator.budget.release(.scope, accession.len);
        const owned_accession = try validator.allocator.dupe(u8, accession);
        errdefer validator.allocator.free(owned_accession);
        try validator.scope_items.append(validator.allocator, .{ .accession = owned_accession, .owned = true });
    }

    pub fn consumeStart(validator: *SemanticValidator, start: StartElement) !void {
        const tag = start.resolvedId();

        var pa: ?[]const u8 = null;
        var cvr: ?[]const u8 = null;
        var ua: ?[]const u8 = null;
        var ucr: ?[]const u8 = null;
        var un: ?[]const u8 = null;
        if (tag == .cvParam or tag == .userParam) {
            if (start.attributes.len > 0) {
                for (start.attributes) |attribute| {
                    setParamAttribute(&pa, &cvr, &ua, &ucr, &un, attribute.name.local_name, attribute.value);
                }
            } else if (start.raw_tag.len > 0) {
                var raw_scanner = xml_scan.RawAttributeScanner.init(start.raw_tag);
                while (try raw_scanner.next()) |attribute| {
                    if (attribute.is_namespace_declaration) continue;
                    setParamAttribute(&pa, &cvr, &ua, &ucr, &un, attribute.local_name, attribute.value);
                }
            }
        }

        switch (tag) {
            .cv => {
                if (start.attr("id")) |id| {
                    if (validator.cv_refs.contains(id)) return;
                    const bytes = std.math.add(usize, @sizeOf([]const u8), id.len) catch {
                        try validator.budget.limitDiagnostic(start.byte_offset);
                        return error.ResourceLimitExceeded;
                    };
                    try validator.budget.reserve(.declaration, bytes, start.byte_offset);
                    errdefer validator.budget.release(.declaration, bytes);
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
                        try validator.appendScopeItem(acc, false, start.byte_offset);
                    } else {
                        try validator.appendScopeItem(acc, true, start.byte_offset);
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
                    if (!try validator.ref_table.declare(
                        &validator.budget,
                        validator.diagnostics,
                        validator.path,
                        id,
                        tag,
                        start.byte_offset,
                    )) {
                        _ = try validator.diagnostics.append(validator.allocator, .{
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
                    try validator.ref_table.addRef(
                        &validator.budget,
                        validator.diagnostics,
                        validator.path,
                        attr.value,
                        expectedReferenceTarget(tag, name_attr),
                        start.byte_offset,
                    );
                }
            }

            if (tag == .referenceableParamGroupRef) {
                if (start.attr("ref")) |ref_id| {
                    if (validator.param_groups.get(ref_id)) |group_terms| {
                        if (validator.scope_frames.items.len >= 1) {
                            for (group_terms.items) |acc| {
                                try validator.appendScopeItem(acc, true, start.byte_offset);
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
                if (frame.element_id == .indexedmzML) continue;
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

            try ensureListCapacity(
                &validator.scope_frames,
                &validator.budget,
                .scope,
                std.math.add(usize, validator.scope_frames.items.len, 1) catch {
                    try validator.budget.limitDiagnostic(start.byte_offset);
                    return error.ResourceLimitExceeded;
                },
                start.byte_offset,
            );
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
                        validator.budget.release(.param_group, old_id.len);
                        validator.current_group_id = null;
                    }
                    if (id_attr) |id| {
                        try validator.budget.reserve(.param_group, id.len, start.byte_offset);
                        const owned_id = validator.allocator.dupe(u8, id) catch |err| {
                            validator.budget.release(.param_group, id.len);
                            return err;
                        };
                        validator.current_group_id = owned_id;
                    }
                },
                else => {},
            }
        }

        if (tag == .cvParam) {
            if (cvr == null) {
                _ = try validator.diagnostics.append(validator.allocator, .{
                    .severity = .@"error",
                    .rule = RuleId.mzml_ref_missing,
                    .location = .{ .byte_offset = start.byte_offset },
                    .path = validator.path,
                    .message = "cvParam is missing required attribute cvRef",
                });
                return;
            }
            if (cvr.?.len == 0) {
                _ = try validator.diagnostics.append(validator.allocator, .{
                    .severity = .@"error",
                    .rule = RuleId.mzml_ref_empty,
                    .location = .{ .byte_offset = start.byte_offset },
                    .path = validator.path,
                    .message = "reference value is empty",
                });
                return;
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
                _ = try validator.diagnostics.append(validator.allocator, .{
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
                _ = try validator.diagnostics.append(validator.allocator, .{
                    .severity = .warning,
                    .rule = RuleId.mzml_cv_obsolete,
                    .location = .{ .byte_offset = start.byte_offset },
                    .path = validator.path,
                    .message = if (t.replaced_by != null)
                        "CV term is obsolete; use its replacement term"
                    else
                        "CV term is obsolete and has no replacement term",
                });
                return;
            }
            if (!std.mem.eql(u8, t.namespace, cv_ref)) {
                // Skip namespace check for BTO/GO/PATO (externally-managed CVs).
                if (!isKnownExternalPrefix(cv_ref)) {
                    _ = try validator.diagnostics.append(validator.allocator, .{
                        .severity = .@"error",
                        .rule = RuleId.mzml_cv_namespace,
                        .location = .{ .byte_offset = start.byte_offset },
                        .path = validator.path,
                        .message = "cvRef does not match term namespace",
                    });
                }
            }
            if (ua) |unit_acc| {
                if (t.allowed_units.len > 0 and validator.cv_table.lookup(unit_acc) != null) {
                    var allowed = false;
                    for (t.allowed_units) |allowed_acc| {
                        if (try validator.matchesDescendant(unit_acc, allowed_acc, start.byte_offset)) {
                            allowed = true;
                            break;
                        }
                    }
                    if (!allowed) {
                        _ = try validator.diagnostics.append(validator.allocator, .{
                            .severity = .@"error",
                            .rule = RuleId.mzml_cv_unit,
                            .location = .{ .byte_offset = start.byte_offset },
                            .path = validator.path,
                            .message = "unit accession is not allowed for CV term",
                        });
                    }
                }
            }
        } else {
            // BTO/GO/PATO terms may not be in our embedded psi-ms.obo.
            if (!isKnownExternalPrefix(extractAccessionPrefix(accession))) {
                _ = try validator.diagnostics.append(validator.allocator, .{
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
                        _ = try validator.diagnostics.append(validator.allocator, .{
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
                        _ = try validator.diagnostics.append(validator.allocator, .{
                            .severity = .info,
                            .rule = RuleId.mzml_cv_unit,
                            .location = .{ .byte_offset = start.byte_offset },
                            .path = validator.path,
                            .message = "unitName does not match the term's canonical name",
                        });
                    }
                }
            } else {
                _ = try validator.diagnostics.append(validator.allocator, .{
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
            for (scope) |item| {
                if (item.owned) {
                    validator.budget.release(.scope, item.accession.len);
                    validator.allocator.free(item.accession);
                }
            }
        }

        if (tag == .binaryDataArray) {
            try validator.validateBinaryDataType(scope, end.byte_offset);
        }

        // Capture referenceableParamGroup cvParams for later ref resolution.
        switch (tag) {
            .referenceableParamGroup => {
                if (validator.current_group_id) |group_id| {
                    if (validator.param_groups.get(group_id) == null) {
                        try validator.budget.reserve(.param_group, group_id.len, end.byte_offset);
                        var key_budget_owned = true;
                        defer if (key_budget_owned) validator.budget.release(.param_group, group_id.len);
                        const owned_id = try validator.allocator.dupe(u8, group_id);
                        var id_owned = true;
                        defer if (id_owned) validator.allocator.free(owned_id);
                        var term_list = std.ArrayList([]const u8).empty;
                        var list_owned = true;
                        defer if (list_owned) {
                            for (term_list.items) |t| {
                                validator.budget.release(.param_group, t.len);
                                validator.allocator.free(t);
                            }
                            const capacity_bytes = std.math.mul(usize, term_list.capacity, @sizeOf([]const u8)) catch unreachable;
                            validator.budget.release(.param_group, capacity_bytes);
                            term_list.deinit(validator.allocator);
                        };
                        for (scope) |item| {
                            try ensureListAppendCapacity(&term_list, &validator.budget, .param_group, end.byte_offset);
                            try validator.budget.reserve(.param_group, item.accession.len, end.byte_offset);
                            var term_owned = true;
                            defer if (term_owned) validator.budget.release(.param_group, item.accession.len);
                            const owned = try validator.allocator.dupe(u8, item.accession);
                            defer if (term_owned) validator.allocator.free(owned);
                            try term_list.append(validator.allocator, owned);
                            term_owned = false;
                        }
                        try validator.param_groups.put(owned_id, term_list);
                        id_owned = false;
                        key_budget_owned = false;
                        list_owned = false;
                    }
                    if (validator.current_group_id) |id| {
                        validator.allocator.free(id);
                        validator.budget.release(.param_group, id.len);
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
                    const is_match = try validator.matchesMappingTerm(st.accession, rt, end.byte_offset);
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
                        _ = try validator.diagnostics.append(validator.allocator, .{
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
                        _ = try validator.diagnostics.append(validator.allocator, .{
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
                                _ = try validator.diagnostics.append(validator.allocator, .{
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
                        const is_match = try validator.matchesMappingTerm(st.accession, rt, end.byte_offset);
                        if (is_match) {
                            or_matched += 1;
                            if (first_term) |idx| {
                                if (i == idx) {
                                    // Same term matched twice.
                                    if (!rt.is_repeatable) {
                                        _ = try validator.diagnostics.append(validator.allocator, .{
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
                        _ = try validator.diagnostics.append(validator.allocator, .{
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

    fn matchesMappingTerm(validator: *SemanticValidator, accession: []const u8, term: MappingTerm, byte_offset: u64) !bool {
        if (!term.allow_children) return std.mem.eql(u8, accession, term.accession);
        return validator.matchesDescendant(accession, term.accession, byte_offset);
    }

    fn matchesDescendant(validator: *SemanticValidator, accession: []const u8, ancestor: []const u8, byte_offset: u64) !bool {
        return switch (validator.cv_table.isDescendantOf(accession, ancestor)) {
            .yes => true,
            .no => false,
            .limit_exceeded => limit: {
                if (!validator.ancestry_limit_reported) {
                    _ = try validator.diagnostics.append(validator.allocator, .{
                        .severity = .@"error",
                        .rule = RuleId.mzml_cv_ancestry_limit,
                        .location = .{ .byte_offset = byte_offset },
                        .path = validator.path,
                        .message = "CV ancestry traversal exceeded its configured limit",
                    });
                    validator.ancestry_limit_reported = true;
                }
                break :limit false;
            },
        };
    }

    fn validateBinaryDataType(validator: *SemanticValidator, scope: []const ScopeItem, byte_offset: u64) !void {
        var allowed_types: ?[][]const u8 = null;
        for (scope) |item| {
            if (validator.cv_table.lookup(item.accession)) |term| {
                if (term.binary_data_types.len > 0) {
                    allowed_types = term.binary_data_types;
                    break;
                }
            }
        }
        const allowed = allowed_types orelse return;

        for (scope) |item| {
            for (allowed) |allowed_type| {
                if (std.mem.eql(u8, item.accession, allowed_type)) return;
            }
        }

        _ = try validator.diagnostics.append(validator.allocator, .{
            .severity = .@"error",
            .rule = RuleId.mzml_binary_type_mismatch,
            .location = .{ .byte_offset = byte_offset },
            .path = validator.path,
            .message = "binary array type is incompatible with its declared precision",
        });
    }

    pub fn finish(validator: *SemanticValidator) !void {
        try validator.ref_table.resolveAll(validator.diagnostics, validator.path);
    }
};

fn setParamAttribute(
    accession: *?[]const u8,
    cv_ref: *?[]const u8,
    unit_accession: *?[]const u8,
    unit_cv_ref: *?[]const u8,
    unit_name: *?[]const u8,
    name: []const u8,
    value: []const u8,
) void {
    if (std.mem.eql(u8, name, "accession") and accession.* == null) {
        accession.* = value;
    } else if (std.mem.eql(u8, name, "cvRef") and cv_ref.* == null) {
        cv_ref.* = value;
    } else if (std.mem.eql(u8, name, "unitAccession") and unit_accession.* == null) {
        unit_accession.* = value;
    } else if (std.mem.eql(u8, name, "unitCvRef") and unit_cv_ref.* == null) {
        unit_cv_ref.* = value;
    } else if (std.mem.eql(u8, name, "unitName") and unit_name.* == null) {
        unit_name.* = value;
    }
}

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

fn expectedReferenceTarget(tag: ElementId, ref_attr: []const u8) ?ElementId {
    if (std.mem.eql(u8, ref_attr, "cvRef") or std.mem.eql(u8, ref_attr, "unitCvRef")) return .cv;
    if (std.mem.eql(u8, ref_attr, "dataProcessingRef") or std.mem.eql(u8, ref_attr, "defaultDataProcessingRef")) return .dataProcessing;
    if (std.mem.eql(u8, ref_attr, "defaultInstrumentConfigurationRef") or std.mem.eql(u8, ref_attr, "instrumentConfigurationRef")) return .instrumentConfiguration;
    if (std.mem.eql(u8, ref_attr, "defaultSourceFileRef") or std.mem.eql(u8, ref_attr, "sourceFileRef")) return .sourceFile;
    if (std.mem.eql(u8, ref_attr, "sampleRef")) return .sample;
    if (std.mem.eql(u8, ref_attr, "scanSettingsRef")) return .scanSettings;
    if (std.mem.eql(u8, ref_attr, "spectrumRef")) return .spectrum;
    if (std.mem.eql(u8, ref_attr, "softwareRef")) return .software;
    if (std.mem.eql(u8, ref_attr, "ref")) {
        return switch (tag) {
            .referenceableParamGroupRef, .paramGroupRef => .referenceableParamGroup,
            .softwareRef => .software,
            .sourceFileRef => .sourceFile,
            else => null,
        };
    }
    return null;
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

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var engine = try testEngine(allocator);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
    defer sv.deinit();
    try consumeCv(&sv, "MS");
    try consumeCvParam(&sv, "MS:1000001", "MS", 0);
    try expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "SemanticValidator: raw attribute fallback ignores namespace declarations" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000001\n" ++ "name: sample name\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var engine = try testEngine(allocator);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
    defer sv.deinit();
    try consumeCv(&sv, "MS");

    var start = test_events.startUnknown("cvParam", &.{}, 10);
    start.raw_tag = " xmlns:accession=\"urn:test\" accession=\"MS:1000001\" cvRef=\"MS\"";
    try sv.consumeStart(start);

    try expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "SemanticValidator: invalid accession produces error" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000001\n" ++ "name: sample name\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: DiagnosticSink = .empty;
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

    var diagnostics: DiagnosticSink = .empty;
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

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var engine = try testEngine(allocator);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
    defer sv.deinit();
    try consumeCv(&sv, "MS");
    try consumeCvParam(&sv, "MS:1000001", "MS", 100);
    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_cv_obsolete, diagnostics.items[0].rule);
    try expectEqualStrings("CV term is obsolete; use its replacement term", diagnostics.items[0].message);
}

test "SemanticValidator: allowed unit restriction produces error" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++
        "id: MS:1000001\n" ++
        "name: sample value\n" ++
        "namespace: MS\n" ++
        "relationship: has_units UO:0000001\n" ++
        "\n[Term]\n" ++
        "id: UO:0000001\n" ++
        "name: allowed unit\n" ++
        "namespace: UO\n" ++
        "\n[Term]\n" ++
        "id: UO:0000002\n" ++
        "name: other unit\n" ++
        "namespace: UO\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var engine = try testEngine(allocator);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
    defer sv.deinit();
    try consumeCv(&sv, "MS");
    try consumeCv(&sv, "UO");
    try consumeUnitParam(&sv, "MS:1000001", "MS", "UO:0000002", 100);

    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_cv_unit, diagnostics.items[0].rule);
    try expectEqualStrings("unit accession is not allowed for CV term", diagnostics.items[0].message);
}

test "SemanticValidator: binary data type restriction produces error" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++
        "id: MS:1000514\n" ++
        "name: m/z array\n" ++
        "namespace: MS\n" ++
        "xref: binary-data-type:MS\\:1000521\n" ++
        "\n[Term]\n" ++
        "id: MS:1000519\n" ++
        "name: 32-bit integer\n" ++
        "namespace: MS\n" ++
        "\n[Term]\n" ++
        "id: MS:1000521\n" ++
        "name: 32-bit float\n" ++
        "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var engine = try testEngine(allocator);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
    defer sv.deinit();
    try consumeCv(&sv, "MS");
    try sv.consumeStart(test_events.startInterned("binaryDataArray", &.{}, 0));
    try consumeCvParam(&sv, "MS:1000514", "MS", 10);
    try consumeCvParam(&sv, "MS:1000519", "MS", 20);
    try sv.consumeEnd(test_events.endInterned("binaryDataArray", 30));

    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_binary_type_mismatch, diagnostics.items[0].rule);
    try expectEqualStrings("binary array type is incompatible with its declared precision", diagnostics.items[0].message);
}

test "SemanticValidator: mismatched cvRef/namespace produces error" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000001\n" ++ "name: sample name\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: DiagnosticSink = .empty;
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

    var diagnostics: DiagnosticSink = .empty;
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

    var diagnostics: DiagnosticSink = .empty;
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

    var diagnostics: DiagnosticSink = .empty;
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

    var diagnostics: DiagnosticSink = .empty;
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

    var diagnostics: DiagnosticSink = .empty;
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

    var diagnostics: DiagnosticSink = .empty;
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

    var diagnostics: DiagnosticSink = .empty;
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

    var diagnostics: DiagnosticSink = .empty;
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

    var diagnostics: DiagnosticSink = .empty;
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

    var diagnostics: DiagnosticSink = .empty;
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

test "SemanticValidator: indexed wrapper preserves mapping paths" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000008\n" ++ "name: ionization type\n" ++ "namespace: MS\n" ++
        "[Term]\n" ++ "id: MS:1000482\n" ++ "name: source attribute\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    const rule_xml = "<CvMapping><CvMappingRuleList>" ++
        "<CvMappingRule id=\"source_must\" cvElementPath=\"/\" requirementLevel=\"MUST\" scopePath=\"/mzML/source\" cvTermsCombinationLogic=\"AND\">" ++
        "<CvTerm termAccession=\"MS:1000008\"></CvTerm>" ++
        "</CvMappingRule></CvMappingRuleList></CvMapping>";
    var engine = try RuleEngine.init(allocator, rule_xml);
    defer engine.deinit();

    for ([_]bool{ false, true }) |indexed| {
        var diagnostics: DiagnosticSink = .empty;
        defer diagnostics.deinit(allocator);

        var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
        defer sv.deinit();
        try consumeCv(&sv, "MS");
        if (indexed) try sv.consumeStart(test_events.startInterned("indexedmzML", &.{}, 0));
        try sv.consumeStart(test_events.startInterned("mzML", &.{}, 1));
        try sv.consumeStart(test_events.startInterned("source", &.{}, 2));
        try consumeCvParam(&sv, "MS:1000482", "MS", 3);
        try sv.consumeEnd(test_events.endInterned("source", 4));
        try sv.consumeEnd(test_events.endInterned("mzML", 5));
        if (indexed) try sv.consumeEnd(test_events.endInterned("indexedmzML", 6));

        try expectEqual(@as(usize, 1), diagnostics.items.len);
        try expectEqualStrings(RuleId.mzml_cv_required, diagnostics.items[0].rule);
    }
}

test "SemanticValidator: must rule passes when term present" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000008\n" ++ "name: ionization type\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: DiagnosticSink = .empty;
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

    var diagnostics: DiagnosticSink = .empty;
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

    var diagnostics: DiagnosticSink = .empty;
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

    var diagnostics: DiagnosticSink = .empty;
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

test "SemanticValidator: resolved forward references release their records" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000001\n" ++ "name: test\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var engine = try testEngine(allocator);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
    defer sv.deinit();

    try sv.consumeStart(test_events.startInterned("instrumentConfiguration", &.{
        .{ .byte_offset = 0, .name = .{ .local_name = "softwareRef" }, .value = "SW1" },
    }, 0));
    const unresolved_before = sv.resourceUsage().semantic_unresolved_bytes;

    try sv.consumeStart(test_events.startInterned("software", &.{
        .{ .byte_offset = 0, .name = .{ .local_name = "id" }, .value = "SW1" },
    }, 10));
    try std.testing.expect(sv.resourceUsage().semantic_unresolved_bytes < unresolved_before);
}

test "SemanticValidator: semantic owner limit is a fatal resource error" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000001\n" ++ "name: test\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var engine = try testEngine(allocator);
    defer engine.deinit();
    var sv = SemanticValidator.initWithLimits(allocator, &cv_table, &engine, &diagnostics, null, .{ .max_semantic_bytes = 1 });
    defer sv.deinit();

    try expectError(error.ResourceLimitExceeded, sv.consumeStart(test_events.startInterned("software", &.{
        .{ .byte_offset = 0, .name = .{ .local_name = "id" }, .value = "SW1" },
    }, 0)));
    try expectEqualStrings(RuleId.runtime_semantic_limit, diagnostics.items[0].rule);
}

test "SemanticValidator: unresolved ref produces error" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000001\n" ++ "name: test\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: DiagnosticSink = .empty;
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

test "SemanticValidator: missing cvRef produces reference diagnostic" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000001\n" ++ "name: test\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var engine = try testEngine(allocator);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
    defer sv.deinit();

    try sv.consumeStart(test_events.startInterned("cvParam", &.{}, 10));

    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_ref_missing, diagnostics.items[0].rule);
}

test "SemanticValidator: empty ref produces distinct diagnostic" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000001\n" ++ "name: test\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var engine = try testEngine(allocator);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
    defer sv.deinit();

    try sv.consumeStart(test_events.startInterned("instrumentConfiguration", &.{
        .{ .byte_offset = 0, .name = .{ .local_name = "softwareRef" }, .value = "" },
    }, 10));

    try sv.finish();
    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_ref_empty, diagnostics.items[0].rule);
}

test "SemanticValidator: wrong ref target produces distinct diagnostic" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000001\n" ++ "name: test\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var engine = try testEngine(allocator);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
    defer sv.deinit();

    try sv.consumeStart(test_events.startInterned("instrumentConfiguration", &.{
        .{ .byte_offset = 0, .name = .{ .local_name = "id" }, .value = "IC1" },
    }, 0));
    try sv.consumeStart(test_events.startInterned("processingMethod", &.{
        .{ .byte_offset = 0, .name = .{ .local_name = "softwareRef" }, .value = "IC1" },
    }, 10));

    try sv.finish();
    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_ref_wrong_target, diagnostics.items[0].rule);
}

test "RefTable: unresolved diagnostic allocation failure propagates" {
    var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(std.testing.allocator);

    var table = RefTable.init(failing_allocator.allocator());
    var unresolved = [_]UnresolvedRef{.{ .ref_value = "missing", .byte_offset = 0 }};
    table.unresolved = .{ .items = &unresolved, .capacity = unresolved.len };
    defer {
        table.unresolved = .empty;
        table.deinit();
    }

    try expectError(error.OutOfMemory, table.resolveAll(&diagnostics, null));
}

test "RefTable: addRef cleans each allocation failure" {
    for (0..2) |fail_index| {
        var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
        var table = RefTable.init(failing_allocator.allocator());
        var diagnostics: DiagnosticSink = .empty;
        defer diagnostics.deinit(std.testing.allocator);
        var budget = SemanticBudget.init(failing_allocator.allocator(), &diagnostics, null, .{});

        try std.testing.expectError(error.OutOfMemory, table.addRef(&budget, &diagnostics, null, "missing", null, 0));
        table.deinit();

        try std.testing.expectEqual(failing_allocator.allocated_bytes, failing_allocator.freed_bytes);
    }
}

test "SemanticValidator: duplicate id produces error" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000001\n" ++ "name: test\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: DiagnosticSink = .empty;
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

    var diagnostics: DiagnosticSink = .empty;
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

    var diagnostics: DiagnosticSink = .empty;
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

    var diagnostics: DiagnosticSink = .empty;
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

    var diagnostics: DiagnosticSink = .empty;
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

    var diagnostics: DiagnosticSink = .empty;
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

    var diagnostics: DiagnosticSink = .empty;
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
