//! CV, mapping-rule, and reference validation for mzML.
//!
//! Tracks element scopes incrementally, validates CV terms and units, detects
//! mapping contradictions, and resolves id/*Ref links within a bounded
//! per-file semantic owner.

const std = @import("std");
const builtin = @import("builtin");
const diagnostic = @import("../diagnostic.zig");
const obo = @import("../obo/parser.zig");
const rule_engine = @import("../obo/rule_engine.zig");
const xml_events = @import("../xml/events.zig");
const xml_scan = @import("../xml/scan.zig");
const elements = @import("elements.zig");

const Attribute = xml_events.Attribute;
const CvTable = obo.CvTable;
const DiagnosticSink = diagnostic.DiagnosticSink;
const RuleEngine = rule_engine.RuleEngine;
const RuleId = diagnostic.RuleId;
const StartElement = xml_events.StartElement;
const EndElement = xml_events.EndElement;
const ElementId = elements.ElementId;
const MappingRule = rule_engine.MappingRule;
const MappingTerm = rule_engine.MappingTerm;

const descendant_cache_len = 128;

const DescendantCacheEntry = struct {
    accession: ?[]const u8 = null,
    ancestor: []const u8 = &.{},
    result: bool = false,
};

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

const Declaration = struct {
    element_id: ElementId,
};

const ScopeItem = struct {
    accession: []const u8,
    // Parser-backed accessions are borrowed; copied accessions are freed at scope exit.
    owned: bool,
};

const ScopeFrame = struct {
    scope_start: usize,
    rules: []const MappingRule,
    parent_path_state: ?rule_engine.PathState,
};

const UnresolvedRef = struct {
    expected_element: ?ElementId = null,
    byte_offset: u64,
    next_same_id: ?usize = null,
    resolved: bool = false,
};

const UnresolvedGroup = struct {
    head: usize,
    tail: usize,
};

fn stringMapStorageBytes(comptime Value: type, capacity: u32) !usize {
    if (capacity == 0) return 0;

    // Mirror the bundled HashMap allocation so the budget includes its alignment padding.
    const Header = struct {
        values: [*]Value,
        keys: [*][]const u8,
        capacity: u32,
    };
    const key_type = []const u8;
    const map_alignment = @max(@alignOf(Header), @alignOf(key_type), @alignOf(Value));
    const metadata_end = try std.math.add(usize, @sizeOf(Header), @intCast(capacity));
    const keys_start = try alignForward(metadata_end, @alignOf(key_type));
    const keys_bytes = try std.math.mul(usize, @intCast(capacity), @sizeOf(key_type));
    const keys_end = try std.math.add(usize, keys_start, keys_bytes);
    const values_start = try alignForward(keys_end, @alignOf(Value));
    const values_bytes = try std.math.mul(usize, @intCast(capacity), @sizeOf(Value));
    const values_end = try std.math.add(usize, values_start, values_bytes);
    return alignForward(values_end, map_alignment);
}

fn alignForward(value: usize, alignment: usize) !usize {
    const with_padding = try std.math.add(usize, value, alignment - 1);
    return with_padding & ~(alignment - 1);
}

fn ensureStringMapAppendCapacity(
    comptime Value: type,
    map: *std.StringHashMap(Value),
    budget: *SemanticBudget,
    owner: SemanticOwner,
    byte_offset: u64,
) !void {
    const required = std.math.add(u32, map.count(), 1) catch {
        try budget.limitDiagnostic(byte_offset);
        return error.ResourceLimitExceeded;
    };
    const old_capacity = map.capacity();
    if (old_capacity != 0) {
        const load_limit = std.math.mul(u64, old_capacity, std.hash_map.default_max_load_percentage) catch unreachable;
        if (@as(u64, required) <= load_limit / 100) return;
    }

    const target_without_minimum = mapCapacityForCount(required) catch {
        try budget.limitDiagnostic(byte_offset);
        return error.ResourceLimitExceeded;
    };
    const target = @max(target_without_minimum, @as(u32, 8));
    if (target <= old_capacity) return;

    const old_bytes = stringMapStorageBytes(Value, old_capacity) catch {
        try budget.limitDiagnostic(byte_offset);
        return error.ResourceLimitExceeded;
    };
    const new_bytes = stringMapStorageBytes(Value, target) catch {
        try budget.limitDiagnostic(byte_offset);
        return error.ResourceLimitExceeded;
    };
    try budget.reserve(owner, new_bytes, byte_offset);
    errdefer budget.release(owner, new_bytes);
    try map.ensureTotalCapacity(required);
    std.debug.assert(map.capacity() == target);
    budget.release(owner, old_bytes);
}

const RefTable = struct {
    allocator: std.mem.Allocator,
    declarations: std.StringHashMap(Declaration),
    unresolved: std.ArrayList(UnresolvedRef),
    unresolved_by_id: std.StringHashMap(UnresolvedGroup),
    resolution_operations: if (builtin.is_test) usize else void = if (builtin.is_test) 0 else {},

    fn init(allocator: std.mem.Allocator) RefTable {
        return .{
            .allocator = allocator,
            .declarations = std.StringHashMap(Declaration).init(allocator),
            .unresolved = std.ArrayList(UnresolvedRef).empty,
            .unresolved_by_id = std.StringHashMap(UnresolvedGroup).init(allocator),
        };
    }

    fn deinit(table: *RefTable, budget: *SemanticBudget) void {
        var it = table.declarations.iterator();
        while (it.next()) |entry| {
            budget.release(.declaration, entry.key_ptr.*.len);
            table.allocator.free(entry.key_ptr.*);
        }
        budget.release(
            .declaration,
            stringMapStorageBytes(Declaration, table.declarations.capacity()) catch unreachable,
        );
        table.declarations.deinit();
        var unresolved_it = table.unresolved_by_id.iterator();
        while (unresolved_it.next()) |entry| {
            budget.release(.unresolved, entry.key_ptr.*.len);
            table.allocator.free(entry.key_ptr.*);
        }
        budget.release(
            .unresolved,
            stringMapStorageBytes(UnresolvedGroup, table.unresolved_by_id.capacity()) catch unreachable,
        );
        table.unresolved_by_id.deinit();
        budget.release(
            .unresolved,
            std.math.mul(usize, table.unresolved.capacity, @sizeOf(UnresolvedRef)) catch unreachable,
        );
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
        if (id.len == 0) return true;
        if (table.declarations.contains(id)) return false;

        try budget.reserve(.declaration, id.len, byte_offset);
        var budget_owned = true;
        defer if (budget_owned) budget.release(.declaration, id.len);
        const owned_id = try table.allocator.dupe(u8, id);
        var id_owned = true;
        defer if (id_owned) table.allocator.free(owned_id);

        try ensureStringMapAppendCapacity(Declaration, &table.declarations, budget, .declaration, byte_offset);
        table.declarations.putAssumeCapacityNoClobber(owned_id, .{
            .element_id = element_id,
        });
        id_owned = false;
        budget_owned = false;
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
        if (ref_value.len == 0) return;

        if (table.declarations.get(ref_value)) |declaration| {
            try table.checkResolved(diagnostics, path, expected_element, declaration, byte_offset);
            return;
        }

        try ensureListAppendCapacity(&table.unresolved, budget, .unresolved, byte_offset);
        const reference_index = table.unresolved.items.len;
        if (table.unresolved_by_id.getPtr(ref_value)) |group| {
            table.unresolved.items[group.tail].next_same_id = reference_index;
            group.tail = reference_index;
            table.unresolved.appendAssumeCapacity(.{
                .expected_element = expected_element,
                .byte_offset = byte_offset,
            });
            return;
        }

        try ensureStringMapAppendCapacity(
            UnresolvedGroup,
            &table.unresolved_by_id,
            budget,
            .unresolved,
            byte_offset,
        );
        try budget.reserve(.unresolved, ref_value.len, byte_offset);
        errdefer budget.release(.unresolved, ref_value.len);
        const owned_value = try table.allocator.dupe(u8, ref_value);
        errdefer table.allocator.free(owned_value);
        table.unresolved_by_id.putAssumeCapacityNoClobber(owned_value, .{
            .head = reference_index,
            .tail = reference_index,
        });
        table.unresolved.appendAssumeCapacity(.{
            .expected_element = expected_element,
            .byte_offset = byte_offset,
        });
    }

    fn resolveAll(table: *RefTable, diagnostics: *DiagnosticSink, path: ?[]const u8) !void {
        for (table.unresolved.items) |r| {
            table.recordResolutionOperations(1);
            if (r.resolved) continue;
            _ = try diagnostics.append(table.allocator, .{
                .severity = .@"error",
                .rule = RuleId.mzml_ref_unresolved,
                .location = .{ .byte_offset = r.byte_offset },
                .path = path,
                .message = "unresolved reference",
            });
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
        const removed = table.unresolved_by_id.fetchRemove(id) orelse return;
        defer {
            budget.release(.unresolved, removed.key.len);
            table.allocator.free(removed.key);
        }

        var current: ?usize = removed.value.head;
        while (current) |index| {
            table.recordResolutionOperations(1);
            const reference = &table.unresolved.items[index];
            reference.resolved = true;
            current = reference.next_same_id;
            try table.checkResolved(
                diagnostics,
                path,
                reference.expected_element,
                .{ .element_id = element_id },
                reference.byte_offset,
            );
        }
    }

    fn recordResolutionOperations(table: *RefTable, operations: usize) void {
        if (comptime builtin.is_test) table.resolution_operations += operations;
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

fn mapCapacityForCount(required: u32) !u32 {
    const scaled = try std.math.mul(u64, required, 100);
    const needed = try std.math.add(u64, scaled / std.hash_map.default_max_load_percentage, 1);
    const bounded = std.math.cast(u32, needed) orelse return error.Overflow;
    return std.math.ceilPowerOfTwo(u32, bounded) catch return error.Overflow;
}

/// CV terms, scope rules, contradictions, and id/*Ref resolution.
pub const SemanticValidator = struct {
    allocator: std.mem.Allocator,
    cv_table: *const CvTable,
    rule_engine: *const RuleEngine,
    diagnostics: *DiagnosticSink,
    path: ?[]const u8,
    budget: SemanticBudget,

    scope_frames: std.ArrayList(ScopeFrame),
    scope_items: std.ArrayList(ScopeItem),
    path_state: ?rule_engine.PathState,

    ref_table: RefTable,

    param_groups: std.StringHashMap(std.ArrayList([]const u8)),
    current_group_id: ?[]const u8 = null,
    ancestry_limit_reported: bool = false,
    descendant_cache: [descendant_cache_len]DescendantCacheEntry = @splat(.{}),

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
            .scope_frames = std.ArrayList(ScopeFrame).empty,
            .scope_items = std.ArrayList(ScopeItem).empty,
            .path_state = rule_engine.root_path_state,
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
        validator.budget.release(
            .scope,
            std.math.mul(usize, validator.scope_frames.capacity, @sizeOf(ScopeFrame)) catch unreachable,
        );
        validator.scope_frames.deinit(validator.allocator);
        for (validator.scope_items.items) |item| {
            if (item.owned) {
                validator.budget.release(.scope, item.accession.len);
                validator.allocator.free(item.accession);
            }
        }
        validator.budget.release(
            .scope,
            std.math.mul(usize, validator.scope_items.capacity, @sizeOf(ScopeItem)) catch unreachable,
        );
        validator.scope_items.deinit(validator.allocator);
        if (validator.current_group_id) |id| {
            validator.budget.release(.param_group, id.len);
            validator.allocator.free(id);
        }
        {
            var pg_it = validator.param_groups.iterator();
            while (pg_it.next()) |entry| {
                validator.budget.release(.param_group, entry.key_ptr.*.len);
                validator.allocator.free(entry.key_ptr.*);
                for (entry.value_ptr.items) |acc| {
                    validator.budget.release(.param_group, acc.len);
                    validator.allocator.free(acc);
                }
                validator.budget.release(
                    .param_group,
                    std.math.mul(usize, entry.value_ptr.capacity, @sizeOf([]const u8)) catch unreachable,
                );
                entry.value_ptr.deinit(validator.allocator);
            }
        }
        validator.budget.release(
            .param_group,
            stringMapStorageBytes(std.ArrayList([]const u8), validator.param_groups.capacity()) catch unreachable,
        );
        validator.param_groups.deinit();
        validator.ref_table.deinit(&validator.budget);
        std.debug.assert(validator.budget.current_bytes == 0);
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
                    if (attribute.is_namespace_declaration or attribute.name.prefix != null or attribute.name.namespace_uri != null) continue;
                    setParamAttribute(&pa, &cvr, &ua, &ucr, &un, attribute.name.local_name, attribute.value);
                }
            } else if (start.raw_tag.len > 0) {
                var raw_scanner = xml_scan.RawAttributeScanner.init(start.raw_tag);
                while (try raw_scanner.next()) |attribute| {
                    if (attribute.is_namespace_declaration) continue;
                    if (!std.mem.eql(u8, attribute.name, attribute.local_name)) continue;
                    setParamAttribute(&pa, &cvr, &ua, &ucr, &un, attribute.local_name, attribute.value);
                }
            }
        }

        switch (tag) {
            .cv => {
                if (start.attr("id")) |id| {
                    if (!try validator.ref_table.declare(
                        &validator.budget,
                        validator.diagnostics,
                        validator.path,
                        trimSchemaWhitespace(id),
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
                // mzML id is neither xs:ID nor a semantic reference target.
                if (tag != .mzML) {
                    const declaration_id = if (hasSchemaId(tag)) trimSchemaWhitespace(id) else id;
                    if (!try validator.ref_table.declare(
                        &validator.budget,
                        validator.diagnostics,
                        validator.path,
                        declaration_id,
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
                if (attr.is_namespace_declaration or attr.name.prefix != null or attr.name.namespace_uri != null) continue;
                const name_attr = attr.name.local_name;
                if (isRefAttr(name_attr)) {
                    const ref_value = if (hasSchemaIdRef(name_attr)) trimSchemaWhitespace(attr.value) else attr.value;
                    try validator.ref_table.addRef(
                        &validator.budget,
                        validator.diagnostics,
                        validator.path,
                        ref_value,
                        expectedReferenceTarget(tag, name_attr),
                        start.byte_offset,
                    );
                }
            }

            if (tag == .referenceableParamGroupRef) {
                if (start.attr("ref")) |ref_id| {
                    if (validator.param_groups.get(trimSchemaWhitespace(ref_id))) |group_terms| {
                        if (validator.scope_frames.items.len >= 1) {
                            for (group_terms.items) |acc| {
                                try validator.appendScopeItem(acc, true, start.byte_offset);
                            }
                        }
                    }
                }
            }

            const scope_start = validator.scope_items.items.len;
            const parent_path_state = validator.path_state;
            const path_state = if (tag == .indexedmzML)
                parent_path_state
            else
                validator.rule_engine.advancePath(parent_path_state, tag);
            const rules = validator.rule_engine.rulesForState(path_state);

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
                .scope_start = scope_start,
                .rules = rules,
                .parent_path_state = parent_path_state,
            });
            validator.path_state = path_state;

            switch (tag) {
                .referenceableParamGroup => {
                    const id_attr = start.attr("id");
                    if (validator.current_group_id) |old_id| {
                        validator.allocator.free(old_id);
                        validator.budget.release(.param_group, old_id.len);
                        validator.current_group_id = null;
                    }
                    if (id_attr) |id| {
                        const normalized_id = trimSchemaWhitespace(id);
                        if (normalized_id.len > 0) {
                            try validator.budget.reserve(.param_group, normalized_id.len, start.byte_offset);
                            const owned_id = validator.allocator.dupe(u8, normalized_id) catch |err| {
                                validator.budget.release(.param_group, normalized_id.len);
                                return err;
                            };
                            validator.current_group_id = owned_id;
                        }
                    }
                },
                else => {},
            }
        }

        if (tag == .cvParam and (cvr == null or cvr.?.len == 0)) return;

        const accession = pa orelse return;

        const cv_ref = if (cvr) |ref|
            ref
        else if (tag == .userParam) blk: {
            const colon = std.mem.indexOfScalar(u8, accession, ':') orelse return;
            break :blk accession[0..colon];
        } else return;

        const cv_declared = if (validator.ref_table.declarations.get(cv_ref)) |declaration|
            declaration.element_id == .cv
        else
            false;
        if (!cv_declared) {
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

        if (ua) |unit_acc| {
            const unit_cv_ref = ucr;
            const unit_name = un;

            if (validator.cv_table.lookup(unit_acc)) |unit_term| {
                if (unit_cv_ref) |ref| {
                    if (ref.len > 0 and !std.mem.eql(u8, ref, unit_term.namespace)) {
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
        defer validator.path_state = frame.parent_path_state;
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
                        try ensureStringMapAppendCapacity(
                            std.ArrayList([]const u8),
                            &validator.param_groups,
                            &validator.budget,
                            .param_group,
                            end.byte_offset,
                        );
                        validator.param_groups.putAssumeCapacityNoClobber(owned_id, term_list);
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

        const rules = frame.rules;
        var repeat_violation = false;
        var contradiction_violation = false;
        for (rules) |rule| {
            var matched: usize = 0;
            if (rule.logic == .@"or" and rule.terms.len <= @bitSizeOf(u64)) {
                var matched_terms: u64 = 0;
                var exact_terms: u64 = 0;
                var matched_scope_items: usize = 0;
                var matched_disallow_children = false;
                var first_term: ?usize = null;
                for (scope) |st| {
                    var scope_term: ?usize = null;
                    for (rule.terms, 0..) |rt, term_index| {
                        const term_bit = @as(u64, 1) << @intCast(term_index);
                        if (std.mem.eql(u8, st.accession, rt.accession)) {
                            if (!rt.is_repeatable and exact_terms & term_bit != 0) repeat_violation = true;
                            exact_terms |= term_bit;
                        }
                        if (scope_term == null and try validator.matchesMappingTerm(st.accession, rt, end.byte_offset)) {
                            scope_term = term_index;
                        }
                    }
                    if (scope_term) |term_index| {
                        const term_bit = @as(u64, 1) << @intCast(term_index);
                        matched_terms |= term_bit;
                        matched_scope_items += 1;
                        matched_disallow_children = matched_disallow_children or
                            !rule.terms[term_index].allow_children;
                        if (first_term) |first_index| {
                            if (first_index == term_index and !rule.terms[term_index].is_repeatable) {
                                contradiction_violation = true;
                            }
                        } else {
                            first_term = term_index;
                        }
                    }
                }
                matched = @popCount(matched_terms);
                if (matched_scope_items > 1 and matched_disallow_children) contradiction_violation = true;
            } else {
                for (rule.terms) |rt| {
                    var term_matched = false;
                    var exact_matches: usize = 0;
                    for (scope) |st| {
                        if (std.mem.eql(u8, st.accession, rt.accession)) exact_matches += 1;
                        if (!term_matched) {
                            term_matched = try validator.matchesMappingTerm(st.accession, rt, end.byte_offset);
                        }
                    }
                    if (term_matched) matched += 1;
                    if (!rt.is_repeatable and exact_matches > 1) repeat_violation = true;
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

        // Exact duplicate counts are folded into the rule-term scan above,
        // avoiding a second quadratic pass over the scope.
        if (repeat_violation) {
            _ = try validator.diagnostics.append(validator.allocator, .{
                .severity = .warning,
                .rule = RuleId.mzml_cv_term_repeat,
                .location = .{ .byte_offset = end.byte_offset },
                .path = validator.path,
                .message = "non-repeatable CV term appears more than once on the same element",
            });
            return;
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
                if (r.logic != .@"or" or r.terms.len <= @bitSizeOf(u64)) continue;
                var or_matched: usize = 0;
                var matched_disallow_children = false;
                var first_term: ?usize = null;
                for (scope) |st| {
                    for (r.terms, 0..) |rt, i| {
                        const is_match = try validator.matchesMappingTerm(st.accession, rt, end.byte_offset);
                        if (is_match) {
                            or_matched += 1;
                            matched_disallow_children = matched_disallow_children or !rt.allow_children;
                            if (first_term) |idx| {
                                if (i == idx) {
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
                if (or_matched > 1 and matched_disallow_children) {
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
        if (contradiction_violation) {
            _ = try validator.diagnostics.append(validator.allocator, .{
                .severity = .warning,
                .rule = RuleId.mzml_cv_contradiction,
                .location = .{ .byte_offset = end.byte_offset },
                .path = validator.path,
                .message = "element has contradictory CV terms",
            });
        }
    }

    fn matchesMappingTerm(validator: *SemanticValidator, accession: []const u8, term: MappingTerm, byte_offset: u64) !bool {
        if (!term.allow_children) return std.mem.eql(u8, accession, term.accession);
        return validator.matchesDescendant(accession, term.accession, byte_offset);
    }

    fn matchesDescendant(validator: *SemanticValidator, accession: []const u8, ancestor: []const u8, byte_offset: u64) !bool {
        if (std.mem.eql(u8, accession, ancestor)) return true;

        const cache_hash = std.hash.Wyhash.hash(
            std.hash.Wyhash.hash(0, accession),
            ancestor,
        );
        const cache_index: usize = @intCast(cache_hash & (descendant_cache_len - 1));
        const cached = validator.descendant_cache[cache_index];
        if (cached.accession) |cached_accession| {
            if (std.mem.eql(u8, cached_accession, accession) and
                std.mem.eql(u8, cached.ancestor, ancestor))
            {
                return cached.result;
            }
        }

        const result = try validator.resolveDescendant(accession, ancestor, byte_offset);
        if (!validator.ancestry_limit_reported) {
            // Scope values may borrow a parser buffer. Retain only canonical
            // invocation-owned slices from the CV table on a cache miss.
            if (validator.cv_table.lookup(accession)) |accession_term| {
                if (validator.cv_table.lookup(ancestor)) |ancestor_term| {
                    validator.descendant_cache[cache_index] = .{
                        .accession = accession_term.accession,
                        .ancestor = ancestor_term.accession,
                        .result = result,
                    };
                }
            }
        }
        return result;
    }

    fn resolveDescendant(validator: *SemanticValidator, accession: []const u8, ancestor: []const u8, byte_offset: u64) !bool {
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

fn trimSchemaWhitespace(value: []const u8) []const u8 {
    return std.mem.trim(u8, value, " \t\r\n");
}

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
        cv_ref.* = trimSchemaWhitespace(value);
    } else if (std.mem.eql(u8, name, "unitAccession") and unit_accession.* == null) {
        unit_accession.* = value;
    } else if (std.mem.eql(u8, name, "unitCvRef") and unit_cv_ref.* == null) {
        unit_cv_ref.* = trimSchemaWhitespace(value);
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

fn extractAccessionPrefix(accession: []const u8) []const u8 {
    const colon = std.mem.indexOfScalar(u8, accession, ':') orelse return accession;
    return accession[0..colon];
}

fn isRefAttr(name: []const u8) bool {
    // Reference elements use attribute name "ref" instead of a *Ref suffix.
    if (std.mem.eql(u8, name, "ref")) return true;
    return name.len >= 3 and std.mem.eql(u8, name[name.len - 3 ..], "Ref");
}

fn hasSchemaId(tag: ElementId) bool {
    return switch (tag) {
        .cv,
        .dataProcessing,
        .instrumentConfiguration,
        .referenceableParamGroup,
        .run,
        .sample,
        .scanSettings,
        .software,
        .sourceFile,
        => true,
        else => false,
    };
}

fn hasSchemaIdRef(name: []const u8) bool {
    return std.mem.eql(u8, name, "ref") or
        std.mem.eql(u8, name, "cvRef") or
        std.mem.eql(u8, name, "unitCvRef") or
        std.mem.eql(u8, name, "scanSettingsRef") or
        std.mem.eql(u8, name, "softwareRef") or
        std.mem.eql(u8, name, "defaultInstrumentConfigurationRef") or
        std.mem.eql(u8, name, "defaultSourceFileRef") or
        std.mem.eql(u8, name, "sampleRef") or
        std.mem.eql(u8, name, "defaultDataProcessingRef") or
        std.mem.eql(u8, name, "sourceFileRef") or
        std.mem.eql(u8, name, "instrumentConfigurationRef") or
        std.mem.eql(u8, name, "dataProcessingRef");
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
            .referenceableParamGroupRef => .referenceableParamGroup,
            .softwareRef => .software,
            .sourceFileRef => .sourceFile,
            else => null,
        };
    }
    return null;
}

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

fn consumeParamGroup(validator: *SemanticValidator, id: []const u8, accession: []const u8, byte_offset: u64) !void {
    try validator.consumeStart(test_events.startInterned("referenceableParamGroup", &.{
        test_events.attr("id", id),
    }, byte_offset));
    try validator.consumeStart(test_events.startInterned("cvParam", &.{
        test_events.attr("accession", accession),
    }, byte_offset + 1));
    try validator.consumeEnd(test_events.endInterned("referenceableParamGroup", byte_offset + 2));
}

fn testEngine(allocator: std.mem.Allocator) !RuleEngine {
    return try RuleEngine.init(allocator, "<CvMapping><CvMappingRuleList></CvMappingRuleList></CvMapping>");
}

// --- Unit Tests ---

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

test "SemanticValidator: descendant cache retains canonical CV accessions" {
    const allocator = testing.allocator;
    var cv_table = try CvTable.init(allocator, @embedFile("../data/psi-ms.obo"));
    defer cv_table.deinit();

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var engine = try testEngine(allocator);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
    defer sv.deinit();

    const borrowed = try allocator.dupe(u8, "MS:1003378");
    defer allocator.free(borrowed);
    try testing.expect(try sv.matchesDescendant(borrowed, "MS:1000031", 0));
    try testing.expect(try sv.matchesDescendant(borrowed, "MS:1000031", 1));

    const canonical = cv_table.lookup("MS:1003378").?.accession;
    var found = false;
    for (sv.descendant_cache) |entry| {
        if (entry.accession) |cached_accession| {
            if (std.mem.eql(u8, cached_accession, canonical)) {
                try testing.expect(cached_accession.ptr == canonical.ptr);
                found = true;
            }
        }
    }
    try testing.expect(found);
}

test "SemanticValidator: raw attribute fallback ignores foreign attributes" {
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
    start.raw_tag = " accession=\"MS:1000001\" xmlns:p=\"urn:test\" p:accession=\"MS:9999999\" cvRef=\"MS\"";
    try sv.consumeStart(start);

    try expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "SemanticValidator: eager attributes ignore foreign names" {
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

    const attributes = [_]Attribute{
        test_events.attr("accession", "MS:1000001"),
        .{ .byte_offset = 11, .name = .{ .prefix = "p", .local_name = "accession", .namespace_uri = "urn:test" }, .value = "MS:9999999" },
        test_events.attr("cvRef", "MS"),
    };
    const start = test_events.startUnknown("cvParam", &attributes, 10);

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

test "[unit]: semantic maps charge all reference-table allocator bytes" {
    var counting_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(counting_allocator.allocator());
    var budget = SemanticBudget.init(counting_allocator.allocator(), &diagnostics, null, .{});

    {
        var table = RefTable.init(counting_allocator.allocator());
        defer table.deinit(&budget);

        try table.addRef(&budget, &diagnostics, null, "r", null, 1);
        try testing.expect(try table.declare(&budget, &diagnostics, null, "d", .software, 2));

        const live_allocator_bytes = counting_allocator.allocated_bytes - counting_allocator.freed_bytes;
        const owner_bytes = budget.declaration_bytes + budget.unresolved_bytes +
            budget.scope_bytes + budget.param_group_bytes;
        try testing.expectEqual(live_allocator_bytes, budget.current_bytes);
        try testing.expectEqual(owner_bytes, budget.current_bytes);
        try testing.expect(budget.declaration_bytes > 1);
        try testing.expect(budget.unresolved_bytes > 1);
        try testing.expect(budget.peak_bytes >= budget.current_bytes);
    }

    try testing.expectEqual(@as(usize, 0), budget.current_bytes);
    try testing.expectEqual(counting_allocator.allocated_bytes, counting_allocator.freed_bytes);
}

test "[unit]: semantic map declaration growth accepts its exact limit and rejects one byte less" {
    const ids = [_][]const u8{ "a", "b", "c", "d", "e", "f", "g" };
    const initial_map_bytes = try stringMapStorageBytes(Declaration, 8);
    const replacement_map_bytes = try stringMapStorageBytes(Declaration, 16);
    const required_peak_bytes = initial_map_bytes + 7 + replacement_map_bytes;
    const allocator = testing.allocator;

    var exact_diagnostics: DiagnosticSink = .empty;
    defer exact_diagnostics.deinit(allocator);
    var exact_budget = SemanticBudget.init(allocator, &exact_diagnostics, null, .{
        .max_semantic_bytes = required_peak_bytes,
    });
    var exact_table = RefTable.init(allocator);
    defer exact_table.deinit(&exact_budget);
    for (ids[0..6]) |id| {
        try testing.expect(try exact_table.declare(&exact_budget, &exact_diagnostics, null, id, .software, 3));
    }

    try testing.expect(try exact_table.declare(&exact_budget, &exact_diagnostics, null, ids[6], .software, 4));

    try testing.expectEqual(replacement_map_bytes + ids.len, exact_budget.current_bytes);
    try testing.expectEqual(required_peak_bytes, exact_budget.peak_bytes);
    try testing.expectEqual(@as(usize, 0), exact_diagnostics.items.len);

    var over_diagnostics: DiagnosticSink = .empty;
    defer over_diagnostics.deinit(allocator);
    var over_budget = SemanticBudget.init(allocator, &over_diagnostics, null, .{
        .max_semantic_bytes = required_peak_bytes - 1,
    });
    var over_table = RefTable.init(allocator);
    defer over_table.deinit(&over_budget);
    for (ids[0..6]) |id| {
        try testing.expect(try over_table.declare(&over_budget, &over_diagnostics, null, id, .software, 3));
    }

    try testing.expectError(
        error.ResourceLimitExceeded,
        over_table.declare(&over_budget, &over_diagnostics, null, ids[6], .software, 5),
    );

    try testing.expectEqual(initial_map_bytes + 6, over_budget.current_bytes);
    try testing.expectEqual(@as(usize, 1), over_diagnostics.items.len);
    try testing.expectEqualStrings(RuleId.runtime_semantic_limit, over_diagnostics.items[0].rule);
    try testing.expectEqual(@as(u64, 5), over_diagnostics.items[0].location.byte_offset);
}

test "[unit]: semantic map parameter-group storage charges all allocator bytes" {
    const catalog_allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000001\n" ++ "name: test\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(catalog_allocator, obo_text);
    defer cv_table.deinit();
    var engine = try testEngine(catalog_allocator);
    defer engine.deinit();

    var counting_allocator = std.testing.FailingAllocator.init(testing.allocator, .{});
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(counting_allocator.allocator());
    var sv = SemanticValidator.init(counting_allocator.allocator(), &cv_table, &engine, &diagnostics, null);
    var sv_live = true;
    defer if (sv_live) sv.deinit();

    try consumeParamGroup(&sv, "g", "a", 10);

    const usage = sv.resourceUsage();
    const live_allocator_bytes = counting_allocator.allocated_bytes - counting_allocator.freed_bytes;
    const owner_bytes = usage.semantic_declaration_bytes + usage.semantic_unresolved_bytes +
        usage.semantic_scope_bytes + usage.semantic_param_group_bytes;
    try testing.expectEqual(live_allocator_bytes, usage.semantic_current_bytes);
    try testing.expectEqual(owner_bytes, usage.semantic_current_bytes);
    try testing.expect(usage.semantic_param_group_bytes > 2);
    try testing.expect(usage.semantic_param_group_peak_bytes >= usage.semantic_param_group_bytes);

    sv.deinit();
    sv_live = false;

    try testing.expectEqual(@as(usize, 0), sv.budget.current_bytes);
    try testing.expectEqual(counting_allocator.allocated_bytes, counting_allocator.freed_bytes);
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

test "SemanticValidator: foreign reference attributes are ignored" {
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

    const attributes = [_]Attribute{
        .{ .byte_offset = 10, .name = .{ .prefix = "x", .local_name = "softwareRef", .namespace_uri = "urn:foreign" }, .value = "NONEXISTENT" },
    };
    const start = test_events.startInterned("instrumentConfiguration", &attributes, 10);

    try sv.consumeStart(start);
    try sv.finish();

    try expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "[unit]: semantic validator leaves missing cvRef to structural validation" {
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

    try expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "[unit]: semantic validator leaves empty references to structural validation" {
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
    try expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "[unit]: semantic validator resolves collapsed IDREF whitespace" {
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

    try sv.consumeStart(test_events.startInterned("software", &.{test_events.attr("id", " SW1 ")}, 0));
    try sv.consumeStart(test_events.startInterned("processingMethod", &.{test_events.attr("softwareRef", "\tSW1\n")}, 10));
    try sv.finish();

    try expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "[unit]: semantic validator includes run IDs in XML ID uniqueness" {
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

    try sv.consumeStart(test_events.startInterned("run", &.{test_events.attr("id", "duplicate")}, 0));
    try sv.consumeStart(test_events.startInterned("software", &.{test_events.attr("id", " duplicate ")}, 10));

    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_ref_duplicate_id, diagnostics.items[0].rule);
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

test "[unit]: unresolved diagnostic allocation failure propagates" {
    var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(std.testing.allocator);
    var budget = SemanticBudget.init(failing_allocator.allocator(), &diagnostics, null, .{});

    var table = RefTable.init(failing_allocator.allocator());
    var unresolved = [_]UnresolvedRef{.{ .byte_offset = 0 }};
    table.unresolved = .{ .items = &unresolved, .capacity = unresolved.len };
    defer {
        table.unresolved = .empty;
        table.deinit(&budget);
    }

    try expectError(error.OutOfMemory, table.resolveAll(&diagnostics, null));
}

test "[unit]: addRef cleans every allocation failure" {
    const reference_count = 8;

    var baseline_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var baseline_diagnostics: DiagnosticSink = .empty;
    var baseline_diagnostics_live = true;
    defer if (baseline_diagnostics_live) baseline_diagnostics.deinit(baseline_allocator.allocator());
    var baseline_budget = SemanticBudget.init(baseline_allocator.allocator(), &baseline_diagnostics, null, .{});
    var baseline_table = RefTable.init(baseline_allocator.allocator());
    var baseline_table_live = true;
    defer if (baseline_table_live) baseline_table.deinit(&baseline_budget);
    for (0..reference_count) |index| {
        var id_buffer: [32]u8 = undefined;
        const id = try std.fmt.bufPrint(&id_buffer, "missing-{d}", .{index});
        try baseline_table.addRef(&baseline_budget, &baseline_diagnostics, null, id, null, index);
    }
    try testing.expect(baseline_table.unresolved_by_id.capacity() > 8);
    baseline_table.deinit(&baseline_budget);
    baseline_table_live = false;
    baseline_diagnostics.deinit(baseline_allocator.allocator());
    baseline_diagnostics_live = false;
    try testing.expectEqual(@as(usize, 0), baseline_budget.current_bytes);
    try testing.expectEqual(baseline_allocator.allocated_bytes, baseline_allocator.freed_bytes);

    for (0..baseline_allocator.alloc_index) |fail_index| {
        var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
        var table = RefTable.init(failing_allocator.allocator());
        var diagnostics: DiagnosticSink = .empty;
        defer diagnostics.deinit(failing_allocator.allocator());
        var budget = SemanticBudget.init(failing_allocator.allocator(), &diagnostics, null, .{});
        var table_live = true;
        defer if (table_live) table.deinit(&budget);

        var failed = false;
        add_refs: for (0..reference_count) |index| {
            var id_buffer: [32]u8 = undefined;
            const id = try std.fmt.bufPrint(&id_buffer, "missing-{d}", .{index});
            table.addRef(&budget, &diagnostics, null, id, null, index) catch |err| {
                try testing.expect(err == error.OutOfMemory);
                failed = true;
                break :add_refs;
            };
        }
        table.deinit(&budget);
        table_live = false;

        try testing.expect(failed);
        try testing.expectEqual(@as(usize, 0), budget.current_bytes);
        try testing.expectEqual(failing_allocator.allocated_bytes, failing_allocator.freed_bytes);
    }
}

test "[unit]: semantic map declaration growth cleans every allocation failure" {
    const declaration_count = 8;

    var baseline_allocator = std.testing.FailingAllocator.init(testing.allocator, .{});
    var baseline_diagnostics: DiagnosticSink = .empty;
    var baseline_diagnostics_live = true;
    defer if (baseline_diagnostics_live) baseline_diagnostics.deinit(baseline_allocator.allocator());
    var baseline_budget = SemanticBudget.init(baseline_allocator.allocator(), &baseline_diagnostics, null, .{});
    var baseline_table = RefTable.init(baseline_allocator.allocator());
    var baseline_table_live = true;
    defer if (baseline_table_live) baseline_table.deinit(&baseline_budget);
    for (0..declaration_count) |index| {
        var id_buffer: [16]u8 = undefined;
        const id = try std.fmt.bufPrint(&id_buffer, "d{d}", .{index});
        try testing.expect(try baseline_table.declare(
            &baseline_budget,
            &baseline_diagnostics,
            null,
            id,
            .software,
            index,
        ));
    }
    try testing.expect(baseline_table.declarations.capacity() > 8);
    baseline_table.deinit(&baseline_budget);
    baseline_table_live = false;
    baseline_diagnostics.deinit(baseline_allocator.allocator());
    baseline_diagnostics_live = false;
    try testing.expectEqual(@as(usize, 0), baseline_budget.current_bytes);
    try testing.expectEqual(baseline_allocator.allocated_bytes, baseline_allocator.freed_bytes);

    for (0..baseline_allocator.alloc_index) |fail_index| {
        var failing_allocator = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fail_index });
        var diagnostics: DiagnosticSink = .empty;
        var diagnostics_live = true;
        defer if (diagnostics_live) diagnostics.deinit(failing_allocator.allocator());
        var budget = SemanticBudget.init(failing_allocator.allocator(), &diagnostics, null, .{});
        var table = RefTable.init(failing_allocator.allocator());
        var table_live = true;
        defer if (table_live) table.deinit(&budget);

        var failed = false;
        declarations: for (0..declaration_count) |index| {
            var id_buffer: [16]u8 = undefined;
            const id = try std.fmt.bufPrint(&id_buffer, "d{d}", .{index});
            _ = table.declare(&budget, &diagnostics, null, id, .software, index) catch |err| {
                try testing.expect(err == error.OutOfMemory);
                failed = true;
                break :declarations;
            };
        }
        table.deinit(&budget);
        table_live = false;
        diagnostics.deinit(failing_allocator.allocator());
        diagnostics_live = false;

        try testing.expect(failed);
        try testing.expectEqual(@as(usize, 0), budget.current_bytes);
        try testing.expectEqual(failing_allocator.allocated_bytes, failing_allocator.freed_bytes);
    }
}

test "[unit]: semantic map parameter-group growth cleans every allocation failure" {
    const group_count = 8;
    const catalog_allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000001\n" ++ "name: test\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(catalog_allocator, obo_text);
    defer cv_table.deinit();
    var engine = try testEngine(catalog_allocator);
    defer engine.deinit();

    var baseline_allocator = std.testing.FailingAllocator.init(testing.allocator, .{});
    var baseline_diagnostics: DiagnosticSink = .empty;
    var baseline_diagnostics_live = true;
    defer if (baseline_diagnostics_live) baseline_diagnostics.deinit(baseline_allocator.allocator());
    var baseline_sv = SemanticValidator.init(
        baseline_allocator.allocator(),
        &cv_table,
        &engine,
        &baseline_diagnostics,
        null,
    );
    var baseline_sv_live = true;
    defer if (baseline_sv_live) baseline_sv.deinit();
    for (0..group_count) |index| {
        var id_buffer: [16]u8 = undefined;
        const id = try std.fmt.bufPrint(&id_buffer, "g{d}", .{index});
        try consumeParamGroup(&baseline_sv, id, "a", index * 3);
    }
    try testing.expect(baseline_sv.param_groups.capacity() > 8);
    baseline_sv.deinit();
    baseline_sv_live = false;
    baseline_diagnostics.deinit(baseline_allocator.allocator());
    baseline_diagnostics_live = false;
    try testing.expectEqual(@as(usize, 0), baseline_sv.budget.current_bytes);
    try testing.expectEqual(baseline_allocator.allocated_bytes, baseline_allocator.freed_bytes);

    for (0..baseline_allocator.alloc_index) |fail_index| {
        var failing_allocator = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fail_index });
        var diagnostics: DiagnosticSink = .empty;
        var diagnostics_live = true;
        defer if (diagnostics_live) diagnostics.deinit(failing_allocator.allocator());
        var sv = SemanticValidator.init(
            failing_allocator.allocator(),
            &cv_table,
            &engine,
            &diagnostics,
            null,
        );
        var sv_live = true;
        defer if (sv_live) sv.deinit();

        var failed = false;
        groups: for (0..group_count) |index| {
            var id_buffer: [16]u8 = undefined;
            const id = try std.fmt.bufPrint(&id_buffer, "g{d}", .{index});
            consumeParamGroup(&sv, id, "a", index * 3) catch |err| {
                try testing.expect(err == error.OutOfMemory);
                failed = true;
                break :groups;
            };
        }
        sv.deinit();
        sv_live = false;
        diagnostics.deinit(failing_allocator.allocator());
        diagnostics_live = false;

        try testing.expect(failed);
        try testing.expectEqual(@as(usize, 0), sv.budget.current_bytes);
        try testing.expectEqual(failing_allocator.allocated_bytes, failing_allocator.freed_bytes);
    }
}

test "[unit]: unresolved-reference index storage obeys the semantic budget" {
    const allocator = testing.allocator;

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var budget = SemanticBudget.init(allocator, &diagnostics, null, .{ .max_semantic_bytes = @sizeOf(UnresolvedRef) });
    var table = RefTable.init(allocator);
    defer table.deinit(&budget);

    try testing.expectError(error.ResourceLimitExceeded, table.addRef(&budget, &diagnostics, null, "missing", null, 7));

    try testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try testing.expectEqualStrings(RuleId.runtime_semantic_limit, diagnostics.items[0].rule);
    try testing.expectEqual(@as(u64, 7), diagnostics.items[0].location.byte_offset);
}

test "[unit]: reference diagnostics retain deterministic order and offsets" {
    const allocator = testing.allocator;

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var budget = SemanticBudget.init(allocator, &diagnostics, null, .{});
    var table = RefTable.init(allocator);
    defer table.deinit(&budget);

    try table.addRef(&budget, &diagnostics, null, "missing-first", .software, 30);
    try table.addRef(&budget, &diagnostics, null, "wrong", .software, 10);
    try table.addRef(&budget, &diagnostics, null, "missing-second", .sourceFile, 20);
    try table.addRef(&budget, &diagnostics, null, "wrong", .sourceFile, 40);
    try testing.expect(try table.declare(&budget, &diagnostics, null, "wrong", .instrumentConfiguration, 50));
    try table.resolveAll(&diagnostics, null);

    try testing.expectEqual(@as(usize, 4), diagnostics.items.len);
    try testing.expectEqualStrings(RuleId.mzml_ref_wrong_target, diagnostics.items[0].rule);
    try testing.expectEqual(@as(u64, 10), diagnostics.items[0].location.byte_offset);
    try testing.expectEqualStrings(RuleId.mzml_ref_wrong_target, diagnostics.items[1].rule);
    try testing.expectEqual(@as(u64, 40), diagnostics.items[1].location.byte_offset);
    try testing.expectEqualStrings(RuleId.mzml_ref_unresolved, diagnostics.items[2].rule);
    try testing.expectEqual(@as(u64, 30), diagnostics.items[2].location.byte_offset);
    try testing.expectEqualStrings(RuleId.mzml_ref_unresolved, diagnostics.items[3].rule);
    try testing.expectEqual(@as(u64, 20), diagnostics.items[3].location.byte_offset);
}

test "[unit]: forward-reference resolution work stays near-linear" {
    const allocator = testing.allocator;
    const reference_count = 64;

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var budget = SemanticBudget.init(allocator, &diagnostics, null, .{});
    var table = RefTable.init(allocator);
    defer table.deinit(&budget);

    for (0..reference_count) |index| {
        var id_buffer: [32]u8 = undefined;
        const id = try std.fmt.bufPrint(&id_buffer, "SW-{d}", .{index});
        try table.addRef(&budget, &diagnostics, null, id, .software, index);
    }
    for (0..reference_count) |index| {
        var id_buffer: [32]u8 = undefined;
        const id = try std.fmt.bufPrint(&id_buffer, "SW-{d}", .{index});
        try testing.expect(try table.declare(&budget, &diagnostics, null, id, .software, index));
    }
    try table.resolveAll(&diagnostics, null);

    try testing.expect(table.resolution_operations <= reference_count * 2);
    try testing.expectEqual(@as(usize, 0), diagnostics.items.len);
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

test "SemanticValidator: duplicate cv id produces error" {
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

    try consumeCv(&sv, "MS");
    try consumeCv(&sv, "MS");

    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_ref_duplicate_id, diagnostics.items[0].rule);
}

test "SemanticValidator: cv id conflicts with another document id" {
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

    try consumeCv(&sv, "shared");
    try sv.consumeStart(test_events.startInterned("software", &.{
        .{ .byte_offset = 0, .name = .{ .local_name = "id" }, .value = "shared" },
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

// --- userParam CV Validation ---

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

// --- BTO/GO/PATO Support ---

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

// --- Contradiction Detection Across All Rules ---

test "SemanticValidator: non-repeatable exact duplicates are detected during rule scan" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000130\n" ++ "name: positive scan\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    const rule_xml = "<CvMapping><CvMappingRuleList>" ++
        "<CvMappingRule id=\"test\" cvElementPath=\"/\" requirementLevel=\"MAY\" scopePath=\"/spectrum\" cvTermsCombinationLogic=\"AND\">" ++
        "<CvTerm termAccession=\"MS:1000130\" isRepeatable=\"false\"></CvTerm>" ++
        "</CvMappingRule></CvMappingRuleList></CvMapping>";
    var engine = try RuleEngine.init(allocator, rule_xml);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
    defer sv.deinit();
    try consumeCv(&sv, "MS");

    try sv.consumeStart(test_events.startInterned("spectrum", &.{}, 0));
    try consumeCvParam(&sv, "MS:1000130", "MS", 10);
    try consumeCvParam(&sv, "MS:1000130", "MS", 20);
    try sv.consumeEnd(test_events.endInterned("spectrum", 30));

    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_cv_term_repeat, diagnostics.items[0].rule);
}

test "SemanticValidator: contradiction detected when two OR alternatives on same element" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++ "id: MS:1000130\n" ++ "name: positive scan\n" ++ "namespace: MS\n" ++
        "[Term]\n" ++ "id: MS:1000129\n" ++ "name: negative scan\n" ++ "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

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

test "SemanticValidator: unmatched exact OR term does not create contradiction" {
    const allocator = testing.allocator;
    const obo_text = "[Term]\n" ++
        "id: MS:1000001\n" ++
        "name: broad term\n" ++
        "namespace: MS\n" ++
        "[Term]\n" ++
        "id: MS:1000002\n" ++
        "name: child one\n" ++
        "namespace: MS\n" ++
        "is_a: MS:1000001 ! broad term\n" ++
        "[Term]\n" ++
        "id: MS:1000003\n" ++
        "name: child two\n" ++
        "namespace: MS\n" ++
        "is_a: MS:1000001 ! broad term\n" ++
        "[Term]\n" ++
        "id: MS:1000004\n" ++
        "name: unmatched exact term\n" ++
        "namespace: MS\n";
    var cv_table = try CvTable.init(allocator, obo_text);
    defer cv_table.deinit();

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    const rule_xml = "<CvMapping><CvMappingRuleList>" ++
        "<CvMappingRule id=\"test\" cvElementPath=\"/\" requirementLevel=\"MAY\" scopePath=\"/spectrum\" cvTermsCombinationLogic=\"OR\">" ++
        "<CvTerm termAccession=\"MS:1000001\" allowChildren=\"true\" isRepeatable=\"true\"></CvTerm>" ++
        "<CvTerm termAccession=\"MS:1000004\" allowChildren=\"false\"></CvTerm>" ++
        "</CvMappingRule>" ++
        "</CvMappingRuleList></CvMapping>";
    var engine = try RuleEngine.init(allocator, rule_xml);
    defer engine.deinit();
    var sv = SemanticValidator.init(allocator, &cv_table, &engine, &diagnostics, null);
    defer sv.deinit();
    try consumeCv(&sv, "MS");

    try sv.consumeStart(test_events.startInterned("spectrum", &.{}, 0));
    try consumeCvParam(&sv, "MS:1000002", "MS", 10);
    try consumeCvParam(&sv, "MS:1000003", "MS", 20);
    try sv.consumeEnd(test_events.endInterned("spectrum", 30));

    try expectEqual(@as(usize, 0), diagnostics.items.len);
}

const test_events = @import("test_events.zig");
const testing = std.testing;
const expectEqual = testing.expectEqual;
const expectEqualStrings = testing.expectEqualStrings;
const expectError = testing.expectError;
const Severity = diagnostic.Severity;
