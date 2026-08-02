//! Parses and indexes PSI-MS CV mapping rules for mzML elements.
//! Owned rule strings are shared by path lookup and the incremental path index.

const std = @import("std");
const obo = @import("parser.zig");
const elements = @import("../mzml/elements.zig");
const xml_events = @import("../xml/events.zig");
const xml_parser = @import("../xml/parser.zig");

const Attribute = xml_events.Attribute;
const max_mapping_rules: usize = 4096;
const max_mapping_terms_per_rule: usize = 256;

pub const RequirementLevel = enum(u8) {
    must,
    should,
    may,
};

pub const CombinationLogic = enum(u8) {
    @"and",
    @"or",
};

/// A CV term reference owned by the containing `RuleEngine`.
pub const MappingTerm = struct {
    accession: []const u8,
    allow_children: bool,
    is_repeatable: bool,
};

/// A mapping rule owned by the containing `RuleEngine`.
pub const MappingRule = struct {
    id: []const u8,
    element_path: []const u8,
    requirement: RequirementLevel,
    logic: CombinationLogic,
    terms: []const MappingTerm,
};

pub const PathState = u16;
/// State used to start incremental path traversal.
pub const root_path_state: PathState = 0;
const no_path_state = std.math.maxInt(PathState);

const PathNode = struct {
    children: [elements.mask_table_len]PathState = @splat(no_path_state),
    rules: []const MappingRule = &.{},
};

/// Path-indexed PSI-MS mapping rules from `ms-mapping.xml`.
pub const RuleEngine = struct {
    allocator: std.mem.Allocator,
    rules: []MappingRule,
    rule_map: std.StringHashMap([]const MappingRule),
    grouped_rules: []MappingRule,
    path_nodes: std.ArrayList(PathNode),

    pub fn init(allocator: std.mem.Allocator, xml_text: []const u8) !RuleEngine {
        var engine = RuleEngine{
            .allocator = allocator,
            .rules = try parseRules(allocator, xml_text),
            .rule_map = std.StringHashMap([]const MappingRule).init(allocator),
            .grouped_rules = &.{},
            .path_nodes = .empty,
        };
        errdefer engine.deinit();

        engine.grouped_rules = try allocator.alloc(MappingRule, engine.rules.len);
        var i: usize = 0;
        var group_index: usize = 0;
        while (i < engine.rules.len) {
            const path = engine.rules[i].element_path;
            i += 1;
            if (engine.rule_map.contains(path)) continue;

            const group_start = group_index;
            for (engine.rules) |rule| {
                if (!std.mem.eql(u8, rule.element_path, path)) continue;
                engine.grouped_rules[group_index] = rule;
                group_index += 1;
            }
            try engine.rule_map.put(path, engine.grouped_rules[group_start..group_index]);
        }
        try engine.buildPathIndex();
        return engine;
    }

    pub fn deinit(engine: *RuleEngine) void {
        engine.rule_map.deinit();

        for (engine.rules) |rule| {
            engine.allocator.free(rule.id);
            engine.allocator.free(rule.element_path);
            for (rule.terms) |term| engine.allocator.free(term.accession);
            engine.allocator.free(rule.terms);
        }
        engine.allocator.free(engine.rules);
        engine.allocator.free(engine.grouped_rules);
        engine.path_nodes.deinit(engine.allocator);
        engine.* = undefined;
    }

    /// Returns rules for `element_path`; the slice remains valid while `engine` lives.
    pub fn rulesFor(engine: *const RuleEngine, element_path: []const u8) []const MappingRule {
        return engine.rule_map.get(element_path) orelse &.{};
    }

    /// Advances an indexed path, returning null for an unknown or unindexed child.
    pub fn advancePath(engine: *const RuleEngine, parent: ?PathState, element_id: elements.ElementId) ?PathState {
        const state = parent orelse return null;
        if (element_id == .unknown) return null;
        const state_index: usize = state;
        if (state_index >= engine.path_nodes.items.len) return null;
        const child = engine.path_nodes.items[state_index].children[@intFromEnum(element_id)];
        return if (child == no_path_state) null else child;
    }

    /// Returns rules for an indexed state, or an empty slice for no state.
    pub fn rulesForState(engine: *const RuleEngine, state: ?PathState) []const MappingRule {
        const state_index: usize = state orelse return &.{};
        if (state_index >= engine.path_nodes.items.len) return &.{};
        return engine.path_nodes.items[state_index].rules;
    }

    /// Returns the first engine-owned mapping accession absent from `table`.
    pub fn firstMissingVocabularyTerm(engine: *const RuleEngine, table: *const obo.CvTable) ?[]const u8 {
        for (engine.rules) |rule| {
            for (rule.terms) |term| {
                if (isExternalPrefix(term.accession)) continue;
                if (table.lookup(term.accession) == null) return term.accession;
            }
        }
        return null;
    }

    fn buildPathIndex(engine: *RuleEngine) !void {
        try engine.path_nodes.append(engine.allocator, .{});
        for (engine.rules) |rule| {
            var state = root_path_state;
            var components = std.mem.tokenizeScalar(u8, rule.element_path, '/');
            var indexable = true;
            while (components.next()) |component| {
                const element_id = elements.idFromLocalName(component);
                if (element_id == .unknown) {
                    indexable = false;
                    break;
                }
                const child_index = @intFromEnum(element_id);
                var child = engine.path_nodes.items[state].children[child_index];
                if (child == no_path_state) {
                    if (engine.path_nodes.items.len >= no_path_state) return error.MappingPathLimitExceeded;
                    child = @intCast(engine.path_nodes.items.len);
                    try engine.path_nodes.append(engine.allocator, .{});
                    engine.path_nodes.items[state].children[child_index] = child;
                }
                state = child;
            }
            if (indexable) engine.path_nodes.items[state].rules = engine.rulesFor(rule.element_path);
        }
    }
};

// Attributes borrow parser storage, so retained values are duplicated here.
fn parseRules(allocator: std.mem.Allocator, xml: []const u8) ![]MappingRule {
    var rules: std.ArrayList(MappingRule) = .empty;
    errdefer {
        for (rules.items) |rule| {
            allocator.free(rule.id);
            allocator.free(rule.element_path);
            for (rule.terms) |term| allocator.free(term.accession);
            allocator.free(rule.terms);
        }
        rules.deinit(allocator);
    }

    var current_terms: ?std.ArrayList(MappingTerm) = null;
    errdefer if (current_terms) |*t| {
        for (t.items) |term| allocator.free(term.accession);
        t.deinit(allocator);
    };

    var token: [4096]u8 = undefined;
    var attributes: [16]Attribute = undefined;
    var namespace_bindings: [16]xml_parser.NamespaceBinding = undefined;
    var namespace_bytes: [4096]u8 = undefined;
    var element_stack: [16]xml_parser.ElementFrame = undefined;
    var element_bytes: [4096]u8 = undefined;

    const buffers = xml_parser.Buffers{
        .token = &token,
        .attributes = &attributes,
        .namespace_bindings = &namespace_bindings,
        .namespace_bytes = &namespace_bytes,
        .element_stack = &element_stack,
        .element_bytes = &element_bytes,
    };

    var parser = xml_parser.Parser.initSlice(xml, buffers);

    var current_id: ?[]u8 = null;
    var current_path: ?[]u8 = null;
    var current_requirement: RequirementLevel = .may;
    var current_logic: CombinationLogic = .@"and";
    var mapping_rule_depth: usize = 0;
    errdefer {
        if (current_id) |id| allocator.free(id);
        if (current_path) |p| allocator.free(p);
    }

    while (true) {
        const event = parser.next() catch |err| return err;
        const ev = event orelse break;

        switch (ev) {
            .start_element => |start| {
                if (std.mem.eql(u8, start.name.local_name, "CvMappingRule")) {
                    mapping_rule_depth = std.math.add(usize, mapping_rule_depth, 1) catch
                        return error.MappingRuleNestingTooDeep;
                    if (mapping_rule_depth != 1) continue;

                    current_id = try dupeRequiredAttr(allocator, start.attributes, "id");
                    current_path = try dupeRequiredAttr(allocator, start.attributes, "scopePath");
                    current_requirement = try parseRequirement(
                        findAttr(start.attributes, "requirementLevel") orelse
                            return error.MissingMappingAttribute,
                    );
                    current_logic = try parseLogic(
                        findAttr(start.attributes, "cvTermsCombinationLogic") orelse
                            return error.MissingMappingAttribute,
                    );

                    var terms: std.ArrayList(MappingTerm) = .empty;
                    errdefer {
                        for (terms.items) |term| allocator.free(term.accession);
                        terms.deinit(allocator);
                    }
                    current_terms = terms;
                } else if (std.mem.eql(u8, start.name.local_name, "CvTerm")) {
                    if (mapping_rule_depth != 1 or current_terms == null) continue;
                    if (current_terms.?.items.len >= max_mapping_terms_per_rule) {
                        return error.MappingTermLimitExceeded;
                    }
                    const owned = try dupeRequiredAttr(allocator, start.attributes, "termAccession");
                    errdefer allocator.free(owned);
                    const allow_children = eqTrue(findAttr(start.attributes, "allowChildren"));
                    const is_repeatable = eqTrue(findAttr(start.attributes, "isRepeatable"));
                    try current_terms.?.append(allocator, .{
                        .accession = owned,
                        .allow_children = allow_children,
                        .is_repeatable = is_repeatable,
                    });
                }
            },
            .end_element => |end| {
                if (!std.mem.eql(u8, end.name.local_name, "CvMappingRule")) continue;
                if (mapping_rule_depth == 0) continue;
                mapping_rule_depth -= 1;
                if (mapping_rule_depth != 0 or current_terms == null) continue;
                if (rules.items.len >= max_mapping_rules) return error.MappingRuleLimitExceeded;

                const owned_terms = try current_terms.?.toOwnedSlice(allocator);
                errdefer {
                    for (owned_terms) |term| allocator.free(term.accession);
                    allocator.free(owned_terms);
                }
                try rules.append(allocator, .{
                    .id = current_id.?,
                    .element_path = current_path.?,
                    .requirement = current_requirement,
                    .logic = current_logic,
                    .terms = owned_terms,
                });

                current_terms = null;
                current_id = null;
                current_path = null;
            },
            .text => {},
        }
    }

    return try rules.toOwnedSlice(allocator);
}

fn findAttr(attrs: []const Attribute, local_name: []const u8) ?[]const u8 {
    for (attrs) |attr| {
        if (attr.is_namespace_declaration) continue;
        if (std.mem.eql(u8, attr.name.local_name, local_name)) return attr.value;
    }
    return null;
}

fn dupeRequiredAttr(allocator: std.mem.Allocator, attrs: []const Attribute, local_name: []const u8) ![]u8 {
    const value = findAttr(attrs, local_name) orelse return error.MissingMappingAttribute;
    return allocator.dupe(u8, value);
}

fn eqTrue(value: ?[]const u8) bool {
    return if (value) |item| std.mem.eql(u8, item, "true") else false;
}

fn parseRequirement(value: []const u8) !RequirementLevel {
    if (std.mem.eql(u8, value, "MUST")) return .must;
    if (std.mem.eql(u8, value, "SHOULD")) return .should;
    if (std.mem.eql(u8, value, "MAY")) return .may;
    return error.InvalidRequirementLevel;
}

fn parseLogic(value: []const u8) !CombinationLogic {
    if (std.mem.eql(u8, value, "AND")) return .@"and";
    if (std.mem.eql(u8, value, "OR")) return .@"or";
    return error.InvalidCombinationLogic;
}

fn isExternalPrefix(accession: []const u8) bool {
    const colon = std.mem.indexOfScalar(u8, accession, ':') orelse return false;
    const prefix = accession[0..colon];
    return std.mem.eql(u8, prefix, "BTO") or
        std.mem.eql(u8, prefix, "GO") or
        std.mem.eql(u8, prefix, "PATO");
}

// --- Unit Tests ---

test "rule engine parses the embedded mapping" {
    const allocator = std.testing.allocator;
    const xml = @embedFile("../data/ms-mapping.xml");
    try std.testing.expect(std.mem.indexOf(u8, xml, "modelName=\"" ++ version.mapping_model ++ "\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "modelVersion=\"" ++ version.mapping_model_version ++ "\"") != null);
    var engine = try RuleEngine.init(allocator, xml);
    defer engine.deinit();

    const rules = engine.rulesFor("/mzML/run/spectrumList/spectrum");
    try std.testing.expect(rules.len > 0);
    for (rules) |r| {
        try std.testing.expect(r.terms.len > 0);
    }
    var has_must = false;
    for (rules) |r| {
        if (r.requirement == .must) has_must = true;
    }
    try std.testing.expect(has_must);

    const ic_rules = engine.rulesFor("/mzML/instrumentConfigurationList/instrumentConfiguration");
    try std.testing.expect(ic_rules.len > 0);

    const source_rules = engine.rulesFor("/mzML/instrumentConfigurationList/instrumentConfiguration/componentList/source");
    try std.testing.expect(source_rules.len > 0);
    try std.testing.expect(source_rules.len >= 2);
}

test "rule engine returns no rules for an unknown path" {
    const allocator = std.testing.allocator;
    const xml = @embedFile("../data/ms-mapping.xml");
    var engine = try RuleEngine.init(allocator, xml);
    defer engine.deinit();

    const rules = engine.rulesFor("/nonexistent/path");
    try std.testing.expectEqual(@as(usize, 0), rules.len);
}

test "rule engine resolves paths with parent context" {
    const allocator = std.testing.allocator;
    const xml = @embedFile("../data/ms-mapping.xml");
    var engine = try RuleEngine.init(allocator, xml);
    defer engine.deinit();

    const spectrum_path = [_]elements.ElementId{
        .mzML, .run, .spectrumList, .spectrum, .binaryDataArrayList, .binaryDataArray,
    };
    var spectrum_state: ?PathState = root_path_state;
    for (spectrum_path) |element_id| spectrum_state = engine.advancePath(spectrum_state, element_id);
    const spectrum_rules = engine.rulesForState(spectrum_state);
    try std.testing.expectEqualStrings("spectrum_binarydataarray_must", spectrum_rules[0].id);
    try std.testing.expectEqualSlices(
        MappingRule,
        engine.rulesFor("/mzML/run/spectrumList/spectrum/binaryDataArrayList/binaryDataArray"),
        spectrum_rules,
    );

    const chromatogram_path = [_]elements.ElementId{
        .mzML, .run, .chromatogramList, .chromatogram, .binaryDataArrayList, .binaryDataArray,
    };
    var chromatogram_state: ?PathState = root_path_state;
    for (chromatogram_path) |element_id| chromatogram_state = engine.advancePath(chromatogram_state, element_id);
    const chromatogram_rules = engine.rulesForState(chromatogram_state);
    try std.testing.expectEqualStrings("chromatogram_binarydataarray_must", chromatogram_rules[0].id);
    try std.testing.expect(spectrum_state != chromatogram_state);

    try std.testing.expect(engine.advancePath(root_path_state, .binaryDataArray) == null);
    try std.testing.expectEqual(@as(usize, 0), engine.rulesForState(null).len);
}

test "rule engine indexes every embedded mapping path" {
    const allocator = std.testing.allocator;
    const xml = @embedFile("../data/ms-mapping.xml");
    var engine = try RuleEngine.init(allocator, xml);
    defer engine.deinit();

    for (engine.rules) |rule| {
        var state: ?PathState = root_path_state;
        var components = std.mem.tokenizeScalar(u8, rule.element_path, '/');
        while (components.next()) |component| {
            const element_id = elements.idFromLocalName(component);
            try std.testing.expect(element_id != .unknown);
            state = engine.advancePath(state, element_id);
            try std.testing.expect(state != null);
        }

        try std.testing.expectEqualSlices(
            MappingRule,
            engine.rulesFor(rule.element_path),
            engine.rulesForState(state),
        );
    }
}

test "rule engine groups rules when paths are interleaved" {
    const allocator = std.testing.allocator;
    const xml =
        "<CvMapping><CvMappingRuleList>" ++
        "<CvMappingRule id=\"run_first\" scopePath=\"/mzML/run\" requirementLevel=\"MUST\" cvTermsCombinationLogic=\"AND\"><CvTerm termAccession=\"MS:1\"/></CvMappingRule>" ++
        "<CvMappingRule id=\"spectrum\" scopePath=\"/mzML/spectrum\" requirementLevel=\"MAY\" cvTermsCombinationLogic=\"OR\"><CvTerm termAccession=\"MS:2\"/></CvMappingRule>" ++
        "<CvMappingRule id=\"run_second\" scopePath=\"/mzML/run\" requirementLevel=\"MAY\" cvTermsCombinationLogic=\"OR\"><CvTerm termAccession=\"MS:3\"/></CvMappingRule>" ++
        "</CvMappingRuleList></CvMapping>";

    var engine = try RuleEngine.init(allocator, xml);
    defer engine.deinit();

    const rules = engine.rulesFor("/mzML/run");
    try std.testing.expectEqual(@as(usize, 2), rules.len);
    try std.testing.expectEqualStrings("run_first", rules[0].id);
    try std.testing.expectEqualStrings("run_second", rules[1].id);

    var state = engine.advancePath(root_path_state, .mzML);
    state = engine.advancePath(state, .run);
    try std.testing.expectEqualSlices(MappingRule, rules, engine.rulesForState(state));
}

test "rule engine ignores nested mapping rules" {
    const allocator = std.testing.allocator;
    const xml =
        "<CvMapping><CvMappingRuleList>" ++
        "<CvMappingRule id=\"outer\" scopePath=\"/mzML/run\" requirementLevel=\"MUST\" cvTermsCombinationLogic=\"AND\">" ++
        "<CvTerm termAccession=\"MS:1\"/>" ++
        "<CvMappingRule id=\"inner\" scopePath=\"/mzML/spectrum\" requirementLevel=\"MAY\" cvTermsCombinationLogic=\"OR\"><CvTerm termAccession=\"MS:2\"/></CvMappingRule>" ++
        "</CvMappingRule></CvMappingRuleList></CvMapping>";

    var engine = try RuleEngine.init(allocator, xml);
    defer engine.deinit();

    try std.testing.expectEqual(@as(usize, 1), engine.rules.len);
    try std.testing.expectEqualStrings("outer", engine.rules[0].id);
    try std.testing.expectEqual(@as(usize, 1), engine.rules[0].terms.len);
}

test "rule engine rejects missing and invalid rule attributes" {
    const allocator = std.testing.allocator;
    const missing_id =
        "<CvMapping><CvMappingRuleList>" ++
        "<CvMappingRule scopePath=\"/mzML/run\" requirementLevel=\"MUST\" cvTermsCombinationLogic=\"AND\"/>" ++
        "</CvMappingRuleList></CvMapping>";
    try std.testing.expectError(error.MissingMappingAttribute, RuleEngine.init(allocator, missing_id));

    const invalid_requirement =
        "<CvMapping><CvMappingRuleList>" ++
        "<CvMappingRule id=\"test\" scopePath=\"/mzML/run\" requirementLevel=\"REQUIRED\" cvTermsCombinationLogic=\"AND\"/>" ++
        "</CvMappingRuleList></CvMapping>";
    try std.testing.expectError(error.InvalidRequirementLevel, RuleEngine.init(allocator, invalid_requirement));

    const invalid_logic =
        "<CvMapping><CvMappingRuleList>" ++
        "<CvMappingRule id=\"test\" scopePath=\"/mzML/run\" requirementLevel=\"MAY\" cvTermsCombinationLogic=\"XOR\"/>" ++
        "</CvMappingRuleList></CvMapping>";
    try std.testing.expectError(error.InvalidCombinationLogic, RuleEngine.init(allocator, invalid_logic));

    const missing_term_accession =
        "<CvMapping><CvMappingRuleList>" ++
        "<CvMappingRule id=\"test\" scopePath=\"/mzML/run\" requirementLevel=\"MAY\" cvTermsCombinationLogic=\"OR\"><CvTerm/></CvMappingRule>" ++
        "</CvMappingRuleList></CvMapping>";
    try std.testing.expectError(error.MissingMappingAttribute, RuleEngine.init(allocator, missing_term_accession));
}

test "rule engine enforces the mapping rule limit" {
    const allocator = std.testing.allocator;
    var xml = std.ArrayList(u8).empty;
    defer xml.deinit(allocator);
    try xml.appendSlice(allocator, "<CvMapping><CvMappingRuleList>");
    for (0..max_mapping_rules + 1) |i| {
        var id_buf: [32]u8 = undefined;
        const id = try std.fmt.bufPrint(&id_buf, "rule_{d}", .{i});
        try xml.appendSlice(allocator, "<CvMappingRule id=\"");
        try xml.appendSlice(allocator, id);
        try xml.appendSlice(allocator, "\" scopePath=\"/mzML/run\" requirementLevel=\"MAY\" cvTermsCombinationLogic=\"OR\"/>");
    }
    try xml.appendSlice(allocator, "</CvMappingRuleList></CvMapping>");

    try std.testing.expectError(error.MappingRuleLimitExceeded, RuleEngine.init(allocator, xml.items));
}

test "rule engine returns empty rules for invalid path state" {
    const allocator = std.testing.allocator;
    const xml = @embedFile("../data/ms-mapping.xml");
    var engine = try RuleEngine.init(allocator, xml);
    defer engine.deinit();

    const invalid_state = std.math.maxInt(PathState);
    try std.testing.expect(engine.advancePath(invalid_state, .mzML) == null);
    try std.testing.expectEqual(@as(usize, 0), engine.rulesForState(invalid_state).len);
}

test "rule engine cleans path index allocation failures" {
    const xml = "<CvMapping><CvMappingRuleList>" ++
        "<CvMappingRule id=\"test\" scopePath=\"/mzML/run\" requirementLevel=\"MUST\" cvTermsCombinationLogic=\"AND\">" ++
        "<CvTerm termAccession=\"MS:1000001\"></CvTerm>" ++
        "</CvMappingRule></CvMappingRuleList></CvMapping>";

    var reached_success = false;
    for (0..64) |fail_index| {
        var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
        if (RuleEngine.init(failing_allocator.allocator(), xml)) |engine_value| {
            var engine = engine_value;
            engine.deinit();
            reached_success = true;
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
        }
        try std.testing.expectEqual(failing_allocator.allocated_bytes, failing_allocator.freed_bytes);
        if (reached_success) break;
    }
    try std.testing.expect(reached_success);
}

test "rule engine ignores commented-out rules" {
    const allocator = std.testing.allocator;
    const xml = @embedFile("../data/ms-mapping.xml");
    var engine = try RuleEngine.init(allocator, xml);
    defer engine.deinit();

    const src_rules = engine.rulesFor("/mzML/fileDescription/sourceFileList/sourceFile");
    try std.testing.expectEqual(@as(usize, 0), src_rules.len);
}

test "rule engine checks mapping terms against the vocabulary" {
    const allocator = std.testing.allocator;
    const mapping_xml = @embedFile("../data/ms-mapping.xml");
    var engine = try RuleEngine.init(allocator, mapping_xml);
    defer engine.deinit();

    const embedded_obo = @embedFile("../data/psi-ms.obo");
    var embedded_table = try obo.CvTable.init(allocator, embedded_obo);
    defer embedded_table.deinit();
    try std.testing.expect(engine.firstMissingVocabularyTerm(&embedded_table) == null);

    var custom_table = try obo.CvTable.init(allocator, "[Term]\nid: MS:9999999\nname: custom\nnamespace: MS\n");
    defer custom_table.deinit();
    try std.testing.expectEqualStrings(
        "MS:1000857",
        engine.firstMissingVocabularyTerm(&custom_table).?,
    );
}

test "[unit]: mapping capacity can share the bounded OBO catalog owner" {
    const allocator = std.testing.allocator;
    var counting_allocator = std.testing.FailingAllocator.init(allocator, .{});
    var table = try obo.CvTable.init(counting_allocator.allocator(), @embedFile("../data/psi-ms.obo"));
    var table_live = true;
    defer if (table_live) table.deinit();
    const obo_current_bytes = table.currentBytes();

    var engine = try RuleEngine.init(table.catalogAllocator(), @embedFile("../data/ms-mapping.xml"));
    var engine_live = true;
    defer if (engine_live) engine.deinit();

    try std.testing.expect(table.currentBytes() > obo_current_bytes);
    try std.testing.expectEqual(
        counting_allocator.allocated_bytes - counting_allocator.freed_bytes,
        table.currentBytes(),
    );

    engine.deinit();
    engine_live = false;
    try std.testing.expectEqual(obo_current_bytes, table.currentBytes());
    table.deinit();
    table_live = false;
    try std.testing.expectEqual(counting_allocator.allocated_bytes, counting_allocator.freed_bytes);
}

const version = @import("../version.zig");
