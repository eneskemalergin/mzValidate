//! Rule engine for PSI-MS CV mapping rules (ms-mapping.xml).
//!
//! Parses the PSI's official mapping rules and provides path-based lookup.
//! Each rule defines which CV terms MUST, SHOULD, or MAY appear on a given
//! XML element path, and whether they combine via AND or OR logic.
//!
//! Usage:
//!   var engine = try RuleEngine.init(allocator, mapping_xml);
//!   defer engine.deinit();
//!   const rules = engine.rulesFor("/mzML/run/spectrumList/spectrum");

const std = @import("std");
const obo = @import("parser.zig");
const elements = @import("../mzml/elements.zig");
const xml_events = @import("../xml/events.zig");
const xml_parser = @import("../xml/parser.zig");
const version = @import("../version.zig");

const Attribute = xml_events.Attribute;

pub const RequirementLevel = enum(u8) {
    must,
    should,
    may,
};

pub const CombinationLogic = enum(u8) {
    @"and",
    @"or",
};

pub const MappingTerm = struct {
    accession: []const u8,
    allow_children: bool,
    is_repeatable: bool,
};

pub const MappingRule = struct {
    id: []const u8,
    element_path: []const u8,
    requirement: RequirementLevel,
    logic: CombinationLogic,
    terms: []const MappingTerm,
};

pub const PathState = u16;
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
    path_nodes: std.ArrayList(PathNode),

    pub fn init(allocator: std.mem.Allocator, xml_text: []const u8) !RuleEngine {
        var engine = RuleEngine{
            .allocator = allocator,
            .rules = try parseRules(allocator, xml_text),
            .rule_map = std.StringHashMap([]const MappingRule).init(allocator),
            .path_nodes = .empty,
        };
        errdefer engine.deinit();
        // Build path-to-rules map. Rules are grouped by path in the XML.
        var i: usize = 0;
        while (i < engine.rules.len) {
            const path = engine.rules[i].element_path;
            const group_start = i;
            i += 1;
            while (i < engine.rules.len and std.mem.eql(u8, engine.rules[i].element_path, path)) : (i += 1) {}
            try engine.rule_map.put(path, engine.rules[group_start..i]);
        }
        try engine.buildPathIndex();
        return engine;
    }

    pub fn deinit(engine: *RuleEngine) void {
        for (engine.rules) |rule| {
            engine.allocator.free(rule.id);
            engine.allocator.free(rule.element_path);
            for (rule.terms) |term| engine.allocator.free(term.accession);
            engine.allocator.free(rule.terms);
        }
        engine.allocator.free(engine.rules);
        engine.rule_map.deinit();
        engine.path_nodes.deinit(engine.allocator);
    }

    /// Look up rules for a given element path via hash map.
    pub fn rulesFor(engine: *const RuleEngine, element_path: []const u8) []const MappingRule {
        return engine.rule_map.get(element_path) orelse &.{};
    }

    pub fn advancePath(engine: *const RuleEngine, parent: ?PathState, element_id: elements.ElementId) ?PathState {
        const state = parent orelse return null;
        if (element_id == .unknown) return null;
        const child = engine.path_nodes.items[state].children[@intFromEnum(element_id)];
        return if (child == no_path_state) null else child;
    }

    pub fn rulesForState(engine: *const RuleEngine, state: ?PathState) []const MappingRule {
        return engine.path_nodes.items[state orelse return &.{}].rules;
    }

    /// Returns the first mapping accession absent from `table`.
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

// --- Parser internals ---

// Walk the mapping document with the project's streaming XML parser and
// collect rules. Single pass; comments and PIs are skipped by the parser.
// Attribute slices borrow the parser's token buffer and are only valid
// until the next event, so we dupe the strings we need to keep.
fn parseRules(allocator: std.mem.Allocator, xml: []const u8) ![]MappingRule {
    var rules: std.ArrayList(MappingRule) = .empty;
    errdefer {
        for (rules.items) |r| {
            allocator.free(r.id);
            allocator.free(r.element_path);
            for (r.terms) |t| allocator.free(t.accession);
            allocator.free(r.terms);
        }
        rules.deinit(allocator);
    }

    var current_terms: ?std.ArrayList(MappingTerm) = null;
    errdefer if (current_terms) |*t| {
        for (t.items) |term| allocator.free(term.accession);
        t.deinit(allocator);
    };

    // Buffers sized for ms-mapping.xml: max nesting ~6 (CvMapping >
    // CvReferenceList/CvMappingRuleList > CvMappingRule > CvTerm), max
    // attributes per element ~7. Generous slack for future schema
    // additions.
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

    // Owned strings for the in-progress rule. Reset to null after the
    // rule's closing tag is processed.
    var current_id: ?[]u8 = null;
    var current_path: ?[]u8 = null;
    var current_requirement: RequirementLevel = .may;
    var current_logic: CombinationLogic = .@"and";
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
                    current_id = try dupeAttr(allocator, start.attributes, "id");
                    current_path = try dupeAttr(allocator, start.attributes, "scopePath");
                    current_requirement = parseRequirement(findAttr(start.attributes, "requirementLevel") orelse "");
                    current_logic = parseLogic(findAttr(start.attributes, "cvTermsCombinationLogic") orelse "AND");

                    if (current_terms != null) {
                        // Stray <CvMappingRule> inside another; ignore.
                        continue;
                    }
                    var terms: std.ArrayList(MappingTerm) = .empty;
                    errdefer {
                        for (terms.items) |term| allocator.free(term.accession);
                        terms.deinit(allocator);
                    }
                    current_terms = terms;
                } else if (std.mem.eql(u8, start.name.local_name, "CvTerm")) {
                    if (current_terms == null) continue;
                    const acc = findAttr(start.attributes, "termAccession") orelse continue;
                    const owned = try allocator.dupe(u8, acc);
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
                if (current_terms == null) continue;

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

                // Rule is now owned by `rules`; release the in-progress state.
                current_terms = null;
                current_id = null;
                current_path = null;
            },
            .text => {},
        }
    }

    return try rules.toOwnedSlice(allocator);
}

// Looks up an attribute by local name on a parsed start element.
// Skips namespace declarations (xmlns, xmlns:foo) so they never match
// a real attribute.
fn findAttr(attrs: []const Attribute, local_name: []const u8) ?[]const u8 {
    for (attrs) |attr| {
        if (attr.is_namespace_declaration) continue;
        if (std.mem.eql(u8, attr.name.local_name, local_name)) return attr.value;
    }
    return null;
}

// Dupe the value of an attribute for storage; the parser's token buffer
// is invalidated by the next event.
fn dupeAttr(allocator: std.mem.Allocator, attrs: []const Attribute, local_name: []const u8) ![]u8 {
    const value = findAttr(attrs, local_name) orelse "";
    return allocator.dupe(u8, value);
}

fn eqTrue(s: ?[]const u8) bool {
    return if (s) |v| std.mem.eql(u8, v, "true") else false;
}

fn parseRequirement(s: []const u8) RequirementLevel {
    if (std.mem.eql(u8, s, "MUST")) return .must;
    if (std.mem.eql(u8, s, "SHOULD")) return .should;
    return .may;
}

fn parseLogic(s: []const u8) CombinationLogic {
    if (std.mem.eql(u8, s, "AND")) return .@"and";
    return .@"or";
}

fn isExternalPrefix(accession: []const u8) bool {
    const colon = std.mem.indexOfScalar(u8, accession, ':') orelse return false;
    const prefix = accession[0..colon];
    return std.mem.eql(u8, prefix, "BTO") or
        std.mem.eql(u8, prefix, "GO") or
        std.mem.eql(u8, prefix, "PATO");
}

test "RuleEngine parses ms-mapping.xml" {
    const allocator = std.testing.allocator;
    const xml = @embedFile("../data/ms-mapping.xml");
    try std.testing.expect(std.mem.indexOf(u8, xml, "modelName=\"" ++ version.mapping_model ++ "\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "modelVersion=\"" ++ version.mapping_model_version ++ "\"") != null);
    var engine = try RuleEngine.init(allocator, xml);
    defer engine.deinit();

    // Verify known rules exist.
    const rules = engine.rulesFor("/mzML/run/spectrumList/spectrum");
    try std.testing.expect(rules.len > 0);
    for (rules) |r| {
        try std.testing.expect(r.terms.len > 0);
    }
    // Verify must rule exists.
    var has_must = false;
    for (rules) |r| {
        if (r.requirement == .must) has_must = true;
    }
    try std.testing.expect(has_must);

    // Verify instrument configuration rules.
    const ic_rules = engine.rulesFor("/mzML/instrumentConfigurationList/instrumentConfiguration");
    try std.testing.expect(ic_rules.len > 0);

    // Verify source rules.
    const source_rules = engine.rulesFor("/mzML/instrumentConfigurationList/instrumentConfiguration/componentList/source");
    try std.testing.expect(source_rules.len > 0);
    // source_must + source_may should be returned.
    try std.testing.expect(source_rules.len >= 2);
}

test "RuleEngine.rulesFor returns empty for unknown path" {
    const allocator = std.testing.allocator;
    const xml = @embedFile("../data/ms-mapping.xml");
    var engine = try RuleEngine.init(allocator, xml);
    defer engine.deinit();

    const rules = engine.rulesFor("/nonexistent/path");
    try std.testing.expectEqual(@as(usize, 0), rules.len);
}

test "RuleEngine incrementally resolves paths with parent context" {
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

test "RuleEngine incremental index covers every embedded mapping path" {
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

test "RuleEngine path index construction cleans allocation failures" {
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

test "RuleEngine does not parse commented-out rules" {
    const allocator = std.testing.allocator;
    const xml = @embedFile("../data/ms-mapping.xml");
    var engine = try RuleEngine.init(allocator, xml);
    defer engine.deinit();

    // sourcefile_must is inside <!-- --> and must not be parsed.
    const src_rules = engine.rulesFor("/mzML/fileDescription/sourceFileList/sourceFile");
    try std.testing.expectEqual(@as(usize, 0), src_rules.len);
}

test "RuleEngine accepts the embedded vocabulary and rejects incompatible custom vocabulary" {
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
