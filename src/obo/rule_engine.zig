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
const xml_events = @import("../xml/events.zig");
const xml_parser = @import("../xml/parser.zig");

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

/// Path-indexed PSI-MS mapping rules from `ms-mapping.xml`.
pub const RuleEngine = struct {
    allocator: std.mem.Allocator,
    rules: []MappingRule,

    pub fn init(allocator: std.mem.Allocator, xml_text: []const u8) !RuleEngine {
        return RuleEngine{
            .allocator = allocator,
            .rules = try parseRules(allocator, xml_text),
        };
    }

    pub fn deinit(engine: *RuleEngine) void {
        for (engine.rules) |rule| {
            engine.allocator.free(rule.id);
            engine.allocator.free(rule.element_path);
            for (rule.terms) |term| engine.allocator.free(term.accession);
            engine.allocator.free(rule.terms);
        }
        engine.allocator.free(engine.rules);
    }

    /// Linear scan to find rules for a given element path.
    /// Returns a slice of the internal rules array that is invalidated
    /// if the engine is mutated.
    pub fn rulesFor(engine: *const RuleEngine, element_path: []const u8) []const MappingRule {
        var start: ?usize = null;
        var end: usize = 0;
        for (engine.rules, 0..) |rule, i| {
            if (std.mem.eql(u8, rule.element_path, element_path)) {
                if (start == null) start = i;
                end = i + 1;
            } else if (start != null) {
                // Rules for the same path are grouped in the XML, so once
                // we see a non-match after a match, we're done.
                break;
            }
        }
        if (start) |s| return engine.rules[s..end];
        return &.{};
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

test "RuleEngine parses ms-mapping.xml" {
    const allocator = std.testing.allocator;
    const xml = @embedFile("../data/ms-mapping.xml");
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

test "RuleEngine does not parse commented-out rules" {
    const allocator = std.testing.allocator;
    const xml = @embedFile("../data/ms-mapping.xml");
    var engine = try RuleEngine.init(allocator, xml);
    defer engine.deinit();

    // sourcefile_must is inside <!-- --> and must not be parsed.
    const src_rules = engine.rulesFor("/mzML/fileDescription/sourceFileList/sourceFile");
    try std.testing.expectEqual(@as(usize, 0), src_rules.len);
}
