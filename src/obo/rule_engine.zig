//! Rule engine for CV term mapping rules from ms-mapping.xml.
//!
//! The rule engine parses the PSI's official CV mapping rules and provides
//! lookup by element path. Each rule defines which CV terms MUST, SHOULD,
//! or MAY appear on a given XML element.
//!
//! Usage:
//!   var engine = try RuleEngine.init(allocator, embedded_xml);
//!   defer engine.deinit();
//!   const rules = engine.rulesFor("/mzML/run/spectrumList/spectrum");

const std = @import("std");

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
    /// Only 34 rules in practice. Returns a slice of the internal rules array.
    /// The caller must not rely on this slice being valid after the engine is mutated.
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

/// Minimal XML parser for ms-mapping.xml. Handles only the subset needed:
/// <CvMappingRule>, <CvTerm>, and their attributes.
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

    var pos: usize = 0;
    while (pos < xml.len) {
        // Skip whitespace and XML comments before each rule.
        // Comments in the mapping file contain disabled rules (e.g. sourcefile_must)
        // that must not be parsed.
        while (true) {
            // Skip whitespace before checking for comment marker.
            while (pos < xml.len and switch (xml[pos]) {
                ' ', '\n', '\r', '\t' => true,
                else => false,
            }) pos += 1;
            if (std.mem.startsWith(u8, xml[pos..], "<!--")) {
                const comment_end = std.mem.indexOfPos(u8, xml, pos, "-->") orelse break;
                pos = comment_end + 3;
            } else {
                break;
            }
        }

        // Find the next <CvMappingRule> tag (note: trailing space avoids matching <CvMappingRuleList>)
        const rule_start = std.mem.indexOfPos(u8, xml, pos, "<CvMappingRule ") orelse break;
        const rule_end = std.mem.indexOfPos(u8, xml, rule_start, ">") orelse break;
        const rule_tag = xml[rule_start..rule_end];

        // Find the closing </CvMappingRule>
        const close_start = std.mem.indexOfPos(u8, xml, rule_end, "</CvMappingRule>") orelse break;
        const inner_start = rule_end + 1;
        const inner_end = close_start;

        // Parse rule attributes
        const id = extractAttr(rule_tag, "id=\"") orelse "";
        const element_path = extractAttr(rule_tag, "scopePath=\"") orelse "";
        const req_str = extractAttr(rule_tag, "requirementLevel=\"") orelse "";
        const logic_str = extractAttr(rule_tag, "cvTermsCombinationLogic=\"") orelse "AND";

        const requirement: RequirementLevel = if (std.mem.eql(u8, req_str, "MUST")) .must else if (std.mem.eql(u8, req_str, "SHOULD")) .should else .may;
        const logic: CombinationLogic = if (std.mem.eql(u8, logic_str, "AND")) .@"and" else .@"or";

        // Parse <CvTerm> children
        var terms: std.ArrayList(MappingTerm) = .empty;
        errdefer {
            for (terms.items) |t| allocator.free(t.accession);
            terms.deinit(allocator);
        }

        var inner_pos = inner_start;
        while (inner_pos < inner_end) {
            const term_start = std.mem.indexOfPos(u8, xml, inner_pos, "<CvTerm") orelse break;
            if (term_start >= inner_end) break;
            const term_close = std.mem.indexOfPos(u8, xml, term_start, ">") orelse break;
            const is_self_closing = term_close > 0 and xml[term_close - 1] == '/';
            const term_tag = xml[term_start..term_close];
            if (is_self_closing) {
                inner_pos = term_close + 1;
            } else {
                const close_tag = std.mem.indexOfPos(u8, xml, term_close, "</CvTerm>") orelse break;
                inner_pos = close_tag + "</CvTerm>".len;
            }
            if (extractAttr(term_tag, "termAccession=\"")) |acc| {
                const owned = try allocator.dupe(u8, acc);
                const allow_children_str = extractAttr(term_tag, "allowChildren=\"");
                const allow_children = if (allow_children_str) |s| std.mem.eql(u8, s, "true") else false;
                const repeatable_str = extractAttr(term_tag, "isRepeatable=\"");
                const is_repeatable = if (repeatable_str) |s| std.mem.eql(u8, s, "true") else false;
                try terms.append(allocator, .{
                    .accession = owned,
                    .allow_children = allow_children,
                    .is_repeatable = is_repeatable,
                });
            }
        }

        const owned_terms = try terms.toOwnedSlice(allocator);
        rules.append(allocator, .{
            .id = try allocator.dupe(u8, id),
            .element_path = try allocator.dupe(u8, element_path),
            .requirement = requirement,
            .logic = logic,
            .terms = owned_terms,
        }) catch |err| {
            for (owned_terms) |t| allocator.free(t.accession);
            allocator.free(owned_terms);
            return err;
        };

        pos = close_start + "</CvMappingRule>".len;
    }

    return try rules.toOwnedSlice(allocator);
}

/// Extracts a quoted attribute value from an XML tag.
/// e.g. extractAttr(`id="foo"`, `id="`) returns "foo".
fn extractAttr(tag: []const u8, prefix: []const u8) ?[]const u8 {
    const start = std.mem.indexOfPos(u8, tag, 0, prefix) orelse return null;
    const value_start = start + prefix.len;
    const end = std.mem.indexOfScalarPos(u8, tag, value_start, '"') orelse return null;
    return tag[value_start..end];
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
