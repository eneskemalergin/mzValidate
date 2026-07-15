//! OBO format 1.4 parser for psi-ms.obo controlled vocabularies.
//!
//! Parses stanzas (`[Term]`, `[Typedef]`), tag-value pairs, line
//! continuations, and escape sequences. Builds a `CvTable` keyed by
//! accession for fast lookup of CV terms, relationships, synonyms,
//! and metadata (obsoletion, unit constraints, xsd types).
//!
//! The table is embedded at compile time via `@embedFile("data/psi-ms.obo")`
//! and overridable at runtime with `-obo`. Callers get a read-only view:
//!
//!   var table = try CvTable.init(allocator, obo_text);
//!   defer table.deinit();
//!   const term = table.lookup("MS:1000001");

const std = @import("std");
const diagnostic = @import("../diagnostic.zig");

const max_xref_accession_bytes = (diagnostic.ResourceLimits{}).max_obo_xref_accession_bytes;

pub const Relationship = struct {
    name: []const u8,
    target: []const u8,
};

pub const CvTerm = struct {
    accession: []const u8,
    name: []const u8,
    namespace: []const u8,
    description: []const u8,
    is_obsolete: bool,
    replaced_by: ?[]const u8,
    is_a: [][]const u8,
    relationships: []Relationship,
    synonyms: [][]const u8,
    /// cvParam value type constraint from `relationship: has_value_type xsd:TYPE`.
    xsd_type: ?[]const u8 = null,
    /// Allowed unit accessions from `relationship: has_units ACC`.
    allowed_units: [][]const u8 = &.{},
    /// Allowed binary data type accessions from `xref: binary-data-type:ACC`.
    binary_data_types: [][]const u8 = &.{},
};

/// Accession-keyed lookup table built from an OBO text buffer.
pub const CvTable = struct {
    allocator: std.mem.Allocator,
    map: std.StringHashMap(CvTerm),
    ns_prefix: std.StringHashMap(void),
    limits: diagnostic.ResourceLimits,

    pub fn init(allocator: std.mem.Allocator, obo_text: []const u8) !CvTable {
        return initWithLimits(allocator, obo_text, .{});
    }

    pub fn initWithLimits(
        allocator: std.mem.Allocator,
        obo_text: []const u8,
        limits: diagnostic.ResourceLimits,
    ) !CvTable {
        var table = CvTable{
            .allocator = allocator,
            .map = std.StringHashMap(CvTerm).init(allocator),
            .ns_prefix = std.StringHashMap(void).init(allocator),
            .limits = limits,
        };
        errdefer table.deinit();
        try table.parse(obo_text);
        return table;
    }

    pub fn deinit(table: *CvTable) void {
        var it = table.map.iterator();
        while (it.next()) |entry| {
            deinitTerm(table.allocator, entry.value_ptr);
        }
        table.map.deinit();

        var ns_it = table.ns_prefix.iterator();
        while (ns_it.next()) |entry| table.allocator.free(entry.key_ptr.*);
        table.ns_prefix.deinit();
    }

    pub fn lookup(table: *const CvTable, accession: []const u8) ?CvTerm {
        return table.map.get(accession);
    }

    /// Validates that `accession` exists in the table and belongs to namespace
    /// `cv_ref`. Returns null on success, or an error message on failure.
    pub fn validate(table: *const CvTable, cv_ref: []const u8, accession: []const u8) ?[]const u8 {
        const term = table.lookup(accession) orelse
            return "unrecognized CV accession";
        if (term.is_obsolete)
            return "CV term is obsolete";
        if (!std.mem.eql(u8, term.namespace, cv_ref))
            return "cvRef does not match term namespace";
        return null;
    }

    /// Returns true if `term_acc` equals `ancestor_acc` or any of its
    /// `is_a` ancestors in the CV hierarchy.
    pub fn isDescendantOf(table: *const CvTable, term_acc: []const u8, ancestor_acc: []const u8) bool {
        if (std.mem.eql(u8, term_acc, ancestor_acc)) return true;
        var stack: [256][]const u8 = undefined;
        var count: usize = 0;
        if (table.lookup(term_acc)) |t| {
            for (t.is_a) |parent| {
                if (count < stack.len) {
                    stack[count] = parent;
                    count += 1;
                }
            }
        }
        var visited: usize = 0;
        while (visited < count) : (visited += 1) {
            const current = stack[visited];
            if (std.mem.eql(u8, current, ancestor_acc)) return true;
            if (table.lookup(current)) |t| {
                for (t.is_a) |parent| {
                    if (count < stack.len) {
                        stack[count] = parent;
                        count += 1;
                    }
                }
            }
        }
        return false;
    }

    fn parse(table: *CvTable, text: []const u8) !void {
        var lines = std.mem.tokenizeScalar(u8, text, '\n');
        var in_term = false;
        var id: ?[]const u8 = null;
        var name: ?[]const u8 = null;
        var def_val: ?[]const u8 = null;
        var namespace: ?[]const u8 = null;
        var is_obsolete: bool = false;
        var replaced_by: ?[]const u8 = null;
        var xsd_type: ?[]const u8 = null;
        var is_a_list: std.ArrayList([]const u8) = .empty;
        var rel_list: std.ArrayList(Relationship) = .empty;
        var syn_list: std.ArrayList([]const u8) = .empty;
        var unit_list: std.ArrayList([]const u8) = .empty;
        var binary_type_list: std.ArrayList([]const u8) = .empty;
        defer {
            deinitPendingStrings(table.allocator, &is_a_list);
            deinitPendingRelationships(table.allocator, &rel_list);
            deinitPendingStrings(table.allocator, &syn_list);
            deinitPendingStrings(table.allocator, &unit_list);
            deinitPendingStrings(table.allocator, &binary_type_list);
        }

        while (lines.next()) |raw_line| {
            const line = raw_line;

            if (line.len > table.limits.max_obo_line_bytes) return error.LineTooLong;

            if (line.len == 0 or line[0] == '!') continue;

            if (line[0] == '[') {
                if (in_term) {
                    try table.insertTerm(id, name, def_val, namespace, is_obsolete, replaced_by, xsd_type, &is_a_list, &rel_list, &syn_list, &unit_list, &binary_type_list);
                    id = null;
                    name = null;
                    def_val = null;
                    namespace = null;
                    is_obsolete = false;
                    replaced_by = null;
                    xsd_type = null;
                    is_a_list.clearRetainingCapacity();
                    rel_list.clearRetainingCapacity();
                    syn_list.clearRetainingCapacity();
                    unit_list.clearRetainingCapacity();
                    binary_type_list.clearRetainingCapacity();
                }
                in_term = true;
                continue;
            }

            if (!in_term) continue;

            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            const tag = std.mem.trim(u8, line[0..colon], " ");
            const value = std.mem.trim(u8, line[colon + 1 ..], " ");

            if (std.mem.eql(u8, tag, "id")) {
                id = value;
                const ns_end = std.mem.indexOfScalar(u8, value, ':') orelse value.len;
                const prefix = value[0..ns_end];
                if (!table.ns_prefix.contains(prefix)) {
                    const owned_prefix = try table.allocator.dupe(u8, prefix);
                    errdefer table.allocator.free(owned_prefix);
                    try table.ns_prefix.put(owned_prefix, {});
                }
            } else if (std.mem.eql(u8, tag, "name")) {
                name = value;
            } else if (std.mem.eql(u8, tag, "def")) {
                def_val = extractQuotedString(value);
            } else if (std.mem.eql(u8, tag, "namespace")) {
                namespace = value;
            } else if (std.mem.eql(u8, tag, "is_obsolete") and std.mem.eql(u8, value, "true")) {
                is_obsolete = true;
            } else if (std.mem.eql(u8, tag, "replaced_by")) {
                replaced_by = value;
            } else if (std.mem.eql(u8, tag, "consider")) {
                if (replaced_by == null) replaced_by = value;
            } else if (std.mem.eql(u8, tag, "xref")) {
                // Parse xref: binary-data-type:MS\:1000521 "32-bit float"
                if (std.mem.startsWith(u8, value, "binary-data-type:")) {
                    const acc_start = "binary-data-type:".len;
                    const rest = value[acc_start..];
                    // The accession may use backslash-escaped colons.
                    const space_pos = std.mem.indexOfScalar(u8, rest, ' ') orelse rest.len;
                    var acc_buf: [max_xref_accession_bytes]u8 = undefined;
                    var acc_len: usize = 0;
                    var i: usize = 0;
                    while (i < space_pos) : (i += 1) {
                        if (rest[i] == '\\' and i + 1 < space_pos) {
                            i += 1;
                        }
                        if (acc_len == @min(table.limits.max_obo_xref_accession_bytes, acc_buf.len)) return error.XrefTooLong;
                        acc_buf[acc_len] = rest[i];
                        acc_len += 1;
                    }
                    const owned = try table.allocator.dupe(u8, acc_buf[0..acc_len]);
                    errdefer table.allocator.free(owned);
                    try binary_type_list.append(table.allocator, owned);
                }
            } else if (std.mem.eql(u8, tag, "is_a")) {
                const space = std.mem.indexOfScalar(u8, value, ' ') orelse value.len;
                try appendOwnedString(table.allocator, &is_a_list, value[0..space]);
            } else if (std.mem.eql(u8, tag, "relationship")) {
                var parts = std.mem.tokenizeScalar(u8, value, ' ');
                const rname = parts.next() orelse continue;
                const rtarget = parts.next() orelse continue;
                try appendOwnedRelationship(table.allocator, &rel_list, rname, rtarget);
                // Extract xsd type for cv value validation.
                if (std.mem.eql(u8, rname, "has_value_type")) {
                    if (std.mem.startsWith(u8, rtarget, "xsd:")) {
                        xsd_type = rtarget;
                    }
                }
                // Extract allowed units.
                if (std.mem.eql(u8, rname, "has_units")) {
                    const space = std.mem.indexOfScalar(u8, rtarget, ' ') orelse rtarget.len;
                    try appendOwnedString(table.allocator, &unit_list, rtarget[0..space]);
                }
            } else if (std.mem.eql(u8, tag, "synonym")) {
                if (value.len > 0 and value[0] == '"') {
                    const close = std.mem.indexOfScalar(u8, value[1..], '"') orelse continue;
                    try appendOwnedString(table.allocator, &syn_list, value[1..][0..close]);
                }
            }
        }

        if (in_term) {
            try table.insertTerm(id, name, def_val, namespace, is_obsolete, replaced_by, xsd_type, &is_a_list, &rel_list, &syn_list, &unit_list, &binary_type_list);
        }
    }

    fn insertTerm(
        table: *CvTable,
        id: ?[]const u8,
        name: ?[]const u8,
        def_val: ?[]const u8,
        namespace: ?[]const u8,
        is_obsolete: bool,
        replaced_by: ?[]const u8,
        xsd_type: ?[]const u8,
        is_a_list: *std.ArrayList([]const u8),
        rel_list: *std.ArrayList(Relationship),
        syn_list: *std.ArrayList([]const u8),
        unit_list: *std.ArrayList([]const u8),
        binary_type_list: *std.ArrayList([]const u8),
    ) !void {
        const acc = id orelse return;
        const nm = name orelse "__unnamed__";

        if (table.map.contains(acc)) return error.DuplicateId;

        const ns_end = std.mem.indexOfScalar(u8, acc, ':') orelse return;
        const raw_ns = if (namespace) |n| n else acc[0..ns_end];
        const ns = if (std.mem.eql(u8, raw_ns, "unit.ontology")) "UO" else raw_ns;

        var term = CvTerm{
            .accession = &.{},
            .name = &.{},
            .namespace = &.{},
            .description = &.{},
            .is_obsolete = is_obsolete,
            .replaced_by = null,
            .is_a = &.{},
            .relationships = &.{},
            .synonyms = &.{},
            .xsd_type = null,
            .allowed_units = &.{},
            .binary_data_types = &.{},
        };
        errdefer deinitTerm(table.allocator, &term);

        term.accession = try table.allocator.dupe(u8, acc);
        term.name = try table.allocator.dupe(u8, nm);
        term.namespace = try table.allocator.dupe(u8, ns);
        term.description = try table.allocator.dupe(u8, def_val orelse "");
        term.replaced_by = if (replaced_by) |r| try table.allocator.dupe(u8, r) else null;
        term.is_a = try is_a_list.toOwnedSlice(table.allocator);
        term.relationships = try rel_list.toOwnedSlice(table.allocator);
        term.synonyms = try syn_list.toOwnedSlice(table.allocator);
        term.xsd_type = if (xsd_type) |v| try table.allocator.dupe(u8, v) else null;
        term.allowed_units = try unit_list.toOwnedSlice(table.allocator);
        term.binary_data_types = try binary_type_list.toOwnedSlice(table.allocator);

        try table.map.put(term.accession, term);
    }
};

/// Returns the bounded diagnostic message for an OBO construction error.
pub fn parseErrorMessage(err: anyerror) []const u8 {
    return switch (err) {
        error.XrefTooLong => "OBO binary-data-type xref accession exceeds its configured limit",
        error.LineTooLong => "OBO line exceeds its configured limit",
        error.DuplicateId => "OBO contains a duplicate term ID",
        else => "unable to parse OBO file",
    };
}

fn appendOwnedString(allocator: std.mem.Allocator, list: *std.ArrayList([]const u8), value: []const u8) !void {
    const owned = try allocator.dupe(u8, value);
    errdefer allocator.free(owned);
    try list.append(allocator, owned);
}

fn appendOwnedRelationship(
    allocator: std.mem.Allocator,
    list: *std.ArrayList(Relationship),
    name: []const u8,
    target: []const u8,
) !void {
    const owned_name = try allocator.dupe(u8, name);
    errdefer allocator.free(owned_name);
    const owned_target = try allocator.dupe(u8, target);
    errdefer allocator.free(owned_target);
    try list.append(allocator, .{ .name = owned_name, .target = owned_target });
}

fn deinitPendingStrings(allocator: std.mem.Allocator, list: *std.ArrayList([]const u8)) void {
    for (list.items) |item| allocator.free(item);
    list.deinit(allocator);
}

fn deinitPendingRelationships(allocator: std.mem.Allocator, list: *std.ArrayList(Relationship)) void {
    for (list.items) |rel| {
        allocator.free(rel.name);
        allocator.free(rel.target);
    }
    list.deinit(allocator);
}

fn deinitTerm(allocator: std.mem.Allocator, term: *const CvTerm) void {
    allocator.free(term.accession);
    allocator.free(term.name);
    allocator.free(term.namespace);
    allocator.free(term.description);
    if (term.replaced_by) |r| allocator.free(r);
    for (term.is_a) |item| allocator.free(item);
    if (term.is_a.len > 0) allocator.free(term.is_a);
    for (term.relationships) |rel| {
        allocator.free(rel.name);
        allocator.free(rel.target);
    }
    if (term.relationships.len > 0) allocator.free(term.relationships);
    for (term.synonyms) |syn| allocator.free(syn);
    if (term.synonyms.len > 0) allocator.free(term.synonyms);
    if (term.xsd_type) |v| allocator.free(v);
    for (term.allowed_units) |u| allocator.free(u);
    if (term.allowed_units.len > 0) allocator.free(term.allowed_units);
    for (term.binary_data_types) |b| allocator.free(b);
    if (term.binary_data_types.len > 0) allocator.free(term.binary_data_types);
}

// Extracts text between the first pair of double-quotes in `value`.
fn extractQuotedString(value: []const u8) []const u8 {
    const start = std.mem.indexOfScalar(u8, value, '"') orelse return value;
    const remaining = value[start + 1 ..];
    const end = std.mem.indexOfScalar(u8, remaining, '"') orelse return value;
    return remaining[0..end];
}

fn readFixture(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, allocator, .limited(64 * 1024));
}

test "CvTable parses known OBO snippet" {
    const allocator = std.testing.allocator;
    const obo =
        "format-version: 1.2\n" ++
        "data-version: test\n" ++
        "\n" ++
        "[Term]\n" ++
        "id: MS:1000001\n" ++
        "name: sample name\n" ++
        "def: \"A test term\" [MS:1000000]\n" ++
        "namespace: MS\n" ++
        "is_obsolete: false\n" ++
        "\n" ++
        "[Term]\n" ++
        "id: MS:1000002\n" ++
        "name: obsolete term\n" ++
        "is_obsolete: true\n" ++
        "replaced_by: MS:1000001\n";

    var table = try CvTable.init(allocator, obo);
    defer table.deinit();

    const t1 = table.lookup("MS:1000001");
    try std.testing.expect(t1 != null);
    try std.testing.expectEqualStrings("sample name", t1.?.name);
    try std.testing.expectEqualStrings("MS", t1.?.namespace);
    try std.testing.expect(!t1.?.is_obsolete);
    // def value should be the clean quoted text, not the raw line
    try std.testing.expectEqualStrings("A test term", t1.?.description);

    const t2 = table.lookup("MS:1000002");
    try std.testing.expect(t2 != null);
    try std.testing.expect(t2.?.is_obsolete);
    try std.testing.expectEqualStrings("MS:1000001", t2.?.replaced_by.?);

    const t3 = table.lookup("MS:9999999");
    try std.testing.expect(t3 == null);
}

test "CvTable parses real psi-ms.obo" {
    const allocator = std.testing.allocator;
    const obo = @embedFile("../data/psi-ms.obo");
    var table = try CvTable.init(allocator, obo);
    defer table.deinit();

    // Verify known accessions
    try std.testing.expect(table.lookup("MS:1000001") != null);
    try std.testing.expect(table.lookup("MS:1000511") != null);
    try std.testing.expect(table.lookup("MS:1000130") != null);
    try std.testing.expect(table.lookup("UO:0000000") != null);

    // Verify namespace prefixes were extracted
    try std.testing.expect(table.ns_prefix.contains("MS"));
    try std.testing.expect(table.ns_prefix.contains("UO"));
}

test "CvTable.validate catches errors" {
    const allocator = std.testing.allocator;
    const obo =
        "[Term]\n" ++
        "id: MS:1000001\n" ++
        "name: test term\n" ++
        "namespace: MS\n" ++
        "\n" ++
        "[Term]\n" ++
        "id: MS:1000002\n" ++
        "name: obsolete\n" ++
        "is_obsolete: true\n";

    var table = try CvTable.init(allocator, obo);
    defer table.deinit();

    // Valid
    try std.testing.expect(table.validate("MS", "MS:1000001") == null);
    // Wrong namespace
    try std.testing.expect(table.validate("UO", "MS:1000001") != null);
    // Obsolete
    try std.testing.expect(table.validate("MS", "MS:1000002") != null);
    // Non-existent
    try std.testing.expect(table.validate("MS", "MS:9999999") != null);
}

test "CvTable parses is_a and relationship" {
    const allocator = std.testing.allocator;
    const obo =
        "[Term]\n" ++
        "id: MS:1000001\n" ++
        "name: parent term\n" ++
        "\n" ++
        "[Term]\n" ++
        "id: MS:1000002\n" ++
        "name: child term\n" ++
        "is_a: MS:1000001 ! parent term\n" ++
        "relationship: part_of MS:1000001 ! parent term\n";

    var table = try CvTable.init(allocator, obo);
    defer table.deinit();

    const t = table.lookup("MS:1000002");
    try std.testing.expect(t != null);
    try std.testing.expectEqual(@as(usize, 1), t.?.is_a.len);
    try std.testing.expectEqualStrings("MS:1000001", t.?.is_a[0]);
    try std.testing.expectEqual(@as(usize, 1), t.?.relationships.len);
    try std.testing.expectEqualStrings("part_of", t.?.relationships[0].name);
    try std.testing.expectEqualStrings("MS:1000001", t.?.relationships[0].target);
}

test "isDescendantOf traverses hierarchy in real OBO" {
    const allocator = std.testing.allocator;
    const obo = @embedFile("../data/psi-ms.obo");
    var table = try CvTable.init(allocator, obo);
    defer table.deinit();

    // MS:1003378 (Orbitrap Astral) -> MS:1000494 -> MS:1000483 -> MS:1000031 (instrument model)
    try std.testing.expect(table.isDescendantOf("MS:1003378", "MS:1000031"));
    // MS:1003378 is not a descendant of itself via is_a (identity check)
    try std.testing.expect(table.isDescendantOf("MS:1003378", "MS:1003378"));
    // MS:1000031 is not a descendant of MS:1003378
    try std.testing.expect(!table.isDescendantOf("MS:1000031", "MS:1003378"));
}

test "CvTable rejects an overlong binary-data xref" {
    const allocator = std.testing.allocator;
    const obo = try readFixture(allocator, "fixtures/obo/adversarial/overlong-xref.obo");
    defer allocator.free(obo);

    try std.testing.expectError(error.XrefTooLong, CvTable.init(allocator, obo));
}

test "CvTable rejects an overlong line before field allocation" {
    const allocator = std.testing.allocator;
    const obo = "[Term]\nname: " ++ "abcdefghijklmnop";

    try std.testing.expectError(
        error.LineTooLong,
        CvTable.initWithLimits(allocator, obo, .{ .max_obo_line_bytes = 8 }),
    );
}

test "CvTable rejects duplicate IDs without replacing the first term" {
    const allocator = std.testing.allocator;
    const obo = try readFixture(allocator, "fixtures/obo/adversarial/duplicate-ids.obo");
    defer allocator.free(obo);

    try std.testing.expectError(error.DuplicateId, CvTable.init(allocator, obo));
}

test "CvTable owns term data after the source is freed" {
    const allocator = std.testing.allocator;
    const source = try readFixture(allocator, "fixtures/obo/adversarial/custom-namespace.obo");
    var table = CvTable.init(allocator, source) catch |err| {
        allocator.free(source);
        return err;
    };
    allocator.free(source);
    defer table.deinit();

    const term = table.lookup("CUSTOM:0000001") orelse return error.TestUnexpectedResult;
    try std.testing.expect(table.ns_prefix.contains("CUSTOM"));
    try std.testing.expectEqualStrings("CUSTOM", term.namespace);
    try std.testing.expectEqualStrings("term with custom namespace storage", term.name);
}

test "CvTable term construction owns every field and cleans allocation failures" {
    const allocator = std.testing.allocator;
    const obo = try readFixture(allocator, "fixtures/obo/adversarial/allocation-failure.obo");
    defer allocator.free(obo);
    var succeeded = false;

    var fail_index: usize = 0;
    while (fail_index < 128) : (fail_index += 1) {
        var failing_allocator = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
        var table = CvTable.init(failing_allocator.allocator(), obo) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            continue;
        };
        succeeded = true;
        table.deinit();
    }

    try std.testing.expect(succeeded);

    var table = try CvTable.init(allocator, obo);
    defer table.deinit();
    const term = table.lookup("MS:9000003") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("MS:1000001", term.replaced_by.?);
    try std.testing.expectEqualStrings("xsd:float", term.xsd_type.?);
    try std.testing.expectEqual(@as(usize, 1), term.is_a.len);
    try std.testing.expectEqual(@as(usize, 3), term.relationships.len);
    try std.testing.expectEqual(@as(usize, 1), term.synonyms.len);
    try std.testing.expectEqual(@as(usize, 1), term.allowed_units.len);
    try std.testing.expectEqual(@as(usize, 1), term.binary_data_types.len);
}
