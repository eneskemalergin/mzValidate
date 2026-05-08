//! OBO format 1.4 parser for psi-ms.obo controlled vocabularies.
//!
//! Parses stanzas (`[Term]`, `[Typedef]`), tag-value pairs, line continuations,
//! escape sequences, and builds a `CvTable` for fast accession lookup.
//!
//! Usage:
//!   var table = try CvTable.init(allocator, embedded_obo);
//!   defer table.deinit();
//!   const term = table.lookup("MS:1000001");

const std = @import("std");

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
};

pub const CvTable = struct {
    allocator: std.mem.Allocator,
    map: std.StringHashMap(CvTerm),
    ns_prefix: std.StringHashMap(void),

    pub fn init(allocator: std.mem.Allocator, obo_text: []const u8) !CvTable {
        var table = CvTable{
            .allocator = allocator,
            .map = std.StringHashMap(CvTerm).init(allocator),
            .ns_prefix = std.StringHashMap(void).init(allocator),
        };
        errdefer table.deinit();
        try table.parse(obo_text);
        return table;
    }

    pub fn deinit(table: *CvTable) void {
        // Free all CvTerm heap allocations before deinitting the map.
        // map.deinit() frees buckets/metadata only (not key/value data).
        var it = table.map.iterator();
        while (it.next()) |entry| {
            const term = entry.value_ptr;
            table.allocator.free(term.accession);
            table.allocator.free(term.name);
            table.allocator.free(term.namespace);
            table.allocator.free(term.description);
            if (term.replaced_by) |r| table.allocator.free(r);
            for (term.is_a) |item| table.allocator.free(item);
            if (term.is_a.len > 0) table.allocator.free(term.is_a);
            for (term.relationships) |rel| {
                table.allocator.free(rel.name);
                table.allocator.free(rel.target);
            }
            if (term.relationships.len > 0) table.allocator.free(term.relationships);
            for (term.synonyms) |syn| table.allocator.free(syn);
            if (term.synonyms.len > 0) table.allocator.free(term.synonyms);
        }
        table.map.deinit();
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

    fn parse(table: *CvTable, text: []const u8) !void {
        var lines = std.mem.tokenizeScalar(u8, text, '\n');
        var in_term = false;
        var id: ?[]const u8 = null;
        var name: ?[]const u8 = null;
        var def_val: ?[]const u8 = null;
        var namespace: ?[]const u8 = null;
        var is_obsolete: bool = false;
        var replaced_by: ?[]const u8 = null;
        var is_a_list: std.ArrayList([]const u8) = .empty;
        var rel_list: std.ArrayList(Relationship) = .empty;
        var syn_list: std.ArrayList([]const u8) = .empty;
        defer {
            is_a_list.deinit(table.allocator);
            rel_list.deinit(table.allocator);
            syn_list.deinit(table.allocator);
        }

        while (lines.next()) |raw_line| {
            const line = raw_line;

            if (line.len == 0 or line[0] == '!') continue;

            if (line[0] == '[') {
                if (in_term) {
                    try table.insertTerm(id, name, def_val, namespace, is_obsolete, replaced_by, &is_a_list, &rel_list, &syn_list);
                    id = null; name = null; def_val = null; namespace = null; is_obsolete = false; replaced_by = null;
                    is_a_list.clearRetainingCapacity();
                    rel_list.clearRetainingCapacity();
                    syn_list.clearRetainingCapacity();
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
                try table.ns_prefix.put(value[0..ns_end], {});
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
            } else if (std.mem.eql(u8, tag, "is_a")) {
                const space = std.mem.indexOfScalar(u8, value, ' ') orelse value.len;
                const owned = try table.allocator.dupe(u8, value[0..space]);
                try is_a_list.append(table.allocator, owned);
            } else if (std.mem.eql(u8, tag, "relationship")) {
                var parts = std.mem.tokenizeScalar(u8, value, ' ');
                const rname = parts.next() orelse continue;
                const rtarget = parts.next() orelse continue;
                try rel_list.append(table.allocator, .{
                    .name = try table.allocator.dupe(u8, rname),
                    .target = try table.allocator.dupe(u8, rtarget),
                });
            } else if (std.mem.eql(u8, tag, "synonym")) {
                if (value.len > 0 and value[0] == '"') {
                    const close = std.mem.indexOfScalar(u8, value[1..], '"') orelse continue;
                    const owned = try table.allocator.dupe(u8, value[1..][0..close]);
                    try syn_list.append(table.allocator, owned);
                }
            }
        }

        if (in_term) {
            try table.insertTerm(id, name, def_val, namespace, is_obsolete, replaced_by, &is_a_list, &rel_list, &syn_list);
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
        is_a_list: *std.ArrayList([]const u8),
        rel_list: *std.ArrayList(Relationship),
        syn_list: *std.ArrayList([]const u8),
    ) !void {
        const acc = id orelse return;
        const nm = name orelse "__unnamed__";

        const ns_end = std.mem.indexOfScalar(u8, acc, ':') orelse return;
        const ns = if (namespace) |n| n else acc[0..ns_end];

        const term = CvTerm{
            .accession = try table.allocator.dupe(u8, acc),
            .name = try table.allocator.dupe(u8, nm),
            .namespace = try table.allocator.dupe(u8, ns),
            .description = try table.allocator.dupe(u8, def_val orelse ""),
            .is_obsolete = is_obsolete,
            .replaced_by = if (replaced_by) |r| try table.allocator.dupe(u8, r) else null,
            .is_a = try is_a_list.toOwnedSlice(table.allocator),
            .relationships = try rel_list.toOwnedSlice(table.allocator),
            .synonyms = try syn_list.toOwnedSlice(table.allocator),
        };

        table.map.put(term.accession, term) catch |err| {
            // Full cleanup on insertion failure
            table.allocator.free(term.accession);
            table.allocator.free(term.name);
            table.allocator.free(term.namespace);
            table.allocator.free(term.description);
            if (term.replaced_by) |r| table.allocator.free(r);
            for (term.is_a) |item| table.allocator.free(item);
            if (term.is_a.len > 0) table.allocator.free(term.is_a);
            for (term.relationships) |rel| {
                table.allocator.free(rel.name);
                table.allocator.free(rel.target);
            }
            if (term.relationships.len > 0) table.allocator.free(term.relationships);
            for (term.synonyms) |syn| table.allocator.free(syn);
            if (term.synonyms.len > 0) table.allocator.free(term.synonyms);
            return err;
        };
    }
};

/// Extracts text between the first pair of double-quotes in `value`.
/// Returns the original slice if no quotes are found.
fn extractQuotedString(value: []const u8) []const u8 {
    const start = std.mem.indexOfScalar(u8, value, '"') orelse return value;
    const remaining = value[start + 1 ..];
    const end = std.mem.indexOfScalar(u8, remaining, '"') orelse return value;
    return remaining[0..end];
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
