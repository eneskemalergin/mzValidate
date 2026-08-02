//! Parses the OBO fields used by mzValidate's CV and mapping checks.
//! `CvTable` owns the term data copied from the input buffer.

const std = @import("std");
const diagnostic = @import("../diagnostic.zig");

const max_xref_accession_bytes = (diagnostic.ResourceLimits{}).max_obo_xref_accession_bytes;

pub const Relationship = struct {
    name: []const u8,
    target: []const u8,
};

pub const DescendantResult = enum {
    yes,
    no,
    limit_exceeded,
};

const max_descendant_nodes: usize = 256;

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

/// Accession-keyed lookup table that owns data copied from an OBO text buffer.
/// Term stanzas without a colon-qualified ID are skipped.
pub const CvTable = struct {
    allocator: std.mem.Allocator,
    budget: *CatalogBudget,
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
        if (limits.max_obo_catalog_bytes < @sizeOf(CatalogBudget)) return error.ResourceLimitExceeded;
        const budget = try allocator.create(CatalogBudget);
        budget.* = CatalogBudget.init(allocator, limits.max_obo_catalog_bytes);
        const catalog_allocator = budget.allocator();
        var table = CvTable{
            .allocator = catalog_allocator,
            .budget = budget,
            .map = std.StringHashMap(CvTerm).init(catalog_allocator),
            .ns_prefix = std.StringHashMap(void).init(catalog_allocator),
            .limits = limits,
        };
        table.parse(obo_text) catch |err| {
            const limit_exceeded = budget.limit_exceeded;
            table.deinit();
            if (err == error.OutOfMemory and limit_exceeded) return error.ResourceLimitExceeded;
            return err;
        };
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

        const budget = table.budget;
        std.debug.assert(budget.current_bytes == @sizeOf(CatalogBudget));
        const parent_allocator = budget.parent_allocator;
        parent_allocator.destroy(budget);
        table.* = undefined;
    }

    /// Returns a term whose slices remain valid while `table` is alive.
    pub fn lookup(table: *const CvTable, accession: []const u8) ?CvTerm {
        return table.map.get(accession);
    }

    /// Returns allocator-requested catalog capacity retained by this table and
    /// any catalog object built with its allocator.
    pub fn currentBytes(table: *const CvTable) usize {
        return table.budget.current_bytes;
    }

    /// Returns the largest allocator-requested catalog capacity observed.
    pub fn peakBytes(table: *const CvTable) usize {
        return table.budget.peak_bytes;
    }

    /// Reports whether the catalog allocator rejected growth at its byte limit.
    pub fn limitExceeded(table: *const CvTable) bool {
        return table.budget.limit_exceeded;
    }

    /// Allocator for catalog data that shares this table's limit. Every allocation
    /// made through it must be released before `deinit` destroys the table.
    pub fn catalogAllocator(table: *CvTable) std.mem.Allocator {
        return table.allocator;
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

    /// Returns whether `term_acc` equals `ancestor_acc` or reaches it through
    /// `is_a`; reports `limit_exceeded` when the bounded traversal is full.
    pub fn isDescendantOf(table: *const CvTable, term_acc: []const u8, ancestor_acc: []const u8) DescendantResult {
        if (std.mem.eql(u8, term_acc, ancestor_acc)) return .yes;
        var stack: [max_descendant_nodes][]const u8 = undefined;
        var count: usize = 0;
        if (table.lookup(term_acc)) |t| {
            for (t.is_a) |parent| {
                if (!queueDescendant(&stack, &count, parent)) return .limit_exceeded;
            }
        }
        var visited: usize = 0;
        while (visited < count) : (visited += 1) {
            const current = stack[visited];
            if (std.mem.eql(u8, current, ancestor_acc)) return .yes;
            if (table.lookup(current)) |t| {
                for (t.is_a) |parent| {
                    if (!queueDescendant(&stack, &count, parent)) return .limit_exceeded;
                }
            }
        }
        return .no;
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
            if (raw_line.len > table.limits.max_obo_line_bytes) return error.LineTooLong;
            const line = std.mem.trim(u8, raw_line, " \t\r");

            if (line.len == 0 or line[0] == '!') continue;

            if (line.len > 0 and line[0] == '[') {
                if (in_term) {
                    try table.insertTerm(id, name, def_val, namespace, is_obsolete, replaced_by, xsd_type, &is_a_list, &rel_list, &syn_list, &unit_list, &binary_type_list);
                    id = null;
                    name = null;
                    def_val = null;
                    namespace = null;
                    is_obsolete = false;
                    replaced_by = null;
                    xsd_type = null;
                    clearPendingStrings(table.allocator, &is_a_list);
                    clearPendingRelationships(table.allocator, &rel_list);
                    clearPendingStrings(table.allocator, &syn_list);
                    clearPendingStrings(table.allocator, &unit_list);
                    clearPendingStrings(table.allocator, &binary_type_list);
                }
                in_term = std.mem.eql(u8, line, "[Term]");
                continue;
            }

            if (!in_term) continue;

            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            const tag = std.mem.trim(u8, line[0..colon], " \t");
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t\r");

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
                def_val = extractQuotedString(value) orelse value;
            } else if (std.mem.eql(u8, tag, "namespace")) {
                namespace = value;
            } else if (std.mem.eql(u8, tag, "is_obsolete") and std.mem.eql(u8, value, "true")) {
                is_obsolete = true;
            } else if (std.mem.eql(u8, tag, "replaced_by")) {
                replaced_by = value;
            } else if (std.mem.eql(u8, tag, "consider")) {
                if (replaced_by == null) replaced_by = value;
            } else if (std.mem.eql(u8, tag, "xref")) {
                if (std.mem.startsWith(u8, value, "binary-data-type:")) {
                    const acc_start = "binary-data-type:".len;
                    const rest = value[acc_start..];
                    const space_pos = std.mem.indexOfAny(u8, rest, " \t") orelse rest.len;
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
                var parts = std.mem.tokenizeAny(u8, value, " \t");
                const parent = parts.next() orelse continue;
                try appendOwnedString(table.allocator, &is_a_list, parent);
            } else if (std.mem.eql(u8, tag, "relationship")) {
                var parts = std.mem.tokenizeAny(u8, value, " \t");
                const rname = parts.next() orelse continue;
                const rtarget = parts.next() orelse continue;
                try appendOwnedRelationship(table.allocator, &rel_list, rname, rtarget);
                if (std.mem.eql(u8, rname, "has_value_type")) {
                    if (std.mem.startsWith(u8, rtarget, "xsd:")) {
                        xsd_type = rtarget;
                    }
                }
                if (std.mem.eql(u8, rname, "has_units")) {
                    const space = std.mem.indexOfScalar(u8, rtarget, ' ') orelse rtarget.len;
                    try appendOwnedString(table.allocator, &unit_list, rtarget[0..space]);
                }
            } else if (std.mem.eql(u8, tag, "synonym")) {
                if (value.len > 0 and value[0] == '"') {
                    const synonym = extractQuotedString(value) orelse continue;
                    try appendOwnedString(table.allocator, &syn_list, synonym);
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
        error.ResourceLimitExceeded => "OBO catalog exceeds the configured memory limit",
        error.XrefTooLong => "OBO binary-data-type xref accession exceeds its configured limit",
        error.LineTooLong => "OBO line exceeds its configured limit",
        error.DuplicateId => "OBO contains a duplicate term ID",
        else => "unable to parse OBO file",
    };
}

const CatalogBudget = struct {
    parent_allocator: std.mem.Allocator,
    limit: usize,
    current_bytes: usize,
    peak_bytes: usize,
    limit_exceeded: bool = false,

    fn init(parent_allocator: std.mem.Allocator, limit: usize) CatalogBudget {
        return .{
            .parent_allocator = parent_allocator,
            .limit = limit,
            .current_bytes = @sizeOf(CatalogBudget),
            .peak_bytes = @sizeOf(CatalogBudget),
        };
    }

    fn allocator(budget: *CatalogBudget) std.mem.Allocator {
        return .{
            .ptr = budget,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn nextBytes(budget: *CatalogBudget, extra: usize) ?usize {
        const next = std.math.add(usize, budget.current_bytes, extra) catch {
            budget.limit_exceeded = true;
            return null;
        };
        if (next > budget.limit) {
            budget.limit_exceeded = true;
            return null;
        }
        return next;
    }

    fn recordBytes(budget: *CatalogBudget, next: usize) void {
        budget.current_bytes = next;
        budget.peak_bytes = @max(budget.peak_bytes, next);
    }

    fn alloc(
        context: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) ?[*]u8 {
        const budget: *CatalogBudget = @ptrCast(@alignCast(context));
        const next = budget.nextBytes(len) orelse return null;
        const result = budget.parent_allocator.rawAlloc(len, alignment, return_address) orelse return null;
        budget.recordBytes(next);
        return result;
    }

    fn resize(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        return_address: usize,
    ) bool {
        const budget: *CatalogBudget = @ptrCast(@alignCast(context));
        const next = if (new_len > memory.len)
            budget.nextBytes(new_len - memory.len) orelse return false
        else
            budget.current_bytes - (memory.len - new_len);
        if (!budget.parent_allocator.rawResize(memory, alignment, new_len, return_address)) return false;
        budget.recordBytes(next);
        return true;
    }

    fn remap(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        return_address: usize,
    ) ?[*]u8 {
        const budget: *CatalogBudget = @ptrCast(@alignCast(context));
        const next = if (new_len > memory.len)
            budget.nextBytes(new_len - memory.len) orelse return null
        else
            budget.current_bytes - (memory.len - new_len);
        const result = budget.parent_allocator.rawRemap(memory, alignment, new_len, return_address) orelse return null;
        budget.recordBytes(next);
        return result;
    }

    fn free(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) void {
        const budget: *CatalogBudget = @ptrCast(@alignCast(context));
        budget.parent_allocator.rawFree(memory, alignment, return_address);
        budget.current_bytes -= memory.len;
    }
};

fn queueDescendant(
    stack: *[max_descendant_nodes][]const u8,
    count: *usize,
    accession: []const u8,
) bool {
    for (stack[0..count.*]) |queued| {
        if (std.mem.eql(u8, queued, accession)) return true;
    }
    if (count.* == stack.len) return false;
    stack[count.*] = accession;
    count.* += 1;
    return true;
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
    clearPendingStrings(allocator, list);
    list.deinit(allocator);
}

fn clearPendingStrings(allocator: std.mem.Allocator, list: *std.ArrayList([]const u8)) void {
    for (list.items) |item| allocator.free(item);
    list.clearRetainingCapacity();
}

fn deinitPendingRelationships(allocator: std.mem.Allocator, list: *std.ArrayList(Relationship)) void {
    clearPendingRelationships(allocator, list);
    list.deinit(allocator);
}

fn clearPendingRelationships(allocator: std.mem.Allocator, list: *std.ArrayList(Relationship)) void {
    for (list.items) |rel| {
        allocator.free(rel.name);
        allocator.free(rel.target);
    }
    list.clearRetainingCapacity();
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

fn extractQuotedString(value: []const u8) ?[]const u8 {
    const start = std.mem.indexOfScalar(u8, value, '"') orelse return null;
    var escaped = false;
    var index = start + 1;
    while (index < value.len) : (index += 1) {
        const byte = value[index];
        if (byte == '\\') {
            escaped = !escaped;
            continue;
        }
        if (byte == '"' and !escaped) return value[start + 1 .. index];
        escaped = false;
    }
    return null;
}

fn readFixture(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(64 * 1024));
}

// --- Unit Tests ---

test "cv table parses a known OBO snippet" {
    const allocator = std.testing.allocator;
    const obo =
        "format-version: 1.2\n" ++
        "data-version: test\n" ++
        "\n" ++
        "[Typedef]\n" ++
        "id: TEST:relation\n" ++
        "name: relation\n" ++
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
    try std.testing.expectEqualStrings("A test term", t1.?.description);

    const t2 = table.lookup("MS:1000002");
    try std.testing.expect(t2 != null);
    try std.testing.expect(t2.?.is_obsolete);
    try std.testing.expectEqualStrings("MS:1000001", t2.?.replaced_by.?);

    const t3 = table.lookup("MS:9999999");
    try std.testing.expect(t3 == null);
    try std.testing.expect(table.lookup("TEST:relation") == null);
}

test "cv table handles CRLF and escaped quotes" {
    const allocator = std.testing.allocator;
    const obo =
        "  [Term]\r\n" ++
        "\tid: MS:1000001\r\n" ++
        " name: quoted term\r\n" ++
        " def: \"A \\\"quoted\\\" term\" []\r\n" ++
        " synonym: \"A \\\"short\\\" name\" EXACT []\r\n";

    var table = try CvTable.init(allocator, obo);
    defer table.deinit();

    const term = table.lookup("MS:1000001") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("A \\\"quoted\\\" term", term.description);
    try std.testing.expectEqualStrings("A \\\"short\\\" name", term.synonyms[0]);
}

test "cv table parses the embedded psi-ms vocabulary" {
    const allocator = std.testing.allocator;
    const obo = @embedFile("../data/psi-ms.obo");
    var table = try CvTable.init(allocator, obo);
    defer table.deinit();

    try std.testing.expect(table.lookup("MS:1000001") != null);
    try std.testing.expect(table.lookup("MS:1000511") != null);
    try std.testing.expect(table.lookup("MS:1000130") != null);
    try std.testing.expect(table.lookup("UO:0000000") != null);

    try std.testing.expect(table.ns_prefix.contains("MS"));
    try std.testing.expect(table.ns_prefix.contains("UO"));
}

test "cv table validates namespace, obsolete, and unknown terms" {
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

    try std.testing.expect(table.validate("MS", "MS:1000001") == null);
    try std.testing.expect(table.validate("UO", "MS:1000001") != null);
    try std.testing.expect(table.validate("MS", "MS:1000002") != null);
    try std.testing.expect(table.validate("MS", "MS:9999999") != null);
}

test "cv table parses is_a and relationships" {
    const allocator = std.testing.allocator;
    const obo =
        "[Term]\n" ++
        "id: MS:1000001\n" ++
        "name: parent term\n" ++
        "\n" ++
        "[Term]\n" ++
        "id: MS:1000002\n" ++
        "name: child term\n" ++
        "is_a:\tMS:1000001\t! parent term\n" ++
        "relationship:\tpart_of\tMS:1000001\t! parent term\n";

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

test "isDescendantOf traverses the embedded hierarchy" {
    const allocator = std.testing.allocator;
    const obo = @embedFile("../data/psi-ms.obo");
    var table = try CvTable.init(allocator, obo);
    defer table.deinit();

    try std.testing.expectEqual(DescendantResult.yes, table.isDescendantOf("MS:1003378", "MS:1000031"));
    try std.testing.expectEqual(DescendantResult.yes, table.isDescendantOf("MS:1003378", "MS:1003378"));
    try std.testing.expectEqual(DescendantResult.no, table.isDescendantOf("MS:1000031", "MS:1003378"));
}

test "isDescendantOf terminates on cyclic hierarchy" {
    const allocator = std.testing.allocator;
    const obo =
        "[Term]\n" ++
        "id: TEST:A\n" ++
        "name: A\n" ++
        "is_a: TEST:B\n" ++
        "\n" ++
        "[Term]\n" ++
        "id: TEST:B\n" ++
        "name: B\n" ++
        "is_a: TEST:A\n";

    var table = try CvTable.init(allocator, obo);
    defer table.deinit();

    try std.testing.expectEqual(DescendantResult.no, table.isDescendantOf("TEST:A", "TEST:C"));
}

test "isDescendantOf reports its traversal limit" {
    const allocator = std.testing.allocator;
    var obo = std.ArrayList(u8).empty;
    defer obo.deinit(allocator);

    for (0..max_descendant_nodes + 2) |i| {
        try obo.appendSlice(allocator, "[Term]\nid: MS:");
        var id_buf: [32]u8 = undefined;
        const id = try std.fmt.bufPrint(&id_buf, "{d}\nname: term\n", .{i});
        try obo.appendSlice(allocator, id);
        if (i > 0) {
            try obo.appendSlice(allocator, "is_a: MS:");
            const parent = try std.fmt.bufPrint(&id_buf, "{d} ! parent\n", .{i - 1});
            try obo.appendSlice(allocator, parent);
        }
    }

    var table = try CvTable.init(allocator, obo.items);
    defer table.deinit();

    try std.testing.expectEqual(
        DescendantResult.limit_exceeded,
        table.isDescendantOf("MS:257", "MS:0"),
    );
}

test "cv table rejects an overlong binary-data xref" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const obo = try readFixture(allocator, io, "fixtures/obo/adversarial/overlong-xref.obo");
    defer allocator.free(obo);

    try std.testing.expectError(error.XrefTooLong, CvTable.init(allocator, obo));
}

test "cv table rejects an overlong line before field allocation" {
    const allocator = std.testing.allocator;
    const obo = "[Term]\nname: " ++ "abcdefghijklmnop";

    try std.testing.expectError(
        error.LineTooLong,
        CvTable.initWithLimits(allocator, obo, .{ .max_obo_line_bytes = 8 }),
    );
}

test "[unit]: malformed term stanzas release pending ownership and parsing continues" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const obo = try readFixture(allocator, io, "fixtures/obo/adversarial/malformed-stanza-ownership.obo");
    defer allocator.free(obo);

    var table = try CvTable.init(allocator, obo);
    defer table.deinit();

    const term = table.lookup("TEST:valid") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 1), table.map.count());
    try std.testing.expectEqualStrings("valid term after malformed stanzas", term.name);
    try std.testing.expect(table.lookup("unusable") == null);
}

test "cv table rejects duplicate IDs without replacing the first term" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const obo = try readFixture(allocator, io, "fixtures/obo/adversarial/duplicate-ids.obo");
    defer allocator.free(obo);

    try std.testing.expectError(error.DuplicateId, CvTable.init(allocator, obo));
}

test "cv table owns term data after the source is freed" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const source = try readFixture(allocator, io, "fixtures/obo/adversarial/custom-namespace.obo");
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

test "[unit]: OBO catalog budget charges all owned allocator bytes" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const obo = try readFixture(allocator, io, "fixtures/obo/adversarial/allocation-failure.obo");
    defer allocator.free(obo);
    var counting_allocator = std.testing.FailingAllocator.init(allocator, .{});
    var table = try CvTable.init(counting_allocator.allocator(), obo);
    var table_live = true;
    defer if (table_live) table.deinit();

    const live_allocator_bytes = counting_allocator.allocated_bytes - counting_allocator.freed_bytes;

    try std.testing.expectEqual(live_allocator_bytes, table.budget.current_bytes);
    try std.testing.expect(table.budget.peak_bytes >= table.budget.current_bytes);
    table.deinit();
    table_live = false;
    try std.testing.expectEqual(counting_allocator.allocated_bytes, counting_allocator.freed_bytes);
}

test "[unit]: OBO catalog accepts its exact peak limit and rejects one byte less" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const obo = try readFixture(allocator, io, "fixtures/obo/adversarial/allocation-failure.obo");
    defer allocator.free(obo);
    var baseline_allocator = std.testing.FailingAllocator.init(allocator, .{ .resize_fail_index = 0 });
    var baseline = try CvTable.init(baseline_allocator.allocator(), obo);
    const required_peak_bytes = baseline.budget.peak_bytes;
    baseline.deinit();

    var exact_allocator = std.testing.FailingAllocator.init(allocator, .{ .resize_fail_index = 0 });
    var exact = try CvTable.initWithLimits(exact_allocator.allocator(), obo, .{
        .max_obo_catalog_bytes = required_peak_bytes,
    });
    defer exact.deinit();

    try std.testing.expectEqual(required_peak_bytes, exact.budget.peak_bytes);
    var over_allocator = std.testing.FailingAllocator.init(allocator, .{ .resize_fail_index = 0 });
    try std.testing.expectError(
        error.ResourceLimitExceeded,
        CvTable.initWithLimits(over_allocator.allocator(), obo, .{
            .max_obo_catalog_bytes = required_peak_bytes - 1,
        }),
    );
    try std.testing.expectEqual(over_allocator.allocated_bytes, over_allocator.freed_bytes);

    var too_small_allocator = std.testing.FailingAllocator.init(allocator, .{});
    try std.testing.expectError(
        error.ResourceLimitExceeded,
        CvTable.initWithLimits(too_small_allocator.allocator(), obo, .{
            .max_obo_catalog_bytes = @sizeOf(CatalogBudget) - 1,
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), too_small_allocator.allocated_bytes);
}

test "cv table cleans every field on allocation failure" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const obo = try readFixture(allocator, io, "fixtures/obo/adversarial/allocation-failure.obo");
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
