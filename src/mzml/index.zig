//! Index and checksum validation for indexed mzML files.
//!
//! During the forward pass the validator records byte offsets of every
//! spectrum and chromatogram, parses `<indexList>` entries, and captures
//! `<indexListOffset>` and `<fileChecksum>` values. Cross-checks and SHA-1
//! verification run in `finish()` against random-access file bytes (mmap).

const std = @import("std");
const diagnostic = @import("../diagnostic.zig");
const xml_events = @import("../xml/events.zig");

const Attribute = xml_events.Attribute;
const Diagnostic = diagnostic.Diagnostic;
const EndElement = xml_events.EndElement;
const RuleId = diagnostic.RuleId;
const StartElement = xml_events.StartElement;
const Text = xml_events.Text;
const QName = xml_events.QName;

/// Namespace matched by the streaming mzML validators.
const mzml_namespace = "http://psi.hupo.org/ms/mzml";

const IndexKind = enum { spectrum, chromatogram };

const IndexEntry = struct {
    id_ref: []const u8,
    offset: u64,
};

/// Validates index offsets, indexListOffset, fileChecksum SHA-1, and truncation.
///
/// Call consumeStart/consumeEnd/consumeText during the forward parse pass,
/// then finish(file_bytes) after the document ends.
pub const IndexValidator = struct {
    allocator: std.mem.Allocator,
    diagnostics: *std.ArrayList(Diagnostic),
    path: ?[]const u8,

    depth: usize = 0,
    mzml_depth: ?usize = null,
    indexed_mzml_depth: ?usize = null,

    // Forward-pass: id → byte_offset for every spectrum/chromatogram.
    spectrum_offsets: std.StringHashMap(u64),
    chromatogram_offsets: std.StringHashMap(u64),

    // --- Index list parsing state ---
    index_list_depth: ?usize = null,
    index_list_actual_offset: ?u64 = null,

    current_index_kind: ?IndexKind = null,
    offset_id_ref_owned: ?[]const u8 = null,

    // Accumulated entries parsed from <indexList>.
    index_entries: std.ArrayList(IndexEntry),

    // --- indexListOffset ---
    index_list_offset_depth: ?usize = null,
    index_list_offset_byte_offset: ?u64 = null,
    index_list_offset_value: ?u64 = null,

    // --- fileChecksum ---
    file_checksum_depth: ?usize = null,
    file_checksum_byte_offset: ?u64 = null,
    file_checksum_raw: [20]u8 = undefined,
    file_checksum_ok: bool = false,

    // Shared text accumulator for offset values, indexListOffset, and fileChecksum.
    text_buf: std.ArrayList(u8),

    // Set true when any index-related element is encountered.
    saw_index_elements: bool = false,

    /// True if the file appears to have an index (we saw at least one index element).
    pub fn isIndexed(validator: *const IndexValidator) bool {
        return validator.saw_index_elements;
    }

    /// Returns the declared fileChecksum value parsed from `<fileChecksum>`.
    /// Returns null if no fileChecksum was encountered.
    pub fn declaredChecksum(validator: *const IndexValidator) ?[20]u8 {
        if (!validator.file_checksum_ok) return null;
        return validator.file_checksum_raw;
    }

    pub fn init(
        allocator: std.mem.Allocator,
        diagnostics: *std.ArrayList(Diagnostic),
        path: ?[]const u8,
    ) IndexValidator {
        return .{
            .allocator = allocator,
            .diagnostics = diagnostics,
            .path = path,
            .spectrum_offsets = std.StringHashMap(u64).init(allocator),
            .chromatogram_offsets = std.StringHashMap(u64).init(allocator),
            .index_entries = std.ArrayList(IndexEntry).empty,
            .text_buf = std.ArrayList(u8).empty,
        };
    }

    pub fn deinit(validator: *IndexValidator) void {
        freeHashMap(validator.allocator, &validator.spectrum_offsets);
        freeHashMap(validator.allocator, &validator.chromatogram_offsets);
        freeIndexEntries(validator.allocator, &validator.index_entries);
        if (validator.offset_id_ref_owned) |owned| validator.allocator.free(owned);
        validator.index_entries.deinit(validator.allocator);
        validator.text_buf.deinit(validator.allocator);
        validator.* = undefined;
    }

    pub fn consumeStart(
        validator: *IndexValidator,
        start: StartElement,
        element_depth: usize,
    ) !void {
        validator.depth = element_depth;

        // Handle indexedmzML wrapper (contains mzML as a child).
        if (start.name.matches(mzml_namespace, "indexedmzML")) {
            validator.indexed_mzml_depth = element_depth;
            return;
        }

        // Track mzML element depth. May appear at depth 0 (standalone) or
        // as a child of indexedmzML.
        if (start.name.matches(mzml_namespace, "mzML") and
            (validator.mzml_depth == null or element_depth < validator.mzml_depth.?))
        {
            validator.mzml_depth = element_depth;
            return;
        }

        if (validator.mzml_depth == null) return;
        if (element_depth <= validator.mzml_depth.?) return;

        // Track spectrum and chromatogram start offsets.
        if (start.name.matches(mzml_namespace, "spectrum")) {
            try recordContainerOffset(validator, start, &validator.spectrum_offsets);
            return;
        }
        if (start.name.matches(mzml_namespace, "chromatogram")) {
            try recordContainerOffset(validator, start, &validator.chromatogram_offsets);
            return;
        }

        // indexList
        if (start.name.matches(mzml_namespace, "indexList")) {
            validator.index_list_depth = element_depth;
            validator.index_list_actual_offset = start.byte_offset;
            validator.saw_index_elements = true;
            return;
        }

        // <index name="spectrum"> or <index name="chromatogram">
        if (start.name.matches(mzml_namespace, "index")) {
            if (validator.index_list_depth == null) return;
            if (element_depth != validator.index_list_depth.? + 1) return;
            const name = attributeValue(start.attributes, "name") orelse {
                try validator.appendDiagnostic(start.byte_offset, RuleId.mzml_index_offset_list, "index element is missing required attribute name");
                return;
            };
            validator.current_index_kind = if (std.mem.eql(u8, name, "spectrum"))
                IndexKind.spectrum
            else if (std.mem.eql(u8, name, "chromatogram"))
                IndexKind.chromatogram
            else
                null;
            return;
        }

        // <offset idRef="X">
        if (start.name.matches(mzml_namespace, "offset")) {
            if (validator.current_index_kind == null) return;
            const id_ref = attributeValue(start.attributes, "idRef") orelse {
                try validator.appendDiagnostic(start.byte_offset, RuleId.mzml_index_offset, "offset element is missing required attribute idRef");
                return;
            };
            if (validator.offset_id_ref_owned) |owned| validator.allocator.free(owned);
            validator.offset_id_ref_owned = try validator.allocator.dupe(u8, id_ref);
            validator.text_buf.clearRetainingCapacity();
            return;
        }

        // indexListOffset
        if (start.name.matches(mzml_namespace, "indexListOffset")) {
            validator.index_list_offset_byte_offset = start.byte_offset;
            validator.index_list_offset_depth = element_depth;
            validator.text_buf.clearRetainingCapacity();
            return;
        }

        // fileChecksum
        if (start.name.matches(mzml_namespace, "fileChecksum")) {
            validator.file_checksum_depth = element_depth;
            validator.file_checksum_byte_offset = start.byte_offset;
            validator.text_buf.clearRetainingCapacity();
            return;
        }
    }

    pub fn consumeEnd(
        validator: *IndexValidator,
        end: EndElement,
        element_depth: usize,
    ) void {
        if (validator.mzml_depth == null) return;
        if (element_depth <= validator.mzml_depth.?) {
            if (end.name.matches(mzml_namespace, "mzML") and validator.mzml_depth == element_depth) {
                validator.mzml_depth = null;
            }
            return;
        }

        // Close offset → create index entry.
        if (end.name.matches(mzml_namespace, "offset") and
            validator.current_index_kind != null and
            validator.offset_id_ref_owned != null)
        {
            const id_ref_owned = validator.offset_id_ref_owned.?;
            validator.offset_id_ref_owned = null;
            const offset = std.fmt.parseUnsigned(u64, validator.text_buf.items, 10) catch {
                validator.allocator.free(id_ref_owned);
                return;
            };
            validator.index_entries.append(validator.allocator, .{ .id_ref = id_ref_owned, .offset = offset }) catch {
                validator.allocator.free(id_ref_owned);
                return;
            };
            return;
        }

        // Close index.
        if (end.name.matches(mzml_namespace, "index")) {
            validator.current_index_kind = null;
            return;
        }

        // Close indexList.
        if (end.name.matches(mzml_namespace, "indexList")) {
            validator.index_list_depth = null;
            validator.index_list_offset_value = null;
            return;
        }

        // Close indexListOffset.
        if (end.name.matches(mzml_namespace, "indexListOffset")) {
            validator.index_list_offset_value = std.fmt.parseUnsigned(u64, validator.text_buf.items, 10) catch null;
            validator.index_list_offset_depth = null;
            return;
        }

        // Close fileChecksum.
        if (end.name.matches(mzml_namespace, "fileChecksum")) {
            decodeHex(validator.text_buf.items, &validator.file_checksum_raw);
            validator.file_checksum_ok = true;
            validator.file_checksum_depth = null;
            return;
        }
    }

    pub fn consumeText(
        validator: *IndexValidator,
        text: Text,
        element_depth: usize,
    ) !void {
        _ = element_depth;
        if (validator.mzml_depth == null) return;

        // Only accumulate text inside elements we care about.
        if (validator.offset_id_ref_owned != null or
            validator.index_list_offset_depth != null or
            validator.file_checksum_depth != null)
        {
            try validator.text_buf.appendSlice(validator.allocator, text.value);
        }
    }

    /// After the document is fully parsed, cross-check all collected data.
    /// `file_bytes` is the complete mmap'd file content (or null if unavailable).
    /// When null, SHA-1 verification and truncation checks are skipped.
    pub fn finish(
        validator: *IndexValidator,
        file_bytes: ?[]const u8,
    ) void {
        if (!validator.saw_index_elements) return;

        // --- indexListOffset verification ---
        if (validator.index_list_offset_value) |declared| {
            if (validator.index_list_actual_offset) |actual| {
                if (declared != actual) {
                    validator.appendDiagnostic(
                        validator.index_list_offset_byte_offset orelse validator.index_list_actual_offset orelse 0,
                        RuleId.mzml_index_offset_list,
                        "declared indexListOffset does not match actual position of indexList",
                    ) catch {};
                }
            }
        }

        // --- Cross-check each index entry ---
        for (validator.index_entries.items) |entry| {
            // Check truncation (offset past EOF).
            if (file_bytes) |bytes| {
                if (entry.offset >= bytes.len) {
                    validator.appendDiagnostic(
                        entry.offset,
                        RuleId.mzml_index_truncated,
                        "index offset points past end of file",
                    ) catch {};
                    continue;
                }
            }

            // Look up the idRef in both maps.
            const recorded_offset = validator.spectrum_offsets.get(entry.id_ref) orelse
                validator.chromatogram_offsets.get(entry.id_ref) orelse
                {
                    validator.appendDiagnostic(
                        entry.offset,
                        RuleId.mzml_index_offset,
                        "index references non-existent spectrum or chromatogram",
                    ) catch {};
                    continue;
                };

            if (entry.offset != recorded_offset) {
                validator.appendDiagnostic(
                    entry.offset,
                    RuleId.mzml_index_offset,
                    "index offset does not match actual byte position",
                ) catch {};
            }
        }

        // --- SHA-1 checksum verification ---
        if (file_bytes) |bytes| {
            if (validator.file_checksum_ok) {
                if (validator.file_checksum_byte_offset) |checksum_offset| {
                    var computed: [20]u8 = undefined;
                    var ctx = std.crypto.hash.Sha1.init(.{});
                    ctx.update(bytes[0..checksum_offset]);
                    ctx.final(&computed);

                    if (!std.mem.eql(u8, &computed, &validator.file_checksum_raw)) {
                        validator.appendDiagnostic(
                            checksum_offset,
                            RuleId.mzml_index_checksum,
                            "fileChecksum SHA-1 does not match recomputed value",
                        ) catch {};
                    }
                }
            }
        }
    }

    // --- Private helpers ---

    fn appendDiagnostic(
        validator: *IndexValidator,
        byte_offset: u64,
        rule: []const u8,
        message: []const u8,
    ) std.mem.Allocator.Error!void {
        try validator.diagnostics.append(validator.allocator, .{
            .severity = .@"error",
            .rule = rule,
            .location = .{ .byte_offset = byte_offset },
            .path = validator.path,
            .message = message,
        });
    }
};

// --- Module-level helpers ---

fn attributeValue(attributes: []const Attribute, name: []const u8) ?[]const u8 {
    for (attributes) |a| {
        if (a.name.matches(null, name)) return a.value;
    }
    return null;
}

fn recordContainerOffset(
    validator: *IndexValidator,
    start: StartElement,
    map: *std.StringHashMap(u64),
) !void {
    const id = attributeValue(start.attributes, "id") orelse return;
    const owned = try validator.allocator.dupe(u8, id);
    const result = try map.getOrPut(owned);
    if (result.found_existing) {
        validator.allocator.free(owned);
        return;
    }
    result.key_ptr.* = owned;
    result.value_ptr.* = start.byte_offset;
}

fn decodeHex(hex: []const u8, out: *[20]u8) void {
    if (hex.len < 40) {
        @memset(out, 0);
        return;
    }
    for (0..20) |i| {
        const hi = charToNibble(hex[2 * i]) orelse {
            @memset(out, 0);
            return;
        };
        const lo = charToNibble(hex[2 * i + 1]) orelse {
            @memset(out, 0);
            return;
        };
        out[i] = @as(u8, @intCast(@as(u8, hi) << 4 | lo));
    }
}

fn charToNibble(c: u8) ?u4 {
    return switch (c) {
        '0'...'9' => @as(u4, @intCast(c - '0')),
        'a'...'f' => @as(u4, @intCast(c - 'a' + 10)),
        'A'...'F' => @as(u4, @intCast(c - 'A' + 10)),
        else => null,
    };
}

fn freeHashMap(allocator: std.mem.Allocator, map: *std.StringHashMap(u64)) void {
    var it = map.iterator();
    while (it.next()) |entry| {
        allocator.free(entry.key_ptr.*);
    }
    map.deinit();
}

fn freeIndexEntries(allocator: std.mem.Allocator, entries: *std.ArrayList(IndexEntry)) void {
    for (entries.items) |entry| {
        allocator.free(entry.id_ref);
    }
}

// --- Tests ---

const testing = std.testing;
const expect = testing.expect;
const expectEqual = testing.expectEqual;
const expectEqualStrings = testing.expectEqualStrings;

fn makeText(text: []const u8) Text {
    return .{ .byte_offset = 0, .value = text, .from_cdata = false };
}

fn makeStart(name: []const u8, attrs: []const Attribute, byte_offset: u64) StartElement {
    return .{ .byte_offset = byte_offset, .name = .{ .local_name = name, .namespace_uri = mzml_namespace }, .attributes = attrs, .self_closing = false };
}

fn makeEnd(name: []const u8) EndElement {
    return .{ .byte_offset = 0, .name = .{ .local_name = name, .namespace_uri = mzml_namespace } };
}

fn attr(name: []const u8, value: []const u8) Attribute {
    return .{ .byte_offset = 0, .name = .{ .local_name = name }, .value = value };
}

test "IndexValidator: non-indexed file produces no diagnostics" {
    const allocator = testing.allocator;
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.init(allocator, &diagnostics, null);
    defer v.deinit();

    // Parse a simple non-indexed mzML structure.
    try v.consumeStart(makeStart("mzML", &.{}, 0), 0);
    try v.consumeStart(makeStart("run", &.{attr("id", "run1")}, 10), 1);
    v.consumeEnd(makeEnd("run"), 1);
    v.consumeEnd(makeEnd("mzML"), 0);

    v.finish(null);

    try expectEqual(@as(usize, 0), diagnostics.items.len);
    try expect(!v.isIndexed());
}

test "IndexValidator: records spectrum and chromatogram offsets" {
    const allocator = testing.allocator;
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.init(allocator, &diagnostics, null);
    defer v.deinit();

    try v.consumeStart(makeStart("mzML", &.{}, 0), 0);
    try v.consumeStart(makeStart("run", &.{attr("id", "run1")}, 10), 1);
    try v.consumeStart(makeStart("spectrum", &.{attr("id", "s1")}, 100), 2);
    v.consumeEnd(makeEnd("spectrum"), 2);
    try v.consumeStart(makeStart("chromatogram", &.{attr("id", "c1")}, 200), 2);
    v.consumeEnd(makeEnd("chromatogram"), 2);
    v.consumeEnd(makeEnd("run"), 1);
    v.consumeEnd(makeEnd("mzML"), 0);

    try expectEqual(@as(u64, 100), v.spectrum_offsets.get("s1").?);
    try expectEqual(@as(u64, 200), v.chromatogram_offsets.get("c1").?);
}

test "IndexValidator: valid indexed mzML cross-checks correctly" {
    const allocator = testing.allocator;
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.init(allocator, &diagnostics, null);
    defer v.deinit();

    try v.consumeStart(makeStart("mzML", &.{}, 0), 0);
    try v.consumeStart(makeStart("run", &.{attr("id", "run1")}, 10), 1);
    try v.consumeStart(makeStart("spectrum", &.{attr("id", "s1")}, 100), 2);
    v.consumeEnd(makeEnd("spectrum"), 2);
    try v.consumeStart(makeStart("spectrum", &.{attr("id", "s2")}, 300), 2);
    v.consumeEnd(makeEnd("spectrum"), 2);
    v.consumeEnd(makeEnd("run"), 1);

    // Index list
    try v.consumeStart(makeStart("indexList", &.{attr("count", "1")}, 500), 1);
    try v.consumeStart(makeStart("index", &.{attr("name", "spectrum")}, 510), 2);
    try v.consumeStart(makeStart("offset", &.{attr("idRef", "s1")}, 520), 3);
    try v.consumeText(makeText("100"), 4);
    v.consumeEnd(makeEnd("offset"), 3);
    try v.consumeStart(makeStart("offset", &.{attr("idRef", "s2")}, 540), 3);
    try v.consumeText(makeText("300"), 4);
    v.consumeEnd(makeEnd("offset"), 3);
    v.consumeEnd(makeEnd("index"), 2);
    v.consumeEnd(makeEnd("indexList"), 1);

    v.consumeEnd(makeEnd("mzML"), 0);

    v.finish(null);

    try expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "IndexValidator: bad offset value produces diagnostic" {
    const allocator = testing.allocator;
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.init(allocator, &diagnostics, null);
    defer v.deinit();

    try v.consumeStart(makeStart("mzML", &.{}, 0), 0);
    try v.consumeStart(makeStart("run", &.{attr("id", "run1")}, 10), 1);
    try v.consumeStart(makeStart("spectrum", &.{attr("id", "s1")}, 100), 2);
    v.consumeEnd(makeEnd("spectrum"), 2);
    v.consumeEnd(makeEnd("run"), 1);

    try v.consumeStart(makeStart("indexList", &.{attr("count", "1")}, 500), 1);
    try v.consumeStart(makeStart("index", &.{attr("name", "spectrum")}, 510), 2);
    try v.consumeStart(makeStart("offset", &.{attr("idRef", "s1")}, 520), 3);
    try v.consumeText(makeText("999"), 4);
    v.consumeEnd(makeEnd("offset"), 3);
    v.consumeEnd(makeEnd("index"), 2);
    v.consumeEnd(makeEnd("indexList"), 1);
    v.consumeEnd(makeEnd("mzML"), 0);

    v.finish(null);

    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_index_offset, diagnostics.items[0].rule);
}

test "IndexValidator: reference to non-existent element produces diagnostic" {
    const allocator = testing.allocator;
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.init(allocator, &diagnostics, null);
    defer v.deinit();

    try v.consumeStart(makeStart("mzML", &.{}, 0), 0);
    try v.consumeStart(makeStart("run", &.{attr("id", "run1")}, 10), 1);
    v.consumeEnd(makeEnd("run"), 1);

    try v.consumeStart(makeStart("indexList", &.{attr("count", "1")}, 500), 1);
    try v.consumeStart(makeStart("index", &.{attr("name", "spectrum")}, 510), 2);
    try v.consumeStart(makeStart("offset", &.{attr("idRef", "nonexistent")}, 520), 3);
    try v.consumeText(makeText("100"), 4);
    v.consumeEnd(makeEnd("offset"), 3);
    v.consumeEnd(makeEnd("index"), 2);
    v.consumeEnd(makeEnd("indexList"), 1);
    v.consumeEnd(makeEnd("mzML"), 0);

    v.finish(null);

    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_index_offset, diagnostics.items[0].rule);
}

test "IndexValidator: indexListOffset mismatch produces diagnostic" {
    const allocator = testing.allocator;
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.init(allocator, &diagnostics, null);
    defer v.deinit();

    try v.consumeStart(makeStart("mzML", &.{}, 0), 0);
    try v.consumeStart(makeStart("run", &.{attr("id", "run1")}, 10), 1);
    v.consumeEnd(makeEnd("run"), 1);

    try v.consumeStart(makeStart("indexList", &.{attr("count", "0")}, 500), 1);
    v.consumeEnd(makeEnd("indexList"), 1);

    try v.consumeStart(makeStart("indexListOffset", &.{}, 600), 1);
    try v.consumeText(makeText("999"), 2);
    v.consumeEnd(makeEnd("indexListOffset"), 1);

    v.consumeEnd(makeEnd("mzML"), 0);

    v.finish(null);

    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_index_offset_list, diagnostics.items[0].rule);
}

test "IndexValidator: truncated offset produces diagnostic" {
    const allocator = testing.allocator;
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.init(allocator, &diagnostics, null);
    defer v.deinit();

    try v.consumeStart(makeStart("mzML", &.{}, 0), 0);
    try v.consumeStart(makeStart("run", &.{attr("id", "run1")}, 10), 1);
    try v.consumeStart(makeStart("spectrum", &.{attr("id", "s1")}, 100), 2);
    v.consumeEnd(makeEnd("spectrum"), 2);
    v.consumeEnd(makeEnd("run"), 1);

    try v.consumeStart(makeStart("indexList", &.{attr("count", "1")}, 500), 1);
    try v.consumeStart(makeStart("index", &.{attr("name", "spectrum")}, 510), 2);
    try v.consumeStart(makeStart("offset", &.{attr("idRef", "s1")}, 520), 3);
    try v.consumeText(makeText("999999"), 4);
    v.consumeEnd(makeEnd("offset"), 3);
    v.consumeEnd(makeEnd("index"), 2);
    v.consumeEnd(makeEnd("indexList"), 1);
    v.consumeEnd(makeEnd("mzML"), 0);

    // file_bytes shorter than 999999
    const file_bytes = "<?xml version=\"1.0\"?><mzML>...</mzML>" ++ [_]u8{0} ** 100;
    v.finish(file_bytes);

    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_index_truncated, diagnostics.items[0].rule);
}

test "IndexValidator: SHA-1 checksum mismatch produces diagnostic" {
    const allocator = testing.allocator;
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.init(allocator, &diagnostics, null);
    defer v.deinit();

    const file_content = "<?xml version=\"1.0\"?><mzML>...</mzML>";
    const file_bytes = file_content ++
        "<fileChecksum>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</fileChecksum>";

    try v.consumeStart(makeStart("mzML", &.{}, 0), 0);
    try v.consumeStart(makeStart("run", &.{attr("id", "run1")}, 10), 1);
    v.consumeEnd(makeEnd("run"), 1);

    try v.consumeStart(makeStart("indexList", &.{attr("count", "0")}, 500), 1);
    v.consumeEnd(makeEnd("indexList"), 1);

    try v.consumeStart(makeStart("fileChecksum", &.{}, @intCast(file_content.len)), 1);
    try v.consumeText(makeText("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), 2);
    v.consumeEnd(makeEnd("fileChecksum"), 1);

    v.consumeEnd(makeEnd("mzML"), 0);

    v.finish(file_bytes);

    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_index_checksum, diagnostics.items[0].rule);
}

test "IndexValidator: valid SHA-1 checksum produces no diagnostic" {
    const allocator = testing.allocator;
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.init(allocator, &diagnostics, null);
    defer v.deinit();

    // Content before <fileChecksum>
    const prefix = "<?xml version=\"1.0\"?><mzML><run id=\"r\"></run>";
    // Compute correct SHA-1
    var expected_sha: [20]u8 = undefined;
    {
        var ctx = std.crypto.hash.Sha1.init(.{});
        ctx.update(prefix);
        ctx.final(&expected_sha);
    }
    // Encode as hex
    var hex_buf: [40]u8 = undefined;
    for (0..20) |i| {
        const hi = expected_sha[i] >> 4;
        const lo = expected_sha[i] & 0xf;
        hex_buf[2 * i] = hexChar(@as(u4, @intCast(hi)));
        hex_buf[2 * i + 1] = hexChar(@as(u4, @intCast(lo)));
    }
    const hex_str = hex_buf[0..];

    const file_bytes = prefix ++ "<fileChecksum>" ++ hex_str ++ "</fileChecksum>";

    try v.consumeStart(makeStart("mzML", &.{}, 0), 0);
    try v.consumeStart(makeStart("run", &.{attr("id", "r")}, 10), 1);
    v.consumeEnd(makeEnd("run"), 1);
    try v.consumeStart(makeStart("fileChecksum", &.{}, @intCast(prefix.len)), 1);
    try v.consumeText(makeText(hex_str), 2);
    v.consumeEnd(makeEnd("fileChecksum"), 1);
    v.consumeEnd(makeEnd("mzML"), 0);

    v.finish(file_bytes);

    try expectEqual(@as(usize, 0), diagnostics.items.len);
}

fn hexChar(nibble: u4) u8 {
    return if (nibble < 10) @as(u8, '0') + nibble else @as(u8, 'a') + nibble - 10;
}
