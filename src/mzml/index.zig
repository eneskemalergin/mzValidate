//! Index offset verification and SHA-1 checksum validation.
//!
//! Forward pass records byte offsets of every spectrum and chromatogram,
//! parses `<indexList>` entries, and captures `<indexListOffset>` and
//! `<fileChecksum>`. When `file_bytes` is available, SHA-1 is fed
//! incrementally during parse; `finish()` cross-checks offsets and the
//! digest without rescanning the mmap slice.
//!
//! Tolerates both pwiz offsets (pointing at `<`) and ThermoRawFileParser
//! offsets (pointing at the line start before whitespace).

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

const mzml_namespace = diagnostic.mzml_namespace;

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
    limits: diagnostic.ResourceLimits,

    depth: usize = 0,
    mzml_depth: ?usize = null,

    // Forward-pass: id → byte_offset for every spectrum/chromatogram.
    spectrum_offsets: std.StringHashMap(u64),
    chromatogram_offsets: std.StringHashMap(u64),

    // --- Index list parsing state ---
    index_list_depth: ?usize = null,
    index_list_actual_offset: ?u64 = null,
    index_list_declared_count: ?u64 = null,
    index_list_actual_count: u64 = 0,

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

    // Online SHA-1 over mmap bytes (D.1). Disabled when file_bytes is null.
    sha_file_bytes: ?[]const u8 = null,
    sha_ctx: std.crypto.hash.Sha1 = undefined,
    sha_bytes_hashed: u64 = 0,
    sha_complete: bool = false,
    sha_computed: [20]u8 = undefined,

    /// True after we see any index-related elements.
    pub fn isIndexed(validator: *const IndexValidator) bool {
        return validator.saw_index_elements;
    }

    /// Returns the declared fileChecksum value parsed from `<fileChecksum>`.
    /// Returns null if no fileChecksum was encountered.
    pub fn declaredChecksum(validator: *const IndexValidator) ?[20]u8 {
        if (!validator.file_checksum_ok) return null;
        return validator.file_checksum_raw;
    }

    /// Start incremental SHA-1 over mmap bytes. Call once before the parse loop
    /// when `file_bytes` is available (checkPath / checkSlice).
    pub fn beginOnlineSha(validator: *IndexValidator, bytes: []const u8) void {
        validator.sha_file_bytes = bytes;
        validator.sha_ctx = std.crypto.hash.Sha1.init(.{});
        validator.sha_bytes_hashed = 0;
        validator.sha_complete = false;
    }

    /// Hash raw file bytes through `exclusive_end` (not hashed). Stops at the
    /// `<fileChecksum>` hex boundary once `file_checksum_byte_offset` is set.
    pub fn feedShaExclusive(validator: *IndexValidator, exclusive_end: u64) void {
        if (validator.sha_file_bytes == null or validator.sha_complete) return;
        const bytes = validator.sha_file_bytes.?;
        const cap = validator.file_checksum_byte_offset orelse exclusive_end;
        const end = @min(exclusive_end, cap, bytes.len);
        if (end <= validator.sha_bytes_hashed) {
            if (validator.file_checksum_byte_offset != null and
                validator.sha_bytes_hashed >= cap)
            {
                validator.finalizeOnlineSha();
            }
            return;
        }
        validator.sha_ctx.update(bytes[validator.sha_bytes_hashed..end]);
        validator.sha_bytes_hashed = end;
        if (validator.file_checksum_byte_offset) |checksum_offset| {
            if (validator.sha_bytes_hashed >= checksum_offset) {
                validator.finalizeOnlineSha();
            }
        }
    }

    pub fn init(
        allocator: std.mem.Allocator,
        diagnostics: *std.ArrayList(Diagnostic),
        path: ?[]const u8,
    ) IndexValidator {
        return initWithLimits(allocator, diagnostics, path, .{});
    }

    pub fn initWithLimits(
        allocator: std.mem.Allocator,
        diagnostics: *std.ArrayList(Diagnostic),
        path: ?[]const u8,
        limits: diagnostic.ResourceLimits,
    ) IndexValidator {
        return .{
            .allocator = allocator,
            .diagnostics = diagnostics,
            .path = path,
            .limits = limits,
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
        const tag = start.resolvedId();

        switch (tag) {
            .indexedmzML => return,
            .mzML => {
                if (validator.mzml_depth == null or element_depth < validator.mzml_depth.?) {
                    validator.mzml_depth = element_depth;
                }
                return;
            },
            else => {},
        }

        if (validator.mzml_depth == null) return;
        if (element_depth < validator.mzml_depth.?) return;

        switch (tag) {
            .spectrum => try recordContainerOffset(validator, start, &validator.spectrum_offsets),
            .spectrumList => {
                const count_attr = start.attr("count");
                if (count_attr) |c| {
                    if (std.fmt.parseUnsigned(u64, c, 10)) |count| {
                        const bounded = try validator.boundedCount(count, start.byte_offset, "spectrumList count exceeds the configured index-entry limit");
                        try validator.spectrum_offsets.ensureTotalCapacity(bounded);
                    } else |_| {}
                }
            },
            .chromatogram => try recordContainerOffset(validator, start, &validator.chromatogram_offsets),
            .chromatogramList => {
                const count_attr = start.attr("count");
                if (count_attr) |c| {
                    if (std.fmt.parseUnsigned(u64, c, 10)) |count| {
                        const bounded = try validator.boundedCount(count, start.byte_offset, "chromatogramList count exceeds the configured index-entry limit");
                        try validator.chromatogram_offsets.ensureTotalCapacity(bounded);
                    } else |_| {}
                }
            },
            .indexList => {
                validator.index_list_depth = element_depth;
                validator.index_list_actual_offset = start.byte_offset;
                validator.saw_index_elements = true;
                const count_attr = start.attr("count");
                validator.index_list_declared_count = if (count_attr) |c|
                    if (std.fmt.parseUnsigned(u64, c, 10)) |count| blk: {
                        _ = try validator.boundedCount(count, start.byte_offset, "indexList count exceeds the configured index-entry limit");
                        break :blk count;
                    } else |_| null
                else
                    null;
            },
            .index => {
                if (validator.index_list_depth == null) return;
                const child_depth = std.math.add(usize, validator.index_list_depth.?, 1) catch {
                    try validator.limitDiagnostic(start.byte_offset, "index nesting depth arithmetic overflow");
                    return error.ResourceLimitExceeded;
                };
                if (element_depth != child_depth) return;
                const next_count = std.math.add(u64, validator.index_list_actual_count, 1) catch {
                    try validator.limitDiagnostic(start.byte_offset, "index element count arithmetic overflow");
                    return error.ResourceLimitExceeded;
                };
                _ = try validator.boundedCount(next_count, start.byte_offset, "index element count exceeds the configured index-entry limit");
                validator.index_list_actual_count = next_count;
                const name = start.attr("name") orelse {
                    try validator.appendDiagnostic(start.byte_offset, RuleId.mzml_index_offset_list, "index element is missing required attribute name");
                    return;
                };
                validator.current_index_kind = if (std.mem.eql(u8, name, "spectrum"))
                    IndexKind.spectrum
                else if (std.mem.eql(u8, name, "chromatogram"))
                    IndexKind.chromatogram
                else blk: {
                    try validator.appendDiagnostic(start.byte_offset, RuleId.mzml_index_offset_list, "index name must be \"spectrum\" or \"chromatogram\"");
                    break :blk null;
                };
            },
            .offset => {
                if (validator.current_index_kind == null) return;
                const id_ref = start.attr("idRef") orelse {
                    try validator.appendDiagnostic(start.byte_offset, RuleId.mzml_index_offset, "offset element is missing required attribute idRef");
                    return;
                };
                if (validator.offset_id_ref_owned) |owned| validator.allocator.free(owned);
                if (id_ref.len > validator.limits.max_index_id_ref_bytes) {
                    try validator.limitDiagnostic(start.byte_offset, "index idRef exceeds the configured field limit");
                    return error.ResourceLimitExceeded;
                }
                validator.offset_id_ref_owned = try validator.allocator.dupe(u8, id_ref);
                validator.text_buf.clearRetainingCapacity();
            },
            .indexListOffset => {
                validator.index_list_offset_byte_offset = start.byte_offset;
                validator.index_list_offset_depth = element_depth;
                validator.text_buf.clearRetainingCapacity();
            },
            .fileChecksum => {
                validator.file_checksum_depth = element_depth;
                const checksum_offset = std.math.add(u64, start.byte_offset, "<fileChecksum>".len) catch {
                    try validator.limitDiagnostic(start.byte_offset, "fileChecksum offset arithmetic overflow");
                    return error.ResourceLimitExceeded;
                };
                validator.file_checksum_byte_offset = checksum_offset;
                validator.feedShaExclusive(checksum_offset);
                validator.text_buf.clearRetainingCapacity();
            },
            else => {},
        }
    }

    pub fn consumeEnd(
        validator: *IndexValidator,
        end: EndElement,
        element_depth: usize,
    ) !void {
        if (validator.mzml_depth == null) return;
        if (element_depth < validator.mzml_depth.?) return;

        const tag = end.resolvedId();

        switch (tag) {
            .offset => {
                if (validator.current_index_kind == null or validator.offset_id_ref_owned == null) return;
                const id_ref_owned = validator.offset_id_ref_owned.?;
                validator.offset_id_ref_owned = null;
                const offset = std.fmt.parseUnsigned(u64, validator.text_buf.items, 10) catch {
                    validator.allocator.free(id_ref_owned);
                    return;
                };
                if (validator.index_entries.items.len >= validator.maxIndexEntries()) {
                    validator.allocator.free(id_ref_owned);
                    try validator.limitDiagnostic(end.byte_offset, "index entry count exceeds the configured index-entry limit");
                    return error.ResourceLimitExceeded;
                }
                errdefer validator.allocator.free(id_ref_owned);
                try validator.index_entries.append(validator.allocator, .{ .id_ref = id_ref_owned, .offset = offset });
            },
            .index => validator.current_index_kind = null,
            .indexList => {
                validator.index_list_depth = null;
                validator.index_list_offset_value = null;
            },
            .indexListOffset => {
                const parsed = std.fmt.parseUnsigned(u64, validator.text_buf.items, 10);
                validator.index_list_offset_value = parsed catch |err| blk: {
                    if (err == error.InvalidCharacter) {
                        validator.appendDiagnostic(
                            validator.index_list_offset_byte_offset orelse 0,
                            RuleId.mzml_index_offset_list,
                            "indexListOffset value is not a valid integer",
                        ) catch |append_err| return append_err;
                    }
                    break :blk null;
                };
                validator.index_list_offset_depth = null;
            },
            .fileChecksum => {
                const raw = validator.text_buf.items;
                const hex = std.mem.trim(u8, raw, " \t\r\n");
                if (hex.len != 40 or !isHexString(hex)) {
                    validator.appendDiagnostic(
                        validator.file_checksum_byte_offset orelse 0,
                        RuleId.mzml_index_checksum,
                        "fileChecksum must be a 40-character hexadecimal string",
                    ) catch |append_err| return append_err;
                } else {
                    decodeHex(hex, &validator.file_checksum_raw);
                    validator.file_checksum_ok = true;
                }
                validator.file_checksum_depth = null;
            },
            else => {},
        }
    }

    pub fn consumeText(validator: *IndexValidator, text: Text) !void {
        if (!validator.wantsText()) return;
        const limit = if (validator.offset_id_ref_owned != null)
            validator.limits.max_index_offset_text_bytes
        else if (validator.index_list_offset_depth != null)
            validator.limits.max_index_list_offset_text_bytes
        else
            validator.limits.max_file_checksum_text_bytes;
        if (validator.text_buf.items.len > limit or text.value.len > limit - validator.text_buf.items.len) {
            const message = if (validator.offset_id_ref_owned != null)
                "index offset text exceeds the configured field limit"
            else if (validator.index_list_offset_depth != null)
                "indexListOffset text exceeds the configured field limit"
            else
                "fileChecksum text exceeds the configured field limit";
            try validator.limitDiagnostic(text.byte_offset, message);
            return error.ResourceLimitExceeded;
        }
        try validator.text_buf.appendSlice(validator.allocator, text.value);
    }

    /// True when accumulating offset, indexListOffset, or fileChecksum text.
    pub fn wantsText(validator: *const IndexValidator) bool {
        if (validator.mzml_depth == null) return false;
        return validator.offset_id_ref_owned != null or
            validator.index_list_offset_depth != null or
            validator.file_checksum_depth != null;
    }

    /// After the document is fully parsed, cross-check all collected data.
    /// `file_bytes` is the complete mmap'd file content (or null if unavailable).
    /// When null, SHA-1 verification and truncation checks are skipped.
    pub fn finish(
        validator: *IndexValidator,
        file_bytes: ?[]const u8,
    ) !void {
        if (!validator.saw_index_elements) return;

        if (file_bytes == null) {
            try validator.diagnostics.append(validator.allocator, .{
                .severity = .info,
                .rule = RuleId.mzml_index_checksum,
                .location = .{ .byte_offset = 0 },
                .path = validator.path,
                .message = "file bytes unavailable; SHA-1 and truncation checks skipped",
            });
        }

        // Verify indexList declared count matches actual children.
        if (validator.index_list_declared_count) |declared| {
            if (declared != validator.index_list_actual_count) {
                try validator.appendDiagnostic(
                    validator.index_list_actual_offset orelse 0,
                    RuleId.mzml_index_offset_list,
                    "indexList count does not match actual index elements",
                );
            }
        }

        // --- indexListOffset verification ---
        if (validator.index_list_offset_value) |declared| {
            if (validator.index_list_actual_offset) |actual| {
                if (declared != actual) {
                    // Accept offset pointing to whitespace before element
                    // (e.g. ThermoRawFileParser writes line-start offsets).
                    if (!offsetsMatchWithWhitespace(file_bytes, declared, actual)) {
                        try validator.appendDiagnostic(
                            validator.index_list_offset_byte_offset orelse validator.index_list_actual_offset orelse 0,
                            RuleId.mzml_index_offset_list,
                            "declared indexListOffset does not match actual position of indexList",
                        );
                    }
                }
            }
        }

        // --- Cross-check each index entry ---
        var prev_offset: ?u64 = null;
        var seen_ids = std.StringHashMap(void).init(validator.allocator);
        defer seen_ids.deinit();
        for (validator.index_entries.items) |entry| {
            // Check for duplicate idRef in index.
            if (seen_ids.contains(entry.id_ref)) {
                try validator.appendDiagnostic(
                    entry.offset,
                    RuleId.mzml_index_offset,
                    "duplicate idRef in index",
                );
            } else {
                try seen_ids.put(entry.id_ref, {});
            }

            // Check monotonic ordering.
            if (prev_offset) |prev| {
                if (entry.offset < prev) {
                    try validator.appendDiagnostic(
                        entry.offset,
                        RuleId.mzml_index_offset,
                        "index offsets are not monotonically increasing",
                    );
                }
            }
            prev_offset = entry.offset;

            // Check truncation (offset past EOF).
            if (file_bytes) |bytes| {
                if (entry.offset >= bytes.len) {
                    try validator.appendDiagnostic(
                        entry.offset,
                        RuleId.mzml_index_truncated,
                        "index offset points past end of file",
                    );
                    continue;
                }
            }

            // Look up the idRef in both maps.
            const recorded_offset = validator.spectrum_offsets.get(entry.id_ref) orelse
                validator.chromatogram_offsets.get(entry.id_ref) orelse
                {
                    try validator.appendDiagnostic(
                        entry.offset,
                        RuleId.mzml_index_offset,
                        "index references non-existent spectrum or chromatogram",
                    );
                    continue;
                };

            if (entry.offset != recorded_offset) {
                // Accept offset pointing to whitespace before the element
                // (ThermoRawFileParser convention: line-start offset).
                if (!offsetsMatchWithWhitespace(file_bytes, entry.offset, recorded_offset)) {
                    try validator.appendDiagnostic(
                        entry.offset,
                        RuleId.mzml_index_offset,
                        "index offset does not match actual byte position",
                    );
                }
            }
        }

        // --- SHA-1 checksum verification ---
        if (file_bytes) |bytes| {
            if (validator.file_checksum_ok) {
                if (validator.file_checksum_byte_offset) |checksum_offset| {
                    if (checksum_offset > bytes.len) {
                        try validator.appendDiagnostic(
                            checksum_offset,
                            RuleId.mzml_index_checksum,
                            "fileChecksum offset exceeds file size",
                        );
                        return;
                    }
                    if (validator.sha_file_bytes != null and !validator.sha_complete) {
                        validator.feedShaExclusive(checksum_offset);
                    }
                    const computed = if (validator.sha_complete)
                        validator.sha_computed
                    else
                        computeChecksumBatch(bytes, checksum_offset);

                    if (!std.mem.eql(u8, &computed, &validator.file_checksum_raw)) {
                        try validator.appendDiagnostic(
                            checksum_offset,
                            RuleId.mzml_index_checksum,
                            "fileChecksum SHA-1 does not match recomputed value",
                        );
                    }
                }
            }
        }
    }

    // --- Private helpers ---

    fn maxIndexEntries(validator: *const IndexValidator) usize {
        if (validator.sha_file_bytes) |bytes| return @min(validator.limits.max_index_entries, bytes.len);
        return validator.limits.max_index_entries;
    }

    fn boundedCount(validator: *IndexValidator, count: u64, byte_offset: u64, message: []const u8) !u32 {
        const bounded = std.math.cast(usize, count) orelse {
            try validator.limitDiagnostic(byte_offset, message);
            return error.ResourceLimitExceeded;
        };
        if (bounded > validator.maxIndexEntries()) {
            try validator.limitDiagnostic(byte_offset, message);
            return error.ResourceLimitExceeded;
        }
        return std.math.cast(u32, bounded) orelse {
            try validator.limitDiagnostic(byte_offset, message);
            return error.ResourceLimitExceeded;
        };
    }

    fn limitDiagnostic(validator: *IndexValidator, byte_offset: u64, message: []const u8) !void {
        try validator.appendDiagnostic(byte_offset, RuleId.mzml_index_offset_list, message);
    }

    fn finalizeOnlineSha(validator: *IndexValidator) void {
        if (validator.sha_complete) return;
        var out: [20]u8 = undefined;
        validator.sha_ctx.final(&out);
        validator.sha_computed = out;
        validator.sha_complete = true;
    }

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

fn recordContainerOffset(
    validator: *IndexValidator,
    start: StartElement,
    map: *std.StringHashMap(u64),
) !void {
    const id = start.attr("id") orelse return;
    if (map.contains(id)) return;
    if (id.len > validator.limits.max_index_id_ref_bytes) {
        try validator.limitDiagnostic(start.byte_offset, "indexable element id exceeds the configured field limit");
        return error.ResourceLimitExceeded;
    }
    if (map.count() >= validator.maxIndexEntries()) {
        try validator.limitDiagnostic(start.byte_offset, "indexable element count exceeds the configured index-entry limit");
        return error.ResourceLimitExceeded;
    }
    const owned = try validator.allocator.dupe(u8, id);
    errdefer validator.allocator.free(owned);
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

fn isHexString(s: []const u8) bool {
    for (s) |c| {
        if (charToNibble(c) == null) return false;
    }
    return true;
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

fn computeChecksumBatch(bytes: []const u8, checksum_offset: u64) [20]u8 {
    var computed: [20]u8 = undefined;
    var ctx = std.crypto.hash.Sha1.init(.{});
    ctx.update(bytes[0..checksum_offset]);
    ctx.final(&computed);
    return computed;
}

// ThermoRawFileParser writes line-start offsets instead of element-start
// offsets. Accept `declared` before `actual` when the gap is all whitespace.
// Falls back to exact match when file_bytes is unavailable.
fn offsetsMatchWithWhitespace(file_bytes: ?[]const u8, declared: u64, actual: u64) bool {
    if (declared == actual) return true;
    if (declared > actual) return false;
    const bytes = file_bytes orelse return false;
    if (actual > bytes.len) return false;
    for (bytes[declared..actual]) |b| {
        switch (b) {
            ' ', '\t', '\n', '\r' => {},
            else => return false,
        }
    }
    return true;
}

// --- Unit tests ---

const test_events = @import("test_events.zig");
const testing = std.testing;
const expect = testing.expect;
const expectEqual = testing.expectEqual;
const expectEqualStrings = testing.expectEqualStrings;
const expectError = testing.expectError;

test "IndexValidator: non-indexed file produces no diagnostics" {
    const allocator = testing.allocator;
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.init(allocator, &diagnostics, null);
    defer v.deinit();

    // Parse a simple non-indexed mzML structure.
    try v.consumeStart(test_events.startUnknown("mzML", &.{}, 0), 0);
    try v.consumeStart(test_events.startUnknown("run", &.{test_events.attr("id", "run1")}, 10), 1);
    try v.consumeEnd(test_events.endUnknown("run"), 1);
    try v.consumeEnd(test_events.endUnknown("mzML"), 0);

    try v.finish(null);

    try expectEqual(@as(usize, 0), diagnostics.items.len);
    try expect(!v.isIndexed());
}

test "IndexValidator: records spectrum and chromatogram offsets" {
    const allocator = testing.allocator;
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.init(allocator, &diagnostics, null);
    defer v.deinit();

    try v.consumeStart(test_events.startUnknown("mzML", &.{}, 0), 0);
    try v.consumeStart(test_events.startUnknown("run", &.{test_events.attr("id", "run1")}, 10), 1);
    try v.consumeStart(test_events.startUnknown("spectrum", &.{test_events.attr("id", "s1")}, 100), 2);
    try v.consumeEnd(test_events.endUnknown("spectrum"), 2);
    try v.consumeStart(test_events.startUnknown("chromatogram", &.{test_events.attr("id", "c1")}, 200), 2);
    try v.consumeEnd(test_events.endUnknown("chromatogram"), 2);
    try v.consumeEnd(test_events.endUnknown("run"), 1);
    try v.consumeEnd(test_events.endUnknown("mzML"), 0);

    try expectEqual(@as(u64, 100), v.spectrum_offsets.get("s1").?);
    try expectEqual(@as(u64, 200), v.chromatogram_offsets.get("c1").?);
}

test "IndexValidator: finish propagates diagnostic allocation failure" {
    var failing_allocator = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(testing.allocator);

    var v = IndexValidator.init(failing_allocator.allocator(), &diagnostics, null);
    defer v.deinit();
    v.saw_index_elements = true;

    try expectError(error.OutOfMemory, v.finish(null));
}

test "IndexValidator: spectrum with unknown intern id still records offsets" {
    const allocator = testing.allocator;
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.init(allocator, &diagnostics, null);
    defer v.deinit();

    try v.consumeStart(test_events.startUnknown("mzML", &.{}, 0), 0);
    try v.consumeStart(test_events.startUnknown("run", &.{test_events.attr("id", "run1")}, 10), 1);
    var spectrum = test_events.startUnknown("spectrum", &.{test_events.attr("id", "s1")}, 100);
    spectrum.element_id = .unknown;
    try v.consumeStart(spectrum, 2);
    try v.consumeEnd(test_events.endUnknown("spectrum"), 2);
    try v.consumeEnd(test_events.endUnknown("run"), 1);
    try v.consumeEnd(test_events.endUnknown("mzML"), 0);

    try expectEqual(@as(u64, 100), v.spectrum_offsets.get("s1").?);
}

test "IndexValidator: valid indexed mzML cross-checks correctly" {
    const allocator = testing.allocator;
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.init(allocator, &diagnostics, null);
    defer v.deinit();

    try v.consumeStart(test_events.startUnknown("mzML", &.{}, 0), 0);
    try v.consumeStart(test_events.startUnknown("run", &.{test_events.attr("id", "run1")}, 10), 1);
    try v.consumeStart(test_events.startUnknown("spectrum", &.{test_events.attr("id", "s1")}, 100), 2);
    try v.consumeEnd(test_events.endUnknown("spectrum"), 2);
    try v.consumeStart(test_events.startUnknown("spectrum", &.{test_events.attr("id", "s2")}, 300), 2);
    try v.consumeEnd(test_events.endUnknown("spectrum"), 2);
    try v.consumeEnd(test_events.endUnknown("run"), 1);

    // Index list
    try v.consumeStart(test_events.startUnknown("indexList", &.{test_events.attr("count", "1")}, 500), 1);
    try v.consumeStart(test_events.startUnknown("index", &.{test_events.attr("name", "spectrum")}, 510), 2);
    try v.consumeStart(test_events.startUnknown("offset", &.{test_events.attr("idRef", "s1")}, 520), 3);
    try v.consumeText(test_events.text("100"));
    try v.consumeEnd(test_events.endUnknown("offset"), 3);
    try v.consumeStart(test_events.startUnknown("offset", &.{test_events.attr("idRef", "s2")}, 540), 3);
    try v.consumeText(test_events.text("300"));
    try v.consumeEnd(test_events.endUnknown("offset"), 3);
    try v.consumeEnd(test_events.endUnknown("index"), 2);
    try v.consumeEnd(test_events.endUnknown("indexList"), 1);

    try v.consumeEnd(test_events.endUnknown("mzML"), 0);

    try v.finish(null);

    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_index_checksum, diagnostics.items[0].rule);
}

test "IndexValidator: bad offset value produces diagnostic" {
    const allocator = testing.allocator;
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.init(allocator, &diagnostics, null);
    defer v.deinit();

    try v.consumeStart(test_events.startUnknown("mzML", &.{}, 0), 0);
    try v.consumeStart(test_events.startUnknown("run", &.{test_events.attr("id", "run1")}, 10), 1);
    try v.consumeStart(test_events.startUnknown("spectrum", &.{test_events.attr("id", "s1")}, 100), 2);
    try v.consumeEnd(test_events.endUnknown("spectrum"), 2);
    try v.consumeEnd(test_events.endUnknown("run"), 1);

    try v.consumeStart(test_events.startUnknown("indexList", &.{test_events.attr("count", "1")}, 500), 1);
    try v.consumeStart(test_events.startUnknown("index", &.{test_events.attr("name", "spectrum")}, 510), 2);
    try v.consumeStart(test_events.startUnknown("offset", &.{test_events.attr("idRef", "s1")}, 520), 3);
    try v.consumeText(test_events.text("999"));
    try v.consumeEnd(test_events.endUnknown("offset"), 3);
    try v.consumeEnd(test_events.endUnknown("index"), 2);
    try v.consumeEnd(test_events.endUnknown("indexList"), 1);
    try v.consumeEnd(test_events.endUnknown("mzML"), 0);

    try v.finish(null);

    try expectEqual(@as(usize, 2), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_index_checksum, diagnostics.items[0].rule);
    try expectEqualStrings(RuleId.mzml_index_offset, diagnostics.items[1].rule);
}

test "IndexValidator: reference to non-existent element produces diagnostic" {
    const allocator = testing.allocator;
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.init(allocator, &diagnostics, null);
    defer v.deinit();

    try v.consumeStart(test_events.startUnknown("mzML", &.{}, 0), 0);
    try v.consumeStart(test_events.startUnknown("run", &.{test_events.attr("id", "run1")}, 10), 1);
    try v.consumeEnd(test_events.endUnknown("run"), 1);

    try v.consumeStart(test_events.startUnknown("indexList", &.{test_events.attr("count", "1")}, 500), 1);
    try v.consumeStart(test_events.startUnknown("index", &.{test_events.attr("name", "spectrum")}, 510), 2);
    try v.consumeStart(test_events.startUnknown("offset", &.{test_events.attr("idRef", "nonexistent")}, 520), 3);
    try v.consumeText(test_events.text("100"));
    try v.consumeEnd(test_events.endUnknown("offset"), 3);
    try v.consumeEnd(test_events.endUnknown("index"), 2);
    try v.consumeEnd(test_events.endUnknown("indexList"), 1);
    try v.consumeEnd(test_events.endUnknown("mzML"), 0);

    try v.finish(null);

    try expectEqual(@as(usize, 2), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_index_checksum, diagnostics.items[0].rule);
    try expectEqualStrings(RuleId.mzml_index_offset, diagnostics.items[1].rule);
}

test "IndexValidator: indexListOffset mismatch produces diagnostic" {
    const allocator = testing.allocator;
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.init(allocator, &diagnostics, null);
    defer v.deinit();

    try v.consumeStart(test_events.startUnknown("mzML", &.{}, 0), 0);
    try v.consumeStart(test_events.startUnknown("run", &.{test_events.attr("id", "run1")}, 10), 1);
    try v.consumeEnd(test_events.endUnknown("run"), 1);

    try v.consumeStart(test_events.startUnknown("indexList", &.{test_events.attr("count", "0")}, 500), 1);
    try v.consumeEnd(test_events.endUnknown("indexList"), 1);

    try v.consumeStart(test_events.startUnknown("indexListOffset", &.{}, 600), 1);
    try v.consumeText(test_events.text("999"));
    try v.consumeEnd(test_events.endUnknown("indexListOffset"), 1);

    try v.consumeEnd(test_events.endUnknown("mzML"), 0);

    try v.finish(null);

    try expectEqual(@as(usize, 2), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_index_checksum, diagnostics.items[0].rule);
    try expectEqualStrings(RuleId.mzml_index_offset_list, diagnostics.items[1].rule);
}

test "IndexValidator: truncated offset produces diagnostic" {
    const allocator = testing.allocator;
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.init(allocator, &diagnostics, null);
    defer v.deinit();

    try v.consumeStart(test_events.startUnknown("mzML", &.{}, 0), 0);
    try v.consumeStart(test_events.startUnknown("run", &.{test_events.attr("id", "run1")}, 10), 1);
    try v.consumeStart(test_events.startUnknown("spectrum", &.{test_events.attr("id", "s1")}, 100), 2);
    try v.consumeEnd(test_events.endUnknown("spectrum"), 2);
    try v.consumeEnd(test_events.endUnknown("run"), 1);

    try v.consumeStart(test_events.startUnknown("indexList", &.{test_events.attr("count", "1")}, 500), 1);
    try v.consumeStart(test_events.startUnknown("index", &.{test_events.attr("name", "spectrum")}, 510), 2);
    try v.consumeStart(test_events.startUnknown("offset", &.{test_events.attr("idRef", "s1")}, 520), 3);
    try v.consumeText(test_events.text("999999"));
    try v.consumeEnd(test_events.endUnknown("offset"), 3);
    try v.consumeEnd(test_events.endUnknown("index"), 2);
    try v.consumeEnd(test_events.endUnknown("indexList"), 1);
    try v.consumeEnd(test_events.endUnknown("mzML"), 0);

    // file_bytes shorter than 999999
    const file_bytes = "<?xml version=\"1.0\"?><mzML>...</mzML>" ++ [_]u8{0} ** 100;
    try v.finish(file_bytes);

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

    try v.consumeStart(test_events.startUnknown("mzML", &.{}, 0), 0);
    try v.consumeStart(test_events.startUnknown("run", &.{test_events.attr("id", "run1")}, 10), 1);
    try v.consumeEnd(test_events.endUnknown("run"), 1);

    try v.consumeStart(test_events.startUnknown("indexList", &.{test_events.attr("count", "0")}, 500), 1);
    try v.consumeEnd(test_events.endUnknown("indexList"), 1);

    try v.consumeStart(test_events.startUnknown("fileChecksum", &.{}, @intCast(file_content.len)), 1);
    try v.consumeText(test_events.text("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    try v.consumeEnd(test_events.endUnknown("fileChecksum"), 1);

    try v.consumeEnd(test_events.endUnknown("mzML"), 0);

    try v.finish(file_bytes);

    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_index_checksum, diagnostics.items[0].rule);
}

test "IndexValidator: valid SHA-1 checksum produces no diagnostic" {
    const allocator = testing.allocator;
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.init(allocator, &diagnostics, null);
    defer v.deinit();

    const prefix = "<?xml version=\"1.0\"?><mzML><run id=\"r\"></run>";
    const checksum_offset = prefix.len + "<fileChecksum>".len;
    var expected_sha: [20]u8 = undefined;
    {
        var ctx = std.crypto.hash.Sha1.init(.{});
        ctx.update(prefix);
        ctx.update("<fileChecksum>");
        ctx.final(&expected_sha);
    }
    var hex_buf: [40]u8 = undefined;
    for (0..20) |i| {
        const hi = expected_sha[i] >> 4;
        const lo = expected_sha[i] & 0xf;
        hex_buf[2 * i] = hexChar(@as(u4, @intCast(hi)));
        hex_buf[2 * i + 1] = hexChar(@as(u4, @intCast(lo)));
    }
    const hex_str = hex_buf[0..];

    const file_bytes = prefix ++ "<fileChecksum>" ++ hex_str ++ "</fileChecksum>";

    v.beginOnlineSha(file_bytes);
    v.feedShaExclusive(prefix.len);
    try v.consumeStart(test_events.startUnknown("mzML", &.{}, 0), 0);
    try v.consumeStart(test_events.startUnknown("run", &.{test_events.attr("id", "r")}, 10), 1);
    try v.consumeEnd(test_events.endUnknown("run"), 1);
    try v.consumeStart(test_events.startUnknown("indexList", &.{test_events.attr("count", "0")}, 500), 1);
    try v.consumeEnd(test_events.endUnknown("indexList"), 1);
    try v.consumeStart(test_events.startUnknown("fileChecksum", &.{}, @intCast(prefix.len)), 1);
    try v.consumeText(test_events.text(hex_str));
    try v.consumeEnd(test_events.endUnknown("fileChecksum"), 1);
    try v.consumeEnd(test_events.endUnknown("mzML"), 0);
    v.feedShaExclusive(checksum_offset);

    try v.finish(file_bytes);

    try expectEqual(@as(usize, 0), diagnostics.items.len);
    try expect(v.sha_complete);
}

test "IndexValidator: online SHA matches batch hash at checksum boundary" {
    const prefix = "<?xml version=\"1.0\"?><mzML><run id=\"r\"></run>";
    const file_bytes = prefix ++ "<fileChecksum>deadbeef" ++ "</fileChecksum>";
    const checksum_offset = prefix.len + "<fileChecksum>".len;

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(testing.allocator);

    var v = IndexValidator.init(testing.allocator, &diagnostics, null);
    defer v.deinit();

    v.beginOnlineSha(file_bytes);
    v.feedShaExclusive(prefix.len / 2);
    v.feedShaExclusive(prefix.len);
    try v.consumeStart(test_events.startUnknown("mzML", &.{}, 0), 0);
    try v.consumeStart(test_events.startUnknown("indexList", &.{test_events.attr("count", "0")}, 100), 1);
    try v.consumeEnd(test_events.endUnknown("indexList"), 1);
    try v.consumeStart(test_events.startUnknown("fileChecksum", &.{}, @intCast(prefix.len)), 1);

    const batch = computeChecksumBatch(file_bytes, checksum_offset);
    try expect(v.sha_complete);
    try testing.expectEqualSlices(u8, &batch, &v.sha_computed);
}

test "IndexValidator: fileChecksum with surrounding whitespace passes validation" {
    const allocator = testing.allocator;
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.init(allocator, &diagnostics, null);
    defer v.deinit();

    const prefix = "<?xml version=\"1.0\"?><mzML><run id=\"r\"></run>";
    var expected_sha: [20]u8 = undefined;
    {
        var ctx = std.crypto.hash.Sha1.init(.{});
        ctx.update(prefix);
        ctx.update("<fileChecksum>");
        ctx.final(&expected_sha);
    }
    var hex_buf: [40]u8 = undefined;
    for (0..20) |i| {
        const hi = expected_sha[i] >> 4;
        const lo = expected_sha[i] & 0xf;
        hex_buf[2 * i] = hexChar(@as(u4, @intCast(hi)));
        hex_buf[2 * i + 1] = hexChar(@as(u4, @intCast(lo)));
    }
    const hex_str = hex_buf[0..];

    // fileChecksum with leading and trailing whitespace (valid XML).
    const file_bytes = prefix ++ "<fileChecksum>\n  " ++ hex_str ++ "\n</fileChecksum>";

    try v.consumeStart(test_events.startUnknown("mzML", &.{}, 0), 0);
    try v.consumeStart(test_events.startUnknown("run", &.{test_events.attr("id", "r")}, 10), 1);
    try v.consumeEnd(test_events.endUnknown("run"), 1);
    try v.consumeStart(test_events.startUnknown("indexList", &.{test_events.attr("count", "0")}, 500), 1);
    try v.consumeEnd(test_events.endUnknown("indexList"), 1);
    try v.consumeStart(test_events.startUnknown("fileChecksum", &.{}, @intCast(prefix.len)), 1);
    try v.consumeText(test_events.text("\n  "));
    try v.consumeText(test_events.text(hex_str));
    try v.consumeText(test_events.text("\n"));
    try v.consumeEnd(test_events.endUnknown("fileChecksum"), 1);
    try v.consumeEnd(test_events.endUnknown("mzML"), 0);

    try v.finish(file_bytes);

    try expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "IndexValidator: duplicate index entries produce diagnostic" {
    const allocator = testing.allocator;
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.init(allocator, &diagnostics, null);
    defer v.deinit();

    try v.consumeStart(test_events.startUnknown("mzML", &.{}, 0), 0);
    try v.consumeStart(test_events.startUnknown("run", &.{test_events.attr("id", "run1")}, 10), 1);
    try v.consumeStart(test_events.startUnknown("spectrum", &.{test_events.attr("id", "s1")}, 100), 2);
    try v.consumeEnd(test_events.endUnknown("spectrum"), 2);
    try v.consumeEnd(test_events.endUnknown("run"), 1);

    // index with duplicate entries for s1
    try v.consumeStart(test_events.startUnknown("indexList", &.{test_events.attr("count", "1")}, 500), 1);
    try v.consumeStart(test_events.startUnknown("index", &.{test_events.attr("name", "spectrum")}, 510), 2);
    try v.consumeStart(test_events.startUnknown("offset", &.{test_events.attr("idRef", "s1")}, 520), 3);
    try v.consumeText(test_events.text("100"));
    try v.consumeEnd(test_events.endUnknown("offset"), 3);
    try v.consumeStart(test_events.startUnknown("offset", &.{test_events.attr("idRef", "s1")}, 540), 3);
    try v.consumeText(test_events.text("100"));
    try v.consumeEnd(test_events.endUnknown("offset"), 3);
    try v.consumeEnd(test_events.endUnknown("index"), 2);
    try v.consumeEnd(test_events.endUnknown("indexList"), 1);
    try v.consumeEnd(test_events.endUnknown("mzML"), 0);

    try v.finish(null);

    try expectEqual(@as(usize, 2), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_index_checksum, diagnostics.items[0].rule);
    try expectEqualStrings(RuleId.mzml_index_offset, diagnostics.items[1].rule);
}

test "IndexValidator: count limit rejects before reservation" {
    const allocator = testing.allocator;
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.initWithLimits(allocator, &diagnostics, null, .{ .max_index_entries = 1 });
    defer v.deinit();

    try v.consumeStart(test_events.startUnknown("mzML", &.{}, 0), 0);
    try expectError(
        error.ResourceLimitExceeded,
        v.consumeStart(test_events.startUnknown("spectrumList", &.{test_events.attr("count", "18446744073709551615")}, 10), 1),
    );

    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_index_offset_list, diagnostics.items[0].rule);
}

test "IndexValidator: count boundaries stay within the configured limit" {
    const allocator = testing.allocator;
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.initWithLimits(allocator, &diagnostics, null, .{ .max_index_entries = 4 });
    defer v.deinit();

    try expectEqual(@as(u32, 0), try v.boundedCount(0, 0, "count exceeds limit"));
    try expectEqual(@as(u32, 1), try v.boundedCount(1, 0, "count exceeds limit"));
    try expectEqual(@as(u32, 4), try v.boundedCount(4, 0, "count exceeds limit"));
    try expectError(error.ResourceLimitExceeded, v.boundedCount(5, 0, "count exceeds limit"));
    try expectError(error.ResourceLimitExceeded, v.boundedCount(std.math.maxInt(u64), 0, "count exceeds limit"));

    try expectEqual(@as(usize, 2), diagnostics.items.len);
}

test "IndexValidator: scalar text limit rejects before buffer growth" {
    const allocator = testing.allocator;
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.initWithLimits(allocator, &diagnostics, null, .{ .max_index_offset_text_bytes = 4 });
    defer v.deinit();

    try v.consumeStart(test_events.startUnknown("mzML", &.{}, 0), 0);
    try v.consumeStart(test_events.startUnknown("indexList", &.{test_events.attr("count", "1")}, 1), 1);
    try v.consumeStart(test_events.startUnknown("index", &.{test_events.attr("name", "spectrum")}, 2), 2);
    try v.consumeStart(test_events.startUnknown("offset", &.{test_events.attr("idRef", "s1")}, 3), 3);
    try expectError(error.ResourceLimitExceeded, v.consumeText(test_events.text("12345")));

    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_index_offset_list, diagnostics.items[0].rule);
}

test "IndexValidator: index scalar fields use separate limits" {
    const allocator = testing.allocator;
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    {
        var v = IndexValidator.initWithLimits(allocator, &diagnostics, null, .{ .max_index_list_offset_text_bytes = 2 });
        defer v.deinit();
        try v.consumeStart(test_events.startUnknown("mzML", &.{}, 0), 0);
        try v.consumeStart(test_events.startUnknown("indexListOffset", &.{}, 1), 1);
        try expectError(error.ResourceLimitExceeded, v.consumeText(test_events.text("123")));
    }

    {
        var v = IndexValidator.initWithLimits(allocator, &diagnostics, null, .{ .max_file_checksum_text_bytes = 4 });
        defer v.deinit();
        try v.consumeStart(test_events.startUnknown("mzML", &.{}, 0), 0);
        try v.consumeStart(test_events.startUnknown("fileChecksum", &.{}, 1), 1);
        try expectError(error.ResourceLimitExceeded, v.consumeText(test_events.text("12345")));
    }

    try expectEqual(@as(usize, 2), diagnostics.items.len);
}

fn hexChar(nibble: u4) u8 {
    return if (nibble < 10) @as(u8, '0') + nibble else @as(u8, 'a') + nibble - 10;
}
