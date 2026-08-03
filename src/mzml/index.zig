//! Indexed mzML offset and SHA-1 checksum validation.
//!
//! A forward pass records container and index metadata. Contiguous and seekable
//! sources verify offsets and checksums without retaining stream input.
//! Both pwiz element offsets and ThermoRawFileParser line offsets are accepted.

const std = @import("std");
const diagnostic = @import("../diagnostic.zig");
const xml_events = @import("../xml/events.zig");

const DiagnosticSink = diagnostic.DiagnosticSink;
const EndElement = xml_events.EndElement;
const RuleId = diagnostic.RuleId;
const StartElement = xml_events.StartElement;
const Text = xml_events.Text;

const online_sha_batch_bytes = 64 * 1024;

const IndexKind = enum { spectrum, chromatogram };

const IndexRecord = struct {
    offset: u64,
    index_seen: bool = false,
    ambiguous: bool = false,
};

/// Validates index offsets, indexListOffset, fileChecksum SHA-1, and truncation.
///
/// Call consumeStart/consumeEnd/consumeText during the forward parse pass,
/// then finish(file_bytes) after the document ends.
pub const IndexValidator = struct {
    allocator: std.mem.Allocator,
    diagnostics: *DiagnosticSink,
    path: ?[]const u8,
    limits: diagnostic.ResourceLimits,

    mzml_depth: ?usize = null,
    indexed_document: bool = false,

    // One key and record for every spectrum or chromatogram.
    spectrum_offsets: std.StringHashMap(IndexRecord),
    chromatogram_offsets: std.StringHashMap(IndexRecord),

    // --- Index list parsing state ---
    index_list_depth: ?usize = null,
    index_list_actual_offset: ?u64 = null,
    index_list_declared_count: ?u64 = null,
    index_list_actual_count: u64 = 0,

    current_index_kind: ?IndexKind = null,
    offset_id_ref: ?[]const u8 = null,
    index_entry_count: usize = 0,
    previous_index_offset: ?u64 = null,

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

    saw_index_elements: bool = false,

    index_state_current_bytes: usize = 0,
    index_state_peak_bytes: usize = 0,
    input_size: ?u64 = null,
    stream_io: ?std.Io = null,
    stream_file: ?std.Io.File = null,

    // Online SHA-1 over contiguous input bytes.
    sha_file_bytes: ?[]const u8 = null,
    sha_ctx: std.crypto.hash.Sha1 = undefined,
    sha_bytes_hashed: u64 = 0,
    sha_complete: bool = false,
    sha_computed: [20]u8 = undefined,

    pub fn isIndexed(validator: *const IndexValidator) bool {
        return validator.saw_index_elements;
    }

    /// Returns the declared fileChecksum value parsed from `<fileChecksum>`.
    /// Returns null if no fileChecksum was encountered.
    pub fn declaredChecksum(validator: *const IndexValidator) ?[20]u8 {
        if (!validator.file_checksum_ok) return null;
        return validator.file_checksum_raw;
    }

    /// Start incremental SHA-1 over contiguous input bytes. Call once before the
    /// parse loop when `file_bytes` is available.
    pub fn beginOnlineSha(validator: *IndexValidator, bytes: []const u8) void {
        validator.sha_file_bytes = bytes;
        validator.input_size = bytes.len;
        validator.sha_ctx = std.crypto.hash.Sha1.init(.{});
        validator.sha_bytes_hashed = 0;
        validator.sha_complete = false;
    }

    /// Feeds a normal parser boundary only after enough raw input accumulated.
    /// The checksum-element boundary always flushes through `feedShaExclusive`.
    pub fn maybeFeedShaExclusive(validator: *IndexValidator, exclusive_end: u64) void {
        if (validator.sha_file_bytes == null or validator.sha_complete) return;
        const bytes = validator.sha_file_bytes.?;
        const cap = validator.file_checksum_byte_offset orelse bytes.len;
        const end = @min(exclusive_end, cap, bytes.len);
        if (end -| validator.sha_bytes_hashed < online_sha_batch_bytes) return;
        validator.feedShaExclusive(end);
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
        diagnostics: *DiagnosticSink,
        path: ?[]const u8,
    ) IndexValidator {
        return initWithLimits(allocator, diagnostics, path, .{});
    }

    pub fn initWithLimits(
        allocator: std.mem.Allocator,
        diagnostics: *DiagnosticSink,
        path: ?[]const u8,
        limits: diagnostic.ResourceLimits,
    ) IndexValidator {
        return .{
            .allocator = allocator,
            .diagnostics = diagnostics,
            .path = path,
            .limits = limits,
            .spectrum_offsets = std.StringHashMap(IndexRecord).init(allocator),
            .chromatogram_offsets = std.StringHashMap(IndexRecord).init(allocator),
            .text_buf = std.ArrayList(u8).empty,
        };
    }

    pub fn deinit(validator: *IndexValidator) void {
        freeHashMap(validator.allocator, &validator.spectrum_offsets);
        freeHashMap(validator.allocator, &validator.chromatogram_offsets);
        if (validator.offset_id_ref) |ref| validator.allocator.free(ref);
        validator.text_buf.deinit(validator.allocator);
        validator.* = undefined;
    }

    /// Set the seekable source and size before parsing stream events.
    pub fn setStreamSource(validator: *IndexValidator, io: std.Io, file: std.Io.File, size: u64) void {
        validator.stream_io = io;
        validator.stream_file = file;
        validator.input_size = size;
    }

    pub fn consumeStart(
        validator: *IndexValidator,
        start: StartElement,
        element_depth: usize,
    ) !void {
        const tag = start.resolvedId();

        switch (tag) {
            .indexedmzML => {
                validator.indexed_document = true;
                return;
            },
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
            .spectrum => try recordContainerOffset(validator, start, .spectrum),
            .spectrumList => {
                const count_attr = start.attr("count");
                if (count_attr) |c| {
                    if (std.fmt.parseUnsigned(u64, c, 10)) |count| {
                        const bounded = try validator.boundedCount(count, start.byte_offset, "spectrumList count exceeds the configured index-entry limit");
                        try validator.ensureMapCapacity(&validator.spectrum_offsets, bounded, start.byte_offset);
                    } else |_| {}
                }
            },
            .chromatogram => try recordContainerOffset(validator, start, .chromatogram),
            .chromatogramList => {
                const count_attr = start.attr("count");
                if (count_attr) |c| {
                    if (std.fmt.parseUnsigned(u64, c, 10)) |count| {
                        const bounded = try validator.boundedCount(count, start.byte_offset, "chromatogramList count exceeds the configured index-entry limit");
                        try validator.ensureMapCapacity(&validator.chromatogram_offsets, bounded, start.byte_offset);
                    } else |_| {}
                }
            },
            .indexList => {
                validator.index_list_depth = element_depth;
                validator.index_list_actual_offset = start.byte_offset;
                validator.saw_index_elements = true;
                const count_attr = start.attr("count");
                validator.index_list_declared_count = if (count_attr) |c|
                    if (std.fmt.parseUnsigned(u64, std.mem.trim(u8, c, " \t\r\n"), 10)) |count| blk: {
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
                const name = start.attr("name") orelse return;
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
                const id_ref = start.attr("idRef") orelse return;
                if (validator.offset_id_ref) |old_ref| {
                    validator.releaseIndexBytes(old_ref.len);
                    validator.allocator.free(old_ref);
                }
                validator.offset_id_ref = null;
                if (id_ref.len > validator.limits.max_index_id_ref_bytes) {
                    try validator.limitDiagnostic(start.byte_offset, "index idRef exceeds the configured field limit");
                    return error.ResourceLimitExceeded;
                }
                try validator.reserveIndexBytes(id_ref.len, start.byte_offset);
                errdefer validator.releaseIndexBytes(id_ref.len);
                const retained = try validator.allocator.dupe(u8, id_ref);
                validator.offset_id_ref = retained;
                validator.text_buf.clearRetainingCapacity();
            },
            .indexListOffset => {
                validator.index_list_offset_byte_offset = start.byte_offset;
                validator.index_list_offset_depth = element_depth;
                validator.text_buf.clearRetainingCapacity();
            },
            .fileChecksum => {
                validator.file_checksum_depth = element_depth;
                const checksum_end = if (start.end_byte_offset) |end_byte_offset|
                    std.math.add(u64, end_byte_offset, 1)
                else
                    std.math.add(u64, start.byte_offset, "<fileChecksum>".len);
                const checksum_offset = checksum_end catch {
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
                if (validator.current_index_kind == null or validator.offset_id_ref == null) return;
                const id_ref = validator.offset_id_ref.?;
                validator.offset_id_ref = null;
                defer {
                    validator.releaseIndexBytes(id_ref.len);
                    validator.allocator.free(id_ref);
                }
                const offset = std.fmt.parseUnsigned(u64, validator.text_buf.items, 10) catch {
                    try validator.appendDiagnostic(
                        end.byte_offset,
                        RuleId.mzml_index_offset,
                        "offset value is not a valid integer",
                    );
                    return;
                };
                try validator.checkIndexEntry(id_ref, offset, end.byte_offset);
            },
            .index => validator.current_index_kind = null,
            .indexList => {
                validator.index_list_depth = null;
                validator.index_list_offset_value = null;
            },
            .indexListOffset => {
                validator.index_list_offset_value = std.fmt.parseUnsigned(u64, validator.text_buf.items, 10) catch {
                    try validator.appendDiagnostic(
                        validator.index_list_offset_byte_offset orelse 0,
                        RuleId.mzml_index_offset_list,
                        "indexListOffset value is not a valid integer",
                    );
                    validator.index_list_offset_depth = null;
                    return;
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
        const limit = if (validator.offset_id_ref != null)
            validator.limits.max_index_offset_text_bytes
        else if (validator.index_list_offset_depth != null)
            validator.limits.max_index_list_offset_text_bytes
        else
            validator.limits.max_file_checksum_text_bytes;
        if (validator.text_buf.items.len > limit or text.value.len > limit - validator.text_buf.items.len) {
            const message = if (validator.offset_id_ref != null)
                "index offset text exceeds the configured field limit"
            else if (validator.index_list_offset_depth != null)
                "indexListOffset text exceeds the configured field limit"
            else
                "fileChecksum text exceeds the configured field limit";
            try validator.limitDiagnostic(text.byte_offset, message);
            return error.ResourceLimitExceeded;
        }
        const required = std.math.add(usize, validator.text_buf.items.len, text.value.len) catch {
            try validator.limitDiagnostic(text.byte_offset, "index text size arithmetic overflow");
            return error.ResourceLimitExceeded;
        };
        if (required > validator.text_buf.capacity) {
            const extra = required - validator.text_buf.capacity;
            try validator.reserveIndexBytes(extra, text.byte_offset);
            errdefer validator.releaseIndexBytes(extra);
            try validator.text_buf.ensureTotalCapacityPrecise(validator.allocator, required);
        }
        try validator.text_buf.appendSlice(validator.allocator, text.value);
    }

    pub fn wantsText(validator: *const IndexValidator) bool {
        if (validator.mzml_depth == null) return false;
        return validator.offset_id_ref != null or
            validator.index_list_offset_depth != null or
            validator.file_checksum_depth != null;
    }

    /// Recomputes fileChecksum from the seekable stream source without retaining input bytes.
    pub fn completeStreamChecksum(validator: *IndexValidator) !void {
        if (!validator.file_checksum_ok or validator.sha_complete) return;
        const checksum_offset = validator.file_checksum_byte_offset orelse return;
        const size = validator.input_size orelse return;
        if (checksum_offset > size) return;

        const file = validator.stream_file orelse return;
        const io = validator.stream_io orelse {
            try validator.appendDiagnostic(
                checksum_offset,
                RuleId.mzml_index_checksum,
                "stream I/O unavailable while verifying fileChecksum",
            );
            return error.InputOutput;
        };
        var buffer: [64 * 1024]u8 = undefined;
        var hashed: u64 = 0;
        var ctx = std.crypto.hash.Sha1.init(.{});
        while (hashed < checksum_offset) {
            const remaining = checksum_offset - hashed;
            const want: usize = @intCast(@min(remaining, @as(u64, buffer.len)));
            const n = std.Io.File.readPositionalAll(file, io, buffer[0..want], hashed) catch return error.InputOutput;
            if (n != want) {
                try validator.appendDiagnostic(
                    checksum_offset,
                    RuleId.mzml_index_checksum,
                    "unable to read input while verifying fileChecksum",
                );
                return error.InputOutput;
            }
            ctx.update(buffer[0..n]);
            hashed = std.math.add(u64, hashed, n) catch return error.InputOutput;
        }
        ctx.final(&validator.sha_computed);
        validator.sha_complete = true;
    }

    /// After the document is fully parsed, cross-check all collected data.
    /// `file_bytes` is the complete contiguous input when available.
    /// Call beginOnlineSha or setStreamSource before parsing when input-size
    /// and truncation checks are required. Returns `error.InputIntegrityUnavailable`
    /// when a declared checksum cannot be verified from the available source.
    pub fn finish(
        validator: *IndexValidator,
        file_bytes: ?[]const u8,
    ) !void {
        if (!validator.saw_index_elements) return;

        if (file_bytes == null and validator.stream_file == null) {
            if (validator.file_checksum_ok) return error.InputIntegrityUnavailable;
            _ = try validator.diagnostics.append(validator.allocator, .{
                .severity = .info,
                .rule = RuleId.mzml_index_checksum,
                .location = .{ .byte_offset = 0 },
                .path = validator.path,
                .message = "file bytes unavailable; SHA-1 and truncation checks skipped",
            });
        }

        if (validator.index_list_declared_count) |declared| {
            if (declared != validator.index_list_actual_count) {
                try validator.appendDiagnostic(
                    validator.index_list_actual_offset orelse 0,
                    RuleId.mzml_index_offset_list,
                    "indexList count does not match actual index elements",
                );
            }
        }

        if (validator.index_list_offset_value) |declared| {
            if (validator.index_list_actual_offset) |actual| {
                if (declared != actual) {
                    if (!try validator.offsetsMatchWithWhitespace(declared, actual)) {
                        try validator.appendDiagnostic(
                            validator.index_list_offset_byte_offset orelse validator.index_list_actual_offset orelse 0,
                            RuleId.mzml_index_offset_list,
                            "declared indexListOffset does not match actual position of indexList",
                        );
                    }
                }
            }
        }

        if (file_bytes == null) try validator.completeStreamChecksum();
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
        } else if (validator.stream_file != null and validator.file_checksum_ok) {
            if (validator.file_checksum_byte_offset) |checksum_offset| {
                const size = validator.input_size orelse {
                    try validator.appendDiagnostic(
                        checksum_offset,
                        RuleId.mzml_index_checksum,
                        "input size unavailable while verifying fileChecksum",
                    );
                    return error.InputOutput;
                };
                if (checksum_offset > size) {
                    try validator.appendDiagnostic(
                        checksum_offset,
                        RuleId.mzml_index_checksum,
                        "fileChecksum offset exceeds file size",
                    );
                } else if (!std.mem.eql(u8, &validator.sha_computed, &validator.file_checksum_raw)) {
                    try validator.appendDiagnostic(
                        checksum_offset,
                        RuleId.mzml_index_checksum,
                        "fileChecksum SHA-1 does not match recomputed value",
                    );
                }
            }
        }
    }

    // --- Private Helpers ---

    fn maxIndexEntries(validator: *const IndexValidator) usize {
        if (validator.input_size) |size| {
            if (std.math.cast(usize, size)) |length| return @min(validator.limits.max_index_entries, length);
        }
        return validator.limits.max_index_entries;
    }

    fn reserveIndexBytes(validator: *IndexValidator, bytes: usize, byte_offset: u64) !void {
        const next = std.math.add(usize, validator.index_state_current_bytes, bytes) catch {
            try validator.limitDiagnostic(byte_offset, "index state size arithmetic overflow");
            return error.ResourceLimitExceeded;
        };
        if (next > validator.limits.max_index_state_bytes) {
            try validator.limitDiagnostic(byte_offset, "index state exceeds the configured byte limit");
            return error.ResourceLimitExceeded;
        }
        validator.index_state_current_bytes = next;
        validator.index_state_peak_bytes = @max(validator.index_state_peak_bytes, next);
    }

    fn releaseIndexBytes(validator: *IndexValidator, bytes: usize) void {
        std.debug.assert(bytes <= validator.index_state_current_bytes);
        validator.index_state_current_bytes -= bytes;
    }

    fn ensureMapCapacity(
        validator: *IndexValidator,
        map: *std.StringHashMap(IndexRecord),
        required: u32,
        byte_offset: u64,
    ) !void {
        if (required == 0) return;
        const old_capacity = map.capacity();
        if (old_capacity != 0) {
            const load_limit = std.math.mul(u64, old_capacity, std.hash_map.default_max_load_percentage) catch unreachable;
            if (@as(u64, required) <= load_limit / 100) return;
        }
        const target_without_minimum = mapCapacityForCount(required) catch {
            try validator.limitDiagnostic(byte_offset, "index map capacity arithmetic overflow");
            return error.ResourceLimitExceeded;
        };
        const target = @max(target_without_minimum, @as(u32, 8));
        if (target <= old_capacity) return;
        const old_bytes = mapStorageBytes(map.capacity()) catch {
            try validator.limitDiagnostic(byte_offset, "index map size arithmetic overflow");
            return error.ResourceLimitExceeded;
        };
        const new_bytes = mapStorageBytes(target) catch {
            try validator.limitDiagnostic(byte_offset, "index map size arithmetic overflow");
            return error.ResourceLimitExceeded;
        };
        try validator.reserveIndexBytes(new_bytes, byte_offset);
        errdefer validator.releaseIndexBytes(new_bytes);
        try map.ensureTotalCapacity(required);
        std.debug.assert(map.capacity() == target);
        validator.releaseIndexBytes(old_bytes);
    }

    fn checkIndexEntry(validator: *IndexValidator, id_ref: []const u8, offset: u64, byte_offset: u64) !void {
        if (validator.index_entry_count >= validator.maxIndexEntries()) {
            try validator.limitDiagnostic(byte_offset, "index entry count exceeds the configured index-entry limit");
            return error.ResourceLimitExceeded;
        }
        validator.index_entry_count = std.math.add(usize, validator.index_entry_count, 1) catch {
            try validator.limitDiagnostic(byte_offset, "index entry count arithmetic overflow");
            return error.ResourceLimitExceeded;
        };

        const map = switch (validator.current_index_kind.?) {
            .spectrum => &validator.spectrum_offsets,
            .chromatogram => &validator.chromatogram_offsets,
        };
        const record = map.getPtr(id_ref);
        if (record) |entry| {
            const duplicate = entry.index_seen;
            entry.index_seen = true;
            if (duplicate) {
                try validator.appendDiagnostic(byte_offset, RuleId.mzml_index_offset, "duplicate idRef in index");
            }
        }
        if (validator.previous_index_offset) |previous| {
            if (offset < previous) {
                try validator.appendDiagnostic(
                    byte_offset,
                    RuleId.mzml_index_offset,
                    "index offsets are not monotonically increasing",
                );
            }
        }
        validator.previous_index_offset = offset;
        if (validator.input_size) |size| {
            if (offset >= size) {
                try validator.appendDiagnostic(
                    offset,
                    RuleId.mzml_index_truncated,
                    "index offset points past end of file",
                );
                return;
            }
        }
        const resolved = record orelse {
            try validator.appendDiagnostic(
                offset,
                RuleId.mzml_index_offset,
                "index references non-existent spectrum or chromatogram",
            );
            return;
        };
        if (resolved.ambiguous) return;
        if (offset != resolved.offset and !try validator.offsetsMatchWithWhitespace(offset, resolved.offset)) {
            try validator.appendDiagnostic(
                offset,
                RuleId.mzml_index_offset,
                "index offset does not match actual byte position",
            );
        }
    }

    fn offsetsMatchWithWhitespace(validator: *IndexValidator, declared: u64, actual: u64) !bool {
        if (declared == actual) return true;
        if (declared > actual) return false;
        if (validator.sha_file_bytes) |bytes| return offsetsMatchWithBytes(bytes, declared, actual);
        const io = validator.stream_io orelse return false;
        const file = validator.stream_file orelse return false;
        if (validator.input_size) |size| if (actual > size) return false;

        var buffer: [4096]u8 = undefined;
        var offset = declared;
        while (offset < actual) {
            const want: usize = @intCast(@min(actual - offset, @as(u64, buffer.len)));
            const n = std.Io.File.readPositionalAll(file, io, buffer[0..want], offset) catch return error.InputOutput;
            if (n != want) return false;
            for (buffer[0..n]) |byte| {
                switch (byte) {
                    ' ', '\t', '\n', '\r' => {},
                    else => return false,
                }
            }
            offset = std.math.add(u64, offset, n) catch return false;
        }
        return true;
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
        _ = try validator.diagnostics.append(validator.allocator, .{
            .severity = .@"error",
            .rule = rule,
            .location = .{ .byte_offset = byte_offset },
            .path = validator.path,
            .message = message,
        });
    }
};

// --- Module-Level Helpers ---

fn recordContainerOffset(
    validator: *IndexValidator,
    start: StartElement,
    kind: IndexKind,
) !void {
    const id = start.attr("id") orelse return;
    const map = switch (kind) {
        .spectrum => &validator.spectrum_offsets,
        .chromatogram => &validator.chromatogram_offsets,
    };
    if (map.getPtr(id)) |record| {
        record.ambiguous = true;
        if (!validator.indexed_document) return;
        const message = switch (kind) {
            .spectrum => "duplicate spectrum id makes index resolution ambiguous",
            .chromatogram => "duplicate chromatogram id makes index resolution ambiguous",
        };
        try validator.appendDiagnostic(start.byte_offset, RuleId.mzml_index_duplicate_id, message);
        return;
    }
    if (id.len > validator.limits.max_index_id_ref_bytes) {
        try validator.limitDiagnostic(start.byte_offset, "indexable element id exceeds the configured field limit");
        return error.ResourceLimitExceeded;
    }
    if (map.count() >= validator.maxIndexEntries()) {
        try validator.limitDiagnostic(start.byte_offset, "indexable element count exceeds the configured index-entry limit");
        return error.ResourceLimitExceeded;
    }
    const count = std.math.add(u32, map.count(), 1) catch {
        try validator.limitDiagnostic(start.byte_offset, "index map count arithmetic overflow");
        return error.ResourceLimitExceeded;
    };
    try validator.ensureMapCapacity(map, count, start.byte_offset);
    try validator.reserveIndexBytes(id.len, start.byte_offset);
    errdefer validator.releaseIndexBytes(id.len);
    const key = try validator.allocator.dupe(u8, id);
    errdefer {
        validator.allocator.free(key);
    }
    const result = try map.getOrPut(key);
    if (result.found_existing) {
        validator.releaseIndexBytes(key.len);
        validator.allocator.free(key);
        return;
    }
    result.key_ptr.* = key;
    result.value_ptr.* = .{ .offset = start.byte_offset };
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

fn freeHashMap(allocator: std.mem.Allocator, map: *std.StringHashMap(IndexRecord)) void {
    var it = map.iterator();
    while (it.next()) |entry| {
        allocator.free(entry.key_ptr.*);
    }
    map.deinit();
}

fn mapCapacityForCount(required: u32) !u32 {
    const scaled = try std.math.mul(u64, required, 100);
    const needed = try std.math.add(u64, scaled / std.hash_map.default_max_load_percentage, 1);
    const bounded = std.math.cast(u32, needed) orelse return error.Overflow;
    return std.math.ceilPowerOfTwo(u32, bounded) catch return error.Overflow;
}

fn mapStorageBytes(capacity: u32) !usize {
    if (capacity == 0) return 0;

    // Mirror the bundled HashMap allocation so the budget includes its alignment padding.
    const Header = struct {
        values: [*]IndexRecord,
        keys: [*][]const u8,
        capacity: u32,
    };
    const key_type = []const u8;
    const map_alignment = @max(@alignOf(Header), @alignOf(key_type), @alignOf(IndexRecord));
    const metadata_end = try std.math.add(usize, @sizeOf(Header), @intCast(capacity));
    const keys_start = try alignForward(metadata_end, @alignOf(key_type));
    const keys_bytes = try std.math.mul(usize, @intCast(capacity), @sizeOf(key_type));
    const keys_end = try std.math.add(usize, keys_start, keys_bytes);
    const values_start = try alignForward(keys_end, @alignOf(IndexRecord));
    const values_bytes = try std.math.mul(usize, @intCast(capacity), @sizeOf(IndexRecord));
    const values_end = try std.math.add(usize, values_start, values_bytes);
    return alignForward(values_end, map_alignment);
}

fn alignForward(value: usize, alignment: usize) !usize {
    const with_padding = try std.math.add(usize, value, alignment - 1);
    return with_padding & ~(alignment - 1);
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
// Used for contiguous input; stream input uses positional reads in the validator.
fn offsetsMatchWithBytes(file_bytes: ?[]const u8, declared: u64, actual: u64) bool {
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

fn hexChar(nibble: u4) u8 {
    return if (nibble < 10) @as(u8, '0') + nibble else @as(u8, 'a') + nibble - 10;
}

// --- Unit Tests ---

test "IndexValidator: non-indexed file produces no diagnostics" {
    const allocator = testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.init(allocator, &diagnostics, null);
    defer v.deinit();

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
    var diagnostics: DiagnosticSink = .empty;
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

    try expectEqual(@as(u64, 100), v.spectrum_offsets.get("s1").?.offset);
    try expectEqual(@as(u64, 200), v.chromatogram_offsets.get("c1").?.offset);
}

test "[unit]: duplicate spectrum id makes index identity ambiguous" {
    const allocator = testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.init(allocator, &diagnostics, null);
    defer v.deinit();

    try v.consumeStart(test_events.startUnknown("indexedmzML", &.{}, 0), 0);
    try v.consumeStart(test_events.startUnknown("mzML", &.{}, 10), 1);
    try v.consumeStart(test_events.startUnknown("spectrum", &.{test_events.attr("id", "s1")}, 100), 2);
    try v.consumeStart(test_events.startUnknown("spectrum", &.{test_events.attr("id", "s1")}, 200), 2);
    try v.consumeStart(test_events.startUnknown("indexList", &.{test_events.attr("count", "1")}, 300), 1);
    try v.consumeStart(test_events.startUnknown("index", &.{test_events.attr("name", "spectrum")}, 310), 2);
    try v.consumeStart(test_events.startUnknown("offset", &.{test_events.attr("idRef", "s1")}, 320), 3);
    try v.consumeText(test_events.text("200"));
    try v.consumeEnd(test_events.endUnknown("offset"), 3);

    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_index_duplicate_id, diagnostics.items[0].rule);
    try expectEqualStrings("duplicate spectrum id makes index resolution ambiguous", diagnostics.items[0].message);
    try expect(v.spectrum_offsets.get("s1").?.ambiguous);
}

test "[unit]: non-indexed duplicate id has no index diagnostic" {
    const allocator = testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.init(allocator, &diagnostics, null);
    defer v.deinit();

    try v.consumeStart(test_events.startUnknown("mzML", &.{}, 0), 0);
    try v.consumeStart(test_events.startUnknown("spectrum", &.{test_events.attr("id", "s1")}, 100), 1);
    try v.consumeStart(test_events.startUnknown("spectrum", &.{test_events.attr("id", "s1")}, 200), 1);

    try expectEqual(@as(usize, 0), diagnostics.items.len);
    try expect(v.spectrum_offsets.get("s1").?.ambiguous);
}

test "[unit]: duplicate chromatogram id makes index identity ambiguous" {
    const allocator = testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.init(allocator, &diagnostics, null);
    defer v.deinit();

    try v.consumeStart(test_events.startUnknown("indexedmzML", &.{}, 0), 0);
    try v.consumeStart(test_events.startUnknown("mzML", &.{}, 10), 1);
    try v.consumeStart(test_events.startUnknown("chromatogram", &.{test_events.attr("id", "c1")}, 100), 2);
    try v.consumeStart(test_events.startUnknown("chromatogram", &.{test_events.attr("id", "c1")}, 200), 2);

    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_index_duplicate_id, diagnostics.items[0].rule);
    try expectEqualStrings("duplicate chromatogram id makes index resolution ambiguous", diagnostics.items[0].message);
    try expect(v.chromatogram_offsets.get("c1").?.ambiguous);
}

test "[unit]: spectrum and chromatogram ids remain kind-specific" {
    const allocator = testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.init(allocator, &diagnostics, null);
    defer v.deinit();

    try v.consumeStart(test_events.startUnknown("indexedmzML", &.{}, 0), 0);
    try v.consumeStart(test_events.startUnknown("mzML", &.{}, 10), 1);
    try v.consumeStart(test_events.startUnknown("spectrum", &.{test_events.attr("id", "shared")}, 100), 2);
    try v.consumeStart(test_events.startUnknown("chromatogram", &.{test_events.attr("id", "shared")}, 200), 2);

    try expectEqual(@as(usize, 0), diagnostics.items.len);
    try expect(!v.spectrum_offsets.get("shared").?.ambiguous);
    try expect(!v.chromatogram_offsets.get("shared").?.ambiguous);
}

test "IndexValidator: index state tracks one key copy per record" {
    const allocator = testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.init(allocator, &diagnostics, null);
    defer v.deinit();

    try v.consumeStart(test_events.startUnknown("mzML", &.{}, 0), 0);
    try v.consumeStart(test_events.startUnknown("spectrum", &.{test_events.attr("id", "s1")}, 100), 1);

    try expectEqualStrings("s1", v.spectrum_offsets.getKey("s1").?);
    try expect(v.index_state_current_bytes > 0);
}

test "[unit]: index state accounting matches live allocator bytes" {
    var allocator = testing.FailingAllocator.init(testing.allocator, .{});
    var diagnostics = DiagnosticSink.init(.{ .retain_details = false });
    defer diagnostics.deinit(allocator.allocator());

    var validator = IndexValidator.init(allocator.allocator(), &diagnostics, null);
    defer validator.deinit();

    try validator.consumeStart(test_events.startUnknown("mzML", &.{}, 0), 0);
    try validator.consumeStart(test_events.startUnknown("spectrum", &.{test_events.attr("id", "s1")}, 100), 1);

    const live_bytes = allocator.allocated_bytes - allocator.freed_bytes;
    try expectEqual(live_bytes, validator.index_state_current_bytes);
}

test "[unit]: zero declared count does not charge unallocated index storage" {
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(testing.allocator);

    var validator = IndexValidator.init(testing.allocator, &diagnostics, null);
    defer validator.deinit();

    try validator.consumeStart(test_events.startUnknown("mzML", &.{}, 0), 0);
    try validator.consumeStart(test_events.startUnknown("spectrumList", &.{test_events.attr("count", "0")}, 10), 1);

    try expectEqual(@as(u32, 0), validator.spectrum_offsets.capacity());
    try expectEqual(@as(usize, 0), validator.index_state_current_bytes);
}

test "[unit]: positional-read failures normalize to input I/O" {
    const io = testing.io;
    var temp_dir = testing.tmpDir(.{});
    defer temp_dir.cleanup();
    const file = try temp_dir.dir.createFile(io, "closed.mzML", .{});
    file.close(io);

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(testing.allocator);
    var validator = IndexValidator.init(testing.allocator, &diagnostics, null);
    defer validator.deinit();
    validator.setStreamSource(io, file, 1);
    validator.file_checksum_ok = true;
    validator.file_checksum_byte_offset = 1;

    try testing.expectError(error.InputOutput, validator.completeStreamChecksum());
    try testing.expectError(error.InputOutput, validator.offsetsMatchWithWhitespace(0, 1));
}

test "IndexValidator: state byte limit rejects map growth" {
    const allocator = testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.initWithLimits(allocator, &diagnostics, null, .{ .max_index_state_bytes = 1 });
    defer v.deinit();

    try v.consumeStart(test_events.startUnknown("mzML", &.{}, 0), 0);
    try expectError(
        error.ResourceLimitExceeded,
        v.consumeStart(test_events.startUnknown("spectrum", &.{test_events.attr("id", "s1")}, 100), 1),
    );

    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqual(@as(usize, 0), v.index_state_current_bytes);
}

test "IndexValidator: finish propagates diagnostic allocation failure" {
    var failing_allocator = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(testing.allocator);

    var v = IndexValidator.init(failing_allocator.allocator(), &diagnostics, null);
    defer v.deinit();
    v.saw_index_elements = true;
    v.index_list_declared_count = 1;

    const file_bytes = [_]u8{};
    try expectError(error.OutOfMemory, v.finish(&file_bytes));
}

test "IndexValidator: spectrum with unknown intern id still records offsets" {
    const allocator = testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
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

    try expectEqual(@as(u64, 100), v.spectrum_offsets.get("s1").?.offset);
}

test "IndexValidator: valid indexed mzML cross-checks correctly" {
    const allocator = testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
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

test "IndexValidator: mismatched offset value produces diagnostic" {
    const allocator = testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
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
    try expectEqualStrings(RuleId.mzml_index_offset, diagnostics.items[0].rule);
    try expectEqualStrings(RuleId.mzml_index_checksum, diagnostics.items[1].rule);
}

test "IndexValidator: invalid offset values produce diagnostics" {
    for ([_][]const u8{ "not-an-offset", "18446744073709551616" }) |value| {
        const allocator = testing.allocator;
        var diagnostics: DiagnosticSink = .empty;
        defer diagnostics.deinit(allocator);

        var v = IndexValidator.init(allocator, &diagnostics, null);
        defer v.deinit();

        try v.consumeStart(test_events.startUnknown("mzML", &.{}, 0), 0);
        try v.consumeStart(test_events.startUnknown("indexList", &.{test_events.attr("count", "1")}, 10), 1);
        try v.consumeStart(test_events.startUnknown("index", &.{test_events.attr("name", "spectrum")}, 20), 2);
        try v.consumeStart(test_events.startUnknown("offset", &.{test_events.attr("idRef", "s1")}, 30), 3);
        try v.consumeText(test_events.text(value));
        try v.consumeEnd(test_events.endUnknown("offset"), 3);

        try expectEqual(@as(usize, 1), diagnostics.items.len);
        try expectEqualStrings(RuleId.mzml_index_offset, diagnostics.items[0].rule);
    }
}

test "IndexValidator: reference to non-existent element produces diagnostic" {
    const allocator = testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
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
    try expectEqualStrings(RuleId.mzml_index_offset, diagnostics.items[0].rule);
    try expectEqualStrings(RuleId.mzml_index_checksum, diagnostics.items[1].rule);
}

test "[unit]: spectrum index does not resolve a chromatogram id" {
    const allocator = testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.init(allocator, &diagnostics, null);
    defer v.deinit();

    try v.consumeStart(test_events.startUnknown("indexedmzML", &.{}, 0), 0);
    try v.consumeStart(test_events.startUnknown("mzML", &.{}, 10), 1);
    try v.consumeStart(test_events.startUnknown("chromatogram", &.{test_events.attr("id", "c1")}, 100), 2);
    try v.consumeStart(test_events.startUnknown("indexList", &.{test_events.attr("count", "1")}, 200), 1);
    try v.consumeStart(test_events.startUnknown("index", &.{test_events.attr("name", "spectrum")}, 210), 2);
    try v.consumeStart(test_events.startUnknown("offset", &.{test_events.attr("idRef", "c1")}, 220), 3);
    try v.consumeText(test_events.text("100"));
    try v.consumeEnd(test_events.endUnknown("offset"), 3);

    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_index_offset, diagnostics.items[0].rule);
    try expectEqualStrings("index references non-existent spectrum or chromatogram", diagnostics.items[0].message);
}

test "IndexValidator: indexListOffset mismatch produces diagnostic" {
    const allocator = testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
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

test "IndexValidator: invalid indexListOffset values produce diagnostics" {
    for ([_][]const u8{ "not-an-offset", "18446744073709551616" }) |value| {
        const allocator = testing.allocator;
        var diagnostics: DiagnosticSink = .empty;
        defer diagnostics.deinit(allocator);

        var v = IndexValidator.init(allocator, &diagnostics, null);
        defer v.deinit();

        try v.consumeStart(test_events.startUnknown("mzML", &.{}, 0), 0);
        try v.consumeStart(test_events.startUnknown("indexListOffset", &.{}, 10), 1);
        try v.consumeText(test_events.text(value));
        try v.consumeEnd(test_events.endUnknown("indexListOffset"), 1);

        try expectEqual(@as(usize, 1), diagnostics.items.len);
        try expectEqualStrings(RuleId.mzml_index_offset_list, diagnostics.items[0].rule);
    }
}

test "IndexValidator: truncated offset produces diagnostic" {
    const allocator = testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var v = IndexValidator.init(allocator, &diagnostics, null);
    defer v.deinit();

    const file_bytes = "<?xml version=\"1.0\"?><mzML>...</mzML>" ++ [_]u8{0} ** 100;
    v.beginOnlineSha(file_bytes);

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

    try v.finish(file_bytes);

    try expectEqual(@as(usize, 1), diagnostics.items.len);
    try expectEqualStrings(RuleId.mzml_index_truncated, diagnostics.items[0].rule);
}

test "IndexValidator: SHA-1 checksum mismatch produces diagnostic" {
    const allocator = testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
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
    var diagnostics: DiagnosticSink = .empty;
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

    var diagnostics: DiagnosticSink = .empty;
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

test "IndexValidator: online SHA batches parser boundaries and flushes checksum boundary" {
    var bytes: [online_sha_batch_bytes * 2 + 7]u8 = undefined;
    @memset(&bytes, 'x');

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(testing.allocator);

    var v = IndexValidator.init(testing.allocator, &diagnostics, null);
    defer v.deinit();

    v.beginOnlineSha(&bytes);
    for (0..bytes.len) |end| v.maybeFeedShaExclusive(end);
    try expectEqual(@as(u64, online_sha_batch_bytes * 2), v.sha_bytes_hashed);

    v.file_checksum_byte_offset = bytes.len;
    v.feedShaExclusive(bytes.len);

    const batch = computeChecksumBatch(&bytes, bytes.len);
    try expect(v.sha_complete);
    try expectEqual(@as(u64, bytes.len), v.sha_bytes_hashed);
    try testing.expectEqualSlices(u8, &batch, &v.sha_computed);
}

test "IndexValidator: fileChecksum with surrounding whitespace passes validation" {
    const allocator = testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
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
    var diagnostics: DiagnosticSink = .empty;
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
    try expectEqualStrings(RuleId.mzml_index_offset, diagnostics.items[0].rule);
    try expectEqualStrings("duplicate idRef in index", diagnostics.items[0].message);
    try expectEqualStrings(RuleId.mzml_index_checksum, diagnostics.items[1].rule);
}

test "IndexValidator: count limit rejects before reservation" {
    const allocator = testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
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

test "[unit]: index validator leaves malformed indexList counts to structural validation" {
    for ([_][]const u8{ "not-a-count", "18446744073709551616" }) |value| {
        const allocator = testing.allocator;
        var diagnostics: DiagnosticSink = .empty;
        defer diagnostics.deinit(allocator);

        var v = IndexValidator.init(allocator, &diagnostics, null);
        defer v.deinit();

        try v.consumeStart(test_events.startUnknown("mzML", &.{}, 0), 0);
        try v.consumeStart(test_events.startUnknown("indexList", &.{test_events.attr("count", value)}, 10), 1);

        try expectEqual(@as(usize, 0), diagnostics.items.len);
    }
}

test "IndexValidator: count boundaries stay within the configured limit" {
    const allocator = testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
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
    var diagnostics: DiagnosticSink = .empty;
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
    var diagnostics: DiagnosticSink = .empty;
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

const test_events = @import("test_events.zig");
const testing = std.testing;
const expect = testing.expect;
const expectEqual = testing.expectEqual;
const expectEqualStrings = testing.expectEqualStrings;
const expectError = testing.expectError;
