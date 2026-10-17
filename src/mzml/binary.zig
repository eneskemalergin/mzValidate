//! Binary integrity checks for mzML payloads.
//!
//! Validates base64, zlib integrity, and decoded array lengths in one pass.
//! Reusable bounded scratch avoids retaining decoded numeric arrays.

const std = @import("std");
const zmz = @import("zmz").mzml;
const diagnostic = @import("../diagnostic.zig");
const xml_events = @import("../xml/events.zig");
const xml_parser = @import("../xml/parser.zig");
const xml_parse_errors = @import("../xml/parse_errors.zig");

const Attribute = xml_events.Attribute;
const Diagnostic = diagnostic.Diagnostic;
const DiagnosticSink = diagnostic.DiagnosticSink;
const EndElement = xml_events.EndElement;
const QName = xml_events.QName;
const RuleId = diagnostic.RuleId;
const StartElement = xml_events.StartElement;

// --- Constants and types ---

pub const mzml_namespace = diagnostic.mzml_namespace;
const base64_simd_chunk_len: comptime_int = std.simd.suggestVectorLength(u8) orelse 32;
// zmz's Base64 decoder writes non-zlib payloads here, one piece at a time.
const base64_window_bytes = 48 * 1024;
// Capacities at or below this bound are useful across ordinary arrays. Larger
// compressed inputs and materialized outputs are one-off allocations and are
// released when their binaryDataArray ends.
const max_retained_binary_buffer_bytes = 1024 * 1024;
const scratch_capacity_classes = [_]usize{
    4 * 1024,
    16 * 1024,
    64 * 1024,
};

fn scratchCapacityClass(required: usize) usize {
    if (required == 0) return 0;
    for (scratch_capacity_classes) |capacity| {
        if (required <= capacity) return capacity;
    }
    return required;
}

const Compression = enum {
    none,
    zlib,
};

const Precision = enum {
    bits32,
    bits64,

    fn width(precision: Precision) usize {
        return switch (precision) {
            .bits32 => 4,
            .bits64 => 8,
        };
    }

    fn label(precision: Precision) []const u8 {
        return switch (precision) {
            .bits32 => "32-bit",
            .bits64 => "64-bit",
        };
    }
};

const BinaryDataType = enum {
    float32,
    float64,
    int32,
    int64,
    ascii,

    fn width(data_type: BinaryDataType) ?usize {
        return switch (data_type) {
            .float32, .int32 => 4,
            .float64, .int64 => 8,
            .ascii => null,
        };
    }

    fn precision(data_type: BinaryDataType) ?Precision {
        return switch (data_type) {
            .float32, .int32 => .bits32,
            .float64, .int64 => .bits64,
            .ascii => null,
        };
    }
};

const ArrayKind = enum {
    unknown,
    mz,
    intensity,
    time,
    metadata,
};

const OwnerKind = enum {
    spectrum,
    chromatogram,
};

const AsciiStats = struct {
    byte_count: usize = 0,
    terminator_count: usize = 0,
    last_byte: ?u8 = null,
    invalid_byte: bool = false,

    fn inspect(stats: *AsciiStats, bytes: []const u8) error{ResourceLimitExceeded}!void {
        stats.byte_count = std.math.add(usize, stats.byte_count, bytes.len) catch return error.ResourceLimitExceeded;
        for (bytes) |byte| {
            if (byte == 0) {
                stats.terminator_count = std.math.add(usize, stats.terminator_count, 1) catch return error.ResourceLimitExceeded;
            } else if (byte > 0x7f) {
                stats.invalid_byte = true;
            }
            stats.last_byte = byte;
        }
    }

    fn isValid(stats: *const AsciiStats) bool {
        return !stats.invalid_byte and (stats.byte_count == 0 or stats.last_byte == 0);
    }
};

// --- mzML element state ---

const OwnerState = struct {
    kind: OwnerKind,
    depth: usize,
    index: ?usize,
    default_array_length: ?usize,
    default_array_length_invalid: bool,
};

const BinaryArrayState = struct {
    byte_offset: u64,
    depth: usize,
    owner_spectrum_index: ?usize,
    owner_kind: OwnerKind,
    default_array_length: ?usize,
    default_array_length_invalid: bool,
    array_length: ?usize = null,
    array_length_declared: bool = false,
    array_length_invalid: bool = false,
    has_data_processing_ref: bool = false,
    encoded_length: ?usize = null,
    encoded_length_declared: ?usize = null,
    data_type: ?BinaryDataType = null,
    data_type_count: usize = 0,
    saw_unsupported_data_type: bool = false,
    saw_no_compression: bool = false,
    saw_zlib_compression: bool = false,
    saw_unsupported_compression: bool = false,
    compression_term_count: usize = 0,
    array_kind: ArrayKind = .unknown,
    array_kind_count: usize = 0,
    binary_depth: ?usize = null,
    binary_byte_offset: ?u64 = null,
    /// zmz checks and decodes the Base64: zlib payloads into `compressed_payload`, others
    /// through the validator's window. A failure is kept until the array is validated.
    base64: zmz.base64.Decoder = .init(&.{}),
    base64_failed: bool = false,
    ascii_stats: AsciiStats = .{},
    encoded_text_len: usize = 0,
    skipped: bool = false,

    fn init(
        byte_offset: u64,
        depth: usize,
        owner: OwnerState,
        encoded_length: ?usize,
        array_length: ?usize,
        array_length_declared: bool,
        array_length_invalid: bool,
        has_data_processing_ref: bool,
    ) BinaryArrayState {
        return .{
            .byte_offset = byte_offset,
            .depth = depth,
            .owner_spectrum_index = owner.index,
            .owner_kind = owner.kind,
            .default_array_length = owner.default_array_length,
            .default_array_length_invalid = owner.default_array_length_invalid,
            .array_length = array_length,
            .array_length_declared = array_length_declared,
            .array_length_invalid = array_length_invalid,
            .has_data_processing_ref = has_data_processing_ref,
            .encoded_length = encoded_length,
            .encoded_length_declared = encoded_length,
        };
    }
};

// --- Public validator ---

/// Base64, zlib, and length/precision checks for `binaryDataArray` payloads.
pub const BinaryValidator = struct {
    allocator: std.mem.Allocator,
    diagnostics: *DiagnosticSink,
    path: ?[]const u8,
    limits: diagnostic.ResourceLimits = .{},
    max_binary_size: ?usize = null,

    // Only one active binary array at a time. No accumulation across spectra.
    depth: usize = 0,
    indexed_mzml_depth: ?usize = null,
    mzml_depth: ?usize = null,
    spectrum: ?OwnerState = null,
    chromatogram: ?OwnerState = null,
    binary_array: ?BinaryArrayState = null,

    // Bit positions are mz, intensity, and time.
    seen_array_kinds: u3 = 0,

    /// Compressed zlib bytes decoded from base64 as text chunks arrive.
    /// Ordinary capacity is reused; one-off capacity above the retention bound
    /// is released after the owning binaryDataArray is validated.
    compressed_payload: std.ArrayList(u8) = .empty,
    /// zmz's streaming zlib decoder, allocated on the first zlib array. Its fixed
    /// allocation is not counted as scratch.
    decompressor: ?zmz.zlib.Decompressor = null,
    /// Decoded Base64 of non-zlib arrays, reused piece by piece; allocated on first use and,
    /// like the decompressor, not counted as scratch.
    base64_window: []u8 = &.{},
    scratch_current_bytes: usize = 0,
    scratch_peak_bytes: usize = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        diagnostics: *DiagnosticSink,
        path: ?[]const u8,
    ) BinaryValidator {
        return .{
            .allocator = allocator,
            .diagnostics = diagnostics,
            .path = path,
        };
    }

    pub fn deinit(validator: *BinaryValidator) void {
        if (validator.decompressor) |*decompressor| decompressor.deinit();
        validator.compressed_payload.deinit(validator.allocator);
        validator.allocator.free(validator.base64_window);
        validator.* = undefined;
    }

    fn ensureScratchCapacity(validator: *BinaryValidator, buffer: *std.ArrayList(u8), required: usize) !void {
        if (required > buffer.capacity) {
            const selected = scratchCapacityClass(required);
            const current = try validator.scratchCapacity();
            const other = std.math.sub(usize, current, buffer.capacity) catch return error.ResourceLimitExceeded;
            const total = std.math.add(usize, other, selected) catch return error.ResourceLimitExceeded;
            if (total > validator.limits.max_binary_scratch_bytes) return error.ResourceLimitExceeded;
            try buffer.ensureTotalCapacityPrecise(validator.allocator, selected);
        }
        try validator.updateScratchAccounting();
    }

    fn scratchCapacity(validator: *const BinaryValidator) !usize {
        return validator.compressed_payload.capacity;
    }

    fn updateScratchAccounting(validator: *BinaryValidator) !void {
        const current = try validator.scratchCapacity();
        if (current > validator.limits.max_binary_scratch_bytes) return error.ResourceLimitExceeded;
        validator.scratch_current_bytes = current;
        validator.scratch_peak_bytes = @max(validator.scratch_peak_bytes, current);
    }

    fn releaseOneOffScratch(validator: *BinaryValidator) void {
        if (validator.compressed_payload.capacity > max_retained_binary_buffer_bytes) {
            validator.compressed_payload.clearAndFree(validator.allocator);
        }

        // Capacity only decreases here, so the configured upper bound cannot
        // be crossed and arithmetic overflow is impossible after a prior
        // successful accounting update.
        validator.scratch_current_bytes = validator.scratchCapacity() catch unreachable;
    }

    pub fn validateReader(
        allocator: std.mem.Allocator,
        io: std.Io,
        reader: *std.Io.Reader,
        diagnostics: *DiagnosticSink,
        path: ?[]const u8,
    ) !void {
        try validateReaderWithLimits(allocator, io, reader, diagnostics, path, .{});
    }

    fn validateReaderWithLimits(
        allocator: std.mem.Allocator,
        io: std.Io,
        reader: *std.Io.Reader,
        diagnostics: *DiagnosticSink,
        path: ?[]const u8,
        limits: diagnostic.ResourceLimits,
    ) !void {
        var attributes: [64]Attribute = undefined;

        var parser = xml_parser.Parser.init(allocator, reader, .{
            .attributes = &attributes,
        });
        defer parser.deinit();

        var validator = BinaryValidator.init(allocator, diagnostics, path);
        validator.limits = limits;
        defer validator.deinit();
        _ = io;
        try validator.run(&parser);
    }

    pub fn consumeStart(validator: *BinaryValidator, start: StartElement) !void {
        const element_depth = validator.depth + 1;
        try validator.handleStart(start, element_depth);
        validator.depth += 1;
    }

    pub fn consumeEnd(validator: *BinaryValidator, end: EndElement) !void {
        const element_depth = validator.depth;
        try validator.handleEnd(end, element_depth);
        validator.depth -= 1;
    }

    pub fn consumeText(validator: *BinaryValidator, text: xml_events.Text) !void {
        try validator.handleText(text);
    }

    /// Used by `runValidation` to avoid feeding text to binary unless a payload is open.
    pub fn wantsText(validator: *const BinaryValidator) bool {
        if (validator.binary_array) |state| return state.binary_depth != null;
        return false;
    }

    /// No document-level finalization; kept for symmetry with other validators.
    pub fn finish(validator: *BinaryValidator) !void {
        _ = validator;
    }

    fn run(validator: *BinaryValidator, parser: *xml_parser.Parser) !void {
        while (true) {
            const maybe_event = parser.next() catch |err| {
                try validator.appendDiagnostic(.{
                    .severity = .@"error",
                    .rule = RuleId.mzml_structure_xml,
                    .location = .{ .byte_offset = parser.byteOffset() },
                    .path = validator.path,
                    .message = xml_parse_errors.parseErrorMessage(err),
                });
                return;
            };
            const event = maybe_event orelse break;

            switch (event) {
                .start_element => |start| try validator.consumeStart(start),
                .end_element => |end| try validator.consumeEnd(end),
                .text => |text| try validator.consumeText(text),
            }
        }

        try validator.finish();
    }

    fn handleStart(validator: *BinaryValidator, start: StartElement, element_depth: usize) !void {
        const tag = start.resolvedId();

        if (validator.mzml_depth == null) {
            switch (tag) {
                .indexedmzML => {
                    if (validator.indexed_mzml_depth == null) {
                        validator.indexed_mzml_depth = element_depth;
                    }
                },
                .mzML => {
                    if (validator.indexed_mzml_depth) |indexed_depth| {
                        if (element_depth != indexed_depth + 1) return;
                    }
                    validator.mzml_depth = element_depth;
                },
                else => {},
            }
            return;
        }

        if (!validator.isWithinMzmlScope(element_depth)) return;

        switch (tag) {
            .cv, .userParam => return,
            .spectrum => {
                const dal_attr = start.attr("defaultArrayLength");
                const dal_signed = parseOptionalSchemaInt(dal_attr);
                if (dal_signed) |value| {
                    if (value < 0) {
                        try validator.appendDiagnostic(.{
                            .severity = .@"error",
                            .rule = RuleId.mzml_binary_base64,
                            .location = .{ .byte_offset = start.byte_offset },
                            .path = validator.path,
                            .message = "spectrum defaultArrayLength must be a non-negative integer",
                        });
                    }
                }
                validator.spectrum = .{
                    .kind = .spectrum,
                    .depth = element_depth,
                    .index = parseOptionalUnsigned(start.attr("index")),
                    .default_array_length = if (dal_signed) |value| if (value >= 0) @intCast(value) else null else null,
                    .default_array_length_invalid = dal_attr != null and (dal_signed == null or dal_signed.? < 0),
                };
            },
            .chromatogram => {
                const dal_attr = start.attr("defaultArrayLength");
                const dal_signed = parseOptionalSchemaInt(dal_attr);
                if (dal_signed) |value| {
                    if (value < 0) {
                        try validator.appendDiagnostic(.{
                            .severity = .@"error",
                            .rule = RuleId.mzml_binary_base64,
                            .location = .{ .byte_offset = start.byte_offset },
                            .path = validator.path,
                            .message = "chromatogram defaultArrayLength must be a non-negative integer",
                        });
                    }
                }
                validator.chromatogram = .{
                    .kind = .chromatogram,
                    .depth = element_depth,
                    .index = null,
                    .default_array_length = if (dal_signed) |value| if (value >= 0) @intCast(value) else null else null,
                    .default_array_length_invalid = dal_attr != null and (dal_signed == null or dal_signed.? < 0),
                };
            },
            .binaryDataArray => {
                if (validator.binary_array != null) return;
                const encoded_length = parseOptionalUnsigned(start.attr("encodedLength"));
                const array_length_attr = start.attr("arrayLength");
                const array_length = parseOptionalUnsigned(array_length_attr);
                const array_length_invalid = array_length_attr != null and array_length == null;
                const has_data_processing_ref = start.attr("dataProcessingRef") != null;
                if (validator.spectrum) |owner| {
                    validator.binary_array = BinaryArrayState.init(
                        start.byte_offset,
                        element_depth,
                        owner,
                        encoded_length,
                        array_length,
                        array_length_attr != null,
                        array_length_invalid,
                        has_data_processing_ref,
                    );
                    return;
                }
                if (validator.chromatogram) |owner| {
                    validator.binary_array = BinaryArrayState.init(
                        start.byte_offset,
                        element_depth,
                        owner,
                        encoded_length,
                        array_length,
                        array_length_attr != null,
                        array_length_invalid,
                        has_data_processing_ref,
                    );
                    return;
                }
            },
            .cvParam => {
                if (validator.binary_array) |*state| {
                    if (element_depth != state.depth + 1) return;
                    const accession = start.attr("accession") orelse return;
                    // zmz's reviewed table, which covers every PSI-MS binary data and compression type.
                    if (zmz.model.encodingTerm(accession)) |term| {
                        const data_type: ?BinaryDataType = switch (term) {
                            .compression => |pipeline| {
                                switch (pipeline) {
                                    .zlib => state.saw_zlib_compression = true,
                                    .none => state.saw_no_compression = true,
                                    else => state.saw_unsupported_compression = true,
                                }
                                state.compression_term_count = std.math.add(usize, state.compression_term_count, 1) catch return error.ResourceLimitExceeded;
                                return;
                            },
                            .unsupported => |declaration| switch (declaration) {
                                .compression => {
                                    state.saw_unsupported_compression = true;
                                    state.compression_term_count = std.math.add(usize, state.compression_term_count, 1) catch return error.ResourceLimitExceeded;
                                    return;
                                },
                                // mzValidate checks null-terminated ASCII strings itself.
                                .primitive => if (std.mem.eql(u8, accession, "MS:1001479")) .ascii else null,
                            },
                            .primitive => |primitive| switch (primitive) {
                                .float32 => .float32,
                                .float64 => .float64,
                                .int32 => .int32,
                                .int64 => .int64,
                            },
                        };
                        state.data_type_count = std.math.add(usize, state.data_type_count, 1) catch return error.ResourceLimitExceeded;
                        if (data_type) |selected| {
                            if (state.data_type == null) state.data_type = selected;
                        } else state.saw_unsupported_data_type = true;
                        return;
                    }
                    if (classifyArrayKind(accession)) |array_kind| {
                        state.array_kind_count = std.math.add(usize, state.array_kind_count, 1) catch return error.ResourceLimitExceeded;
                        if (state.array_kind == .unknown) state.array_kind = array_kind;
                        return;
                    }
                }
            },
            .binary => {
                if (validator.binary_array) |*state| {
                    if (element_depth == state.depth + 1) {
                        state.binary_depth = element_depth;
                        state.binary_byte_offset = start.byte_offset;
                        validator.compressed_payload.clearRetainingCapacity();
                        if (state.encoded_length) |encoded_length| {
                            if (encoded_length > validator.maxEncodedBytes()) {
                                try validator.appendDiagnostic(.{
                                    .severity = .@"error",
                                    .rule = RuleId.mzml_binary_oversized,
                                    .location = .{ .byte_offset = start.byte_offset },
                                    .path = validator.path,
                                    .message = "binary payload exceeds the configured encoded-size limit",
                                });
                                state.skipped = true;
                                state.binary_depth = null;
                                return error.ResourceLimitExceeded;
                            }
                            if (state.saw_zlib_compression) {
                                const capacity = base64SizeUpperBound(encoded_length) catch {
                                    try validator.appendDiagnostic(.{
                                        .severity = .@"error",
                                        .rule = RuleId.mzml_binary_oversized,
                                        .location = .{ .byte_offset = start.byte_offset },
                                        .path = validator.path,
                                        .message = "binary payload encoded-size arithmetic overflow",
                                    });
                                    state.skipped = true;
                                    state.binary_depth = null;
                                    return error.ResourceLimitExceeded;
                                };
                                try validator.ensureCompressedCapacity(state, capacity);
                                state.encoded_length = null;
                            }
                        }
                    }
                }
            },
            else => {},
        }
    }

    fn handleEnd(validator: *BinaryValidator, end: EndElement, element_depth: usize) !void {
        if (validator.mzml_depth == null) return;
        if (!validator.isWithinMzmlScope(element_depth)) return;

        const tag = end.resolvedId();

        switch (tag) {
            .binary => {
                if (validator.binary_array) |*state| {
                    if (state.binary_depth == element_depth) {
                        state.binary_depth = null;
                    }
                }
            },
            .binaryDataArray => {
                if (validator.binary_array) |*state| {
                    if (state.depth == element_depth) {
                        defer validator.releaseOneOffScratch();
                        try validator.validateBinaryArray(state);

                        if (state.array_kind == .mz or state.array_kind == .intensity or state.array_kind == .time) {
                            const kind_bit: u3 = switch (state.array_kind) {
                                .mz => 1 << 0,
                                .intensity => 1 << 1,
                                .time => 1 << 2,
                                .unknown, .metadata => unreachable,
                            };
                            if (validator.seen_array_kinds & kind_bit != 0) {
                                try validator.appendDiagnostic(.{
                                    .severity = .@"error",
                                    .rule = RuleId.mzml_binary_type_mismatch,
                                    .location = .{
                                        .byte_offset = state.binary_byte_offset orelse state.byte_offset,
                                        .spectrum_index = state.owner_spectrum_index,
                                    },
                                    .path = validator.path,
                                    .message = "binaryDataArrayList contains duplicate array type",
                                });
                            } else {
                                validator.seen_array_kinds |= kind_bit;
                            }
                        }

                        validator.binary_array = null;
                    }
                }
            },
            .spectrum => {
                if (validator.spectrum) |state| {
                    if (state.depth == element_depth) {
                        validator.spectrum = null;
                        validator.seen_array_kinds = 0;
                    }
                }
            },
            .chromatogram => {
                if (validator.chromatogram) |state| {
                    if (state.depth == element_depth) {
                        validator.chromatogram = null;
                        validator.seen_array_kinds = 0;
                    }
                }
            },
            .mzML => {
                if (validator.mzml_depth == element_depth) {
                    validator.mzml_depth = null;
                }
            },
            else => {},
        }
    }

    fn handleText(validator: *BinaryValidator, text: xml_events.Text) !void {
        if (validator.binary_array) |*state| {
            if (state.binary_depth != null) {
                if (state.saw_zlib_compression and validator.feedDeclaredZlibText(state, text.value)) return;
                const text_len = std.math.add(
                    usize,
                    state.encoded_text_len,
                    countBase64Significant(text.value),
                ) catch {
                    try validator.appendBinaryLimitDiagnostic(state, "binary payload encoded-size arithmetic overflow");
                    state.skipped = true;
                    state.binary_depth = null;
                    return error.ResourceLimitExceeded;
                };
                if (text_len > validator.maxEncodedBytes()) {
                    try validator.appendBinaryLimitDiagnostic(state, "binary payload exceeds the configured encoded-size limit");
                    state.skipped = true;
                    state.binary_depth = null;
                    return error.ResourceLimitExceeded;
                }
                state.encoded_text_len = text_len;
                if (state.saw_zlib_compression) {
                    const capacity = base64SizeUpperBound(text_len) catch {
                        try validator.appendBinaryLimitDiagnostic(state, "binary payload encoded-size arithmetic overflow");
                        state.skipped = true;
                        state.binary_depth = null;
                        return error.ResourceLimitExceeded;
                    };
                    try validator.ensureCompressedCapacity(state, capacity);
                }
                validator.feedBase64(state, text.value) catch |err| switch (err) {
                    error.ResourceLimitExceeded => {
                        try validator.appendBinaryLimitDiagnostic(state, "binary payload decoded-size arithmetic overflow");
                        state.skipped = true;
                        state.binary_depth = null;
                        return error.ResourceLimitExceeded;
                    },
                    else => return err,
                };
            }
        }
    }

    /// Checks and decodes one text chunk: a zlib payload into `compressed_payload`, whose
    /// capacity the caller reserved for every significant character so far; other payloads
    /// through the window, where ASCII arrays are inspected and the rest is discarded.
    fn feedBase64(validator: *BinaryValidator, state: *BinaryArrayState, text: []const u8) !void {
        if (state.base64_failed) return;
        if (state.saw_zlib_compression) {
            state.base64.retarget(validator.compressed_payload.unusedCapacitySlice());
            state.base64.update(text) catch {
                state.base64_failed = true;
                return;
            };
            validator.compressed_payload.items.len += state.base64.take().len;
            return;
        }
        if (validator.base64_window.len == 0) validator.base64_window = try validator.allocator.alloc(u8, base64_window_bytes);
        var rest = text;
        while (rest.len != 0) {
            const piece = @min(rest.len, zmz.base64.Decoder.pieceFor(validator.base64_window.len));
            state.base64.retarget(validator.base64_window);
            state.base64.update(rest[0..piece]) catch {
                state.base64_failed = true;
                return;
            };
            if (state.data_type == .ascii) try state.ascii_stats.inspect(state.base64.take());
            rest = rest[piece..];
        }
    }

    fn feedDeclaredZlibText(validator: *BinaryValidator, state: *BinaryArrayState, chunk: []const u8) bool {
        const declared = state.encoded_length_declared orelse return false;
        // Opening binary clears encoded_length only after reserving the declared output bound.
        if (state.encoded_length != null or state.base64_failed or state.base64.counts.significant_bytes != state.encoded_text_len) return false;
        const remaining = std.math.sub(usize, declared, state.encoded_text_len) catch return false;
        if (chunk.len > remaining) return false;

        const decoder_before = state.base64;
        const output_len_before = validator.compressed_payload.items.len;
        var accepted = false;
        defer if (!accepted) {
            state.base64 = decoder_before;
            validator.compressed_payload.shrinkRetainingCapacity(output_len_before);
        };

        // Clean text (no whitespace, no error) is all significant, so no separate count is needed.
        state.base64.retarget(validator.compressed_payload.unusedCapacitySlice());
        state.base64.update(chunk) catch return false;
        validator.compressed_payload.items.len += state.base64.take().len;
        const expected_sig_len = std.math.add(usize, decoder_before.counts.significant_bytes, chunk.len) catch return false;
        if (state.base64.counts.significant_bytes != expected_sig_len) return false;

        state.encoded_text_len = expected_sig_len;
        accepted = true;
        return true;
    }

    fn validateBinaryArray(validator: *BinaryValidator, state: *const BinaryArrayState) !void {
        if (state.skipped) return;

        const location: diagnostic.Location = .{
            .byte_offset = state.binary_byte_offset orelse state.byte_offset,
            .spectrum_index = state.owner_spectrum_index,
        };

        if (state.encoded_length_declared) |declared| {
            if (declared == 0 and state.encoded_text_len > 0) {
                try validator.appendDiagnostic(.{
                    .severity = .@"error",
                    .rule = RuleId.mzml_binary_length_mismatch,
                    .location = .{ .byte_offset = state.binary_byte_offset orelse state.byte_offset },
                    .path = validator.path,
                    .message = "binaryDataArray declares encodedLength=0 but contains data",
                });
                return;
            }
            if (declared > 0 and state.encoded_text_len == 0) {
                try validator.appendDiagnostic(.{
                    .severity = .@"error",
                    .rule = RuleId.mzml_binary_length_mismatch,
                    .location = location,
                    .path = validator.path,
                    .message = "binary payload is empty but encodedLength declares data",
                });
                return;
            }
            if (declared > 0 and state.encoded_text_len > 0 and declared != state.encoded_text_len) {
                try validator.appendDiagnostic(.{
                    .severity = .@"error",
                    .rule = RuleId.mzml_binary_length_mismatch,
                    .location = location,
                    .path = validator.path,
                    .message = "encodedLength does not match binary payload length",
                });
                return;
            }
        }

        const compression_terms = state.compression_term_count;
        if (compression_terms > 1) {
            try validator.appendDiagnostic(.{
                .severity = .@"error",
                .rule = RuleId.mzml_binary_compression,
                .location = location,
                .path = validator.path,
                .message = "binaryDataArray declares conflicting compression terms",
            });
            return;
        }
        if (state.saw_unsupported_compression) {
            try validator.appendDiagnostic(.{
                .severity = .@"error",
                .rule = RuleId.mzml_binary_compression,
                .location = location,
                .path = validator.path,
                .message = "binaryDataArray declares unsupported compression terms",
            });
            return;
        }
        if (compression_terms == 0) {
            try validator.appendDiagnostic(.{
                .severity = .@"error",
                .rule = RuleId.mzml_binary_compression,
                .location = location,
                .path = validator.path,
                .message = "binaryDataArray is missing a compression type declaration",
            });
            return;
        }

        // Without a declaration, only the completed payload establishes the limit.
        if (state.encoded_length_declared == null) {
            if (state.encoded_text_len > validator.maxEncodedBytes()) {
                try validator.appendDiagnostic(.{
                    .severity = .@"error",
                    .rule = RuleId.mzml_binary_oversized,
                    .location = location,
                    .path = validator.path,
                    .message = "binary payload exceeds the configured encoded-size limit",
                });
                return error.ResourceLimitExceeded;
            }
        }

        if (state.data_type_count > 1) {
            try validator.appendDiagnostic(.{
                .severity = .@"error",
                .rule = RuleId.mzml_binary_type_mismatch,
                .location = location,
                .path = validator.path,
                .message = "binaryDataArray declares more than one binary datatype",
            });
            return;
        }
        if (state.saw_unsupported_data_type) {
            try validator.appendDiagnostic(.{
                .severity = .@"error",
                .rule = RuleId.mzml_binary_type_mismatch,
                .location = location,
                .path = validator.path,
                .message = "binaryDataArray declares an unsupported binary datatype",
            });
            return;
        }
        const data_type = state.data_type orelse {
            try validator.appendDiagnostic(.{
                .severity = .@"error",
                .rule = RuleId.mzml_binary_type_mismatch,
                .location = location,
                .path = validator.path,
                .message = "binaryDataArray is missing a binary datatype declaration",
            });
            return;
        };

        if (state.array_kind_count > 1) {
            try validator.appendDiagnostic(.{
                .severity = .@"error",
                .rule = RuleId.mzml_binary_type_mismatch,
                .location = location,
                .path = validator.path,
                .message = "binaryDataArray declares more than one array type",
            });
            return;
        }

        const default_array = switch (state.owner_kind) {
            .spectrum => state.array_kind == .mz or state.array_kind == .intensity,
            .chromatogram => state.array_kind == .time or state.array_kind == .intensity,
        };
        if (default_array and state.array_length_declared) {
            try validator.appendDiagnostic(.{
                .severity = .@"error",
                .rule = RuleId.mzml_binary_default_array,
                .location = location,
                .path = validator.path,
                .message = "default binary array must not declare arrayLength",
            });
            return;
        }
        if (default_array and state.has_data_processing_ref) {
            try validator.appendDiagnostic(.{
                .severity = .@"error",
                .rule = RuleId.mzml_binary_default_array,
                .location = location,
                .path = validator.path,
                .message = "default binary array must not declare dataProcessingRef",
            });
            return;
        }
        if (state.array_length_invalid) return;
        const expected_array_length = if (!default_array and state.array_length_declared)
            state.array_length
        else if (!state.default_array_length_invalid)
            state.default_array_length
        else
            null;

        var inflated_ascii_stats: AsciiStats = .{};
        const decoded_bytes = blk: {
            if (state.saw_zlib_compression) {
                _ = decodedBase64Bytes(state) catch {
                    try validator.appendDiagnostic(.{
                        .severity = .@"error",
                        .rule = RuleId.mzml_binary_base64,
                        .location = location,
                        .path = validator.path,
                        .message = "binary payload is not valid base64",
                    });
                    return;
                };
                if (state.encoded_text_len == 0) break :blk 0;

                const expected_decoded_bytes = if (data_type.width()) |width|
                    if (expected_array_length) |count|
                        std.math.mul(usize, count, width) catch {
                            try validator.appendDiagnostic(.{
                                .severity = .@"error",
                                .rule = RuleId.mzml_binary_oversized,
                                .location = location,
                                .path = validator.path,
                                .message = "binary payload decoded size exceeds decompressed output limit",
                            });
                            return error.ResourceLimitExceeded;
                        }
                    else
                        null
                else
                    null;
                if (expected_decoded_bytes) |expected| {
                    if (expected > validator.decodedOutputLimit()) {
                        try validator.appendDiagnostic(.{
                            .severity = .@"error",
                            .rule = RuleId.mzml_binary_oversized,
                            .location = location,
                            .path = validator.path,
                            .message = "binary payload decoded size exceeds decompressed output limit",
                        });
                        return error.ResourceLimitExceeded;
                    }
                }
                break :blk (validator.inflateDecodedZlib(
                    validator.compressed_payload.items,
                    expected_decoded_bytes,
                    if (data_type == .ascii) &inflated_ascii_stats else null,
                ) catch |err| switch (err) {
                    error.InvalidBinaryPayload => {
                        try validator.appendDiagnostic(.{
                            .severity = .@"error",
                            .rule = RuleId.mzml_binary_decompress,
                            .location = location,
                            .path = validator.path,
                            .message = "binary payload is not valid zlib data",
                        });
                        return;
                    },
                    error.ResourceLimitExceeded => {
                        try validator.appendDiagnostic(.{
                            .severity = .@"error",
                            .rule = RuleId.mzml_binary_oversized,
                            .location = location,
                            .path = validator.path,
                            .message = "binary payload decoded size arithmetic overflow",
                        });
                        return error.ResourceLimitExceeded;
                    },
                    error.DecodedLimitExceeded => {
                        try validator.appendDiagnostic(.{
                            .severity = .@"error",
                            .rule = RuleId.mzml_binary_oversized,
                            .location = location,
                            .path = validator.path,
                            .message = "binary payload decoded size exceeds the configured limit",
                        });
                        return error.ResourceLimitExceeded;
                    },
                    error.OutOfMemory => |oom| return oom,
                });
            } else {
                break :blk decodedBase64Bytes(state) catch {
                    try validator.appendDiagnostic(.{
                        .severity = .@"error",
                        .rule = RuleId.mzml_binary_base64,
                        .location = location,
                        .path = validator.path,
                        .message = "binary payload is not valid base64",
                    });
                    return;
                };
            }
        };

        if (data_type == .ascii) {
            const ascii_stats = if (state.saw_zlib_compression)
                &inflated_ascii_stats
            else
                &state.ascii_stats;
            if (!ascii_stats.isValid()) {
                try validator.appendDiagnostic(.{
                    .severity = .@"error",
                    .rule = RuleId.mzml_binary_type_mismatch,
                    .location = location,
                    .path = validator.path,
                    .message = "decoded ASCII array contains an invalid byte or unterminated string",
                });
                return;
            }
            if (expected_array_length == null and state.default_array_length_invalid) return;
            if (expected_array_length == null and decoded_bytes > 0) {
                try validator.appendDiagnostic(.{
                    .severity = .@"error",
                    .rule = RuleId.mzml_binary_length_mismatch,
                    .location = location,
                    .path = validator.path,
                    .message = "non-empty binary payload is missing required defaultArrayLength",
                });
                return;
            }
            const declared_count = expected_array_length orelse return;
            if (ascii_stats.terminator_count != declared_count) {
                try validator.appendDiagnostic(.{
                    .severity = .@"error",
                    .rule = RuleId.mzml_binary_length_mismatch,
                    .location = location,
                    .path = validator.path,
                    .message = "decoded ASCII string count does not match effective array length",
                });
            }
            return;
        }

        const width = data_type.width().?;
        const precision = data_type.precision().?;
        if (decoded_bytes % width != 0) {
            try validator.appendDiagnostic(.{
                .severity = .@"error",
                .rule = RuleId.mzml_binary_precision_mismatch,
                .location = location,
                .path = validator.path,
                .message = precisionDivisibilityMessage(precision),
            });
            return;
        }

        const element_count = decoded_bytes / width;
        if (expected_array_length == null and state.default_array_length_invalid) return;
        if (expected_array_length == null and decoded_bytes > 0) {
            try validator.appendDiagnostic(.{
                .severity = .@"error",
                .rule = RuleId.mzml_binary_length_mismatch,
                .location = location,
                .path = validator.path,
                .message = "non-empty binary payload is missing required defaultArrayLength",
            });
            return;
        }
        const declared_count = expected_array_length orelse return;
        if (element_count == declared_count) return;

        const alternate_width: usize = if (width == 4) 8 else 4;
        const alternate_bytes: ?usize = std.math.mul(usize, declared_count, alternate_width) catch null;
        if (declared_count != 0 and alternate_bytes != null and decoded_bytes == alternate_bytes.?) {
            try validator.appendDiagnostic(.{
                .severity = .@"error",
                .rule = RuleId.mzml_binary_precision_mismatch,
                .location = location,
                .path = validator.path,
                .message = precisionDeclaredMismatchMessage(precision),
            });
            return;
        }

        try validator.appendDiagnostic(.{
            .severity = .@"error",
            .rule = RuleId.mzml_binary_length_mismatch,
            .location = location,
            .path = validator.path,
            .message = "decoded array length does not match defaultArrayLength",
        });
    }

    fn isWithinMzmlScope(validator: *BinaryValidator, element_depth: usize) bool {
        if (validator.mzml_depth == null) return false;
        return element_depth >= validator.mzml_depth.?;
    }

    fn inflateDecodedZlib(
        validator: *BinaryValidator,
        compressed: []const u8,
        expected_decoded_bytes: ?usize,
        ascii_stats: ?*AsciiStats,
    ) (error{ InvalidBinaryPayload, OutOfMemory, ResourceLimitExceeded, DecodedLimitExceeded }!usize) {
        // zmz streams the payload in fixed memory, whatever its decoded size.
        if (validator.decompressor == null) validator.decompressor = try zmz.zlib.Decompressor.init(validator.allocator);
        const materialized = if (expected_decoded_bytes) |expected| expected > 0 and expected <= validator.limits.max_binary_materialized_bytes else false;
        return inflateCount(&validator.decompressor.?, compressed, validator.limits.max_binary_decoded_bytes, ascii_stats) catch |err| switch (err) {
            error.InspectionFailed => if (materialized) error.ResourceLimitExceeded else error.DecodedLimitExceeded,
            else => |other| other,
        };
    }

    fn maxEncodedBytes(validator: *const BinaryValidator) usize {
        return @min(validator.limits.max_binary_encoded_bytes, validator.max_binary_size orelse validator.limits.max_binary_encoded_bytes);
    }

    fn decodedOutputLimit(validator: *const BinaryValidator) usize {
        return validator.limits.max_binary_decoded_bytes;
    }

    fn ensureCompressedCapacity(validator: *BinaryValidator, state: *BinaryArrayState, required: usize) !void {
        validator.ensureScratchCapacity(&validator.compressed_payload, required) catch |err| switch (err) {
            error.ResourceLimitExceeded => {
                try validator.appendBinaryLimitDiagnostic(state, "binary scratch exceeds the configured limit");
                state.skipped = true;
                state.binary_depth = null;
                return error.ResourceLimitExceeded;
            },
            else => return err,
        };
    }

    fn appendBinaryLimitDiagnostic(validator: *BinaryValidator, state: *const BinaryArrayState, message: []const u8) !void {
        try validator.appendDiagnostic(.{
            .severity = .@"error",
            .rule = RuleId.mzml_binary_oversized,
            .location = .{
                .byte_offset = state.binary_byte_offset orelse state.byte_offset,
                .spectrum_index = state.owner_spectrum_index,
            },
            .path = validator.path,
            .message = message,
        });
    }

    fn appendDiagnostic(validator: *BinaryValidator, item: Diagnostic) !void {
        @branchHint(.cold);
        _ = try validator.diagnostics.append(validator.allocator, item);
    }
};

fn inflateCount(
    decompressor: *zmz.zlib.Decompressor,
    compressed: []const u8,
    max_output_bytes: usize,
    ascii_stats: ?*AsciiStats,
) error{ InvalidBinaryPayload, DecodedLimitExceeded, InspectionFailed }!usize {
    // zmz checks the header, Adler-32, truncation, and trailing bytes.
    decompressor.start(compressed);
    var count: usize = 0;
    while (decompressor.next(std.math.maxInt(usize)) catch return error.InvalidBinaryPayload) |chunk| {
        count = std.math.add(usize, count, chunk.len) catch return error.DecodedLimitExceeded;
        if (count > max_output_bytes) return error.DecodedLimitExceeded;
        if (ascii_stats) |stats| stats.inspect(chunk) catch return error.InspectionFailed;
    }
    return count;
}

/// The decoded size of a completed payload, or InvalidBase64 for any Base64 error zmz found.
fn decodedBase64Bytes(state: *const BinaryArrayState) error{InvalidBase64}!usize {
    if (state.base64_failed) return error.InvalidBase64;
    var decoder = state.base64;
    const counts = decoder.finish() catch return error.InvalidBase64;
    return counts.decoded_bytes;
}

/// Non-whitespace bytes, valid or not, as encodedLength counts them.
fn countBase64Significant(value: []const u8) usize {
    const Vector = @Vector(base64_simd_chunk_len, u8);
    var count: usize = 0;
    var offset: usize = 0;
    while (value.len - offset >= base64_simd_chunk_len) : (offset += base64_simd_chunk_len) {
        const bytes: Vector = value[offset..][0..base64_simd_chunk_len].*;
        const whitespace = (bytes == @as(Vector, @splat(' '))) | (bytes == @as(Vector, @splat('\t'))) |
            (bytes == @as(Vector, @splat('\r'))) | (bytes == @as(Vector, @splat('\n')));
        count += base64_simd_chunk_len - @popCount(@as(std.meta.Int(.unsigned, base64_simd_chunk_len), @bitCast(whitespace)));
    }
    for (value[offset..]) |byte| {
        switch (byte) {
            ' ', '\t', '\n', '\r' => {},
            else => count += 1,
        }
    }
    return count;
}

fn parseOptionalUnsigned(value: ?[]const u8) ?usize {
    var slice = std.mem.trim(u8, value orelse return null, " \t\r\n");
    if (slice.len > 0 and slice[0] == '+') slice = slice[1..];
    const parsed = std.fmt.parseUnsigned(u64, slice, 10) catch return null;
    return std.math.cast(usize, parsed);
}

fn parseOptionalSchemaInt(value: ?[]const u8) ?i32 {
    const slice = value orelse return null;
    return std.fmt.parseInt(i32, std.mem.trim(u8, slice, " \t\r\n"), 10) catch null;
}

fn base64SizeUpperBound(encoded_len: usize) error{Overflow}!usize {
    if (encoded_len == 0) return 0;
    const rounded = std.math.add(usize, encoded_len, 3) catch return error.Overflow;
    return std.math.mul(usize, rounded / 4, 3) catch error.Overflow;
}

fn classifyArrayKind(accession: []const u8) ?ArrayKind {
    if (std.mem.eql(u8, accession, "MS:1000514")) return .mz;
    if (std.mem.eql(u8, accession, "MS:1000515")) return .intensity;
    if (std.mem.eql(u8, accession, "MS:1000595")) return .time;
    const metadata_accessions = std.StaticStringMap(void).initComptime(.{
        .{ "MS:1000516", {} },
        .{ "MS:1000517", {} },
        .{ "MS:1000617", {} },
        .{ "MS:1000786", {} },
        .{ "MS:1000820", {} },
        .{ "MS:1000821", {} },
        .{ "MS:1000822", {} },
        .{ "MS:1002477", {} },
        .{ "MS:1002478", {} },
        .{ "MS:1002529", {} },
        .{ "MS:1002530", {} },
        .{ "MS:1002742", {} },
        .{ "MS:1002743", {} },
        .{ "MS:1002744", {} },
        .{ "MS:1002745", {} },
        .{ "MS:1002816", {} },
        .{ "MS:1002893", {} },
        .{ "MS:1003006", {} },
        .{ "MS:1003007", {} },
        .{ "MS:1003008", {} },
        .{ "MS:1003143", {} },
        .{ "MS:1003153", {} },
        .{ "MS:1003154", {} },
        .{ "MS:1003155", {} },
        .{ "MS:1003156", {} },
        .{ "MS:1003157", {} },
        .{ "MS:1003158", {} },
    });
    return if (metadata_accessions.has(accession)) .metadata else null;
}

test "[catalog]: binary array-type classifier covers every embedded CV descendant" {
    const obo = @import("../obo/parser.zig");
    var table = try obo.CvTable.init(std.testing.allocator, @embedFile("../data/psi-ms.obo"));
    defer table.deinit();

    var covered: usize = 0;
    var terms = table.map.iterator();
    while (terms.next()) |entry| {
        const term = entry.value_ptr.*;
        if (std.mem.eql(u8, term.accession, "MS:1000513")) continue;
        if (table.isDescendantOf(term.accession, "MS:1000513") != .yes) continue;
        try std.testing.expect(classifyArrayKind(term.accession) != null);
        covered += 1;
    }
    try std.testing.expect(covered > 0);
}

fn precisionDivisibilityMessage(precision: Precision) []const u8 {
    return switch (precision) {
        .bits32 => "decoded payload size is not compatible with declared 32-bit precision",
        .bits64 => "decoded payload size is not compatible with declared 64-bit precision",
    };
}

fn precisionDeclaredMismatchMessage(precision: Precision) []const u8 {
    return switch (precision) {
        .bits32 => "declared 32-bit precision does not match decoded payload size",
        .bits64 => "declared 64-bit precision does not match decoded payload size",
    };
}

// --- Unit tests ---

test "binary validator C.0 parity snapshots fixture diagnostics" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const clean_fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/examples/mzml/single-spectrum-missing-cv-terms.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(clean_fixture);
    try expectBinaryDiagnosticsSnapshot(allocator, io, clean_fixture, &.{});

    const small_fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/valid/small.pwiz.1.1.mzML", allocator, .limited(6 * 1024 * 1024));
    defer allocator.free(small_fixture);
    try expectBinaryDiagnosticsSnapshot(allocator, io, small_fixture, &.{});

    const small_zlib_fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/valid/small_zlib.pwiz.1.1.mzML", allocator, .limited(6 * 1024 * 1024));
    defer allocator.free(small_zlib_fixture);
    try expectBinaryDiagnosticsSnapshot(allocator, io, small_zlib_fixture, &.{});

    const invalid_base64 = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/invalid/invalid-base64.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(invalid_base64);
    try expectBinaryDiagnosticsSnapshot(allocator, io, invalid_base64, &.{
        .{
            .severity = .@"error",
            .rule = RuleId.mzml_binary_base64,
            .byte_offset = binaryTagOffset(invalid_base64, 0),
            .spectrum_index = 0,
            .message = "binary payload is not valid base64",
        },
    });

    const invalid_zlib = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/invalid/invalid-zlib.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(invalid_zlib);
    try expectBinaryDiagnosticsSnapshot(allocator, io, invalid_zlib, &.{
        .{
            .severity = .@"error",
            .rule = RuleId.mzml_binary_decompress,
            .byte_offset = binaryTagOffset(invalid_zlib, 0),
            .spectrum_index = 0,
            .message = "binary payload is not valid zlib data",
        },
    });

    const conflicting_compression = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/invalid/conflicting-compression.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(conflicting_compression);
    try expectBinaryDiagnosticsSnapshot(allocator, io, conflicting_compression, &.{
        .{
            .severity = .@"error",
            .rule = RuleId.mzml_binary_compression,
            .byte_offset = binaryTagOffset(conflicting_compression, 0),
            .spectrum_index = 0,
            .message = "binaryDataArray declares conflicting compression terms",
        },
    });
}

test "binary validator C.0 parity snapshots decision order edge cases" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const missing_compression =
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">" ++
        "<run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\">" ++
        "<spectrumList count=\"1\" defaultDataProcessingRef=\"DP1\">" ++
        "<spectrum index=\"11\" id=\"scan=11\" defaultArrayLength=\"1\">" ++
        "<binaryDataArrayList count=\"1\">" ++
        "<binaryDataArray encodedLength=\"8\">" ++
        "<cvParam accession=\"MS:1000521\"/>" ++
        "<cvParam accession=\"MS:1000515\"/>" ++
        "<binary>AACAPw==</binary>" ++
        "</binaryDataArray></binaryDataArrayList></spectrum>" ++
        "</spectrumList></run></mzML>";
    try expectBinaryDiagnosticsSnapshot(allocator, io, missing_compression, &.{
        .{
            .severity = .@"error",
            .rule = RuleId.mzml_binary_compression,
            .byte_offset = binaryTagOffset(missing_compression, 0),
            .spectrum_index = 11,
            .message = "binaryDataArray is missing a compression type declaration",
        },
    });

    const encoded_zero_with_payload =
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">" ++
        "<run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\">" ++
        "<spectrumList count=\"1\" defaultDataProcessingRef=\"DP1\">" ++
        "<spectrum index=\"12\" id=\"scan=12\" defaultArrayLength=\"1\">" ++
        "<binaryDataArrayList count=\"1\">" ++
        "<binaryDataArray encodedLength=\"0\">" ++
        "<cvParam accession=\"MS:1000521\"/>" ++
        "<cvParam accession=\"MS:1000576\"/>" ++
        "<cvParam accession=\"MS:1000515\"/>" ++
        "<binary>AACAPw==</binary>" ++
        "</binaryDataArray></binaryDataArrayList></spectrum>" ++
        "</spectrumList></run></mzML>";
    try expectBinaryDiagnosticsSnapshot(allocator, io, encoded_zero_with_payload, &.{
        .{
            .severity = .@"error",
            .rule = RuleId.mzml_binary_length_mismatch,
            .byte_offset = binaryTagOffset(encoded_zero_with_payload, 0),
            .spectrum_index = null,
            .message = "binaryDataArray declares encodedLength=0 but contains data",
        },
    });

    const no_default_array_length =
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">" ++
        "<run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\">" ++
        "<spectrumList count=\"1\" defaultDataProcessingRef=\"DP1\">" ++
        "<spectrum index=\"13\" id=\"scan=13\">" ++
        "<binaryDataArrayList count=\"1\">" ++
        "<binaryDataArray encodedLength=\"16\">" ++
        "<cvParam accession=\"MS:1000521\"/>" ++
        "<cvParam accession=\"MS:1000574\"/>" ++
        "<cvParam accession=\"MS:1000515\"/>" ++
        "<binary>eJxjYGBgAAAABAAB</binary>" ++
        "</binaryDataArray></binaryDataArrayList></spectrum>" ++
        "</spectrumList></run></mzML>";
    var no_default_diagnostics: DiagnosticSink = .empty;
    defer no_default_diagnostics.deinit(allocator);
    try runBinaryValidationInto(allocator, io, no_default_array_length, &no_default_diagnostics);
    try expectSingleBinaryDiagnostic(
        no_default_diagnostics.items,
        RuleId.mzml_binary_length_mismatch,
        "non-empty binary payload is missing required defaultArrayLength",
    );
}

test "binary validator rejects non-empty chromatogram without array length" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture =
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">" ++
        "<run id=\"run-1\"><chromatogramList count=\"1\">" ++
        "<chromatogram index=\"0\" id=\"tic=1\"><binaryDataArrayList count=\"1\">" ++
        "<binaryDataArray encodedLength=\"8\">" ++
        "<cvParam accession=\"MS:1000521\"/>" ++
        "<cvParam accession=\"MS:1000576\"/>" ++
        "<cvParam accession=\"MS:1000595\"/>" ++
        "<binary>AAAAAA==</binary></binaryDataArray>" ++
        "</binaryDataArrayList></chromatogram></chromatogramList></run></mzML>";

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try runBinaryValidationInto(allocator, io, fixture, &diagnostics);
    try expectSingleBinaryDiagnostic(
        diagnostics.items,
        RuleId.mzml_binary_length_mismatch,
        "non-empty binary payload is missing required defaultArrayLength",
    );
}

test "Base64 significant-byte count preserves SIMD boundaries" {
    var payload: [base64_simd_chunk_len * 2 + 3]u8 = @splat('A');
    payload[0] = ' ';
    payload[base64_simd_chunk_len - 1] = '\t';
    payload[base64_simd_chunk_len] = '\r';
    payload[payload.len - 1] = '\n';

    try std.testing.expectEqual(payload.len - 4, countBase64Significant(&payload));
}

test "[unit]: declared zlib text derives clean count from decoder" {
    const allocator = std.testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var validator = BinaryValidator.init(allocator, &diagnostics, null);
    defer validator.deinit();
    var state: BinaryArrayState = .{
        .byte_offset = 0,
        .depth = 1,
        .owner_spectrum_index = null,
        .owner_kind = .spectrum,
        .default_array_length = null,
        .default_array_length_invalid = false,
        .encoded_length_declared = 8,
        .saw_zlib_compression = true,
        .binary_depth = 2,
    };
    try validator.ensureCompressedCapacity(&state, try base64SizeUpperBound(8));

    try std.testing.expect(validator.feedDeclaredZlibText(&state, "QUJDREVG"));

    try std.testing.expectEqual(@as(usize, 8), state.encoded_text_len);
    try std.testing.expectEqual(@as(usize, 8), state.base64.counts.significant_bytes);
    try std.testing.expectEqualStrings("ABCDEF", validator.compressed_payload.items);
}

test "[unit]: declared zlib text restores decoder and output for fallback" {
    const allocator = std.testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var validator = BinaryValidator.init(allocator, &diagnostics, null);
    defer validator.deinit();
    var state: BinaryArrayState = .{
        .byte_offset = 0,
        .depth = 1,
        .owner_spectrum_index = null,
        .owner_kind = .spectrum,
        .default_array_length = null,
        .default_array_length_invalid = false,
        .encoded_length_declared = 65,
        .saw_zlib_compression = true,
        .binary_depth = 2,
    };
    try validator.ensureCompressedCapacity(&state, try base64SizeUpperBound(65));

    try std.testing.expect(!validator.feedDeclaredZlibText(&state, "QUJD REVG"));
    try std.testing.expectEqual(@as(usize, 0), state.encoded_text_len);
    try std.testing.expectEqual(@as(usize, 0), state.base64.counts.significant_bytes);
    try std.testing.expectEqual(@as(usize, 0), validator.compressed_payload.items.len);

    var invalid: [65]u8 = @splat('A');
    invalid[64] = '!';
    try std.testing.expect(!validator.feedDeclaredZlibText(&state, &invalid));
    try std.testing.expectEqual(@as(usize, 0), state.encoded_text_len);
    try std.testing.expectEqual(@as(usize, 0), state.base64.counts.significant_bytes);
    try std.testing.expectEqual(@as(usize, 0), validator.compressed_payload.items.len);
}

test "[unit]: binary Base64 larger than the window keeps exact sizes and ASCII counts" {
    const allocator = std.testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var validator = BinaryValidator.init(allocator, &diagnostics, null);
    defer validator.deinit();
    // Strings "a" with their terminators, four windows long once decoded.
    const decoded = try allocator.alloc(u8, base64_window_bytes * 4 + 2);
    defer allocator.free(decoded);
    for (decoded, 0..) |*byte, i| byte.* = if (i % 2 == 0) 'a' else 0;
    const text = try allocator.alloc(u8, try zmz.base64.encodedSize(decoded.len));
    defer allocator.free(text);
    _ = try zmz.base64.encode(text, decoded);

    for ([_]BinaryDataType{ .ascii, .float32 }) |data_type| {
        var state: BinaryArrayState = .{
            .byte_offset = 0,
            .depth = 1,
            .owner_spectrum_index = null,
            .owner_kind = .spectrum,
            .default_array_length = null,
            .default_array_length_invalid = false,
            .data_type = data_type,
        };
        // Text arrives in uneven chunks, as XML events deliver it.
        var rest: []const u8 = text;
        while (rest.len != 0) {
            const chunk = @min(rest.len, 70_001);
            try validator.feedBase64(&state, rest[0..chunk]);
            rest = rest[chunk..];
        }
        try std.testing.expectEqual(decoded.len, try decodedBase64Bytes(&state));
        if (data_type == .ascii) {
            try std.testing.expect(state.ascii_stats.isValid());
            try std.testing.expectEqual(decoded.len / 2, state.ascii_stats.terminator_count);
        }
    }
}

test "[unit]: binary Base64 rejects noncanonical final pad bits" {
    const allocator = std.testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var validator = BinaryValidator.init(allocator, &diagnostics, null);
    defer validator.deinit();
    const cases = [_]struct {
        payload: []const u8,
        valid: bool,
    }{
        .{ .payload = "AA==", .valid = true },
        .{ .payload = "AAA=", .valid = true },
        .{ .payload = "AB==", .valid = false },
        .{ .payload = "AAB=", .valid = false },
        .{ .payload = "AA=A", .valid = false },
        .{ .payload = "AAAAA", .valid = false },
    };

    for (cases) |case| {
        for ([_]bool{ false, true }) |zlib| {
            var state: BinaryArrayState = .{
                .byte_offset = 0,
                .depth = 1,
                .owner_spectrum_index = null,
                .owner_kind = .spectrum,
                .default_array_length = null,
                .default_array_length_invalid = false,
                .saw_zlib_compression = zlib,
            };
            validator.compressed_payload.clearRetainingCapacity();
            if (zlib) try validator.ensureCompressedCapacity(&state, try base64SizeUpperBound(case.payload.len));
            try validator.feedBase64(&state, case.payload);
            if (case.valid) {
                _ = try decodedBase64Bytes(&state);
            } else {
                try std.testing.expectError(error.InvalidBase64, decodedBase64Bytes(&state));
            }
        }
    }
}

test "[unit]: binary validator compares every nonzero encodedLength with significant Base64 length" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixtures = [_][]const u8{
        minimalSpectrumMzmlWithEncodedLength("AACAPw==", 1, "MS:1000576", 4),
        minimalSpectrumMzmlWithEncodedLength("eJxzdIQAAAksAgk=", 2, "MS:1000574", 20),
    };

    try std.testing.expectEqual(@as(?usize, 12), parseOptionalUnsigned(" +12 "));

    for (fixtures) |fixture| {
        var diagnostics = try runBinaryValidation(allocator, io, fixture);
        defer diagnostics.deinit(allocator);

        try expectSingleBinaryDiagnostic(
            diagnostics.items,
            RuleId.mzml_binary_length_mismatch,
            "encodedLength does not match binary payload length",
        );
        try std.testing.expectEqual(@as(?usize, 0), diagnostics.items[0].location.spectrum_index);
    }
}

test "[unit]: binary validator excludes XML whitespace from encodedLength" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixtures = [_][]const u8{
        minimalSpectrumMzmlWithEncodedLength("AA CA\tPw ==\n", 1, "MS:1000576", 8),
        minimalSpectrumMzmlWithEncodedLength("eJxz dIQA\nAAks Agk=", 2, "MS:1000574", 16),
    };

    for (fixtures) |fixture| {
        var diagnostics = try runBinaryValidation(allocator, io, fixture);
        defer diagnostics.deinit(allocator);

        try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
    }
}

test "[unit]: binary validator accepts mixed ordinary and CDATA Base64 text" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixtures = [_][]const u8{
        minimalSpectrumMzmlWithEncodedLength("AA<![CDATA[CA]]>Pw==", 1, "MS:1000576", 8),
        minimalSpectrumMzmlWithEncodedLength("eJxz<![CDATA[dIQA]]>AAksAgk=", 2, "MS:1000574", 16),
    };

    for (fixtures) |fixture| {
        var diagnostics = try runBinaryValidation(allocator, io, fixture);
        defer diagnostics.deinit(allocator);

        try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
    }
}

test "[unit]: binary validator preserves final Base64 checks across reader chunks" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const valid_fixtures = [_][]const u8{
        minimalSpectrumMzmlWithEncodedLength("AACAPw==", 1, "MS:1000576", 8),
        minimalSpectrumMzmlWithEncodedLength("eJxzdIQAAAksAgk=", 2, "MS:1000574", 16),
    };
    const invalid_fixtures = [_][]const u8{
        minimalSpectrumMzmlWithEncodedLength("AAB=", 1, "MS:1000576", 4),
        minimalSpectrumMzmlWithEncodedLength("eJxzdIQAAAksAgl=", 2, "MS:1000574", 16),
    };

    for (1..10) |chunk_size| {
        for (valid_fixtures) |fixture| {
            var diagnostics = try runChunkedBinaryValidation(allocator, io, fixture, chunk_size);
            defer diagnostics.deinit(allocator);

            try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
        }
        for (invalid_fixtures) |fixture| {
            var diagnostics = try runChunkedBinaryValidation(allocator, io, fixture, chunk_size);
            defer diagnostics.deinit(allocator);

            try expectSingleBinaryDiagnostic(
                diagnostics.items,
                RuleId.mzml_binary_base64,
                "binary payload is not valid base64",
            );
        }
    }
}

test "binary validator accepts clean single spectrum fixture" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/examples/mzml/single-spectrum-missing-cv-terms.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "binary validator accepts valid zlib PSI fixture" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/valid/small_zlib.pwiz.1.1.mzML", allocator, .limited(6 * 1024 * 1024));
    defer allocator.free(fixture);

    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "binary validator rejects zlib integrity and trailing-byte mutations" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const paths = [_][]const u8{
        "fixtures/mzml/adversarial/corrupt-adler.mzML",
        "fixtures/mzml/adversarial/truncated-zlib.mzML",
        "fixtures/mzml/adversarial/trailing-zlib.mzML",
    };

    for (paths) |path| {
        const fixture = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(64 * 1024));
        defer allocator.free(fixture);

        var diagnostics = try runBinaryValidation(allocator, io, fixture);
        defer diagnostics.deinit(allocator);

        try expectSingleBinaryDiagnostic(
            diagnostics.items,
            RuleId.mzml_binary_decompress,
            "binary payload is not valid zlib data",
        );
    }
}

test "binary zlib decoding counts within its bound and rejects trailing or corrupt streams" {
    const compressed = [_]u8{
        0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07,
        0x00, 0x06, 0x2c, 0x02, 0x15,
    };
    var decompressor = try zmz.zlib.Decompressor.init(std.testing.allocator);
    defer decompressor.deinit();

    try std.testing.expectEqual(@as(usize, 5), try inflateCount(&decompressor, &compressed, 5, null));
    try std.testing.expectError(error.DecodedLimitExceeded, inflateCount(&decompressor, &compressed, 4, null));

    const with_trailing = compressed ++ [_]u8{0};
    try std.testing.expectError(error.InvalidBinaryPayload, inflateCount(&decompressor, &with_trailing, 5, null));

    var corrupt = compressed;
    corrupt[5] ^= 1;
    try std.testing.expectError(error.InvalidBinaryPayload, inflateCount(&decompressor, &corrupt, 5, null));
}

test "binary zlib decoding keeps no payload-sized scratch" {
    const compressed = [_]u8{
        0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07,
        0x00, 0x06, 0x2c, 0x02, 0x15,
    };
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(std.testing.allocator);

    var validator = BinaryValidator.init(std.testing.allocator, &diagnostics, "fixture");
    defer validator.deinit();

    try std.testing.expectEqual(
        @as(usize, 5),
        try validator.inflateDecodedZlib(&compressed, null, null),
    );
    try std.testing.expectEqual(@as(usize, 0), validator.scratch_current_bytes);
    try std.testing.expectEqual(validator.scratch_current_bytes, validator.scratch_peak_bytes);
}

test "binary zlib validation bounds insufficient materialized output" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = minimalSpectrumMzml("eJzLSM3JyQcABiwCFQ==", 1, "MS:1000574");

    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    try expectSingleBinaryDiagnostic(
        diagnostics.items,
        RuleId.mzml_binary_precision_mismatch,
        "decoded payload size is not compatible with declared 32-bit precision",
    );
}

test "binary validator reports fallback decoded limit" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = minimalSpectrumMzml("eJzLSM3JyQcABiwCFQ==", 1, "MS:1000574");
    var limits = diagnostic.ResourceLimits{};
    limits.max_binary_decoded_bytes = 4;

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try std.testing.expectError(
        error.ResourceLimitExceeded,
        runBinaryValidationIntoWithLimits(allocator, io, fixture, &diagnostics, limits),
    );
    try expectSingleBinaryDiagnostic(
        diagnostics.items,
        RuleId.mzml_binary_oversized,
        "binary payload decoded size exceeds the configured limit",
    );
}

test "binary scratch uses bounded capacity classes and reuses them" {
    var counting_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const allocator = counting_allocator.allocator();
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(std.testing.allocator);

    var validator = BinaryValidator.init(allocator, &diagnostics, "fixture");
    defer validator.deinit();

    try validator.ensureScratchCapacity(&validator.compressed_payload, 1);
    try std.testing.expectEqual(@as(usize, 4 * 1024), validator.compressed_payload.capacity);
    const operations_after_first_growth = counting_allocator.allocations + counting_allocator.resize_index;

    try validator.ensureScratchCapacity(&validator.compressed_payload, 4 * 1024);
    try std.testing.expectEqual(
        operations_after_first_growth,
        counting_allocator.allocations + counting_allocator.resize_index,
    );

    try validator.ensureScratchCapacity(&validator.compressed_payload, 4 * 1024 + 1);
    try std.testing.expectEqual(@as(usize, 16 * 1024), validator.compressed_payload.capacity);

    try validator.ensureScratchCapacity(&validator.compressed_payload, 64 * 1024 + 1);
    try std.testing.expectEqual(@as(usize, 64 * 1024 + 1), validator.compressed_payload.capacity);
    try std.testing.expectEqual(validator.compressed_payload.capacity, validator.scratch_current_bytes);
    try std.testing.expectEqual(validator.scratch_current_bytes, validator.scratch_peak_bytes);
}

test "[unit]: ending a binary array releases only capacities above the reuse bound" {
    const allocator = std.testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var validator = BinaryValidator.init(allocator, &diagnostics, "fixture");
    defer validator.deinit();

    try validator.ensureScratchCapacity(&validator.compressed_payload, max_retained_binary_buffer_bytes);
    validator.mzml_depth = 1;
    validator.binary_array = .{
        .byte_offset = 0,
        .depth = 2,
        .owner_spectrum_index = null,
        .owner_kind = .spectrum,
        .default_array_length = null,
        .default_array_length_invalid = false,
        .skipped = true,
    };

    try validator.handleEnd(.{
        .byte_offset = 0,
        .name = .{ .local_name = "binaryDataArray", .namespace_uri = mzml_namespace },
        .element_id = .binaryDataArray,
    }, 2);

    try std.testing.expectEqual(max_retained_binary_buffer_bytes, validator.compressed_payload.capacity);
    try std.testing.expectEqual(max_retained_binary_buffer_bytes, validator.scratch_current_bytes);

    try validator.ensureScratchCapacity(&validator.compressed_payload, max_retained_binary_buffer_bytes + 1);
    const peak = validator.scratch_peak_bytes;
    validator.binary_array = .{
        .byte_offset = 0,
        .depth = 2,
        .owner_spectrum_index = null,
        .owner_kind = .spectrum,
        .default_array_length = null,
        .default_array_length_invalid = false,
        .skipped = true,
    };

    try validator.handleEnd(.{
        .byte_offset = 0,
        .name = .{ .local_name = "binaryDataArray", .namespace_uri = mzml_namespace },
        .element_id = .binaryDataArray,
    }, 2);

    try std.testing.expect(validator.binary_array == null);
    try std.testing.expectEqual(@as(usize, 0), validator.compressed_payload.capacity);
    try std.testing.expectEqual(@as(usize, 0), validator.scratch_current_bytes);
    try std.testing.expectEqual(max_retained_binary_buffer_bytes + 1, peak);
}

test "binary scratch limit applies to selected capacity class" {
    const allocator = std.testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var validator = BinaryValidator.init(allocator, &diagnostics, "fixture");
    defer validator.deinit();
    validator.limits.max_binary_scratch_bytes = 8 * 1024;

    try validator.ensureScratchCapacity(&validator.compressed_payload, 1);
    try std.testing.expectEqual(@as(usize, 4 * 1024), validator.scratch_current_bytes);
    try std.testing.expectError(
        error.ResourceLimitExceeded,
        validator.ensureScratchCapacity(&validator.compressed_payload, 4 * 1024 + 1),
    );
    try std.testing.expectEqual(@as(usize, 4 * 1024), validator.scratch_current_bytes);
    try std.testing.expectEqual(@as(usize, 4 * 1024), validator.scratch_peak_bytes);
}

test "binary scratch growth failure releases retained capacity" {
    const backing = try std.testing.allocator.alloc(u8, 64 * 1024);
    defer std.testing.allocator.free(backing);
    var fixed = std.heap.FixedBufferAllocator.init(backing);
    var failing_allocator = std.testing.FailingAllocator.init(fixed.allocator(), .{
        .fail_index = 1,
        .resize_fail_index = 0,
    });
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(std.testing.allocator);

    {
        var validator = BinaryValidator.init(failing_allocator.allocator(), &diagnostics, "fixture");
        defer validator.deinit();

        try validator.ensureScratchCapacity(&validator.compressed_payload, 1);
        try std.testing.expectError(
            error.OutOfMemory,
            validator.ensureScratchCapacity(&validator.compressed_payload, 4 * 1024 + 1),
        );
    }

    try std.testing.expect(failing_allocator.has_induced_failure);
    try std.testing.expectEqual(failing_allocator.allocated_bytes, failing_allocator.freed_bytes);
}

test "[unit]: binary decompression preserves scratch allocation failure" {
    const compressed = [_]u8{
        0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07,
        0x00, 0x06, 0x2c, 0x02, 0x15,
    };
    var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{
        .fail_index = 0,
    });
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(std.testing.allocator);

    {
        var validator = BinaryValidator.init(failing_allocator.allocator(), &diagnostics, "fixture");
        defer validator.deinit();
        const expected_bytes: ?usize = 5;
        try std.testing.expectError(
            error.OutOfMemory,
            validator.inflateDecodedZlib(&compressed, expected_bytes, null),
        );
    }

    try std.testing.expect(failing_allocator.has_induced_failure);
    try std.testing.expectEqual(failing_allocator.allocated_bytes, failing_allocator.freed_bytes);
}

test "binary validator accepts valid chromatogram payloads" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const fixture = minimalChromatogramMzml(
        "AAAAAA==",
        "AAAAAA==",
    );

    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "binary validator reports invalid base64 payload" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/invalid/invalid-base64.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_binary_base64, diagnostics.items[0].rule);
    try std.testing.expectEqual(@as(?usize, 0), diagnostics.items[0].location.spectrum_index);
}

test "binary validator reports invalid zlib payload" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/invalid/invalid-zlib.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_binary_decompress, diagnostics.items[0].rule);
}

test "binary validator cvParam with unknown intern id still records zlib compression" {
    const allocator = std.testing.allocator;

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var validator = BinaryValidator.init(allocator, &diagnostics, null);
    defer validator.deinit();

    const a = test_events.attr;
    try validator.consumeStart(test_events.startUnknown("mzML", &.{}, 0));
    try validator.consumeStart(test_events.startUnknown("run", &.{a("id", "run1")}, 10));
    try validator.consumeStart(test_events.startUnknown("spectrumList", &.{a("count", "1")}, 20));
    try validator.consumeStart(test_events.startUnknown("spectrum", &.{ a("index", "0"), a("id", "s1"), a("defaultArrayLength", "1") }, 30));
    try validator.consumeStart(test_events.startUnknown("binaryDataArrayList", &.{a("count", "1")}, 40));
    try validator.consumeStart(test_events.startUnknown("binaryDataArray", &.{a("encodedLength", "12")}, 50));
    try validator.consumeStart(test_events.startUnknown("cvParam", &.{a("accession", "MS:1000521")}, 60));
    try validator.consumeEnd(test_events.endUnknown("cvParam"));
    var zlib_param = test_events.startUnknown("cvParam", &.{a("accession", "MS:1000574")}, 70);
    zlib_param.element_id = .unknown;
    try validator.consumeStart(zlib_param);
    try validator.consumeEnd(test_events.endUnknown("cvParam"));
    try validator.consumeStart(test_events.startUnknown("cvParam", &.{a("accession", "MS:1000515")}, 80));
    try validator.consumeEnd(test_events.endUnknown("cvParam"));
    try validator.consumeStart(test_events.startUnknown("binary", &.{}, 90));
    try validator.consumeText(.{ .byte_offset = 100, .value = "eJxjYGBgAAAA", .from_cdata = false });
    try validator.consumeEnd(test_events.endUnknown("binary"));
    try validator.consumeEnd(test_events.endUnknown("binaryDataArray"));
    try validator.consumeEnd(test_events.endUnknown("binaryDataArrayList"));
    try validator.consumeEnd(test_events.endUnknown("spectrum"));
    try validator.consumeEnd(test_events.endUnknown("spectrumList"));
    try validator.consumeEnd(test_events.endUnknown("run"));
    try validator.consumeEnd(test_events.endUnknown("mzML"));

    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_binary_decompress, diagnostics.items[0].rule);
}

test "binary validator reports precision mismatch" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/invalid/conflicting-precision.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_binary_type_mismatch, diagnostics.items[0].rule);
    try std.testing.expectEqualStrings("binaryDataArray declares more than one binary datatype", diagnostics.items[0].message);
}

test "[unit]: binary datatype declarations do not collapse exact or same-width duplicates" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cases = [_][]const u8{
        "<cvParam accession=\"MS:1000521\"/><cvParam accession=\"MS:1000521\"/>",
        "<cvParam accession=\"MS:1000521\"/><cvParam accession=\"MS:1000519\"/>",
    };

    for (cases) |declarations| {
        const fixture = try std.fmt.allocPrint(
            allocator,
            "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\"><run><spectrumList>" ++
                "<spectrum index=\"0\" defaultArrayLength=\"1\"><binaryDataArrayList>" ++
                "<binaryDataArray encodedLength=\"8\">{s}<cvParam accession=\"MS:1000576\"/>" ++
                "<cvParam accession=\"MS:1000515\"/><binary>AACAPw==</binary>" ++
                "</binaryDataArray></binaryDataArrayList></spectrum></spectrumList></run></mzML>",
            .{declarations},
        );
        defer allocator.free(fixture);

        var diagnostics = try runBinaryValidation(allocator, io, fixture);
        defer diagnostics.deinit(allocator);
        try expectSingleBinaryDiagnostic(
            diagnostics.items,
            RuleId.mzml_binary_type_mismatch,
            "binaryDataArray declares more than one binary datatype",
        );
    }
}

test "[unit]: obsolete embedded 16-bit datatype fails explicitly as unsupported" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture =
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\"><run><spectrumList>" ++
        "<spectrum index=\"0\" defaultArrayLength=\"1\"><binaryDataArrayList>" ++
        "<binaryDataArray encodedLength=\"4\"><cvParam accession=\"MS:1000520\"/>" ++
        "<cvParam accession=\"MS:1000576\"/><cvParam accession=\"MS:1000515\"/>" ++
        "<binary>AAA=</binary></binaryDataArray></binaryDataArrayList>" ++
        "</spectrum></spectrumList></run></mzML>";

    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);
    try expectSingleBinaryDiagnostic(
        diagnostics.items,
        RuleId.mzml_binary_type_mismatch,
        "binaryDataArray declares an unsupported binary datatype",
    );
}

test "[unit]: multiple metadata array types in one binary array fail without semantic validation" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture =
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\"><run><spectrumList>" ++
        "<spectrum index=\"0\" defaultArrayLength=\"1\"><binaryDataArrayList>" ++
        "<binaryDataArray encodedLength=\"8\"><cvParam accession=\"MS:1000521\"/>" ++
        "<cvParam accession=\"MS:1000576\"/><cvParam accession=\"MS:1000516\"/>" ++
        "<cvParam accession=\"MS:1000517\"/><binary>AACAPw==</binary>" ++
        "</binaryDataArray></binaryDataArrayList></spectrum></spectrumList></run></mzML>";

    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);
    try expectSingleBinaryDiagnostic(
        diagnostics.items,
        RuleId.mzml_binary_type_mismatch,
        "binaryDataArray declares more than one array type",
    );
}

test "[unit]: distinct metadata array types remain legal in separate arrays" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture =
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\"><run><spectrumList>" ++
        "<spectrum index=\"0\" defaultArrayLength=\"1\"><binaryDataArrayList>" ++
        "<binaryDataArray encodedLength=\"8\"><cvParam accession=\"MS:1000521\"/>" ++
        "<cvParam accession=\"MS:1000576\"/><cvParam accession=\"MS:1000516\"/>" ++
        "<binary>AACAPw==</binary></binaryDataArray>" ++
        "<binaryDataArray encodedLength=\"8\"><cvParam accession=\"MS:1000521\"/>" ++
        "<cvParam accession=\"MS:1000576\"/><cvParam accession=\"MS:1000517\"/>" ++
        "<binary>AACAPw==</binary></binaryDataArray>" ++
        "</binaryDataArrayList></spectrum></spectrumList></run></mzML>";

    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "[unit]: raw and zlib ASCII metadata arrays validate bytes terminators and string count" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cases = [_]struct {
        compression: []const u8,
        payload: []const u8,
        encoded_length: usize,
    }{
        .{ .compression = "MS:1000576", .payload = "YQBiAA==", .encoded_length = 8 },
        .{ .compression = "MS:1000574", .payload = "eJxLZEhiAAACTADE", .encoded_length = 16 },
    };

    for (cases) |case| {
        const fixture = try asciiMetadataArrayFixture(
            allocator,
            case.compression,
            case.payload,
            case.encoded_length,
            2,
        );
        defer allocator.free(fixture);

        var diagnostics = try runBinaryValidation(allocator, io, fixture);
        defer diagnostics.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
    }
}

test "[unit]: ASCII metadata arrays reject invalid bytes unterminated strings and count mismatch" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cases = [_]struct {
        payload: []const u8,
        array_length: usize,
        rule: []const u8,
        message: []const u8,
    }{
        .{
            .payload = "gAA=",
            .array_length = 1,
            .rule = RuleId.mzml_binary_type_mismatch,
            .message = "decoded ASCII array contains an invalid byte or unterminated string",
        },
        .{
            .payload = "YQ==",
            .array_length = 1,
            .rule = RuleId.mzml_binary_type_mismatch,
            .message = "decoded ASCII array contains an invalid byte or unterminated string",
        },
        .{
            .payload = "YQA=",
            .array_length = 2,
            .rule = RuleId.mzml_binary_length_mismatch,
            .message = "decoded ASCII string count does not match effective array length",
        },
    };

    for (cases) |case| {
        const fixture = try asciiMetadataArrayFixture(
            allocator,
            "MS:1000576",
            case.payload,
            case.payload.len,
            case.array_length,
        );
        defer allocator.free(fixture);

        var diagnostics = try runBinaryValidation(allocator, io, fixture);
        defer diagnostics.deinit(allocator);
        try expectSingleBinaryDiagnostic(diagnostics.items, case.rule, case.message);
    }
}

test "binary validator reports defaultArrayLength mismatch" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const fixture =
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">" ++
        "<run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\">" ++
        "<spectrumList count=\"1\" defaultDataProcessingRef=\"DP1\">" ++
        "<spectrum index=\"9\" id=\"scan=9\" defaultArrayLength=\"2\">" ++
        "<binaryDataArrayList count=\"1\">" ++
        "<binaryDataArray encodedLength=\"8\">" ++
        "<cvParam accession=\"MS:1000521\"/>" ++
        "<cvParam accession=\"MS:1000576\"/>" ++
        "<cvParam accession=\"MS:1000515\"/>" ++
        "<binary>AACAPw==</binary>" ++
        "</binaryDataArray>" ++
        "</binaryDataArrayList>" ++
        "</spectrum>" ++
        "</spectrumList>" ++
        "</run>" ++
        "</mzML>";

    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_binary_length_mismatch, diagnostics.items[0].rule);
    try std.testing.expectEqualStrings("decoded array length does not match defaultArrayLength", diagnostics.items[0].message);
}

test "[unit]: default spectrum array rejects arrayLength override" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture =
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\"><run><spectrumList><spectrum index=\"0\" defaultArrayLength=\"1\">" ++
        "<binaryDataArrayList><binaryDataArray encodedLength=\"8\" arrayLength=\"1\">" ++
        "<cvParam accession=\"MS:1000521\"/><cvParam accession=\"MS:1000576\"/>" ++
        "<cvParam accession=\"MS:1000514\"/><binary>AACAPw==</binary>" ++
        "</binaryDataArray></binaryDataArrayList></spectrum></spectrumList></run></mzML>";

    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    try expectSingleBinaryDiagnostic(
        diagnostics.items,
        RuleId.mzml_binary_default_array,
        "default binary array must not declare arrayLength",
    );
}

test "[unit]: default spectrum array rejects dataProcessingRef override" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture =
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\"><run><spectrumList><spectrum index=\"0\" defaultArrayLength=\"1\">" ++
        "<binaryDataArrayList><binaryDataArray encodedLength=\"8\" dataProcessingRef=\"DP2\">" ++
        "<cvParam accession=\"MS:1000521\"/><cvParam accession=\"MS:1000576\"/>" ++
        "<cvParam accession=\"MS:1000514\"/><binary>AACAPw==</binary>" ++
        "</binaryDataArray></binaryDataArrayList></spectrum></spectrumList></run></mzML>";

    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    try expectSingleBinaryDiagnostic(
        diagnostics.items,
        RuleId.mzml_binary_default_array,
        "default binary array must not declare dataProcessingRef",
    );
}

test "[unit]: default chromatogram time array rejects arrayLength override" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture =
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\"><run><chromatogramList><chromatogram index=\"0\" defaultArrayLength=\"1\">" ++
        "<binaryDataArrayList><binaryDataArray encodedLength=\"8\" arrayLength=\"1\">" ++
        "<cvParam accession=\"MS:1000521\"/><cvParam accession=\"MS:1000576\"/>" ++
        "<cvParam accession=\"MS:1000595\"/><binary>AACAPw==</binary>" ++
        "</binaryDataArray></binaryDataArrayList></chromatogram></chromatogramList></run></mzML>";

    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    try expectSingleBinaryDiagnostic(
        diagnostics.items,
        RuleId.mzml_binary_default_array,
        "default binary array must not declare arrayLength",
    );
}

test "[unit]: non-default arrays may override owner length for raw and zlib payloads" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cases = [_]struct {
        compression: []const u8,
        payload: []const u8,
        encoded_length: usize,
    }{
        .{ .compression = "MS:1000576", .payload = "AACAPw==", .encoded_length = 8 },
        .{ .compression = "MS:1000574", .payload = "eJxjYGBgAAAABAAB", .encoded_length = 16 },
    };

    for (cases) |case| {
        const fixture = try std.fmt.allocPrint(
            allocator,
            "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\"><run><spectrumList><spectrum index=\"0\" defaultArrayLength=\"2\">" ++
                "<binaryDataArrayList><binaryDataArray encodedLength=\"{d}\" arrayLength=\"1\">" ++
                "<cvParam accession=\"MS:1000521\"/><cvParam accession=\"{s}\"/>" ++
                "<cvParam accession=\"MS:1000786\"/><binary>{s}</binary>" ++
                "</binaryDataArray></binaryDataArrayList></spectrum></spectrumList></run></mzML>",
            .{ case.encoded_length, case.compression, case.payload },
        );
        defer allocator.free(fixture);

        var diagnostics = try runBinaryValidation(allocator, io, fixture);
        defer diagnostics.deinit(allocator);

        try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
    }
}

test "binary validator reports empty binary payload when declared length is nonzero" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const fixture = minimalSpectrumMzml("", 1, "MS:1000576");

    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    try expectSingleBinaryDiagnostic(
        diagnostics.items,
        RuleId.mzml_binary_length_mismatch,
        "decoded array length does not match defaultArrayLength",
    );
}

test "binary validator reports empty payload with non-zero encodedLength and no defaultArrayLength" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const fixture =
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">" ++
        "<run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\">" ++
        "<spectrumList count=\"1\" defaultDataProcessingRef=\"DP1\">" ++
        "<spectrum index=\"0\" id=\"scan=1\">" ++
        "<binaryDataArrayList count=\"1\">" ++
        "<binaryDataArray encodedLength=\"8\">" ++
        "<cvParam accession=\"MS:1000521\"/>" ++
        "<cvParam accession=\"MS:1000574\"/>" ++
        "<cvParam accession=\"MS:1000515\"/>" ++
        "<binary/></binaryDataArray>" ++
        "</binaryDataArrayList></spectrum>" ++
        "</spectrumList></run></mzML>";

    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    try expectSingleBinaryDiagnostic(
        diagnostics.items,
        RuleId.mzml_binary_length_mismatch,
        "binary payload is empty but encodedLength declares data",
    );
    try std.testing.expectEqual(@as(?usize, 0), diagnostics.items[0].location.spectrum_index);
}

test "binary validator does not report error for encodedLength=0 with no payload and no defaultArrayLength" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const fixture =
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">" ++
        "<run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\">" ++
        "<spectrumList count=\"1\" defaultDataProcessingRef=\"DP1\">" ++
        "<spectrum index=\"0\" id=\"scan=1\">" ++
        "<binaryDataArrayList count=\"1\">" ++
        "<binaryDataArray encodedLength=\"0\">" ++
        "<cvParam accession=\"MS:1000521\"/>" ++
        "<cvParam accession=\"MS:1000574\"/>" ++
        "<cvParam accession=\"MS:1000515\"/>" ++
        "<binary/></binaryDataArray>" ++
        "</binaryDataArrayList></spectrum>" ++
        "</spectrumList></run></mzML>";

    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "binary validator reports decoded length mismatch after valid zlib decompression" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const fixture = minimalSpectrumMzml("eJxjYGBgAAAABAAB", 2, "MS:1000574");

    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    try expectSingleBinaryDiagnostic(
        diagnostics.items,
        RuleId.mzml_binary_length_mismatch,
        "decoded array length does not match defaultArrayLength",
    );
}

test "binary validator reports conflicting compression terms" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/invalid/conflicting-compression.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_binary_compression, diagnostics.items[0].rule);
    try std.testing.expectEqualStrings("binaryDataArray declares conflicting compression terms", diagnostics.items[0].message);
}

test "[unit]: exact duplicate compression declarations remain conflicting without semantic validation" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture =
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\"><run><spectrumList>" ++
        "<spectrum index=\"0\" defaultArrayLength=\"1\"><binaryDataArrayList>" ++
        "<binaryDataArray encodedLength=\"8\"><cvParam accession=\"MS:1000521\"/>" ++
        "<cvParam accession=\"MS:1000576\"/><cvParam accession=\"MS:1000576\"/>" ++
        "<cvParam accession=\"MS:1000515\"/><binary>AACAPw==</binary>" ++
        "</binaryDataArray></binaryDataArrayList></spectrum></spectrumList></run></mzML>";

    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);
    try expectSingleBinaryDiagnostic(
        diagnostics.items,
        RuleId.mzml_binary_compression,
        "binaryDataArray declares conflicting compression terms",
    );
}

test "binary validator reports unsupported compression terms" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/invalid/unsupported-compression.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_binary_compression, diagnostics.items[0].rule);
    try std.testing.expectEqualStrings("binaryDataArray declares unsupported compression terms", diagnostics.items[0].message);
}

test "[unit]: every newer embedded compression term fails closed as unsupported" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const accessions = [_][]const u8{
        "MS:1003088",
        "MS:1003780",
        "MS:1003781",
        "MS:1003782",
        "MS:1003783",
        "MS:1003784",
        "MS:1003785",
        "MS:1003826",
    };
    inline for (accessions) |accession| {
        const fixture = minimalSpectrumMzml("AACAPw==", 1, accession);
        var diagnostics = try runBinaryValidation(allocator, io, fixture);
        defer diagnostics.deinit(allocator);

        try expectSingleBinaryDiagnostic(
            diagnostics.items,
            RuleId.mzml_binary_compression,
            "binaryDataArray declares unsupported compression terms",
        );
    }
}

test "binary validator reports invalid chromatogram payload without spectrum index" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const fixture = minimalChromatogramMzml(
        "%%%%%%%%",
        "AAAAAA==",
    );

    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    try expectSingleBinaryDiagnostic(
        diagnostics.items,
        RuleId.mzml_binary_base64,
        "binary payload is not valid base64",
    );
    try std.testing.expectEqual(@as(?usize, null), diagnostics.items[0].location.spectrum_index);
}

test "binary validator rejects short and mutated invalid base64 payload matrix" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const payloads = [_][]const u8{
        "%",
        "A",
        "AA=A",
        "A===",
        "AA!A",
        "~!@#",
    };

    inline for (payloads) |payload| {
        const fixture = minimalSpectrumMzml(payload, 1, "MS:1000576");
        var diagnostics = try runBinaryValidation(allocator, io, fixture);
        defer diagnostics.deinit(allocator);

        try expectSingleBinaryDiagnostic(
            diagnostics.items,
            RuleId.mzml_binary_base64,
            "binary payload is not valid base64",
        );
    }
}

test "binary validator reports non-XML payload characters as parser errors" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const payloads = [_][]const u8{ "\x0b", "\x0c" };

    inline for (payloads) |payload| {
        const fixture = minimalSpectrumMzml(payload, 0, "MS:1000576");
        var diagnostics = try runBinaryValidation(allocator, io, fixture);
        defer diagnostics.deinit(allocator);

        try expectSingleBinaryDiagnostic(
            diagnostics.items,
            RuleId.mzml_structure_xml,
            "character is not permitted by the XML version",
        );
    }
}

test "binary validator rejects invalid zlib base64 before inflate" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const payloads = [_][]const u8{
        "%",
        "A",
        "AA=A",
        "A===",
        "AA!A",
        "~!@#",
    };

    inline for (payloads) |payload| {
        const fixture = minimalSpectrumMzml(payload, 1, "MS:1000574");
        var diagnostics = try runBinaryValidation(allocator, io, fixture);
        defer diagnostics.deinit(allocator);

        try expectSingleBinaryDiagnostic(
            diagnostics.items,
            RuleId.mzml_binary_base64,
            "binary payload is not valid base64",
        );
    }
}

test "binary validator rejects truncated and high entropy zlib payload matrix" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const payloads = [_][]const u8{
        "eJxjYGBgAAAA",
        "QUJDREVGR0hJSktM",
        "////////////////",
    };

    inline for (payloads) |payload| {
        const fixture = minimalSpectrumMzml(payload, 1, "MS:1000574");
        var diagnostics = try runBinaryValidation(allocator, io, fixture);
        defer diagnostics.deinit(allocator);

        try expectSingleBinaryDiagnostic(
            diagnostics.items,
            RuleId.mzml_binary_decompress,
            "binary payload is not valid zlib data",
        );
    }
}

test "binary validator repeated clean and corrupt runs do not accumulate diagnostics" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const clean_fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/examples/mzml/single-spectrum-missing-cv-terms.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(clean_fixture);
    const corrupt_fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/invalid/invalid-base64.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(corrupt_fixture);

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    for (0..24) |index| {
        const fixture = if (index % 2 == 0) clean_fixture else corrupt_fixture;
        try runBinaryValidationInto(allocator, io, fixture, &diagnostics);

        if (index % 2 == 0) {
            try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
        } else {
            try expectSingleBinaryDiagnostic(diagnostics.items, RuleId.mzml_binary_base64, null);
        }
    }
}

fn runBinaryValidation(allocator: std.mem.Allocator, io: std.Io, fixture: []const u8) !DiagnosticSink {
    var diagnostics: DiagnosticSink = .empty;
    errdefer diagnostics.deinit(allocator);
    try runBinaryValidationInto(allocator, io, fixture, &diagnostics);
    return diagnostics;
}

fn runBinaryValidationInto(
    allocator: std.mem.Allocator,
    io: std.Io,
    fixture: []const u8,
    diagnostics: *DiagnosticSink,
) !void {
    diagnostics.clearRetainingCapacity();
    var reader = std.Io.Reader.fixed(fixture);
    try BinaryValidator.validateReader(allocator, io, &reader, diagnostics, "fixture");
}

fn runBinaryValidationIntoWithLimits(
    allocator: std.mem.Allocator,
    io: std.Io,
    fixture: []const u8,
    diagnostics: *DiagnosticSink,
    limits: diagnostic.ResourceLimits,
) !void {
    diagnostics.clearRetainingCapacity();
    var reader = std.Io.Reader.fixed(fixture);
    try BinaryValidator.validateReaderWithLimits(allocator, io, &reader, diagnostics, "fixture", limits);
}

const ChunkedBinaryReader = struct {
    reader: std.Io.Reader,
    input: []const u8,
    offset: usize,
    chunk_size: usize,
    buffer: [64]u8 = undefined,

    fn init(reader: *ChunkedBinaryReader, input: []const u8, chunk_size: usize) void {
        reader.* = .{
            .reader = undefined,
            .input = input,
            .offset = 0,
            .chunk_size = chunk_size,
        };
        reader.reader = .{
            .vtable = &.{ .stream = stream },
            .buffer = &reader.buffer,
            .seek = 0,
            .end = 0,
        };
    }

    fn stream(reader: *std.Io.Reader, writer: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const chunked: *ChunkedBinaryReader = @alignCast(@fieldParentPtr("reader", reader));
        if (chunked.offset == chunked.input.len) return error.EndOfStream;
        const available = chunked.input.len - chunked.offset;
        const allowed = limit.toInt() orelse available;
        const count = @min(chunked.chunk_size, @min(available, allowed));
        if (count == 0) return error.EndOfStream;
        try writer.writeAll(chunked.input[chunked.offset..][0..count]);
        chunked.offset += count;
        return count;
    }
};

fn runChunkedBinaryValidation(
    allocator: std.mem.Allocator,
    io: std.Io,
    fixture: []const u8,
    chunk_size: usize,
) !DiagnosticSink {
    var diagnostics: DiagnosticSink = .empty;
    errdefer diagnostics.deinit(allocator);
    var chunked: ChunkedBinaryReader = undefined;
    chunked.init(fixture, chunk_size);
    try BinaryValidator.validateReader(allocator, io, &chunked.reader, &diagnostics, "fixture");
    return diagnostics;
}

fn expectSingleBinaryDiagnostic(diagnostics: []const Diagnostic, expected_rule: []const u8, expected_message: ?[]const u8) !void {
    try std.testing.expectEqual(@as(usize, 1), diagnostics.len);
    try std.testing.expectEqualStrings(expected_rule, diagnostics[0].rule);
    if (expected_message) |message| {
        try std.testing.expectEqualStrings(message, diagnostics[0].message);
    }
}

const ExpectedBinaryDiagnostic = struct {
    severity: diagnostic.Severity,
    rule: []const u8,
    byte_offset: ?u64 = null,
    spectrum_index: ?usize = null,
    path: ?[]const u8 = "fixture",
    message: []const u8,
};

fn expectBinaryDiagnosticsSnapshot(
    allocator: std.mem.Allocator,
    io: std.Io,
    fixture: []const u8,
    expected: []const ExpectedBinaryDiagnostic,
) !void {
    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    try std.testing.expectEqual(expected.len, diagnostics.items.len);
    for (expected, 0..) |want, index| {
        const got = diagnostics.items[index];
        try std.testing.expectEqual(want.severity, got.severity);
        try std.testing.expectEqualStrings(want.rule, got.rule);
        try std.testing.expectEqual(want.byte_offset, got.location.byte_offset);
        try std.testing.expectEqual(want.spectrum_index, got.location.spectrum_index);
        try expectOptionalStringEqual(want.path, got.path);
        try std.testing.expectEqualStrings(want.message, got.message);
    }
}

fn expectOptionalStringEqual(expected: ?[]const u8, actual: ?[]const u8) !void {
    if (expected) |expected_value| {
        if (actual) |actual_value| {
            try std.testing.expectEqualStrings(expected_value, actual_value);
            return;
        }
        try std.testing.expect(false);
        return;
    }
    try std.testing.expect(actual == null);
}

fn binaryTagOffset(fixture: []const u8, occurrence: usize) u64 {
    var cursor: usize = 0;
    var seen: usize = 0;
    while (std.mem.indexOfPos(u8, fixture, cursor, "<binary>")) |pos| {
        if (seen == occurrence) return @intCast(pos);
        seen += 1;
        cursor = pos + "<binary>".len;
    }
    std.debug.panic("missing <binary> occurrence {d} in test fixture", .{occurrence});
}

test "binary validator oversized payload produces diagnostic" {
    const allocator = std.testing.allocator;

    const xml = minimalSpectrumMzml("AAAAAA==", 1, "MS:1000576");

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var validator = BinaryValidator{
        .allocator = allocator,
        .diagnostics = &diagnostics,
        .path = "fixture",
        .max_binary_size = 1,
    };
    defer validator.deinit();

    var reader = std.Io.Reader.fixed(xml);

    var attributes: [64]Attribute = undefined;

    var parser = xml_parser.Parser.init(allocator, &reader, .{
        .attributes = &attributes,
    });
    defer parser.deinit();

    try std.testing.expectError(error.ResourceLimitExceeded, validator.run(&parser));

    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_binary_oversized, diagnostics.items[0].rule);
}

test "binary validator oversized limit is inclusive" {
    const allocator = std.testing.allocator;

    const xml = minimalSpectrumMzml("AAAAAA==", 1, "MS:1000576");

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var validator = BinaryValidator{
        .allocator = allocator,
        .diagnostics = &diagnostics,
        .path = "fixture",
        .max_binary_size = 8,
    };
    defer validator.deinit();

    var reader = std.Io.Reader.fixed(xml);

    var attributes: [64]Attribute = undefined;

    var parser = xml_parser.Parser.init(allocator, &reader, .{
        .attributes = &attributes,
    });
    defer parser.deinit();

    try validator.run(&parser);

    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "binary validator default policy accepts small payloads" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var diagnostics = try runBinaryValidation(allocator, io, minimalSpectrumMzml("AAAAAA==", 1, "MS:1000576"));
    defer diagnostics.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "binary validator rejects huge encodedLength before zlib reservation" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture =
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">" ++
        "<run id=\"run-1\"><spectrumList count=\"1\"><spectrum index=\"0\" defaultArrayLength=\"0\">" ++
        "<binaryDataArrayList count=\"1\"><binaryDataArray encodedLength=\"18446744073709551615\">" ++
        "<cvParam accession=\"MS:1000521\"/><cvParam accession=\"MS:1000574\"/>" ++
        "<binary/></binaryDataArray></binaryDataArrayList></spectrum></spectrumList></run></mzML>";

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try std.testing.expectError(error.ResourceLimitExceeded, runBinaryValidationInto(allocator, io, fixture, &diagnostics));

    try expectSingleBinaryDiagnostic(diagnostics.items, RuleId.mzml_binary_oversized, null);
}

test "[unit]: alternate-width overflow remains an ordinary length mismatch" {
    const allocator = std.testing.allocator;

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var validator = BinaryValidator.init(allocator, &diagnostics, null);
    defer validator.deinit();

    var state: BinaryArrayState = .{
        .byte_offset = 0,
        .depth = 0,
        .owner_spectrum_index = null,
        .owner_kind = .spectrum,
        .default_array_length = std.math.maxInt(usize),
        .default_array_length_invalid = false,
        .encoded_length = 8,
        .encoded_length_declared = 8,
        .encoded_text_len = 8,
        .data_type = .float32,
        .data_type_count = 1,
        .saw_no_compression = true,
        .compression_term_count = 1,
    };
    try validator.feedBase64(&state, "AAAAAA==");

    try validator.validateBinaryArray(&state);

    try expectSingleBinaryDiagnostic(
        diagnostics.items,
        RuleId.mzml_binary_length_mismatch,
        "decoded array length does not match defaultArrayLength",
    );
}

test "[unit]: malformed owner length does not suppress binary payload validation" {
    const allocator = std.testing.allocator;

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var validator = BinaryValidator.init(allocator, &diagnostics, null);
    defer validator.deinit();

    var state: BinaryArrayState = .{
        .byte_offset = 0,
        .depth = 0,
        .owner_spectrum_index = null,
        .owner_kind = .spectrum,
        .default_array_length = null,
        .default_array_length_invalid = true,
        .encoded_length = 4,
        .encoded_length_declared = 4,
        .encoded_text_len = 4,
        .data_type = .float32,
        .data_type_count = 1,
        .saw_no_compression = true,
        .compression_term_count = 1,
    };
    try validator.feedBase64(&state, "%%%%");

    try validator.validateBinaryArray(&state);

    try expectSingleBinaryDiagnostic(diagnostics.items, RuleId.mzml_binary_base64, null);
}

test "binary base64 size upper bound checks arithmetic boundaries" {
    try std.testing.expectEqual(@as(usize, 0), try base64SizeUpperBound(0));
    try std.testing.expectEqual(@as(usize, 3), try base64SizeUpperBound(1));

    const max_valid = (std.math.maxInt(usize) - 3) / 4 * 4;
    try std.testing.expectEqual(max_valid / 4 * 3, try base64SizeUpperBound(max_valid));
    try std.testing.expectError(error.Overflow, base64SizeUpperBound(std.math.maxInt(usize) - 2));
}

test "binary validator rejects zlib decoded size above output cap" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const oversized_count = (diagnostic.ResourceLimits{}).max_binary_decoded_bytes / 4 + 1;

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try std.testing.expectError(
        error.ResourceLimitExceeded,
        runBinaryValidationInto(allocator, io, minimalSpectrumMzml("AAAA", oversized_count, "MS:1000574"), &diagnostics),
    );

    try expectSingleBinaryDiagnostic(
        diagnostics.items,
        RuleId.mzml_binary_oversized,
        "binary payload decoded size exceeds decompressed output limit",
    );
}

test "binary validator accepts multiple uncompressed arrays without scratch state" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var diagnostics = try runBinaryValidation(allocator, io, minimalChromatogramMzml("AAAAAA==", "AAAAAA=="));
    defer diagnostics.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

fn minimalChromatogramMzml(comptime first_payload: []const u8, comptime second_payload: []const u8) []const u8 {
    return "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">" ++
        "<run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\">" ++
        "<chromatogramList count=\"1\" defaultDataProcessingRef=\"DP1\">" ++
        "<chromatogram index=\"0\" id=\"tic=1\" defaultArrayLength=\"1\">" ++
        "<precursor/>" ++
        "<product/>" ++
        "<binaryDataArrayList count=\"2\">" ++
        "<binaryDataArray encodedLength=\"8\">" ++
        "<cvParam accession=\"MS:1000521\"/>" ++
        "<cvParam accession=\"MS:1000576\"/>" ++
        "<cvParam accession=\"MS:1000595\"/>" ++
        "<binary>" ++ first_payload ++ "</binary>" ++
        "</binaryDataArray>" ++
        "<binaryDataArray encodedLength=\"8\">" ++
        "<cvParam accession=\"MS:1000521\"/>" ++
        "<cvParam accession=\"MS:1000576\"/>" ++
        "<cvParam accession=\"MS:1000515\"/>" ++
        "<binary>" ++ second_payload ++ "</binary>" ++
        "</binaryDataArray>" ++
        "</binaryDataArrayList>" ++
        "</chromatogram>" ++
        "</chromatogramList>" ++
        "</run>" ++
        "</mzML>";
}

fn minimalSpectrumMzml(comptime payload: []const u8, comptime default_array_length: usize, comptime compression_accession: []const u8) []const u8 {
    return minimalSpectrumMzmlWithEncodedLength(payload, default_array_length, compression_accession, payload.len);
}

fn minimalSpectrumMzmlWithEncodedLength(
    comptime payload: []const u8,
    comptime default_array_length: usize,
    comptime compression_accession: []const u8,
    comptime encoded_length: usize,
) []const u8 {
    return "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">" ++
        "<run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\">" ++
        "<spectrumList count=\"1\" defaultDataProcessingRef=\"DP1\">" ++
        "<spectrum index=\"0\" id=\"scan=1\" defaultArrayLength=\"" ++ std.fmt.comptimePrint("{d}", .{default_array_length}) ++ "\">" ++
        "<binaryDataArrayList count=\"1\">" ++
        "<binaryDataArray encodedLength=\"" ++ std.fmt.comptimePrint("{d}", .{encoded_length}) ++ "\">" ++
        "<cvParam accession=\"MS:1000521\"/>" ++
        "<cvParam accession=\"" ++ compression_accession ++ "\"/>" ++
        "<cvParam accession=\"MS:1000515\"/>" ++
        "<binary>" ++ payload ++ "</binary>" ++
        "</binaryDataArray>" ++
        "</binaryDataArrayList>" ++
        "</spectrum>" ++
        "</spectrumList>" ++
        "</run>" ++
        "</mzML>";
}

fn asciiMetadataArrayFixture(
    allocator: std.mem.Allocator,
    compression: []const u8,
    payload: []const u8,
    encoded_length: usize,
    array_length: usize,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\"><run><spectrumList>" ++
            "<spectrum index=\"0\" defaultArrayLength=\"1\"><binaryDataArrayList>" ++
            "<binaryDataArray encodedLength=\"{d}\" arrayLength=\"{d}\">" ++
            "<cvParam accession=\"MS:1001479\"/><cvParam accession=\"{s}\"/>" ++
            "<cvParam accession=\"MS:1000786\"/><binary>{s}</binary>" ++
            "</binaryDataArray></binaryDataArrayList></spectrum></spectrumList></run></mzML>",
        .{ encoded_length, array_length, compression, payload },
    );
}

const test_events = @import("test_events.zig");
