//! Binary integrity checks for mzML payloads.
//!
//! Decodes base64, decompresses zlib, and validates array lengths against
//! `defaultArrayLength` and declared precision. Skips materializing the
//! decoded output for uncompressed arrays (streaming base64 counter).
//! For zlib arrays, streams base64 into reusable compressed-byte scratch
//! and counts decompressed bytes without keeping the decoded numeric array.

const std = @import("std");
const build_options = @import("build_options");
const diagnostic = @import("../diagnostic.zig");
const xml_events = @import("../xml/events.zig");
const xml_parser = @import("../xml/parser.zig");
const xml_parse_errors = @import("../xml/parse_errors.zig");
const libdeflate = if (build_options.enable_libdeflate) @cImport({
    @cInclude("libdeflate.h");
}) else struct {};

const Attribute = xml_events.Attribute;
const Diagnostic = diagnostic.Diagnostic;
const EndElement = xml_events.EndElement;
const QName = xml_events.QName;
const RuleId = diagnostic.RuleId;
const StartElement = xml_events.StartElement;

pub const mzml_namespace = diagnostic.mzml_namespace;
const max_binary_token_bytes = 1024 * 1024;
const base64_decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
const base64_simd_chunk_len = 32;
const base64_scalar_short_len = 64;
const flate_buffer_len = 128 * 1024;
const libdeflate_max_output_bytes = 8 * 1024 * 1024;
const LibdeflateDecompressor = if (build_options.enable_libdeflate) libdeflate.libdeflate_decompressor else opaque {};
const OptionalLibdeflateDecompressor = if (build_options.enable_libdeflate) ?*LibdeflateDecompressor else void;

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

const ArrayKind = enum {
    unknown,
    mz,
    intensity,
    time,
};

// Tracks the decoded byte count of a base64 payload across chunked text events.
// No decoded bytes are materialized. Whitespace is ignored per the mzML spec.
const StreamingBase64Counter = struct {
    sig_len: usize = 0,
    padding: usize = 0,
    saw_pad: bool = false,
    errored: bool = false,

    fn feed(self: *@This(), chunk: []const u8) void {
        if (self.errored) return;
        if (chunk.len < base64_scalar_short_len or self.saw_pad) {
            self.feedScalar(chunk);
            return;
        }

        var offset: usize = 0;
        while (offset + base64_simd_chunk_len <= chunk.len) {
            const bytes = loadBase64Chunk(chunk, offset);
            const base64_chars = base64CharLanes(bytes);
            const whitespace = whitespaceLanes(bytes);
            const pre_pad_allowed = base64_chars | whitespace;

            if (@reduce(.And, base64_chars)) {
                self.sig_len += base64_simd_chunk_len;
                offset += base64_simd_chunk_len;
                continue;
            }

            if (@reduce(.And, pre_pad_allowed)) {
                self.sig_len += countTrueLanes(base64_chars);
                offset += base64_simd_chunk_len;
                continue;
            }

            // Padding and errors are rare, but order-sensitive. Let the scalar
            // path preserve the exact pre-SIMD state transition.
            self.feedScalar(chunk[offset..][0..base64_simd_chunk_len]);
            if (self.errored) return;
            offset += base64_simd_chunk_len;
            if (self.saw_pad) {
                self.feedScalar(chunk[offset..]);
                return;
            }
        }

        self.feedScalar(chunk[offset..]);
    }

    fn feedScalar(self: *@This(), chunk: []const u8) void {
        for (chunk) |c| switch (c) {
            ' ', '\t', '\r', '\n' => {},
            'A'...'Z', 'a'...'z', '0'...'9', '+', '/' => {
                if (self.saw_pad) {
                    self.errored = true;
                    return;
                }
                self.sig_len += 1;
            },
            '=' => {
                self.padding += 1;
                self.saw_pad = true;
                self.sig_len += 1;
                if (self.padding > 2) {
                    self.errored = true;
                    return;
                }
            },
            else => {
                self.errored = true;
                return;
            },
        };
    }

    fn loadBase64Chunk(bytes: []const u8, offset: usize) @Vector(base64_simd_chunk_len, u8) {
        var buf: [base64_simd_chunk_len]u8 = undefined;
        @memcpy(&buf, bytes[offset..][0..base64_simd_chunk_len]);
        return buf;
    }

    fn splatByte(byte: u8) @Vector(base64_simd_chunk_len, u8) {
        return @as(@Vector(base64_simd_chunk_len, u8), @splat(byte));
    }

    fn base64CharLanes(bytes: @Vector(base64_simd_chunk_len, u8)) @Vector(base64_simd_chunk_len, bool) {
        const upper = (bytes >= splatByte('A')) & (bytes <= splatByte('Z'));
        const lower = (bytes >= splatByte('a')) & (bytes <= splatByte('z'));
        const digit = (bytes >= splatByte('0')) & (bytes <= splatByte('9'));
        const symbol = (bytes == splatByte('+')) | (bytes == splatByte('/'));
        return upper | lower | digit | symbol;
    }

    fn whitespaceLanes(bytes: @Vector(base64_simd_chunk_len, u8)) @Vector(base64_simd_chunk_len, bool) {
        return (bytes == splatByte(' ')) |
            (bytes == splatByte('\t')) |
            (bytes == splatByte('\r')) |
            (bytes == splatByte('\n'));
    }

    fn countTrueLanes(lanes: @Vector(base64_simd_chunk_len, bool)) usize {
        const values: [base64_simd_chunk_len]bool = lanes;
        var count: usize = 0;
        for (values) |value| {
            count += @intFromBool(value);
        }
        return count;
    }

    fn result(self: *const @This()) error{InvalidBase64}!usize {
        if (self.errored) return error.InvalidBase64;
        if (self.sig_len % 4 != 0) return error.InvalidBase64;
        if (self.sig_len == 0) return 0;
        return (self.sig_len / 4) * 3 - self.padding;
    }
};

// Decodes base64 payload text into compressed bytes as XML text chunks arrive.
// Diagnostics are still emitted later, after the existing declaration checks.
const StreamingBase64Decoder = struct {
    sig_len: usize = 0,
    padding: usize = 0,
    saw_pad: bool = false,
    errored: bool = false,
    quad: [4]u8 = undefined,
    quad_len: usize = 0,

    fn feed(self: *@This(), allocator: std.mem.Allocator, out: *std.ArrayList(u8), chunk: []const u8) !void {
        if (self.errored) return;

        var offset: usize = 0;
        while (offset < chunk.len) {
            if (!self.saw_pad and self.quad_len == 0 and chunk.len - offset >= base64_scalar_short_len) {
                const clean_prefix = cleanBase64DataPrefixLen(chunk[offset..]);
                const bulk_len = clean_prefix - (clean_prefix % 4);
                if (bulk_len >= base64_scalar_short_len) {
                    try self.decodeCleanRun(allocator, out, chunk[offset..][0..bulk_len]);
                    offset += bulk_len;
                    continue;
                }
            }

            try self.feedByte(allocator, out, chunk[offset]);
            offset += 1;
            if (self.errored) return;
        }
    }

    fn feedByte(self: *@This(), allocator: std.mem.Allocator, out: *std.ArrayList(u8), c: u8) !void {
        switch (c) {
            ' ', '\t', '\r', '\n' => {},
            'A'...'Z', 'a'...'z', '0'...'9', '+', '/' => {
                if (self.saw_pad) {
                    self.errored = true;
                    return;
                }
                self.sig_len += 1;
                try self.pushSextet(allocator, out, base64Value(c));
            },
            '=' => {
                self.padding += 1;
                self.saw_pad = true;
                self.sig_len += 1;
                if (self.padding > 2) {
                    self.errored = true;
                    return;
                }
                try self.pushSextet(allocator, out, 0);
            },
            else => {
                self.errored = true;
                return;
            },
        }
    }

    fn finish(self: *const @This()) error{InvalidBase64}!void {
        if (self.errored) return error.InvalidBase64;
        if (self.sig_len % 4 != 0) return error.InvalidBase64;
        if (self.quad_len != 0) return error.InvalidBase64;
    }

    fn pushSextet(self: *@This(), allocator: std.mem.Allocator, out: *std.ArrayList(u8), value: u8) !void {
        self.quad[self.quad_len] = value;
        self.quad_len += 1;
        if (self.quad_len < 4) return;

        try out.append(allocator, (self.quad[0] << 2) | (self.quad[1] >> 4));
        if (self.padding < 2) {
            try out.append(allocator, ((self.quad[1] & 0x0f) << 4) | (self.quad[2] >> 2));
        }
        if (self.padding == 0) {
            try out.append(allocator, ((self.quad[2] & 0x03) << 6) | self.quad[3]);
        }

        self.quad_len = 0;
    }

    fn decodeCleanRun(self: *@This(), allocator: std.mem.Allocator, out: *std.ArrayList(u8), encoded: []const u8) !void {
        std.debug.assert(encoded.len % 4 == 0);

        const decoded_len = (encoded.len / 4) * 3;
        const start = out.items.len;
        try out.resize(allocator, start + decoded_len);
        std.base64.standard.Decoder.decode(out.items[start..][0..decoded_len], encoded) catch unreachable;
        self.sig_len += encoded.len;
    }

    fn cleanBase64DataPrefixLen(bytes: []const u8) usize {
        var offset: usize = 0;
        while (offset + base64_simd_chunk_len <= bytes.len) {
            const chunk = StreamingBase64Counter.loadBase64Chunk(bytes, offset);
            if (!@reduce(.And, StreamingBase64Counter.base64CharLanes(chunk))) break;
            offset += base64_simd_chunk_len;
        }

        while (offset < bytes.len) : (offset += 1) {
            switch (bytes[offset]) {
                'A'...'Z', 'a'...'z', '0'...'9', '+', '/' => {},
                else => break,
            }
        }
        return offset;
    }

    fn base64Value(c: u8) u8 {
        return switch (c) {
            'A'...'Z' => c - 'A',
            'a'...'z' => c - 'a' + 26,
            '0'...'9' => c - '0' + 52,
            '+' => 62,
            '/' => 63,
            else => unreachable,
        };
    }
};

const OwnerState = struct {
    depth: usize,
    index: ?usize,
    default_array_length: ?usize,
};

const BinaryArrayState = struct {
    allocator: std.mem.Allocator,
    byte_offset: u64,
    depth: usize,
    owner_spectrum_index: ?usize,
    default_array_length: ?usize,
    encoded_length: ?usize = null,
    encoded_length_declared: ?usize = null,
    precision: ?Precision = null,
    saw_precision_32: bool = false,
    saw_precision_64: bool = false,
    saw_no_compression: bool = false,
    saw_zlib_compression: bool = false,
    saw_unsupported_compression: bool = false,
    array_kind: ArrayKind = .unknown,
    binary_depth: ?usize = null,
    binary_byte_offset: ?u64 = null,
    base64_stream: StreamingBase64Counter = .{},
    zlib_base64_stream: StreamingBase64Decoder = .{},
    zlib_encoded_len: usize = 0,
    skipped: bool = false,

    fn init(
        allocator: std.mem.Allocator,
        byte_offset: u64,
        depth: usize,
        owner: OwnerState,
        encoded_length: ?usize,
    ) BinaryArrayState {
        return .{
            .allocator = allocator,
            .byte_offset = byte_offset,
            .depth = depth,
            .owner_spectrum_index = owner.index,
            .default_array_length = owner.default_array_length,
            .encoded_length = encoded_length,
            .encoded_length_declared = encoded_length,
        };
    }
};

/// Base64, zlib, and length/precision checks for `binaryDataArray` payloads.
pub const BinaryValidator = struct {
    allocator: std.mem.Allocator,
    diagnostics: *std.ArrayList(Diagnostic),
    path: ?[]const u8,
    max_binary_size: ?usize = null,

    // Only one active binary array at a time. No accumulation across spectra.
    depth: usize = 0,
    indexed_mzml_depth: ?usize = null,
    mzml_depth: ?usize = null,
    spectrum: ?OwnerState = null,
    chromatogram: ?OwnerState = null,
    binary_array: ?BinaryArrayState = null,

    /// Compressed zlib bytes decoded from base64 as text chunks arrive.
    /// Cleared with `clearRetainingCapacity` at the start of each binary element.
    compressed_payload: std.ArrayList(u8) = .empty,
    flate_buffer: std.ArrayList(u8) = .empty,
    libdeflate_output: std.ArrayList(u8) = .empty,
    libdeflate_decompressor: OptionalLibdeflateDecompressor = if (build_options.enable_libdeflate) null else {},

    pub fn init(
        allocator: std.mem.Allocator,
        diagnostics: *std.ArrayList(Diagnostic),
        path: ?[]const u8,
    ) BinaryValidator {
        return .{
            .allocator = allocator,
            .diagnostics = diagnostics,
            .path = path,
        };
    }

    pub fn deinit(validator: *BinaryValidator) void {
        if (comptime build_options.enable_libdeflate) {
            if (validator.libdeflate_decompressor) |decompressor| {
                libdeflate.libdeflate_free_decompressor(decompressor);
            }
        }
        validator.compressed_payload.deinit(validator.allocator);
        validator.flate_buffer.deinit(validator.allocator);
        validator.libdeflate_output.deinit(validator.allocator);
        validator.* = undefined;
    }

    // Prevent a single oversized array from hogging scratch capacity.
    // Only kicks in when capacity > 1 MiB AND 4x the actual data.
    fn maybeShrinkScratch(validator: *BinaryValidator) void {
        validator.maybeShrinkPayload(&validator.compressed_payload, validator.compressed_payload.items.len);
        validator.maybeShrinkPayload(&validator.libdeflate_output, validator.libdeflate_output.items.len);
    }

    fn maybeShrinkPayload(validator: *BinaryValidator, payload: *std.ArrayList(u8), used: usize) void {
        if (used == 0) return;
        const min_threshold: usize = 1024 * 1024; // 1 MiB
        const max_headroom: usize = 4;
        if (payload.capacity > min_threshold and
            payload.capacity > used * max_headroom)
        {
            payload.shrinkAndFree(validator.allocator, used);
        }
    }

    pub fn validateReader(
        allocator: std.mem.Allocator,
        io: std.Io,
        reader: *std.Io.Reader,
        diagnostics: *std.ArrayList(Diagnostic),
        path: ?[]const u8,
    ) !void {
        const token_buffer = try allocator.alloc(u8, max_binary_token_bytes);
        defer allocator.free(token_buffer);

        var attributes: [64]Attribute = undefined;
        var namespace_bindings: [32]xml_parser.NamespaceBinding = undefined;
        var namespace_bytes: [2048]u8 = undefined;
        var element_stack: [128]xml_parser.ElementFrame = undefined;
        var element_bytes: [4096]u8 = undefined;

        var parser = xml_parser.Parser.init(reader, .{
            .token = token_buffer,
            .attributes = &attributes,
            .namespace_bindings = &namespace_bindings,
            .namespace_bytes = &namespace_bytes,
            .element_stack = &element_stack,
            .element_bytes = &element_bytes,
        });

        var validator = BinaryValidator.init(allocator, diagnostics, path);
        defer validator.deinit();
        try validator.run(io, &parser);
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
        try validator.handleText(text.value);
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

    fn run(validator: *BinaryValidator, io: std.Io, parser: *xml_parser.Parser) !void {
        _ = io;

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
                const index_attr = xml_events.attributeByLocalName(start.attributes, "index");
                const dal_attr = xml_events.attributeByLocalName(start.attributes, "defaultArrayLength");
                const index = parseOptionalUnsigned(index_attr);
                const dal = parseOptionalUnsigned(dal_attr);
                if (index_attr != null and index == null) {
                    try validator.appendDiagnostic(.{
                        .severity = .@"error",
                        .rule = RuleId.mzml_binary_base64,
                        .location = .{ .byte_offset = start.byte_offset },
                        .path = validator.path,
                        .message = "spectrum index must be a non-negative integer",
                    });
                }
                if (dal_attr != null and dal == null) {
                    try validator.appendDiagnostic(.{
                        .severity = .@"error",
                        .rule = RuleId.mzml_binary_base64,
                        .location = .{ .byte_offset = start.byte_offset },
                        .path = validator.path,
                        .message = "spectrum defaultArrayLength must be a non-negative integer",
                    });
                }
                validator.spectrum = .{
                    .depth = element_depth,
                    .index = index,
                    .default_array_length = dal,
                };
            },
            .chromatogram => {
                const dal_attr = xml_events.attributeByLocalName(start.attributes, "defaultArrayLength");
                const dal = parseOptionalUnsigned(dal_attr);
                if (dal_attr != null and dal == null) {
                    try validator.appendDiagnostic(.{
                        .severity = .@"error",
                        .rule = RuleId.mzml_binary_base64,
                        .location = .{ .byte_offset = start.byte_offset },
                        .path = validator.path,
                        .message = "chromatogram defaultArrayLength must be a non-negative integer",
                    });
                }
                validator.chromatogram = .{
                    .depth = element_depth,
                    .index = null,
                    .default_array_length = dal,
                };
            },
            .binaryDataArray => {
                if (validator.binary_array != null) return;
                const enc_attr = xml_events.attributeByLocalName(start.attributes, "encodedLength");
                const encoded_length = parseOptionalUnsigned(enc_attr);
                if (enc_attr != null and encoded_length == null) {
                    try validator.appendDiagnostic(.{
                        .severity = .@"error",
                        .rule = RuleId.mzml_binary_base64,
                        .location = .{ .byte_offset = start.byte_offset },
                        .path = validator.path,
                        .message = "binaryDataArray encodedLength must be a non-negative integer",
                    });
                }
                if (validator.spectrum) |owner| {
                    validator.binary_array = BinaryArrayState.init(validator.allocator, start.byte_offset, element_depth, owner, encoded_length);
                    return;
                }
                if (validator.chromatogram) |owner| {
                    validator.binary_array = BinaryArrayState.init(validator.allocator, start.byte_offset, element_depth, owner, encoded_length);
                    return;
                }
            },
            .cvParam => {
                if (validator.binary_array) |*state| {
                    if (element_depth != state.depth + 1) return;
                    const accession = xml_events.attributeByLocalName(start.attributes, "accession") orelse return;
                    if (std.mem.eql(u8, accession, "MS:1000574")) {
                        state.saw_zlib_compression = true;
                        return;
                    }
                    if (std.mem.eql(u8, accession, "MS:1000576")) {
                        state.saw_no_compression = true;
                        return;
                    }
                    if (std.mem.startsWith(u8, accession, "MS:") and isCompressionAccession(accession)) {
                        state.saw_unsupported_compression = true;
                        return;
                    }
                    if (std.mem.eql(u8, accession, "MS:1000521") or std.mem.eql(u8, accession, "MS:1000519")) {
                        state.saw_precision_32 = true;
                        return;
                    }
                    if (std.mem.eql(u8, accession, "MS:1000523") or std.mem.eql(u8, accession, "MS:1000522")) {
                        state.saw_precision_64 = true;
                        return;
                    }
                    if (std.mem.eql(u8, accession, "MS:1000514")) {
                        state.array_kind = .mz;
                        return;
                    }
                    if (std.mem.eql(u8, accession, "MS:1000515")) {
                        state.array_kind = .intensity;
                        return;
                    }
                    if (std.mem.eql(u8, accession, "MS:1000595")) {
                        state.array_kind = .time;
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
                            if (encoded_length == 0) {
                                // encodedLength=0 is suspicious; allow it but flag
                                // if the actual payload is non-empty (caught below).
                            }
                            if (validator.max_binary_size) |max_size| {
                                if (encoded_length > max_size) {
                                    try validator.appendDiagnostic(.{
                                        .severity = .@"error",
                                        .rule = RuleId.mzml_binary_oversized,
                                        .location = .{ .byte_offset = start.byte_offset },
                                        .path = validator.path,
                                        .message = "binary payload exceeds -max-binary-size limit",
                                    });
                                    state.skipped = true;
                                    state.binary_depth = null;
                                    return;
                                }
                            }
                            if (state.saw_zlib_compression) {
                                try validator.compressed_payload.ensureTotalCapacity(
                                    validator.allocator,
                                    base64_decoder.calcSizeUpperBound(encoded_length),
                                );
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
                        try validator.validateBinaryArray(state);
                        validator.maybeShrinkScratch();
                        validator.binary_array = null;
                    }
                }
            },
            .spectrum => {
                if (validator.spectrum) |state| {
                    if (state.depth == element_depth) validator.spectrum = null;
                }
            },
            .chromatogram => {
                if (validator.chromatogram) |state| {
                    if (state.depth == element_depth) validator.chromatogram = null;
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

    fn handleText(validator: *BinaryValidator, value: []const u8) !void {
        if (validator.binary_array) |*state| {
            if (state.binary_depth != null) {
                if (state.saw_zlib_compression) {
                    state.zlib_encoded_len += value.len;
                    try state.zlib_base64_stream.feed(validator.allocator, &validator.compressed_payload, value);
                } else {
                    state.base64_stream.feed(value);
                }
            }
        }
    }

    fn validateBinaryArray(validator: *BinaryValidator, state: *const BinaryArrayState) !void {
        if (state.skipped) return;

        // Check encodedLength sanity: if declared as 0 but we have content.
        if (state.encoded_length_declared) |declared| {
            const has_content = if (state.saw_zlib_compression)
                state.zlib_encoded_len > 0
            else
                state.base64_stream.sig_len > 0;
            if (declared == 0 and has_content) {
                try validator.appendDiagnostic(.{
                    .severity = .@"error",
                    .rule = RuleId.mzml_binary_length_mismatch,
                    .location = .{ .byte_offset = state.binary_byte_offset orelse state.byte_offset },
                    .path = validator.path,
                    .message = "binaryDataArray declares encodedLength=0 but contains data",
                });
                return;
            }
        }

        const location: diagnostic.Location = .{
            .byte_offset = state.binary_byte_offset orelse state.byte_offset,
            .spectrum_index = state.owner_spectrum_index,
        };

        const compression_terms: u8 =
            @as(u8, @intFromBool(state.saw_no_compression)) +
            @as(u8, @intFromBool(state.saw_zlib_compression)) +
            @as(u8, @intFromBool(state.saw_unsupported_compression));
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
                .severity = .info,
                .rule = RuleId.mzml_binary_compression,
                .location = location,
                .path = validator.path,
                .message = "binaryDataArray is missing a compression type declaration",
            });
        }

        // If encodedLength was omitted, the early oversized check in
        // handleStart was skipped. Check actual payload size here.
        if (state.encoded_length_declared == null) {
            if (validator.max_binary_size) |max_size| {
                const actual = if (state.saw_zlib_compression)
                    state.zlib_encoded_len
                else
                    state.base64_stream.sig_len;
                if (actual > max_size) {
                    try validator.appendDiagnostic(.{
                        .severity = .@"error",
                        .rule = RuleId.mzml_binary_oversized,
                        .location = location,
                        .path = validator.path,
                        .message = "binary payload exceeds -max-binary-size limit",
                    });
                    return;
                }
            }
        }

        const precision = blk: {
            if (state.saw_precision_32 and state.saw_precision_64) {
                try validator.appendDiagnostic(.{
                    .severity = .@"error",
                    .rule = RuleId.mzml_binary_precision_mismatch,
                    .location = location,
                    .path = validator.path,
                    .message = "binaryDataArray declares conflicting 32-bit and 64-bit precision",
                });
                return;
            }
            if (state.saw_precision_32) break :blk Precision.bits32;
            if (state.saw_precision_64) break :blk Precision.bits64;
            try validator.appendDiagnostic(.{
                .severity = .@"error",
                .rule = RuleId.mzml_binary_precision_mismatch,
                .location = location,
                .path = validator.path,
                .message = "binaryDataArray is missing declared 32-bit or 64-bit precision",
            });
            return;
        };

        const width = precision.width();

        const decoded_bytes = blk: {
            if (state.saw_zlib_compression) {
                state.zlib_base64_stream.finish() catch {
                    try validator.appendDiagnostic(.{
                        .severity = .@"error",
                        .rule = RuleId.mzml_binary_base64,
                        .location = location,
                        .path = validator.path,
                        .message = "binary payload is not valid base64",
                    });
                    return;
                };
                if (state.zlib_encoded_len == 0) break :blk 0;

                const expected_decoded_bytes = if (state.default_array_length) |count|
                    std.math.mul(usize, count, width) catch null
                else
                    null;
                break :blk (validator.inflateDecodedZlib(validator.compressed_payload.items, expected_decoded_bytes) catch |err| switch (err) {
                    error.InvalidBase64 => {
                        try validator.appendDiagnostic(.{
                            .severity = .@"error",
                            .rule = RuleId.mzml_binary_base64,
                            .location = location,
                            .path = validator.path,
                            .message = "binary payload is not valid base64",
                        });
                        return;
                    },
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
                    error.OutOfMemory => |oom| return oom,
                });
            } else {
                break :blk state.base64_stream.result() catch {
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

        // Empty payload with a non-zero encodedLength is always a mismatch:
        // something declared data that never arrived.
        if (decoded_bytes == 0) {
            if (state.encoded_length_declared) |declared| {
                if (declared > 0) {
                    try validator.appendDiagnostic(.{
                        .severity = .@"error",
                        .rule = RuleId.mzml_binary_length_mismatch,
                        .location = location,
                        .path = validator.path,
                        .message = "binary payload is empty but encodedLength declares data",
                    });
                    return;
                }
            }
        }

        const element_count = decoded_bytes / width;
        // TODO: missing defaultArrayLength lets non-empty payloads slip through unchecked.
        const declared_count = state.default_array_length orelse return;
        if (element_count == declared_count) return;

        const alternate_width: usize = if (width == 4) 8 else 4;
        if (declared_count != 0 and decoded_bytes == declared_count * alternate_width) {
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

    fn inflateDecodedZlib(validator: *BinaryValidator, compressed: []const u8, expected_decoded_bytes: ?usize) (error{ InvalidBase64, InvalidBinaryPayload, OutOfMemory }!usize) {
        if (comptime build_options.enable_libdeflate) {
            if (expected_decoded_bytes) |expected| {
                if (expected <= libdeflate_max_output_bytes) {
                    if (try validator.inflateWithLibdeflate(compressed, expected)) |decoded_bytes| {
                        return decoded_bytes;
                    }
                }
            }
        }

        try validator.flate_buffer.resize(validator.allocator, flate_buffer_len);
        return inflateCountWithBuffer(compressed, validator.flate_buffer.items);
    }

    fn inflateWithLibdeflate(validator: *BinaryValidator, compressed: []const u8, expected_decoded_bytes: usize) (error{ InvalidBinaryPayload, OutOfMemory }!?usize) {
        if (comptime build_options.enable_libdeflate) {
            const decompressor = try validator.ensureLibdeflateDecompressor();
            try validator.libdeflate_output.resize(validator.allocator, expected_decoded_bytes);

            var actual_in: usize = 0;
            var actual_out: usize = 0;
            const output_ptr = if (expected_decoded_bytes == 0) null else validator.libdeflate_output.items.ptr;
            const result = libdeflate.libdeflate_zlib_decompress_ex(
                decompressor,
                compressed.ptr,
                compressed.len,
                output_ptr,
                expected_decoded_bytes,
                &actual_in,
                &actual_out,
            );

            return switch (result) {
                libdeflate.LIBDEFLATE_SUCCESS => if (actual_in == compressed.len and actual_out == expected_decoded_bytes)
                    expected_decoded_bytes
                else
                    null,
                libdeflate.LIBDEFLATE_BAD_DATA => error.InvalidBinaryPayload,
                libdeflate.LIBDEFLATE_SHORT_OUTPUT, libdeflate.LIBDEFLATE_INSUFFICIENT_SPACE => null,
                else => error.InvalidBinaryPayload,
            };
        }

        unreachable;
    }

    fn ensureLibdeflateDecompressor(validator: *BinaryValidator) error{OutOfMemory}!*LibdeflateDecompressor {
        if (comptime build_options.enable_libdeflate) {
            if (validator.libdeflate_decompressor) |decompressor| return decompressor;
            const decompressor = libdeflate.libdeflate_alloc_decompressor() orelse return error.OutOfMemory;
            validator.libdeflate_decompressor = decompressor;
            return decompressor;
        }

        unreachable;
    }

    fn appendDiagnostic(validator: *BinaryValidator, item: Diagnostic) !void {
        try validator.diagnostics.append(validator.allocator, item);
    }
};

// Streaming inflate: decompresses zlib data and returns the decoded byte count
// without materializing the decompressed output. Uses a small stack buffer.
fn inflateCount(compressed: []const u8) error{InvalidBinaryPayload}!usize {
    var flate_buffer: [std.compress.flate.max_window_len]u8 = undefined;
    return inflateCountWithBuffer(compressed, &flate_buffer);
}

fn inflateCountWithBuffer(compressed: []const u8, flate_buffer: []u8) error{InvalidBinaryPayload}!usize {
    var input = std.Io.Reader.fixed(compressed);
    var decompress: std.compress.flate.Decompress = .init(&input, .zlib, flate_buffer);

    var count: usize = 0;
    const max_peek = flate_buffer.len - std.compress.flate.history_len;
    while (true) {
        const slice = decompress.reader.peekGreedy(max_peek) catch |err| switch (err) {
            error.EndOfStream => {
                count += decompress.reader.buffered().len;
                break;
            },
            else => return error.InvalidBinaryPayload,
        };
        if (slice.len == 0) break;
        count += slice.len;
        decompress.reader.toss(slice.len);
    }
    return count;
}

fn parseOptionalUnsigned(value: ?[]const u8) ?usize {
    const slice = value orelse return null;
    return std.fmt.parseUnsigned(usize, slice, 10) catch null;
}

// Recognise unsupported compression types so we can report them instead
// of silently treating them as "no compression".
fn isCompressionAccession(accession: []const u8) bool {
    return std.mem.eql(u8, accession, "MS:1000574") or
        std.mem.eql(u8, accession, "MS:1000576") or
        std.mem.eql(u8, accession, "MS:1002312") or
        std.mem.eql(u8, accession, "MS:1002313") or
        std.mem.eql(u8, accession, "MS:1002314") or
        std.mem.eql(u8, accession, "MS:1002746") or
        std.mem.eql(u8, accession, "MS:1002747") or
        std.mem.eql(u8, accession, "MS:1002748") or
        std.mem.eql(u8, accession, "MS:1003089") or
        std.mem.eql(u8, accession, "MS:1003090");
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

const test_events = @import("test_events.zig");

// Tests: valid fixtures.

test "binary validator C.0 parity snapshots fixture diagnostics" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const clean_fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/examples/mzml/clean-single-spectrum.mzML", allocator, .limited(64 * 1024));
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
            .spectrum_index = 7,
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
            .spectrum_index = 4,
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
            .spectrum_index = 3,
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
            .severity = .info,
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
        "<binaryDataArray encodedLength=\"8\">" ++
        "<cvParam accession=\"MS:1000521\"/>" ++
        "<cvParam accession=\"MS:1000576\"/>" ++
        "<cvParam accession=\"MS:1000515\"/>" ++
        "<binary>AACAPw==</binary>" ++
        "</binaryDataArray></binaryDataArrayList></spectrum>" ++
        "</spectrumList></run></mzML>";
    try expectBinaryDiagnosticsSnapshot(allocator, io, no_default_array_length, &.{});
}

test "streaming base64 counter C.2 scalar short path stays exact" {
    var counter: StreamingBase64Counter = .{};
    counter.feed("AAAAAA==");

    try std.testing.expectEqual(@as(usize, 8), counter.sig_len);
    try std.testing.expectEqual(@as(usize, 2), counter.padding);
    try std.testing.expectEqual(@as(usize, 4), try counter.result());
}

test "streaming base64 counter C.1 SIMD counts long clean and whitespace runs" {
    var payload: [160]u8 = undefined;
    @memset(payload[0..64], 'A');
    payload[64] = '\n';
    payload[65] = '\t';
    @memset(payload[66..130], 'A');
    payload[130] = '\r';
    payload[131] = ' ';
    @memset(payload[132..160], 'A');

    var counter: StreamingBase64Counter = .{};
    counter.feed(&payload);

    try std.testing.expectEqual(@as(usize, 156), counter.sig_len);
    try std.testing.expectEqual(@as(usize, 0), counter.padding);
    try std.testing.expectEqual(@as(usize, 117), try counter.result());
}

test "streaming base64 counter C.1 SIMD preserves padding boundary behavior" {
    var payload: [64]u8 = undefined;
    @memset(&payload, 'A');
    payload[62] = '=';
    payload[63] = '=';

    var counter: StreamingBase64Counter = .{};
    counter.feed(&payload);

    try std.testing.expectEqual(@as(usize, 64), counter.sig_len);
    try std.testing.expectEqual(@as(usize, 2), counter.padding);
    try std.testing.expectEqual(@as(usize, 46), try counter.result());
}

test "streaming base64 counter C.1 SIMD rejects valid data after padding" {
    var payload: [65]u8 = undefined;
    @memset(&payload, 'A');
    payload[62] = '=';
    payload[63] = '=';
    payload[64] = 'A';

    var counter: StreamingBase64Counter = .{};
    counter.feed(&payload);

    try std.testing.expect(counter.errored);
    try std.testing.expectError(error.InvalidBase64, counter.result());
}

test "streaming base64 counter C.1 SIMD rejects invalid byte after counted prefix" {
    var payload: [96]u8 = undefined;
    @memset(&payload, 'A');
    payload[70] = '!';

    var counter: StreamingBase64Counter = .{};
    counter.feed(&payload);

    try std.testing.expect(counter.errored);
    try std.testing.expectError(error.InvalidBase64, counter.result());
}

test "streaming base64 decoder decodes split chunks and whitespace" {
    const allocator = std.testing.allocator;

    var decoded: std.ArrayList(u8) = .empty;
    defer decoded.deinit(allocator);

    var stream: StreamingBase64Decoder = .{};
    try stream.feed(allocator, &decoded, "QU");
    try stream.feed(allocator, &decoded, "JD\n");
    try stream.feed(allocator, &decoded, "REVG");
    try stream.finish();

    try std.testing.expectEqualStrings("ABCDEF", decoded.items);
}

test "streaming base64 decoder preserves invalid padding behavior" {
    const allocator = std.testing.allocator;

    var decoded: std.ArrayList(u8) = .empty;
    defer decoded.deinit(allocator);

    var stream: StreamingBase64Decoder = .{};
    try stream.feed(allocator, &decoded, "AA=A");

    try std.testing.expect(stream.errored);
    try std.testing.expectError(error.InvalidBase64, stream.finish());
}

test "binary validator accepts clean single spectrum fixture" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/examples/mzml/clean-single-spectrum.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    // Act.
    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    // Assert.
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "binary validator accepts valid zlib PSI fixture" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/valid/small_zlib.pwiz.1.1.mzML", allocator, .limited(6 * 1024 * 1024));
    defer allocator.free(fixture);

    // Act.
    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    // Assert.
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "binary validator accepts valid chromatogram payloads" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    const fixture = minimalChromatogramMzml(
        "AAAAAA==",
        "AAAAAA==",
    );

    // Act.
    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    // Assert.
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

// Tests: invalid payloads and declarations.

test "binary validator reports invalid base64 payload" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/invalid/invalid-base64.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    // Act.
    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    // Assert.
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_binary_base64, diagnostics.items[0].rule);
    try std.testing.expectEqual(@as(?usize, 7), diagnostics.items[0].location.spectrum_index);
}

test "binary validator reports invalid zlib payload" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/invalid/invalid-zlib.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    // Act.
    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    // Assert.
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_binary_decompress, diagnostics.items[0].rule);
}

test "binary validator cvParam with unknown intern id still records zlib compression" {
    const allocator = std.testing.allocator;

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
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

    // Arrange.
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/invalid/conflicting-precision.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    // Act.
    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    // Assert.
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_binary_precision_mismatch, diagnostics.items[0].rule);
    try std.testing.expectEqualStrings("binaryDataArray declares conflicting 32-bit and 64-bit precision", diagnostics.items[0].message);
}

test "binary validator reports defaultArrayLength mismatch" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
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

    // Act.
    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    // Assert.
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_binary_length_mismatch, diagnostics.items[0].rule);
    try std.testing.expectEqualStrings("decoded array length does not match defaultArrayLength", diagnostics.items[0].message);
}

test "binary validator reports empty binary payload when declared length is nonzero" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    const fixture = minimalSpectrumMzml("", 1, "MS:1000576");

    // Act.
    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    // Assert.
    try expectSingleBinaryDiagnostic(
        diagnostics.items,
        RuleId.mzml_binary_length_mismatch,
        "decoded array length does not match defaultArrayLength",
    );
}

test "binary validator reports empty payload with non-zero encodedLength and no defaultArrayLength" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange. A fixture with encodedLength=8, empty payload, zlib, and
    // NO defaultArrayLength attribute on the spectrum. The validator
    // previously exited via orelse return without producing any error.
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

    // Act.
    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    // Assert.
    try expectSingleBinaryDiagnostic(
        diagnostics.items,
        RuleId.mzml_binary_length_mismatch,
        "binary payload is empty but encodedLength declares data",
    );
}

test "binary validator does not report error for encodedLength=0 with no payload and no defaultArrayLength" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange. encodedLength=0, empty payload, no defaultArrayLength.
    // This is a valid empty array.
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

    // Act.
    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    // Assert.
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "binary validator reports decoded length mismatch after valid zlib decompression" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    const fixture = minimalSpectrumMzml("eJxjYGBgAAAABAAB", 2, "MS:1000574");

    // Act.
    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    // Assert.
    try expectSingleBinaryDiagnostic(
        diagnostics.items,
        RuleId.mzml_binary_length_mismatch,
        "decoded array length does not match defaultArrayLength",
    );
}

test "binary validator reports conflicting compression terms" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/invalid/conflicting-compression.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    // Act.
    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    // Assert.
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_binary_compression, diagnostics.items[0].rule);
    try std.testing.expectEqualStrings("binaryDataArray declares conflicting compression terms", diagnostics.items[0].message);
}

test "binary validator reports unsupported compression terms" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/invalid/unsupported-compression.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    // Act.
    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    // Assert.
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_binary_compression, diagnostics.items[0].rule);
    try std.testing.expectEqualStrings("binaryDataArray declares unsupported compression terms", diagnostics.items[0].message);
}

test "binary validator reports invalid chromatogram payload without spectrum index" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    const fixture = minimalChromatogramMzml(
        "%%%%",
        "AAAAAA==",
    );

    // Act.
    var diagnostics = try runBinaryValidation(allocator, io, fixture);
    defer diagnostics.deinit(allocator);

    // Assert.
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

    // Act.
    inline for (payloads) |payload| {
        const fixture = minimalSpectrumMzml(payload, 1, "MS:1000576");
        var diagnostics = try runBinaryValidation(allocator, io, fixture);
        defer diagnostics.deinit(allocator);

        // Assert.
        try expectSingleBinaryDiagnostic(
            diagnostics.items,
            RuleId.mzml_binary_base64,
            "binary payload is not valid base64",
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

    // Act.
    inline for (payloads) |payload| {
        const fixture = minimalSpectrumMzml(payload, 1, "MS:1000574");
        var diagnostics = try runBinaryValidation(allocator, io, fixture);
        defer diagnostics.deinit(allocator);

        // Assert.
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

    // Act.
    inline for (payloads) |payload| {
        const fixture = minimalSpectrumMzml(payload, 1, "MS:1000574");
        var diagnostics = try runBinaryValidation(allocator, io, fixture);
        defer diagnostics.deinit(allocator);

        // Assert.
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

    // Arrange.
    const clean_fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/examples/mzml/clean-single-spectrum.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(clean_fixture);
    const corrupt_fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/invalid/invalid-base64.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(corrupt_fixture);

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    for (0..24) |index| {
        const fixture = if (index % 2 == 0) clean_fixture else corrupt_fixture;
        try runBinaryValidationInto(allocator, io, fixture, &diagnostics);

        // Assert.
        if (index % 2 == 0) {
            try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
        } else {
            try expectSingleBinaryDiagnostic(diagnostics.items, RuleId.mzml_binary_base64, null);
        }
    }
}

fn runBinaryValidation(allocator: std.mem.Allocator, io: std.Io, fixture: []const u8) !std.ArrayList(Diagnostic) {
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    try runBinaryValidationInto(allocator, io, fixture, &diagnostics);
    return diagnostics;
}

fn runBinaryValidationInto(
    allocator: std.mem.Allocator,
    io: std.Io,
    fixture: []const u8,
    diagnostics: *std.ArrayList(Diagnostic),
) !void {
    diagnostics.clearRetainingCapacity();
    var reader = std.Io.Reader.fixed(fixture);
    try BinaryValidator.validateReader(allocator, io, &reader, diagnostics, "fixture");
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
    const io = std.testing.io;

    // Fixture with encodedLength=8 but limit of 1.
    const xml = minimalSpectrumMzml("AAAAAA==", 1, "MS:1000576");

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var validator = BinaryValidator{
        .allocator = allocator,
        .diagnostics = &diagnostics,
        .path = "fixture",
        .max_binary_size = 1,
    };
    defer validator.deinit();

    var reader = std.Io.Reader.fixed(xml);
    const token_buffer = try allocator.alloc(u8, max_binary_token_bytes);
    defer allocator.free(token_buffer);

    var attributes: [64]Attribute = undefined;
    var namespace_bindings: [32]xml_parser.NamespaceBinding = undefined;
    var namespace_bytes: [2048]u8 = undefined;
    var element_stack: [128]xml_parser.ElementFrame = undefined;
    var element_bytes: [4096]u8 = undefined;

    var parser = xml_parser.Parser.init(&reader, .{
        .token = token_buffer,
        .attributes = &attributes,
        .namespace_bindings = &namespace_bindings,
        .namespace_bytes = &namespace_bytes,
        .element_stack = &element_stack,
        .element_bytes = &element_bytes,
    });

    try validator.run(io, &parser);

    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_binary_oversized, diagnostics.items[0].rule);
}

test "binary validator oversized limit is inclusive" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // encodedLength=8 exactly equals limit of 8 → should pass.
    const xml = minimalSpectrumMzml("AAAAAA==", 1, "MS:1000576");

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var validator = BinaryValidator{
        .allocator = allocator,
        .diagnostics = &diagnostics,
        .path = "fixture",
        .max_binary_size = 8,
    };
    defer validator.deinit();

    var reader = std.Io.Reader.fixed(xml);
    const token_buffer = try allocator.alloc(u8, max_binary_token_bytes);
    defer allocator.free(token_buffer);

    var attributes: [64]Attribute = undefined;
    var namespace_bindings: [32]xml_parser.NamespaceBinding = undefined;
    var namespace_bytes: [2048]u8 = undefined;
    var element_stack: [128]xml_parser.ElementFrame = undefined;
    var element_bytes: [4096]u8 = undefined;

    var parser = xml_parser.Parser.init(&reader, .{
        .token = token_buffer,
        .attributes = &attributes,
        .namespace_bindings = &namespace_bindings,
        .namespace_bytes = &namespace_bytes,
        .element_stack = &element_stack,
        .element_bytes = &element_bytes,
    });

    try validator.run(io, &parser);

    // At limit, no oversized diagnostic.
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "binary validator unlimited default does not reject large payloads" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Default max_binary_size=null → no limit.
    var diagnostics = try runBinaryValidation(allocator, io, minimalSpectrumMzml("AAAAAA==", 1, "MS:1000576"));
    defer diagnostics.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "binary validator scratch buffer shrink survives multi-array file" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Uncompressed arrays exercise the shrink path as a no-op.
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
    return "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">" ++
        "<run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\">" ++
        "<spectrumList count=\"1\" defaultDataProcessingRef=\"DP1\">" ++
        "<spectrum index=\"0\" id=\"scan=1\" defaultArrayLength=\"" ++ std.fmt.comptimePrint("{d}", .{default_array_length}) ++ "\">" ++
        "<binaryDataArrayList count=\"1\">" ++
        "<binaryDataArray encodedLength=\"" ++ std.fmt.comptimePrint("{d}", .{payload.len}) ++ "\">" ++
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
