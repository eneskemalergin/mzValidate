//! Binary integrity checks for mzML payloads.
//!
//! Validates base64, zlib integrity, and decoded array lengths in one pass.
//! Reusable bounded scratch avoids retaining decoded numeric arrays.

const std = @import("std");
const build_options = @import("build_options");
const diagnostic = @import("../diagnostic.zig");
const xml_events = @import("../xml/events.zig");
const xml_parser = @import("../xml/parser.zig");
const xml_parse_errors = @import("../xml/parse_errors.zig");

// Optional libdeflate binding. Keep this ABI surface narrow so the build does
// not need a C header translation step for three decompression calls.
const libdeflate = if (build_options.enable_libdeflate) struct {
    const libdeflate_decompressor = opaque {};

    const LIBDEFLATE_SUCCESS: c_int = 0;
    const LIBDEFLATE_INSUFFICIENT_SPACE: c_int = 3;

    extern fn libdeflate_alloc_decompressor() ?*libdeflate_decompressor;
    extern fn libdeflate_free_decompressor(decompressor: *libdeflate_decompressor) void;
    extern fn libdeflate_zlib_decompress_ex(
        decompressor: *libdeflate_decompressor,
        input: [*]const u8,
        input_nbytes: usize,
        output: [*]u8,
        output_nbytes_avail: usize,
        actual_in_nbytes_ret: *usize,
        actual_out_nbytes_ret: *usize,
    ) c_int;
} else struct {};

const Attribute = xml_events.Attribute;
const Diagnostic = diagnostic.Diagnostic;
const DiagnosticSink = diagnostic.DiagnosticSink;
const EndElement = xml_events.EndElement;
const QName = xml_events.QName;
const RuleId = diagnostic.RuleId;
const StartElement = xml_events.StartElement;

// --- Constants and types ---

pub const mzml_namespace = diagnostic.mzml_namespace;
const max_binary_token_bytes = 1024 * 1024;
const base64_decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
const base64_simd_chunk_len: comptime_int = std.simd.suggestVectorLength(u8) orelse 32;
const base64_scalar_short_len = 64;
// Keep one extra decoder window beyond Zig's required 64 KiB minimum so ordinary
// arrays need fewer output toss cycles without retaining the former 1 MiB.
const flate_buffer_len = 2 * std.compress.flate.max_window_len;
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

// --- Base64 streaming codec ---

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

fn base64DecodedSize(sig_len: usize, padding: usize, last_value: u8, errored: bool) error{InvalidBase64}!usize {
    if (errored or sig_len % 4 != 0) return error.InvalidBase64;
    if (sig_len == 0) return 0;
    if ((padding == 1 and last_value & 0x03 != 0) or
        (padding == 2 and last_value & 0x0f != 0))
    {
        return error.InvalidBase64;
    }
    const decoded = std.math.mul(usize, sig_len / 4, 3) catch return error.InvalidBase64;
    return std.math.sub(usize, decoded, padding) catch error.InvalidBase64;
}

const StreamingBase64Counter = struct {
    sig_len: usize = 0,
    padding: usize = 0,
    last_value: u8 = 0,
    saw_pad: bool = false,
    errored: bool = false,

    fn feed(self: *@This(), chunk: []const u8) void {
        if (self.errored) return;
        if (chunk.len < base64_scalar_short_len or self.saw_pad) {
            self.feedScalar(chunk);
            return;
        }

        var offset: usize = 0;
        while (chunk.len - offset >= base64_simd_chunk_len) {
            const bytes = loadBase64Chunk(chunk, offset);
            const base64_chars = base64CharLanes(bytes);
            const whitespace = whitespaceLanes(bytes);
            const pre_pad_allowed = base64_chars | whitespace;

            if (@reduce(.And, base64_chars)) {
                self.sig_len = std.math.add(usize, self.sig_len, base64_simd_chunk_len) catch {
                    self.errored = true;
                    return;
                };
                self.last_value = base64Value(chunk[offset + base64_simd_chunk_len - 1]);
                offset += base64_simd_chunk_len;
                continue;
            }

            if (@reduce(.And, pre_pad_allowed)) {
                self.sig_len = std.math.add(usize, self.sig_len, countTrueLanes(base64_chars)) catch {
                    self.errored = true;
                    return;
                };
                var reverse = offset + base64_simd_chunk_len;
                while (reverse > offset) {
                    reverse -= 1;
                    const byte = chunk[reverse];
                    if (base64ValueOrNull(byte)) |value| {
                        self.last_value = value;
                        break;
                    }
                }
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
                self.sig_len = std.math.add(usize, self.sig_len, 1) catch {
                    self.errored = true;
                    return;
                };
                self.last_value = base64Value(c);
            },
            '=' => {
                self.padding = std.math.add(usize, self.padding, 1) catch {
                    self.errored = true;
                    return;
                };
                self.saw_pad = true;
                self.sig_len = std.math.add(usize, self.sig_len, 1) catch {
                    self.errored = true;
                    return;
                };
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
        return @popCount(@as(std.meta.Int(.unsigned, base64_simd_chunk_len), @bitCast(lanes)));
    }

    fn result(self: *const @This()) error{InvalidBase64}!usize {
        return base64DecodedSize(self.sig_len, self.padding, self.last_value, self.errored);
    }
};

// Defers diagnostics until declaration checks establish the required context.
const StreamingBase64Decoder = struct {
    sig_len: usize = 0,
    padding: usize = 0,
    last_value: u8 = 0,
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
                self.sig_len = std.math.add(usize, self.sig_len, 1) catch return error.ResourceLimitExceeded;
                self.last_value = base64Value(c);
                try self.pushSextet(allocator, out, self.last_value);
            },
            '=' => {
                self.padding = std.math.add(usize, self.padding, 1) catch return error.ResourceLimitExceeded;
                self.saw_pad = true;
                self.sig_len = std.math.add(usize, self.sig_len, 1) catch return error.ResourceLimitExceeded;
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
        _ = try base64DecodedSize(self.sig_len, self.padding, self.last_value, self.errored);
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

        const decoded_len = std.math.mul(usize, encoded.len / 4, 3) catch return error.ResourceLimitExceeded;
        const start = out.items.len;
        const end = std.math.add(usize, start, decoded_len) catch return error.ResourceLimitExceeded;
        try out.resize(allocator, end);
        std.base64.standard.Decoder.decode(out.items[start..][0..decoded_len], encoded) catch {
            try out.resize(allocator, start);
            self.errored = true;
            return;
        };
        self.sig_len = std.math.add(usize, self.sig_len, encoded.len) catch return error.ResourceLimitExceeded;
        self.last_value = base64Value(encoded[encoded.len - 1]);
    }

    fn cleanBase64DataPrefixLen(bytes: []const u8) usize {
        var offset: usize = 0;
        while (bytes.len - offset >= base64_simd_chunk_len) {
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
};

fn base64ValueOrNull(c: u8) ?u8 {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '+', '/' => base64Value(c),
        else => null,
    };
}

// --- mzML element state ---

const OwnerState = struct {
    depth: usize,
    index: ?usize,
    default_array_length: ?usize,
    default_array_length_invalid: bool,
};

const BinaryArrayState = struct {
    byte_offset: u64,
    depth: usize,
    owner_spectrum_index: ?usize,
    default_array_length: ?usize,
    default_array_length_invalid: bool,
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
    encoded_text_len: usize = 0,
    skipped: bool = false,

    fn init(
        byte_offset: u64,
        depth: usize,
        owner: OwnerState,
        encoded_length: ?usize,
    ) BinaryArrayState {
        return .{
            .byte_offset = byte_offset,
            .depth = depth,
            .owner_spectrum_index = owner.index,
            .default_array_length = owner.default_array_length,
            .default_array_length_invalid = owner.default_array_length_invalid,
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
    /// Cleared with `clearRetainingCapacity` at the start of each binary element.
    compressed_payload: std.ArrayList(u8) = .empty,
    flate_buffer: std.ArrayList(u8) = .empty,
    libdeflate_output: std.ArrayList(u8) = .empty,
    libdeflate_decompressor: OptionalLibdeflateDecompressor = if (build_options.enable_libdeflate) null else {},
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
        var total: usize = 0;
        total = std.math.add(usize, total, validator.compressed_payload.capacity) catch return error.ResourceLimitExceeded;
        total = std.math.add(usize, total, validator.flate_buffer.capacity) catch return error.ResourceLimitExceeded;
        return std.math.add(usize, total, validator.libdeflate_output.capacity) catch error.ResourceLimitExceeded;
    }

    fn updateScratchAccounting(validator: *BinaryValidator) !void {
        const current = try validator.scratchCapacity();
        if (current > validator.limits.max_binary_scratch_bytes) return error.ResourceLimitExceeded;
        validator.scratch_current_bytes = current;
        validator.scratch_peak_bytes = @max(validator.scratch_peak_bytes, current);
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
                    .depth = element_depth,
                    .index = null,
                    .default_array_length = if (dal_signed) |value| if (value >= 0) @intCast(value) else null else null,
                    .default_array_length_invalid = dal_attr != null and (dal_signed == null or dal_signed.? < 0),
                };
            },
            .binaryDataArray => {
                if (validator.binary_array != null) return;
                const encoded_length = parseOptionalUnsigned(start.attr("encodedLength"));
                if (validator.spectrum) |owner| {
                    validator.binary_array = BinaryArrayState.init(start.byte_offset, element_depth, owner, encoded_length);
                    return;
                }
                if (validator.chromatogram) |owner| {
                    validator.binary_array = BinaryArrayState.init(start.byte_offset, element_depth, owner, encoded_length);
                    return;
                }
            },
            .cvParam => {
                if (validator.binary_array) |*state| {
                    if (element_depth != state.depth + 1) return;
                    const accession = start.attr("accession") orelse return;
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
                        try validator.validateBinaryArray(state);

                        if (state.array_kind != .unknown) {
                            const kind_bit: u3 = switch (state.array_kind) {
                                .mz => 1 << 0,
                                .intensity => 1 << 1,
                                .time => 1 << 2,
                                .unknown => unreachable,
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
                    state.zlib_base64_stream.feed(validator.allocator, &validator.compressed_payload, text.value) catch |err| switch (err) {
                        error.ResourceLimitExceeded => {
                            try validator.appendBinaryLimitDiagnostic(state, "binary payload decoded-size arithmetic overflow");
                            state.skipped = true;
                            state.binary_depth = null;
                            return error.ResourceLimitExceeded;
                        },
                        else => return err,
                    };
                } else {
                    state.base64_stream.feed(text.value);
                }
            }
        }
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
                if (state.encoded_text_len == 0) break :blk 0;

                const expected_decoded_bytes = if (state.default_array_length) |count|
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
                    error.ScratchLimitExceeded => {
                        try validator.appendDiagnostic(.{
                            .severity = .@"error",
                            .rule = RuleId.mzml_binary_oversized,
                            .location = location,
                            .path = validator.path,
                            .message = "binary scratch exceeds the configured limit",
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

        const element_count = decoded_bytes / width;
        if (state.default_array_length_invalid) return;
        if (state.default_array_length == null and decoded_bytes > 0) {
            try validator.appendDiagnostic(.{
                .severity = .@"error",
                .rule = RuleId.mzml_binary_length_mismatch,
                .location = location,
                .path = validator.path,
                .message = "non-empty binary payload is missing required defaultArrayLength",
            });
            return;
        }
        const declared_count = state.default_array_length orelse return;
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

    fn inflateDecodedZlib(validator: *BinaryValidator, compressed: []const u8, expected_decoded_bytes: ?usize) (error{ InvalidBase64, InvalidBinaryPayload, OutOfMemory, ResourceLimitExceeded, ScratchLimitExceeded, DecodedLimitExceeded }!usize) {
        const expected_adler = try zlibAdler32(compressed);
        if (comptime build_options.enable_libdeflate) {
            if (expected_decoded_bytes) |expected| {
                if (expected > 0 and expected <= validator.limits.max_binary_materialized_bytes) {
                    validator.ensureScratchCapacity(&validator.libdeflate_output, expected) catch return error.ScratchLimitExceeded;
                    const decompressor = try validator.ensureLibdeflateDecompressor();
                    try validator.libdeflate_output.resize(validator.allocator, expected);

                    var actual_in: usize = 0;
                    var actual_out: usize = 0;
                    const result = libdeflate.libdeflate_zlib_decompress_ex(
                        decompressor,
                        compressed.ptr,
                        compressed.len,
                        validator.libdeflate_output.items.ptr,
                        expected,
                        &actual_in,
                        &actual_out,
                    );

                    switch (result) {
                        libdeflate.LIBDEFLATE_SUCCESS => {
                            if (actual_in != compressed.len) return error.InvalidBinaryPayload;
                            return actual_out;
                        },
                        libdeflate.LIBDEFLATE_INSUFFICIENT_SPACE => {},
                        else => return error.InvalidBinaryPayload,
                    }
                }
            }
        }

        validator.ensureScratchCapacity(&validator.flate_buffer, flate_buffer_len) catch return error.ScratchLimitExceeded;
        try validator.flate_buffer.resize(validator.allocator, flate_buffer_len);
        return inflateCountWithBuffer(
            compressed,
            validator.flate_buffer.items,
            validator.limits.max_binary_decoded_bytes,
            expected_adler,
        );
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

fn inflateCountWithBuffer(
    compressed: []const u8,
    flate_buffer: []u8,
    max_output_bytes: usize,
    expected_adler: u32,
) error{ InvalidBinaryPayload, DecodedLimitExceeded }!usize {
    var input = std.Io.Reader.fixed(compressed);
    var decompress: std.compress.flate.Decompress = .init(&input, .zlib, flate_buffer);
    var adler: std.hash.Adler32 = .{};

    var count: usize = 0;
    const max_peek = flate_buffer.len - std.compress.flate.history_len;
    while (true) {
        const slice = decompress.reader.peekGreedy(max_peek) catch |err| switch (err) {
            error.EndOfStream => {
                const buffered = decompress.reader.buffered();
                addDecodedChunk(&count, &adler, buffered, max_output_bytes) catch return error.DecodedLimitExceeded;
                break;
            },
            else => return error.InvalidBinaryPayload,
        };
        if (slice.len == 0) break;
        addDecodedChunk(&count, &adler, slice, max_output_bytes) catch return error.DecodedLimitExceeded;
        decompress.reader.toss(slice.len);
    }
    if (input.seek != input.end or adler.adler != expected_adler) return error.InvalidBinaryPayload;
    return count;
}

fn addDecodedChunk(count: *usize, adler: *std.hash.Adler32, chunk: []const u8, limit: usize) error{DecodedLimitExceeded}!void {
    const next = std.math.add(usize, count.*, chunk.len) catch return error.DecodedLimitExceeded;
    if (next > limit) return error.DecodedLimitExceeded;
    adler.update(chunk);
    count.* = next;
}

fn countBase64Significant(value: []const u8) usize {
    var count: usize = 0;
    for (value) |byte| {
        switch (byte) {
            ' ', '\t', '\n', '\r' => {},
            else => count += 1,
        }
    }
    return count;
}

fn zlibAdler32(compressed: []const u8) error{InvalidBinaryPayload}!u32 {
    if (compressed.len < 6) return error.InvalidBinaryPayload;
    const cmf = compressed[0];
    const flg = compressed[1];
    const header = (@as(u16, cmf) << 8) | @as(u16, flg);
    if (cmf & 0x0f != 8 or cmf >> 4 > 7 or header % 31 != 0 or flg & 0x20 != 0) {
        return error.InvalidBinaryPayload;
    }
    return std.mem.readInt(u32, compressed[compressed.len - 4 ..][0..4], .big);
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

test "streaming base64 decoder decodes long clean bulk runs" {
    const allocator = std.testing.allocator;

    var payload: [128]u8 = undefined;
    @memset(&payload, 'A');

    var decoded: std.ArrayList(u8) = .empty;
    defer decoded.deinit(allocator);

    var stream: StreamingBase64Decoder = .{};
    try stream.feed(allocator, &decoded, &payload);
    try stream.finish();

    try std.testing.expectEqual(@as(usize, 96), decoded.items.len);
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

test "[unit]: streaming base64 codecs reject noncanonical final pad bits" {
    const allocator = std.testing.allocator;
    const cases = [_]struct {
        payload: []const u8,
        valid: bool,
    }{
        .{ .payload = "AA==", .valid = true },
        .{ .payload = "AAA=", .valid = true },
        .{ .payload = "AB==", .valid = false },
        .{ .payload = "AAB=", .valid = false },
    };

    for (cases) |case| {
        var counter: StreamingBase64Counter = .{};
        counter.feed(case.payload);
        var decoded: std.ArrayList(u8) = .empty;
        defer decoded.deinit(allocator);
        var decoder: StreamingBase64Decoder = .{};
        try decoder.feed(allocator, &decoded, case.payload);

        if (case.valid) {
            _ = try counter.result();
            try decoder.finish();
        } else {
            try std.testing.expectError(error.InvalidBase64, counter.result());
            try std.testing.expectError(error.InvalidBase64, decoder.finish());
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

test "binary fallback uses the bounded flate workspace and validates boundaries" {
    const allocator = std.testing.allocator;
    const compressed = [_]u8{
        0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07,
        0x00, 0x06, 0x2c, 0x02, 0x15,
    };
    const flate_buffer = try allocator.alloc(u8, flate_buffer_len);
    defer allocator.free(flate_buffer);
    var adler: std.hash.Adler32 = .{};
    adler.update("hello");

    try std.testing.expectEqual(@as(usize, 2 * std.compress.flate.max_window_len), flate_buffer.len);
    try std.testing.expectEqual(
        @as(usize, 5),
        try inflateCountWithBuffer(&compressed, flate_buffer, 5, adler.adler),
    );
    try std.testing.expectError(
        error.DecodedLimitExceeded,
        inflateCountWithBuffer(&compressed, flate_buffer, 4, adler.adler),
    );

    const with_trailing = compressed ++ [_]u8{0};
    try std.testing.expectError(
        error.InvalidBinaryPayload,
        inflateCountWithBuffer(&with_trailing, flate_buffer, 5, adler.adler),
    );

    var corrupt = compressed;
    corrupt[5] ^= 1;
    try std.testing.expectError(
        error.InvalidBinaryPayload,
        inflateCountWithBuffer(&corrupt, flate_buffer, 5, adler.adler),
    );
}

test "binary fallback owner accounts only the bounded flate workspace" {
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
        try validator.inflateDecodedZlib(&compressed, null),
    );
    try std.testing.expectEqual(@as(usize, 2 * std.compress.flate.max_window_len), validator.flate_buffer.capacity);
    try std.testing.expectEqual(validator.flate_buffer.capacity, validator.scratch_current_bytes);
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
        validator.ensureScratchCapacity(&validator.flate_buffer, 4 * 1024 + 1),
    );
    try std.testing.expectEqual(@as(usize, 4 * 1024), validator.scratch_current_bytes);
    try std.testing.expectEqual(@as(usize, 4 * 1024), validator.scratch_peak_bytes);
}

test "binary scratch growth failure releases retained capacity" {
    var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 1 });
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
    try std.testing.expectEqual(@as(?usize, 7), diagnostics.items[0].location.spectrum_index);
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
    try std.testing.expectEqualStrings(RuleId.mzml_binary_precision_mismatch, diagnostics.items[0].rule);
    try std.testing.expectEqualStrings("binaryDataArray declares conflicting 32-bit and 64-bit precision", diagnostics.items[0].message);
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
        .default_array_length = std.math.maxInt(usize),
        .default_array_length_invalid = false,
        .encoded_length = 8,
        .encoded_length_declared = 8,
        .encoded_text_len = 8,
        .saw_precision_32 = true,
        .saw_no_compression = true,
    };
    state.base64_stream.feed("AAAAAA==");

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
        .default_array_length = null,
        .default_array_length_invalid = true,
        .encoded_length = 4,
        .encoded_length_declared = 4,
        .encoded_text_len = 4,
        .saw_precision_32 = true,
        .saw_no_compression = true,
    };
    state.base64_stream.feed("%%%%");

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

const test_events = @import("test_events.zig");
