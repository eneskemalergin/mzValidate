//! One-pass Phase 1 binary integrity checks for mzML payloads.

const std = @import("std");
const diagnostic = @import("../diagnostic.zig");
const xml_events = @import("../xml/events.zig");
const xml_parser = @import("../xml/parser.zig");

const Attribute = xml_events.Attribute;
const Diagnostic = diagnostic.Diagnostic;
const EndElement = xml_events.EndElement;
const ParseError = xml_parser.ParseError;
const QName = xml_events.QName;
const RuleId = diagnostic.RuleId;
const StartElement = xml_events.StartElement;

/// Namespace matched by the streaming mzML validators.
pub const mzml_namespace = "http://psi.hupo.org/ms/mzml";
const max_binary_token_bytes = 1024 * 1024;
const base64_decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");

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

/// Tracks the decoded byte count of a base64 payload across chunked text events.
/// No decoded bytes are materialized. Whitespace is ignored per the mzML spec.
const StreamingBase64Counter = struct {
    sig_len: usize = 0,
    padding: usize = 0,
    saw_pad: bool = false,
    errored: bool = false,

    fn feed(self: *@This(), chunk: []const u8) void {
        if (self.errored) return;
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

    fn result(self: *const @This()) error{InvalidBase64}!usize {
        if (self.errored) return error.InvalidBase64;
        if (self.sig_len % 4 != 0) return error.InvalidBase64;
        if (self.sig_len == 0) return 0;
        return (self.sig_len / 4) * 3 - self.padding;
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
    precision: ?Precision = null,
    saw_precision_32: bool = false,
    saw_precision_64: bool = false,
    saw_no_compression: bool = false,
    saw_zlib_compression: bool = false,
    saw_unsupported_compression: bool = false,
    array_kind: ArrayKind = .unknown,
    binary_depth: ?usize = null,
    binary_byte_offset: ?u64 = null,
    payload: std.ArrayList(u8) = .empty,
    base64_stream: StreamingBase64Counter = .{},
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
        };
    }

    fn deinit(state: *BinaryArrayState) void {
        if (state.saw_zlib_compression) {
            state.payload.deinit(state.allocator);
        }
        state.* = undefined;
    }
};

pub const BinaryValidator = struct {
    allocator: std.mem.Allocator,
    diagnostics: *std.ArrayList(Diagnostic),
    path: ?[]const u8,
    max_binary_size: ?usize = null,

    // Binary validation retains only the current owner metadata plus one active
    // binaryDataArray payload and its declarations. This bounds retained state to the
    // current spectrum or chromatogram and one decoded workspace rather than the full file.
    depth: usize = 0,
    indexed_mzml_depth: ?usize = null,
    mzml_depth: ?usize = null,
    spectrum: ?OwnerState = null,
    chromatogram: ?OwnerState = null,
    binary_array: ?BinaryArrayState = null,

    /// Creates a validator that appends diagnostics to the shared result list.
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

    /// Releases any active binary array workspace owned by the validator.
    pub fn deinit(validator: *BinaryValidator) void {
        if (validator.binary_array) |*state| state.deinit();
    }

    /// Runs the standalone binary validator over a reader-backed XML stream.
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

    /// Consumes one start-element event from the shared XML traversal.
    pub fn consumeStart(validator: *BinaryValidator, start: StartElement) !void {
        const element_depth = validator.depth + 1;
        try validator.handleStart(start, element_depth);
        validator.depth += 1;
    }

    /// Consumes one end-element event from the shared XML traversal.
    pub fn consumeEnd(validator: *BinaryValidator, end: EndElement) !void {
        const element_depth = validator.depth;
        try validator.handleEnd(end, element_depth);
        validator.depth -= 1;
    }

    /// Consumes one text event from the shared XML traversal.
    pub fn consumeText(validator: *BinaryValidator, text: xml_events.Text) !void {
        try validator.handleText(text.value);
    }

    /// Finalizes one-pass binary validation after the last XML event.
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
                    .message = parseErrorMessage(err),
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
        if (validator.mzml_depth == null) {
            if (validator.indexed_mzml_depth == null and start.name.matches(mzml_namespace, "indexedmzML")) {
                validator.indexed_mzml_depth = element_depth;
                return;
            }
            if (start.name.matches(mzml_namespace, "mzML")) {
                if (validator.indexed_mzml_depth) |indexed_depth| {
                    if (element_depth != indexed_depth + 1) return;
                }
                validator.mzml_depth = element_depth;
            }
            return;
        }

        if (!validator.isWithinMzmlScope(element_depth)) return;

        if (start.name.matches(mzml_namespace, "spectrum")) {
            validator.spectrum = .{
                .depth = element_depth,
                .index = parseOptionalUnsigned(attributeValue(start.attributes, "index")),
                .default_array_length = parseOptionalUnsigned(attributeValue(start.attributes, "defaultArrayLength")),
            };
            return;
        }

        if (start.name.matches(mzml_namespace, "chromatogram")) {
            validator.chromatogram = .{
                .depth = element_depth,
                .index = null,
                .default_array_length = parseOptionalUnsigned(attributeValue(start.attributes, "defaultArrayLength")),
            };
            return;
        }

        if (start.name.matches(mzml_namespace, "binaryDataArray")) {
            if (validator.binary_array != null) return;
            const encoded_length = parseOptionalUnsigned(attributeValue(start.attributes, "encodedLength"));
            if (validator.spectrum) |owner| {
                validator.binary_array = BinaryArrayState.init(validator.allocator, start.byte_offset, element_depth, owner, encoded_length);
                return;
            }
            if (validator.chromatogram) |owner| {
                validator.binary_array = BinaryArrayState.init(validator.allocator, start.byte_offset, element_depth, owner, encoded_length);
                return;
            }
            return;
        }

        if (start.name.matches(mzml_namespace, "cvParam")) {
            if (validator.binary_array) |*state| {
                if (element_depth != state.depth + 1) return;
                const accession = attributeValue(start.attributes, "accession") orelse return;
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
            return;
        }

        if (start.name.matches(mzml_namespace, "binary")) {
            if (validator.binary_array) |*state| {
                if (element_depth == state.depth + 1) {
                    state.binary_depth = element_depth;
                    state.binary_byte_offset = start.byte_offset;
                    if (state.encoded_length) |encoded_length| {
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
                            try state.payload.ensureTotalCapacity(validator.allocator, encoded_length);
                            state.encoded_length = null;
                        }
                    }
                }
            }
        }
    }

    fn handleEnd(validator: *BinaryValidator, end: EndElement, element_depth: usize) !void {
        if (validator.mzml_depth == null) return;
        if (!validator.isWithinMzmlScope(element_depth)) return;

        if (end.name.matches(mzml_namespace, "binary")) {
            if (validator.binary_array) |*state| {
                if (state.binary_depth == element_depth) {
                    state.binary_depth = null;
                }
            }
            return;
        }

        if (end.name.matches(mzml_namespace, "binaryDataArray")) {
            if (validator.binary_array) |*state| {
                if (state.depth == element_depth) {
                    try validator.validateBinaryArray(state);
                    state.deinit();
                    validator.binary_array = null;
                }
            }
            return;
        }

        if (end.name.matches(mzml_namespace, "spectrum")) {
            if (validator.spectrum) |state| {
                if (state.depth == element_depth) validator.spectrum = null;
            }
            return;
        }

        if (end.name.matches(mzml_namespace, "chromatogram")) {
            if (validator.chromatogram) |state| {
                if (state.depth == element_depth) validator.chromatogram = null;
            }
            return;
        }

        if (end.name.matches(mzml_namespace, "mzML") and validator.mzml_depth == element_depth) {
            validator.mzml_depth = null;
        }
    }

    fn handleText(validator: *BinaryValidator, value: []const u8) !void {
        if (validator.binary_array) |*state| {
            if (state.binary_depth != null) {
                if (state.saw_zlib_compression) {
                    try state.payload.appendSlice(validator.allocator, value);
                } else {
                    state.base64_stream.feed(value);
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
                const encoded = state.payload.items;
                const decoded_upper_bound = base64_decoder.calcSizeUpperBound(encoded.len);
                const decoded_buffer = try validator.allocator.alloc(u8, decoded_upper_bound);
                defer validator.allocator.free(decoded_buffer);

                const decoded_len = base64_decoder.decode(decoded_buffer, encoded) catch {
                    try validator.appendDiagnostic(.{
                        .severity = .@"error",
                        .rule = RuleId.mzml_binary_base64,
                        .location = location,
                        .path = validator.path,
                        .message = "binary payload is not valid base64",
                    });
                    return;
                };

                break :blk (inflateCount(decoded_buffer[0..decoded_len]) catch {
                    try validator.appendDiagnostic(.{
                        .severity = .@"error",
                        .rule = RuleId.mzml_binary_decompress,
                        .location = location,
                        .path = validator.path,
                        .message = "binary payload is not valid zlib data",
                    });
                    return;
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

    fn appendDiagnostic(validator: *BinaryValidator, item: Diagnostic) !void {
        try validator.diagnostics.append(validator.allocator, item);
    }
};

/// Streaming inflate: decompresses zlib data and returns the decoded byte count
/// without materializing the decompressed output. Uses a small stack buffer.
fn inflateCount(compressed: []const u8) error{InvalidBinaryPayload}!usize {
    var input = std.Io.Reader.fixed(compressed);
    var flate_buffer: [std.compress.flate.max_window_len]u8 = undefined;
    var decompress: std.compress.flate.Decompress = .init(&input, .zlib, &flate_buffer);

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

fn attributeValue(attributes: []const Attribute, local_name: []const u8) ?[]const u8 {
    for (attributes) |attribute| {
        if (attribute.is_namespace_declaration) continue;
        if (std.mem.eql(u8, attribute.name.local_name, local_name)) return attribute.value;
    }
    return null;
}

fn parseOptionalUnsigned(value: ?[]const u8) ?usize {
    const slice = value orelse return null;
    return std.fmt.parseUnsigned(usize, slice, 10) catch null;
}

/// All `is_a: MS:1000572` (binary data compression type) terms from the
/// PSI-MS controlled vocabulary. Unsupported terms are accepted for
/// recognition and diagnostic reporting — they produce a
/// `mzml.binary.compression` diagnostic rather than being silently
/// treated as "no compression".
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

fn parseErrorMessage(err: ParseError) []const u8 {
    return switch (err) {
        error.UnexpectedEof => "unexpected end of XML input",
        error.InvalidUtf8 => "invalid UTF-8 in XML input",
        error.TokenTooLong => "XML token exceeds the configured parser buffer",
        error.TooManyAttributes => "XML element has more attributes than the configured parser limit",
        error.TooManyNamespaces,
        error.NamespaceStorageExceeded,
        error.ElementNestingTooDeep,
        error.ElementStorageExceeded,
        error.MalformedXml,
        error.UnknownEntity,
        error.InvalidCharacterReference,
        error.UnsupportedMarkup,
        error.MismatchedEndTag,
        error.ReadFailed,
        => "malformed XML input",
    };
}

// Tests: valid fixtures.

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
