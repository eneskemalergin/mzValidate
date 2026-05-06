//! Phase 1 binary integrity validation for mzML payloads.

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

    fn init(allocator: std.mem.Allocator, byte_offset: u64, depth: usize, owner: OwnerState) BinaryArrayState {
        return .{
            .allocator = allocator,
            .byte_offset = byte_offset,
            .depth = depth,
            .owner_spectrum_index = owner.index,
            .default_array_length = owner.default_array_length,
        };
    }

    fn deinit(state: *BinaryArrayState) void {
        state.payload.deinit(state.allocator);
        state.* = undefined;
    }
};

pub const BinaryValidator = struct {
    allocator: std.mem.Allocator,
    diagnostics: *std.ArrayList(Diagnostic),
    path: ?[]const u8,

    depth: usize = 0,
    indexed_mzml_depth: ?usize = null,
    mzml_depth: ?usize = null,
    spectrum: ?OwnerState = null,
    chromatogram: ?OwnerState = null,
    binary_array: ?BinaryArrayState = null,

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
        if (validator.binary_array) |*state| state.deinit();
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
            if (validator.spectrum) |owner| {
                validator.binary_array = BinaryArrayState.init(validator.allocator, start.byte_offset, element_depth, owner);
                return;
            }
            if (validator.chromatogram) |owner| {
                validator.binary_array = BinaryArrayState.init(validator.allocator, start.byte_offset, element_depth, owner);
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
                try state.payload.appendSlice(validator.allocator, value);
            }
        }
    }

    fn validateBinaryArray(validator: *BinaryValidator, state: *const BinaryArrayState) !void {
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

        const compression: Compression = if (state.saw_zlib_compression) .zlib else .none;
        const binary_bytes = switch (compression) {
            .none => decoded_buffer[0..decoded_len],
            .zlib => validator.inflateZlib(decoded_buffer[0..decoded_len], location) catch |err| switch (err) {
                error.InvalidBinaryPayload => return,
                else => return err,
            },
        };
        defer if (compression == .zlib) validator.allocator.free(binary_bytes);

        const width = precision.width();
        if (binary_bytes.len % width != 0) {
            try validator.appendDiagnostic(.{
                .severity = .@"error",
                .rule = RuleId.mzml_binary_precision_mismatch,
                .location = location,
                .path = validator.path,
                .message = precisionDivisibilityMessage(precision),
            });
            return;
        }

        const element_count = binary_bytes.len / width;
        const declared_count = state.default_array_length orelse return;
        if (element_count == declared_count) return;

        const alternate_width: usize = if (width == 4) 8 else 4;
        if (declared_count != 0 and binary_bytes.len == declared_count * alternate_width) {
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

    fn inflateZlib(validator: *BinaryValidator, compressed: []const u8, location: diagnostic.Location) ![]u8 {
        var input = std.Io.Reader.fixed(compressed);
        var flate_buffer: [std.compress.flate.max_window_len]u8 = undefined;
        var decompress: std.compress.flate.Decompress = .init(&input, .zlib, &flate_buffer);
        var output: std.ArrayList(u8) = .empty;
        errdefer output.deinit(validator.allocator);

        decompress.reader.appendRemainingUnlimited(validator.allocator, &output) catch {
            try validator.appendDiagnostic(.{
                .severity = .@"error",
                .rule = RuleId.mzml_binary_decompress,
                .location = location,
                .path = validator.path,
                .message = "binary payload is not valid zlib data",
            });
            return error.InvalidBinaryPayload;
        };
        return try output.toOwnedSlice(validator.allocator);
    }

    fn isWithinMzmlScope(validator: *BinaryValidator, element_depth: usize) bool {
        if (validator.mzml_depth == null) return false;
        return element_depth >= validator.mzml_depth.?;
    }

    fn appendDiagnostic(validator: *BinaryValidator, item: Diagnostic) !void {
        try validator.diagnostics.append(validator.allocator, item);
    }
};

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

fn isCompressionAccession(accession: []const u8) bool {
    return std.mem.eql(u8, accession, "MS:1000574") or
        std.mem.eql(u8, accession, "MS:1000576") or
        std.mem.eql(u8, accession, "MS:1002312") or
        std.mem.eql(u8, accession, "MS:1002313") or
        std.mem.eql(u8, accession, "MS:1002314") or
        std.mem.eql(u8, accession, "MS:1002746") or
        std.mem.eql(u8, accession, "MS:1002747") or
        std.mem.eql(u8, accession, "MS:1002748") or
        std.mem.eql(u8, accession, "MS:1002848") or
        std.mem.eql(u8, accession, "MS:1002849") or
        std.mem.eql(u8, accession, "MS:1002850") or
        std.mem.eql(u8, accession, "MS:1003089") or
        std.mem.eql(u8, accession, "MS:1003090") or
        std.mem.eql(u8, accession, "MS:1003091");
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

test "binary validator accepts clean single spectrum fixture" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/examples/mzml/clean-single-spectrum.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    try BinaryValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "binary validator accepts valid zlib PSI fixture" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/valid/small_zlib.pwiz.1.1.mzML", allocator, .limited(6 * 1024 * 1024));
    defer allocator.free(fixture);

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    try BinaryValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "binary validator reports invalid base64 payload" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/invalid/invalid-base64.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    try BinaryValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_binary_base64, diagnostics.items[0].rule);
    try std.testing.expectEqual(@as(?usize, 7), diagnostics.items[0].location.spectrum_index);
}

test "binary validator reports invalid zlib payload" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/invalid/invalid-zlib.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    try BinaryValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_binary_decompress, diagnostics.items[0].rule);
}

test "binary validator reports precision mismatch" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/invalid/conflicting-precision.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    try BinaryValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
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

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    try BinaryValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_binary_length_mismatch, diagnostics.items[0].rule);
    try std.testing.expectEqualStrings("decoded array length does not match defaultArrayLength", diagnostics.items[0].message);
}

test "binary validator reports conflicting compression terms" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/invalid/conflicting-compression.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    try BinaryValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_binary_compression, diagnostics.items[0].rule);
    try std.testing.expectEqualStrings("binaryDataArray declares conflicting compression terms", diagnostics.items[0].message);
}

test "binary validator reports unsupported compression terms" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/invalid/unsupported-compression.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    try BinaryValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_binary_compression, diagnostics.items[0].rule);
    try std.testing.expectEqualStrings("binaryDataArray declares unsupported compression terms", diagnostics.items[0].message);
}
