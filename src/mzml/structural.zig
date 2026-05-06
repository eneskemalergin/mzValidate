//! Phase 1 streaming mzML structural validation.

const std = @import("std");
const diagnostic = @import("../diagnostic.zig");
const xml_events = @import("../xml/events.zig");
const xml_parser = @import("../xml/parser.zig");

const Attribute = xml_events.Attribute;
const Diagnostic = diagnostic.Diagnostic;
const EndElement = xml_events.EndElement;
const Event = xml_events.Event;
const ParseError = xml_parser.ParseError;
const QName = xml_events.QName;
const RuleId = diagnostic.RuleId;
const Severity = diagnostic.Severity;
const StartElement = xml_events.StartElement;

pub const mzml_namespace = "http://psi.hupo.org/ms/mzml";

const ContainerKind = enum {
    spectrum,
    chromatogram,

    fn label(kind: ContainerKind) []const u8 {
        return switch (kind) {
            .spectrum => "spectrum",
            .chromatogram => "chromatogram",
        };
    }
};

const ContainerState = struct {
    byte_offset: u64,
    has_binary_data_array_list: bool = false,
};

pub const StructuralValidator = struct {
    allocator: std.mem.Allocator,
    diagnostics: *std.ArrayList(Diagnostic),
    path: ?[]const u8,

    depth: usize = 0,
    root_seen: bool = false,
    root_valid: bool = false,
    root_byte_offset: u64 = 0,

    run_seen: bool = false,
    run_depth: ?usize = null,
    run_byte_offset: ?u64 = null,
    run_has_spectrum_list: bool = false,
    run_has_chromatogram_list: bool = false,

    spectrum_list_depth: ?usize = null,
    chromatogram_list_depth: ?usize = null,

    spectrum: ?ContainerState = null,
    chromatogram: ?ContainerState = null,

    pub fn validateReader(
        allocator: std.mem.Allocator,
        io: std.Io,
        reader: *std.Io.Reader,
        diagnostics: *std.ArrayList(Diagnostic),
        path: ?[]const u8,
    ) !void {
        var token_buffer: [4096]u8 = undefined;
        var attributes: [64]Attribute = undefined;
        var namespace_bindings: [32]xml_parser.NamespaceBinding = undefined;
        var namespace_bytes: [2048]u8 = undefined;
        var element_stack: [128]xml_parser.ElementFrame = undefined;
        var element_bytes: [4096]u8 = undefined;

        var parser = xml_parser.Parser.init(reader, .{
            .token = &token_buffer,
            .attributes = &attributes,
            .namespace_bindings = &namespace_bindings,
            .namespace_bytes = &namespace_bytes,
            .element_stack = &element_stack,
            .element_bytes = &element_bytes,
        });

        var validator = StructuralValidator{
            .allocator = allocator,
            .diagnostics = diagnostics,
            .path = path,
        };
        try validator.run(io, &parser);
    }

    fn run(validator: *StructuralValidator, io: std.Io, parser: *xml_parser.Parser) !void {
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
                .start_element => |start| {
                    const element_depth = validator.depth + 1;
                    try validator.handleStart(start, element_depth);
                    validator.depth += 1;
                },
                .end_element => |end| {
                    const element_depth = validator.depth;
                    try validator.handleEnd(end, element_depth);
                    validator.depth -= 1;
                },
                .text => |text| try validator.handleText(text.value, text.byte_offset),
            }
        }

        if (!validator.root_seen) {
            try validator.appendDiagnostic(.{
                .severity = .@"error",
                .rule = RuleId.mzml_structure_root,
                .path = validator.path,
                .message = "document is missing the mzML root element",
            });
            return;
        }

        if (validator.root_valid and !validator.run_seen) {
            try validator.appendDiagnostic(.{
                .severity = .@"error",
                .rule = RuleId.mzml_structure_missing_child,
                .location = .{ .byte_offset = validator.root_byte_offset },
                .path = validator.path,
                .message = "mzML is missing required child run",
            });
        }
    }

    fn handleStart(validator: *StructuralValidator, start: StartElement, element_depth: usize) !void {
        if (!validator.root_seen) {
            validator.root_seen = true;
            validator.root_byte_offset = start.byte_offset;
            validator.root_valid = start.name.matches(mzml_namespace, "mzML");
            if (!validator.root_valid) {
                try validator.appendDiagnostic(.{
                    .severity = .@"error",
                    .rule = RuleId.mzml_structure_root,
                    .location = .{ .byte_offset = start.byte_offset },
                    .path = validator.path,
                    .message = "root element must be mzML in the http://psi.hupo.org/ms/mzml namespace",
                });
            }
            return;
        }

        if (!validator.rootValidName(start.name)) return;

        if (start.name.matches(mzml_namespace, "run")) {
            if (element_depth != 2) {
                try validator.nestingError(start.byte_offset, "run must be a direct child of mzML");
                return;
            }
            validator.run_seen = true;
            validator.run_depth = element_depth;
            validator.run_byte_offset = start.byte_offset;
            validator.run_has_spectrum_list = false;
            validator.run_has_chromatogram_list = false;
            return;
        }

        if (start.name.matches(mzml_namespace, "spectrumList")) {
            if (validator.run_depth != element_depth - 1) {
                try validator.nestingError(start.byte_offset, "spectrumList must be a child of run");
            } else {
                validator.run_has_spectrum_list = true;
            }
            validator.spectrum_list_depth = element_depth;
            try validator.requireAttribute(start, "count", "spectrumList is missing required attribute count");
            return;
        }

        if (start.name.matches(mzml_namespace, "chromatogramList")) {
            if (validator.run_depth != element_depth - 1) {
                try validator.nestingError(start.byte_offset, "chromatogramList must be a child of run");
            } else {
                validator.run_has_chromatogram_list = true;
            }
            validator.chromatogram_list_depth = element_depth;
            try validator.requireAttribute(start, "count", "chromatogramList is missing required attribute count");
            return;
        }

        if (start.name.matches(mzml_namespace, "spectrum")) {
            if (validator.spectrum_list_depth != element_depth - 1) {
                try validator.nestingError(start.byte_offset, "spectrum must be a child of spectrumList");
            }
            validator.spectrum = .{ .byte_offset = start.byte_offset };
            try validator.requireSpectrumLikeAttributes(start, .spectrum);
            return;
        }

        if (start.name.matches(mzml_namespace, "chromatogram")) {
            if (validator.chromatogram_list_depth != element_depth - 1) {
                try validator.nestingError(start.byte_offset, "chromatogram must be a child of chromatogramList");
            }
            validator.chromatogram = .{ .byte_offset = start.byte_offset };
            try validator.requireSpectrumLikeAttributes(start, .chromatogram);
            return;
        }

        if (start.name.matches(mzml_namespace, "binaryDataArrayList")) {
            try validator.requireAttribute(start, "count", "binaryDataArrayList is missing required attribute count");

            if (validator.spectrum != null and validator.spectrum_list_depth != null and validator.spectrum_list_depth.? < element_depth) {
                validator.spectrum.?.has_binary_data_array_list = true;
                return;
            }
            if (validator.chromatogram != null and validator.chromatogram_list_depth != null and validator.chromatogram_list_depth.? < element_depth) {
                validator.chromatogram.?.has_binary_data_array_list = true;
                return;
            }

            try validator.nestingError(start.byte_offset, "binaryDataArrayList must be a child of spectrum or chromatogram");
        }
    }

    fn handleEnd(validator: *StructuralValidator, end: EndElement, element_depth: usize) !void {
        if (!validator.rootValidName(end.name)) return;

        if (end.name.matches(mzml_namespace, "run")) {
            if (!validator.run_has_spectrum_list and !validator.run_has_chromatogram_list) {
                try validator.appendDiagnostic(.{
                    .severity = .@"error",
                    .rule = RuleId.mzml_structure_missing_child,
                    .location = .{ .byte_offset = validator.run_byte_offset },
                    .path = validator.path,
                    .message = "run must contain spectrumList or chromatogramList",
                });
            }
            validator.run_depth = null;
            validator.run_byte_offset = null;
            return;
        }

        if (end.name.matches(mzml_namespace, "spectrumList") and validator.spectrum_list_depth == element_depth) {
            validator.spectrum_list_depth = null;
            return;
        }

        if (end.name.matches(mzml_namespace, "chromatogramList") and validator.chromatogram_list_depth == element_depth) {
            validator.chromatogram_list_depth = null;
            return;
        }

        if (end.name.matches(mzml_namespace, "spectrum")) {
            if (validator.spectrum) |state| {
                if (!state.has_binary_data_array_list) {
                    try validator.appendDiagnostic(.{
                        .severity = .@"error",
                        .rule = RuleId.mzml_structure_missing_child,
                        .location = .{ .byte_offset = state.byte_offset },
                        .path = validator.path,
                        .message = "spectrum is missing required child binaryDataArrayList",
                    });
                }
            }
            validator.spectrum = null;
            return;
        }

        if (end.name.matches(mzml_namespace, "chromatogram")) {
            if (validator.chromatogram) |state| {
                if (!state.has_binary_data_array_list) {
                    try validator.appendDiagnostic(.{
                        .severity = .@"error",
                        .rule = RuleId.mzml_structure_missing_child,
                        .location = .{ .byte_offset = state.byte_offset },
                        .path = validator.path,
                        .message = "chromatogram is missing required child binaryDataArrayList",
                    });
                }
            }
            validator.chromatogram = null;
        }
    }

    fn handleText(validator: *StructuralValidator, value: []const u8, byte_offset: u64) !void {
        if (std.mem.trim(u8, value, &std.ascii.whitespace).len == 0) return;
        if (validator.depth == 0) {
            try validator.appendDiagnostic(.{
                .severity = .@"error",
                .rule = RuleId.mzml_structure_xml,
                .location = .{ .byte_offset = byte_offset },
                .path = validator.path,
                .message = "text outside the mzML root element is not allowed",
            });
        }
    }

    fn rootValidName(validator: *StructuralValidator, name: QName) bool {
        _ = name;
        return validator.root_valid;
    }

    fn requireSpectrumLikeAttributes(validator: *StructuralValidator, start: StartElement, kind: ContainerKind) !void {
        if (!hasAttribute(start.attributes, "id")) {
            try validator.attributeError(start.byte_offset, if (kind == .spectrum)
                "spectrum is missing required attribute id"
            else
                "chromatogram is missing required attribute id");
        }
        if (!hasAttribute(start.attributes, "index")) {
            try validator.attributeError(start.byte_offset, if (kind == .spectrum)
                "spectrum is missing required attribute index"
            else
                "chromatogram is missing required attribute index");
        }
        if (!hasAttribute(start.attributes, "defaultArrayLength")) {
            try validator.attributeError(start.byte_offset, if (kind == .spectrum)
                "spectrum is missing required attribute defaultArrayLength"
            else
                "chromatogram is missing required attribute defaultArrayLength");
        }
    }

    fn requireAttribute(validator: *StructuralValidator, start: StartElement, attribute_name: []const u8, message: []const u8) !void {
        if (hasAttribute(start.attributes, attribute_name)) return;
        try validator.attributeError(start.byte_offset, message);
    }

    fn attributeError(validator: *StructuralValidator, byte_offset: u64, message: []const u8) !void {
        try validator.appendDiagnostic(.{
            .severity = .@"error",
            .rule = RuleId.mzml_structure_attribute,
            .location = .{ .byte_offset = byte_offset },
            .path = validator.path,
            .message = message,
        });
    }

    fn nestingError(validator: *StructuralValidator, byte_offset: u64, message: []const u8) !void {
        try validator.appendDiagnostic(.{
            .severity = .@"error",
            .rule = RuleId.mzml_structure_nesting,
            .location = .{ .byte_offset = byte_offset },
            .path = validator.path,
            .message = message,
        });
    }

    fn appendDiagnostic(validator: *StructuralValidator, item: Diagnostic) !void {
        try validator.diagnostics.append(validator.allocator, item);
    }
};

fn hasAttribute(attributes: []const Attribute, local_name: []const u8) bool {
    for (attributes) |attribute| {
        if (attribute.is_namespace_declaration) continue;
        if (std.mem.eql(u8, attribute.name.local_name, local_name)) return true;
    }
    return false;
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

test "structural validator accepts realistic one-spectrum mzML fixture" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try readFixtureAlloc(allocator, io, "fixtures/examples/mzml/clean-single-spectrum.mzML");
    defer allocator.free(fixture);

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "structural validator reports wrong root namespace" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try readFixtureAlloc(allocator, io, "fixtures/examples/mzml/wrong-namespace.mzML");
    defer allocator.free(fixture);

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_structure_root, diagnostics.items[0].rule);
}

test "structural validator reports missing binaryDataArrayList" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try readFixtureAlloc(allocator, io, "fixtures/examples/mzml/missing-binary-data-array-list.mzML");
    defer allocator.free(fixture);

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_structure_missing_child, diagnostics.items[0].rule);
}

fn readFixtureAlloc(allocator: std.mem.Allocator, io: std.Io, sub_path: []const u8) ![]u8 {
    return try std.Io.Dir.cwd().readFileAlloc(io, sub_path, allocator, .limited(64 * 1024));
}
