//! Incremental mzML 1.1 structural validation.
//!
//! Checks nesting, child order, required attributes, and declared list counts
//! with fixed per-file state. Binary payloads, index cross-checks, and CV terms
//! remain owned by their stage validators.

const std = @import("std");
const diagnostic = @import("../diagnostic.zig");
const elements = @import("elements.zig");
const xml_characters = @import("../xml/characters.zig");
const xml_events = @import("../xml/events.zig");
const xml_parser = @import("../xml/parser.zig");
const xml_parse_errors = @import("../xml/parse_errors.zig");

const Attribute = xml_events.Attribute;
const Diagnostic = diagnostic.Diagnostic;
const DiagnosticSink = diagnostic.DiagnosticSink;
const EndElement = xml_events.EndElement;
const RuleId = diagnostic.RuleId;
const StartElement = xml_events.StartElement;
const ElementId = elements.ElementId;

pub const mzml_namespace = diagnostic.mzml_namespace;
const max_structural_token_bytes = 1024 * 1024;
const max_structural_depth = 128;

const ElementFrame = struct {
    tag: ElementId = .unknown,
    param_phase: u8 = 0,
    nilled: bool = false,
};

const AttributeValueKind = enum {
    string,
    any_uri,
    id,
    id_ref,
    non_negative_integer,
    int,
    date_time,
    double,
    spectrum_id,
};

const AttributeSpec = struct {
    kind: AttributeValueKind,
};

const TopLevelSlot = enum(u8) {
    cv_list = 1,
    file_description = 2,
    referenceable_param_group_list = 3,
    sample_list = 4,
    software_list = 5,
    scan_settings_list = 6,
    instrument_configuration_list = 7,
    data_processing_list = 8,
    run = 9,
};

const IndexedChildSlot = enum(u8) {
    index_list = 1,
    index_list_offset = 2,
    file_checksum = 3,
};

const RunChildSlot = enum(u8) {
    spectrum_list = 1,
    chromatogram_list = 2,
};

const SpectrumChildSlot = enum(u8) {
    scan_list = 1,
    precursor_list = 2,
    product_list = 3,
    binary_data_array_list = 4,
};

const ChromatogramChildSlot = enum(u8) {
    precursor = 1,
    product = 2,
    binary_data_array_list = 3,
};

const ComponentChildSlot = enum(u8) {
    source = 1,
    analyzer = 2,
    detector = 3,
};

const ContainerState = struct {
    byte_offset: u64,
    depth: usize,
    last_child_slot: u8 = 0,
    scan_list_seen: bool = false,
    precursor_list_seen: bool = false,
    product_list_seen: bool = false,
    binary_list_seen: bool = false,
};

const ListCountState = struct {
    byte_offset: u64,
    depth: usize,
    declared_count: usize,
    actual_count: usize = 0,
    min_count: usize,
    label: []const u8,
    child_label: []const u8,
};

const FileDescriptionState = struct {
    byte_offset: u64,
    depth: usize,
    has_file_content: bool = false,
    source_file_list_seen: bool = false,
    contact_seen: bool = false,
};

const DataProcessingState = struct {
    byte_offset: u64,
    depth: usize,
    processing_method_seen: bool = false,
};

const InstrumentConfigurationState = struct {
    byte_offset: u64,
    depth: usize,
    component_list_seen: bool = false,
    software_ref_seen: bool = false,
};

const ComponentListState = struct {
    count_state: ListCountState,
    source_count: usize = 0,
    analyzer_count: usize = 0,
    detector_count: usize = 0,
    last_child_slot: u8 = 0,
};

const ScanSettingsState = struct {
    source_file_ref_list_seen: bool = false,
    target_list_seen: bool = false,
};

const ScanState = struct {
    scan_window_list_seen: bool = false,
};

const PrecursorState = struct {
    byte_offset: u64,
    depth: usize,
    isolation_window_seen: bool = false,
    selected_ion_list_seen: bool = false,
    activation_seen: bool = false,
    last_child_slot: u8 = 0,
};

const ProductState = struct {
    isolation_window_seen: bool = false,
};

const BinaryDataArrayState = struct {
    byte_offset: u64,
    depth: usize,
    binary_seen: bool = false,
};

const IndexState = struct {
    byte_offset: u64,
    depth: usize,
    offset_count: usize = 0,
};

/// Incremental validator whose retained state is independent of document length.
pub const StructuralValidator = struct {
    allocator: std.mem.Allocator,
    diagnostics: *DiagnosticSink,
    path: ?[]const u8,

    // Container state is replaced at its end tag, independent of spectrum count.
    depth: usize = 0,
    frames: [max_structural_depth]ElementFrame = @splat(.{}),
    root_seen: bool = false,
    root_valid: bool = false,
    root_byte_offset: u64 = 0,
    indexed_mzml_depth: ?usize = null,
    indexed_mzml_seen: bool = false,
    mzml_depth: ?usize = null,
    cv_list_seen: bool = false,
    file_description_seen: bool = false,
    referenceable_param_group_list_seen: bool = false,
    sample_list_seen: bool = false,
    software_list_seen: bool = false,
    scan_settings_list_seen: bool = false,
    instrument_configuration_list_seen: bool = false,
    data_processing_list_seen: bool = false,
    last_top_level_slot: u8 = 0,
    // Suppresses repeated diagnostics for the same duplicated top-level slot.
    dup_reported_mask: u32 = 0,

    run_seen: bool = false,
    run_depth: ?usize = null,
    run_has_spectrum_list: bool = false,
    run_has_chromatogram_list: bool = false,
    run_last_child_slot: u8 = 0,

    index_list_seen: bool = false,
    index_list_offset_seen: bool = false,
    file_checksum_seen: bool = false,
    last_indexed_child_slot: u8 = 0,

    file_description: ?FileDescriptionState = null,

    cv_list: ?ListCountState = null,
    referenceable_param_group_list: ?ListCountState = null,
    sample_list: ?ListCountState = null,
    software_list: ?ListCountState = null,
    scan_settings_list: ?ListCountState = null,
    instrument_configuration_list: ?ListCountState = null,
    data_processing_list: ?ListCountState = null,
    source_file_list: ?ListCountState = null,
    source_file_ref_list: ?ListCountState = null,
    target_list: ?ListCountState = null,
    index_list: ?ListCountState = null,
    component_list: ?ComponentListState = null,

    instrument_configuration: ?InstrumentConfigurationState = null,
    data_processing: ?DataProcessingState = null,
    scan_settings: ?ScanSettingsState = null,
    scan: ?ScanState = null,
    precursor: ?PrecursorState = null,
    product: ?ProductState = null,
    binary_data_array: ?BinaryDataArrayState = null,
    index: ?IndexState = null,

    spectrum_list_depth: ?usize = null,
    chromatogram_list_depth: ?usize = null,
    spectrum_list: ?ListCountState = null,
    chromatogram_list: ?ListCountState = null,
    scan_list: ?ListCountState = null,
    precursor_list: ?ListCountState = null,
    product_list: ?ListCountState = null,
    scan_window_list: ?ListCountState = null,
    selected_ion_list: ?ListCountState = null,
    binary_data_array_list: ?ListCountState = null,

    spectrum: ?ContainerState = null,
    chromatogram: ?ContainerState = null,

    pub fn init(
        allocator: std.mem.Allocator,
        diagnostics: *DiagnosticSink,
        path: ?[]const u8,
    ) StructuralValidator {
        return .{
            .allocator = allocator,
            .diagnostics = diagnostics,
            .path = path,
        };
    }

    pub fn deinit(validator: *StructuralValidator) void {
        _ = validator;
    }

    pub fn validateReader(
        allocator: std.mem.Allocator,
        io: std.Io,
        reader: *std.Io.Reader,
        diagnostics: *DiagnosticSink,
        path: ?[]const u8,
    ) !void {
        const token_buffer = try allocator.alloc(u8, max_structural_token_bytes);
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

        var validator = StructuralValidator.init(allocator, diagnostics, path);
        defer validator.deinit();
        _ = io;
        try validator.run(&parser);
    }

    pub fn consumeStart(validator: *StructuralValidator, start: StartElement) !void {
        if (validator.depth == max_structural_depth) return error.ResourceLimitExceeded;
        const element_depth = validator.depth + 1;
        const tag = start.resolvedId();

        var accepted = true;
        if (validator.depth > 0) {
            const parent = &validator.frames[validator.depth - 1];
            if (parent.tag == .unknown) {
                accepted = false;
            } else if (!isAllowedParent(tag, parent.tag)) {
                try validator.nestingError(start.byte_offset, invalidParentMessage(tag, parent.tag));
                accepted = false;
            } else if (!try validator.noteParamGroupOrder(parent, tag, start.byte_offset)) {
                accepted = false;
            }
        }

        const nilled = if (accepted and tag != .unknown)
            try validator.validateAttributes(start, tag)
        else
            false;
        validator.frames[validator.depth] = .{ .tag = if (accepted) tag else .unknown, .nilled = nilled };
        if (!accepted) {
            validator.depth += 1;
            return;
        }
        try validator.handleStart(start, element_depth);
        validator.depth += 1;
    }

    pub fn consumeEnd(validator: *StructuralValidator, end: EndElement) !void {
        if (validator.depth == 0) return error.ResourceLimitExceeded;
        const element_depth = validator.depth;
        const frame = validator.frames[validator.depth - 1];
        if (frame.tag != .unknown) try validator.handleEnd(end, element_depth);
        validator.frames[validator.depth - 1] = .{};
        validator.depth -= 1;
    }

    pub fn consumeText(validator: *StructuralValidator, text: xml_events.Text) !void {
        try validator.handleText(text.value, text.byte_offset);
    }

    pub fn finish(validator: *StructuralValidator) !void {
        if (!validator.root_seen) {
            try validator.appendDiagnostic(.{
                .severity = .@"error",
                .rule = RuleId.mzml_structure_root,
                .path = validator.path,
                .message = "document is missing the mzML root element",
            });
            return;
        }

        if (!validator.root_valid and validator.indexed_mzml_depth != null) {
            try validator.appendDiagnostic(.{
                .severity = .@"error",
                .rule = RuleId.mzml_structure_root,
                .location = .{ .byte_offset = validator.root_byte_offset },
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

        try validator.reportMissingTopLevelChildren();

        if (validator.indexed_mzml_depth != null) {
            if (!validator.index_list_seen) {
                try validator.appendDiagnostic(.{
                    .severity = .@"error",
                    .rule = RuleId.mzml_structure_missing_child,
                    .location = .{ .byte_offset = validator.root_byte_offset },
                    .path = validator.path,
                    .message = "indexedmzML is missing required child indexList",
                });
            }
            if (!validator.index_list_offset_seen) {
                try validator.appendDiagnostic(.{
                    .severity = .@"error",
                    .rule = RuleId.mzml_structure_missing_child,
                    .location = .{ .byte_offset = validator.root_byte_offset },
                    .path = validator.path,
                    .message = "indexedmzML is missing required child indexListOffset",
                });
            }
            if (!validator.file_checksum_seen) {
                try validator.appendDiagnostic(.{
                    .severity = .@"error",
                    .rule = RuleId.mzml_structure_missing_child,
                    .location = .{ .byte_offset = validator.root_byte_offset },
                    .path = validator.path,
                    .message = "indexedmzML is missing required child fileChecksum",
                });
            }
        }
    }

    fn run(validator: *StructuralValidator, parser: *xml_parser.Parser) !void {
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

    fn handleStart(validator: *StructuralValidator, start: StartElement, element_depth: usize) !void {
        const tag = start.resolvedId();

        if (!validator.root_seen) {
            validator.root_seen = true;
            validator.root_byte_offset = start.byte_offset;
            if (tag == .indexedmzML) {
                validator.indexed_mzml_depth = element_depth;
                return;
            }

            validator.root_valid = tag == .mzML;
            if (!validator.root_valid) {
                try validator.appendDiagnostic(.{
                    .severity = .@"error",
                    .rule = RuleId.mzml_structure_root,
                    .location = .{ .byte_offset = start.byte_offset },
                    .path = validator.path,
                    .message = "root element must be mzML in the http://psi.hupo.org/ms/mzml namespace",
                });
            } else {
                validator.mzml_depth = element_depth;
            }
            return;
        }

        if (validator.indexed_mzml_depth != null and
            element_depth == validator.indexed_mzml_depth.? + 1 and
            tag == .mzML)
        {
            if (validator.indexed_mzml_seen) {
                try validator.nestingError(start.byte_offset, "indexedmzML must not contain more than one mzML element");
                return;
            }
            validator.indexed_mzml_seen = true;
            validator.root_valid = true;
            validator.root_byte_offset = start.byte_offset;
            validator.mzml_depth = element_depth;
            return;
        }

        // Wrapper metadata is outside mzML scope but still structurally required.
        if (validator.indexed_mzml_depth != null and
            element_depth == validator.indexed_mzml_depth.? + 1)
        {
            switch (tag) {
                .indexList => {
                    try validator.noteIndexedChild(start.byte_offset, &validator.index_list_seen, .index_list);
                    validator.index_list = try validator.initListCountState(start, element_depth, "indexList", "index", 1);
                    return;
                },
                .indexListOffset => {
                    try validator.noteIndexedChild(start.byte_offset, &validator.index_list_offset_seen, .index_list_offset);
                    return;
                },
                .fileChecksum => {
                    try validator.noteIndexedChild(start.byte_offset, &validator.file_checksum_seen, .file_checksum);
                    return;
                },
                else => {
                    try validator.nestingError(start.byte_offset, "element is not allowed as a direct child of indexedmzML");
                    return;
                },
            }
        }

        if (validator.indexed_mzml_depth != null and validator.mzml_depth == null) {
            switch (tag) {
                .index => {
                    validator.bumpListItemCount(&validator.index_list, element_depth);
                    validator.index = .{ .byte_offset = start.byte_offset, .depth = element_depth };
                    return;
                },
                .offset => {
                    if (validator.index) |*state| state.offset_count += 1;
                    return;
                },
                else => {},
            }
        }

        if (!validator.isWithinMzmlStartScope()) return;

        switch (tag) {
            .cvList => {
                try validator.recordTopLevelElement(start.byte_offset, element_depth, &validator.cv_list_seen, "cvList", .cv_list);
                validator.cv_list = try validator.initListCountState(start, element_depth, "cvList", "cv", 1);
            },
            .fileDescription => {
                try validator.recordTopLevelElement(start.byte_offset, element_depth, &validator.file_description_seen, "fileDescription", .file_description);
                validator.file_description = .{ .byte_offset = start.byte_offset, .depth = element_depth };
            },
            .referenceableParamGroupList => {
                try validator.recordTopLevelElement(start.byte_offset, element_depth, &validator.referenceable_param_group_list_seen, "referenceableParamGroupList", .referenceable_param_group_list);
                validator.referenceable_param_group_list = try validator.initListCountState(start, element_depth, "referenceableParamGroupList", "referenceableParamGroup", 1);
            },
            .sampleList => {
                try validator.recordTopLevelElement(start.byte_offset, element_depth, &validator.sample_list_seen, "sampleList", .sample_list);
                validator.sample_list = try validator.initListCountState(start, element_depth, "sampleList", "sample", 1);
            },
            .softwareList => {
                try validator.recordTopLevelElement(start.byte_offset, element_depth, &validator.software_list_seen, "softwareList", .software_list);
                validator.software_list = try validator.initListCountState(start, element_depth, "softwareList", "software", 1);
            },
            .scanSettingsList => {
                try validator.recordTopLevelElement(start.byte_offset, element_depth, &validator.scan_settings_list_seen, "scanSettingsList", .scan_settings_list);
                validator.scan_settings_list = try validator.initListCountState(start, element_depth, "scanSettingsList", "scanSettings", 1);
            },
            .instrumentConfigurationList => {
                try validator.recordTopLevelElement(start.byte_offset, element_depth, &validator.instrument_configuration_list_seen, "instrumentConfigurationList", .instrument_configuration_list);
                validator.instrument_configuration_list = try validator.initListCountState(start, element_depth, "instrumentConfigurationList", "instrumentConfiguration", 1);
            },
            .dataProcessingList => {
                try validator.recordTopLevelElement(start.byte_offset, element_depth, &validator.data_processing_list_seen, "dataProcessingList", .data_processing_list);
                validator.data_processing_list = try validator.initListCountState(start, element_depth, "dataProcessingList", "dataProcessing", 1);
            },
            .run => {
                if (element_depth != validator.topLevelChildDepth()) {
                    try validator.nestingError(start.byte_offset, "run must be a direct child of mzML");
                    return;
                }
                try validator.recordTopLevelElement(start.byte_offset, element_depth, &validator.run_seen, "run", .run);
                validator.run_seen = true;
                validator.run_depth = element_depth;
                validator.run_has_spectrum_list = false;
                validator.run_has_chromatogram_list = false;
                validator.run_last_child_slot = 0;
            },
            .indexList, .indexListOffset, .fileChecksum => try validator.nestingError(start.byte_offset, "index metadata must be a direct child of indexedmzML"),
            .fileContent => {
                if (validator.file_description) |*state| {
                    if (state.depth + 1 != element_depth) {
                        try validator.nestingError(start.byte_offset, "fileContent must be a direct child of fileDescription");
                    } else {
                        if (state.has_file_content) {
                            try validator.nestingError(start.byte_offset, "fileDescription must not contain more than one fileContent");
                            return;
                        }
                        if (state.source_file_list_seen or state.contact_seen) {
                            try validator.nestingError(start.byte_offset, "fileContent appears out of order under fileDescription");
                            return;
                        }
                        state.has_file_content = true;
                    }
                }
            },
            .sourceFileList => {
                if (validator.file_description) |*state| {
                    if (state.depth + 1 != element_depth) {
                        try validator.nestingError(start.byte_offset, "sourceFileList must be a direct child of fileDescription");
                    } else {
                        if (state.source_file_list_seen) {
                            try validator.nestingError(start.byte_offset, "fileDescription must not contain more than one sourceFileList");
                        }
                        state.source_file_list_seen = true;
                        if (!state.has_file_content) {
                            try validator.nestingError(start.byte_offset, "sourceFileList appears out of order under fileDescription");
                        }
                        if (state.contact_seen) {
                            try validator.nestingError(start.byte_offset, "sourceFileList appears out of order under fileDescription");
                        }
                    }
                }
                validator.source_file_list = try validator.initListCountState(start, element_depth, "sourceFileList", "sourceFile", 1);
            },
            .sourceFile => {
                validator.bumpListItemCount(&validator.source_file_list, element_depth);
            },
            .spectrumList => {
                try validator.noteRunChild(start.byte_offset, .spectrum_list);
                if (validator.run_depth != element_depth - 1) {
                    try validator.nestingError(start.byte_offset, "spectrumList must be a child of run");
                } else {
                    validator.run_has_spectrum_list = true;
                }
                validator.spectrum_list_depth = element_depth;
                validator.spectrum_list = try validator.initListCountState(start, element_depth, "spectrumList", "spectrum", 0);
            },
            .chromatogramList => {
                try validator.noteRunChild(start.byte_offset, .chromatogram_list);
                if (validator.run_depth != element_depth - 1) {
                    try validator.nestingError(start.byte_offset, "chromatogramList must be a child of run");
                } else {
                    validator.run_has_chromatogram_list = true;
                }
                validator.chromatogram_list_depth = element_depth;
                validator.chromatogram_list = try validator.initListCountState(start, element_depth, "chromatogramList", "chromatogram", 1);
            },
            .spectrum => {
                validator.bumpListItemCount(&validator.spectrum_list, element_depth);
                if (validator.spectrum_list_depth != element_depth - 1) {
                    try validator.nestingError(start.byte_offset, "spectrum must be a child of spectrumList");
                }
                validator.spectrum = .{ .byte_offset = start.byte_offset, .depth = element_depth };
            },
            .chromatogram => {
                validator.bumpListItemCount(&validator.chromatogram_list, element_depth);
                if (validator.chromatogram_list_depth != element_depth - 1) {
                    try validator.nestingError(start.byte_offset, "chromatogram must be a child of chromatogramList");
                }
                validator.chromatogram = .{ .byte_offset = start.byte_offset, .depth = element_depth };
            },
            .cv => {
                validator.bumpListItemCount(&validator.cv_list, element_depth);
            },
            .referenceableParamGroup => {
                validator.bumpListItemCount(&validator.referenceable_param_group_list, element_depth);
            },
            .referenceableParamGroupRef => {},
            .sample => {
                validator.bumpListItemCount(&validator.sample_list, element_depth);
            },
            .software => {
                validator.bumpListItemCount(&validator.software_list, element_depth);
            },
            .scanSettings => {
                validator.bumpListItemCount(&validator.scan_settings_list, element_depth);
                validator.scan_settings = .{};
            },
            .instrumentConfiguration => {
                validator.bumpListItemCount(&validator.instrument_configuration_list, element_depth);
                validator.instrument_configuration = .{ .byte_offset = start.byte_offset, .depth = element_depth };
            },
            .componentList => {
                if (validator.instrument_configuration) |*state| {
                    if (state.depth + 1 != element_depth) {
                        try validator.nestingError(start.byte_offset, "componentList must be a direct child of instrumentConfiguration");
                    } else {
                        if (state.component_list_seen) {
                            try validator.nestingError(start.byte_offset, "instrumentConfiguration must not contain more than one componentList");
                        }
                        if (state.software_ref_seen) {
                            try validator.nestingError(start.byte_offset, "componentList appears out of order under instrumentConfiguration");
                        }
                        state.component_list_seen = true;
                    }
                }
                const count_state = try validator.initListCountState(start, element_depth, "componentList", "component", 3);
                if (count_state) |active| {
                    validator.component_list = .{ .count_state = active };
                } else {
                    validator.component_list = null;
                }
            },
            .softwareRef => {
                if (validator.instrument_configuration) |*state| {
                    if (state.depth + 1 != element_depth) {
                        try validator.nestingError(start.byte_offset, "softwareRef must be a direct child of instrumentConfiguration");
                    } else {
                        if (state.software_ref_seen) {
                            try validator.nestingError(start.byte_offset, "instrumentConfiguration must not contain more than one softwareRef");
                        }
                        state.software_ref_seen = true;
                    }
                }
            },
            .sourceFileRef => {
                validator.bumpListItemCount(&validator.source_file_ref_list, element_depth);
            },
            .source => {
                try validator.noteComponentChild(start.byte_offset, .source);
            },
            .analyzer => {
                try validator.noteComponentChild(start.byte_offset, .analyzer);
            },
            .detector => {
                try validator.noteComponentChild(start.byte_offset, .detector);
            },
            .dataProcessing => {
                validator.bumpListItemCount(&validator.data_processing_list, element_depth);
                validator.data_processing = .{ .byte_offset = start.byte_offset, .depth = element_depth };
            },
            .processingMethod => {
                if (validator.data_processing) |*state| {
                    if (state.depth + 1 != element_depth) {
                        try validator.nestingError(start.byte_offset, "processingMethod must be a direct child of dataProcessing");
                    } else {
                        state.processing_method_seen = true;
                    }
                }
            },
            .scanList => {
                if (validator.spectrum == null) {
                    try validator.nestingError(start.byte_offset, "scanList must be a child of spectrum");
                }
                try validator.noteSpectrumChild(start.byte_offset, .scan_list);
                validator.scan_list = try validator.initListCountState(start, element_depth, "scanList", "scan", 1);
            },
            .precursorList => {
                if (validator.spectrum == null) {
                    try validator.nestingError(start.byte_offset, "precursorList must be a child of spectrum");
                }
                try validator.noteSpectrumChild(start.byte_offset, .precursor_list);
                validator.precursor_list = try validator.initListCountState(start, element_depth, "precursorList", "precursor", 1);
            },
            .productList => {
                if (validator.spectrum == null) {
                    try validator.nestingError(start.byte_offset, "productList must be a child of spectrum");
                }
                try validator.noteSpectrumChild(start.byte_offset, .product_list);
                validator.product_list = try validator.initListCountState(start, element_depth, "productList", "product", 1);
            },
            .precursor => {
                if (validator.chromatogram) |state| {
                    if (state.depth + 1 == element_depth) {
                        try validator.noteChromatogramChild(start.byte_offset, .precursor);
                    }
                } else if (validator.spectrum != null) {
                    validator.bumpListItemCount(&validator.precursor_list, element_depth);
                } else {
                    try validator.nestingError(start.byte_offset, "precursor must be a child of chromatogram");
                }
                validator.precursor = .{ .byte_offset = start.byte_offset, .depth = element_depth };
            },
            .product => {
                if (validator.chromatogram) |state| {
                    if (state.depth + 1 == element_depth) {
                        try validator.noteChromatogramChild(start.byte_offset, .product);
                    }
                } else if (validator.spectrum != null) {
                    validator.bumpListItemCount(&validator.product_list, element_depth);
                } else {
                    try validator.nestingError(start.byte_offset, "product must be a child of chromatogram");
                }
                validator.product = .{};
            },
            .scan => {
                validator.bumpListItemCount(&validator.scan_list, element_depth);
                validator.scan = .{};
            },
            .scanWindowList => {
                if (validator.scan) |*state| {
                    if (state.scan_window_list_seen) {
                        try validator.nestingError(start.byte_offset, "scan must not contain more than one scanWindowList");
                    }
                    state.scan_window_list_seen = true;
                }
                validator.scan_window_list = try validator.initListCountState(start, element_depth, "scanWindowList", "scanWindow", 1);
            },
            .scanWindow => {
                validator.bumpListItemCount(&validator.scan_window_list, element_depth);
            },
            .selectedIonList => {
                if (validator.precursor) |*state| {
                    try validator.notePrecursorChild(state, start.byte_offset, 2);
                }
                validator.selected_ion_list = try validator.initListCountState(start, element_depth, "selectedIonList", "selectedIon", 1);
            },
            .selectedIon => {
                validator.bumpListItemCount(&validator.selected_ion_list, element_depth);
            },
            .binaryDataArrayList => {
                try validator.noteBinaryDataArrayListChild(start.byte_offset);
                validator.binary_data_array_list = try validator.initListCountState(start, element_depth, "binaryDataArrayList", "binaryDataArray", 2);
            },
            .binaryDataArray => {
                validator.bumpListItemCount(&validator.binary_data_array_list, element_depth);
                validator.binary_data_array = .{ .byte_offset = start.byte_offset, .depth = element_depth };
            },
            .binary => {
                if (validator.binary_data_array) |*state| {
                    if (state.binary_seen) {
                        try validator.nestingError(start.byte_offset, "binaryDataArray must not contain more than one binary element");
                    }
                    state.binary_seen = true;
                }
            },
            .sourceFileRefList => {
                if (validator.scan_settings) |*state| {
                    if (state.source_file_ref_list_seen) {
                        try validator.nestingError(start.byte_offset, "scanSettings must not contain more than one sourceFileRefList");
                    }
                    if (state.target_list_seen) {
                        try validator.nestingError(start.byte_offset, "sourceFileRefList appears out of order under scanSettings");
                    }
                    state.source_file_ref_list_seen = true;
                }
                validator.source_file_ref_list = try validator.initListCountState(start, element_depth, "sourceFileRefList", "sourceFileRef", 0);
            },
            .targetList => {
                if (validator.scan_settings) |*state| {
                    if (state.target_list_seen) {
                        try validator.nestingError(start.byte_offset, "scanSettings must not contain more than one targetList");
                    }
                    state.target_list_seen = true;
                }
                validator.target_list = try validator.initListCountState(start, element_depth, "targetList", "target", 1);
            },
            .target => validator.bumpListItemCount(&validator.target_list, element_depth),
            .index => {
                validator.bumpListItemCount(&validator.index_list, element_depth);
                validator.index = .{ .byte_offset = start.byte_offset, .depth = element_depth };
            },
            .offset => {
                if (validator.index) |*state| state.offset_count += 1;
            },
            .contact => {
                if (validator.file_description) |*state| state.contact_seen = true;
            },
            .isolationWindow => {
                if (validator.precursor) |*state| {
                    try validator.notePrecursorChild(state, start.byte_offset, 1);
                } else if (validator.product) |*state| {
                    if (state.isolation_window_seen) {
                        try validator.nestingError(start.byte_offset, "product must not contain more than one isolationWindow");
                    }
                    state.isolation_window_seen = true;
                }
            },
            .activation => {
                if (validator.precursor) |*state| {
                    try validator.notePrecursorChild(state, start.byte_offset, 3);
                }
            },
            // SemanticValidator owns CV terms, including unknown intern IDs.
            .cvParam, .userParam => return,
            else => {
                const in_mzml_ns = if (start.name.namespace_uri) |ns|
                    std.mem.eql(u8, ns, mzml_namespace)
                else
                    true;
                if (in_mzml_ns and !elements.isKnownMzmlLocalName(start.name.local_name)) {
                    try validator.appendDiagnostic(.{
                        .severity = .@"error",
                        .rule = RuleId.mzml_structure_nesting,
                        .location = .{ .byte_offset = start.byte_offset },
                        .path = validator.path,
                        .message = "unrecognized element in mzML scope",
                    });
                }
            },
        }
    }

    fn handleEnd(validator: *StructuralValidator, end: EndElement, element_depth: usize) !void {
        const tag = end.resolvedId();

        if (validator.indexed_mzml_depth != null) {
            switch (tag) {
                .indexList => {
                    try validator.finishListCount(&validator.index_list, element_depth);
                    return;
                },
                .index => {
                    if (validator.index) |state| {
                        if (state.depth == element_depth and state.offset_count == 0) {
                            try validator.appendDiagnostic(.{
                                .severity = .@"error",
                                .rule = RuleId.mzml_structure_missing_child,
                                .location = .{ .byte_offset = state.byte_offset },
                                .path = validator.path,
                                .message = "index must contain at least 1 offset element",
                            });
                        }
                    }
                    validator.index = null;
                    return;
                },
                .offset, .indexListOffset, .fileChecksum, .indexedmzML => return,
                else => {},
            }
        }

        if (!validator.isWithinMzmlEndScope(element_depth)) return;

        switch (tag) {
            .cv, .cvParam, .userParam => return,
            .mzML => {
                if (validator.mzml_depth == element_depth) {
                    validator.mzml_depth = null;
                }
            },
            .run => {
                validator.run_depth = null;
            },
            .fileDescription => {
                if (validator.file_description) |state| {
                    if (!state.has_file_content) {
                        try validator.appendDiagnostic(.{
                            .severity = .@"error",
                            .rule = RuleId.mzml_structure_missing_child,
                            .location = .{ .byte_offset = state.byte_offset },
                            .path = validator.path,
                            .message = "fileDescription is missing required child fileContent",
                        });
                    }
                }
                validator.file_description = null;
            },
            .cvList => try validator.finishListCount(&validator.cv_list, element_depth),
            .sourceFileList => try validator.finishListCount(&validator.source_file_list, element_depth),
            .sourceFileRefList => try validator.finishListCount(&validator.source_file_ref_list, element_depth),
            .targetList => try validator.finishListCount(&validator.target_list, element_depth),
            .referenceableParamGroupList => try validator.finishListCount(&validator.referenceable_param_group_list, element_depth),
            .sampleList => try validator.finishListCount(&validator.sample_list, element_depth),
            .softwareList => try validator.finishListCount(&validator.software_list, element_depth),
            .scanSettingsList => try validator.finishListCount(&validator.scan_settings_list, element_depth),
            .instrumentConfigurationList => try validator.finishListCount(&validator.instrument_configuration_list, element_depth),
            .componentList => try validator.finishComponentList(element_depth),
            .instrumentConfiguration => validator.instrument_configuration = null,
            .scanSettings => validator.scan_settings = null,
            .dataProcessingList => try validator.finishListCount(&validator.data_processing_list, element_depth),
            .dataProcessing => {
                if (validator.data_processing) |state| {
                    if (!state.processing_method_seen) {
                        try validator.appendDiagnostic(.{
                            .severity = .@"error",
                            .rule = RuleId.mzml_structure_missing_child,
                            .location = .{ .byte_offset = state.byte_offset },
                            .path = validator.path,
                            .message = "dataProcessing is missing required child processingMethod",
                        });
                    }
                }
                validator.data_processing = null;
            },
            .spectrumList => {
                if (validator.spectrum_list_depth == element_depth) {
                    try validator.finishListCount(&validator.spectrum_list, element_depth);
                    validator.spectrum_list_depth = null;
                }
            },
            .chromatogramList => {
                if (validator.chromatogram_list_depth == element_depth) {
                    try validator.finishListCount(&validator.chromatogram_list, element_depth);
                    validator.chromatogram_list_depth = null;
                }
            },
            .scanList => try validator.finishListCount(&validator.scan_list, element_depth),
            .binaryDataArrayList => try validator.finishListCount(&validator.binary_data_array_list, element_depth),
            .precursorList => try validator.finishListCount(&validator.precursor_list, element_depth),
            .productList => try validator.finishListCount(&validator.product_list, element_depth),
            .scanWindowList => try validator.finishListCount(&validator.scan_window_list, element_depth),
            .selectedIonList => try validator.finishListCount(&validator.selected_ion_list, element_depth),
            .scan => validator.scan = null,
            .precursor => {
                if (validator.precursor) |state| {
                    if (state.depth == element_depth and !state.activation_seen) {
                        try validator.appendDiagnostic(.{
                            .severity = .@"error",
                            .rule = RuleId.mzml_structure_missing_child,
                            .location = .{ .byte_offset = state.byte_offset },
                            .path = validator.path,
                            .message = "precursor is missing required child activation",
                        });
                    }
                }
                validator.precursor = null;
            },
            .product => validator.product = null,
            .binaryDataArray => {
                if (validator.binary_data_array) |state| {
                    if (state.depth == element_depth and !state.binary_seen) {
                        try validator.appendDiagnostic(.{
                            .severity = .@"error",
                            .rule = RuleId.mzml_structure_missing_child,
                            .location = .{ .byte_offset = state.byte_offset },
                            .path = validator.path,
                            .message = "binaryDataArray is missing required child binary",
                        });
                    }
                }
                validator.binary_data_array = null;
            },
            .spectrum => {
                validator.spectrum = null;
            },
            .chromatogram => {
                if (validator.chromatogram) |state| {
                    if (!state.binary_list_seen) {
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
            },
            else => {},
        }
    }
    fn handleText(validator: *StructuralValidator, value: []const u8, byte_offset: u64) !void {
        if (std.mem.trim(u8, value, " \t\r\n").len == 0) return;
        if (validator.depth == 0) {
            try validator.appendDiagnostic(.{
                .severity = .@"error",
                .rule = RuleId.mzml_structure_xml,
                .location = .{ .byte_offset = byte_offset },
                .path = validator.path,
                .message = "text outside the mzML root element is not allowed",
            });
            return;
        }

        const frame = validator.frames[validator.depth - 1];
        if (frame.tag == .unknown) return;
        if (frame.nilled) {
            try validator.nestingError(byte_offset, "nilled element must not contain text");
            return;
        }
        switch (frame.tag) {
            .binary, .offset, .indexListOffset, .fileChecksum => return,
            else => try validator.nestingError(byte_offset, "non-whitespace text is not allowed in element-only mzML content"),
        }
    }

    fn noteParamGroupOrder(validator: *StructuralValidator, parent: *ElementFrame, child: ElementId, byte_offset: u64) !bool {
        const phase = paramGroupChildPhase(parent.tag, child) orelse return true;
        if (phase < parent.param_phase) {
            try validator.nestingError(byte_offset, "parameter element appears out of order in mzML content");
            return false;
        }
        parent.param_phase = phase;
        return true;
    }

    fn notePrecursorChild(validator: *StructuralValidator, state: *PrecursorState, byte_offset: u64, slot: u8) !void {
        const seen = switch (slot) {
            1 => &state.isolation_window_seen,
            2 => &state.selected_ion_list_seen,
            3 => &state.activation_seen,
            else => unreachable,
        };
        if (seen.*) {
            const message = switch (slot) {
                1 => "precursor must not contain more than one isolationWindow",
                2 => "precursor must not contain more than one selectedIonList",
                3 => "precursor must not contain more than one activation",
                else => unreachable,
            };
            try validator.nestingError(byte_offset, message);
            return;
        }
        seen.* = true;
        if (slot < state.last_child_slot) {
            const message = switch (slot) {
                1 => "isolationWindow appears out of order under precursor",
                2 => "selectedIonList appears out of order under precursor",
                3 => unreachable,
                else => unreachable,
            };
            try validator.nestingError(byte_offset, message);
            return;
        }
        state.last_child_slot = slot;
    }

    fn noteRunChild(validator: *StructuralValidator, byte_offset: u64, slot: RunChildSlot) !void {
        if (validator.run_depth == null) return;

        switch (slot) {
            .spectrum_list => {
                if (validator.run_has_spectrum_list) {
                    try validator.nestingError(byte_offset, "run must not contain more than one spectrumList");
                    return;
                }
                if (validator.run_last_child_slot > @intFromEnum(slot)) {
                    try validator.nestingError(byte_offset, "spectrumList appears out of order under run");
                    return;
                }
            },
            .chromatogram_list => {
                if (validator.run_has_chromatogram_list) {
                    try validator.nestingError(byte_offset, "run must not contain more than one chromatogramList");
                    return;
                }
            },
        }

        validator.run_last_child_slot = @intFromEnum(slot);
    }

    fn noteIndexedChild(validator: *StructuralValidator, byte_offset: u64, seen: *bool, slot: IndexedChildSlot) !void {
        if (!validator.root_valid) {
            try validator.nestingError(byte_offset, indexedChildBeforeMzmlMessage(slot));
        }
        if (seen.*) {
            try validator.nestingError(byte_offset, duplicateIndexedChildMessage(slot));
            return;
        }

        const slot_value = @intFromEnum(slot);
        if (slot_value < validator.last_indexed_child_slot) {
            try validator.nestingError(byte_offset, indexedChildOutOfOrderMessage(slot));
        } else {
            validator.last_indexed_child_slot = slot_value;
        }
        seen.* = true;
    }

    fn noteSpectrumChild(validator: *StructuralValidator, byte_offset: u64, slot: SpectrumChildSlot) !void {
        if (validator.spectrum) |*state| {
            switch (slot) {
                .scan_list => {
                    if (state.scan_list_seen) {
                        try validator.nestingError(byte_offset, "spectrum must not contain more than one scanList");
                        return;
                    }
                    state.scan_list_seen = true;
                },
                .precursor_list => {
                    if (state.precursor_list_seen) {
                        try validator.nestingError(byte_offset, "spectrum must not contain more than one precursorList");
                        return;
                    }
                    state.precursor_list_seen = true;
                },
                .product_list => {
                    if (state.product_list_seen) {
                        try validator.nestingError(byte_offset, "spectrum must not contain more than one productList");
                        return;
                    }
                    state.product_list_seen = true;
                },
                .binary_data_array_list => {
                    if (state.binary_list_seen) {
                        try validator.nestingError(byte_offset, "spectrum must not contain more than one binaryDataArrayList");
                        return;
                    }
                    state.binary_list_seen = true;
                },
            }

            if (state.last_child_slot > @intFromEnum(slot)) {
                try validator.nestingError(byte_offset, spectrumChildOutOfOrderMessage(slot));
                return;
            }
            state.last_child_slot = @intFromEnum(slot);
        }
    }

    fn noteChromatogramChild(validator: *StructuralValidator, byte_offset: u64, slot: ChromatogramChildSlot) !void {
        if (validator.chromatogram) |*state| {
            switch (slot) {
                .precursor => {
                    if (state.precursor_list_seen) {
                        try validator.nestingError(byte_offset, "chromatogram must not contain more than one precursor");
                        return;
                    }
                    state.precursor_list_seen = true;
                },
                .product => {
                    if (state.product_list_seen) {
                        try validator.nestingError(byte_offset, "chromatogram must not contain more than one product");
                        return;
                    }
                    state.product_list_seen = true;
                },
                .binary_data_array_list => {
                    if (state.binary_list_seen) {
                        try validator.nestingError(byte_offset, "chromatogram must not contain more than one binaryDataArrayList");
                        return;
                    }
                    state.binary_list_seen = true;
                },
            }

            if (state.last_child_slot > @intFromEnum(slot)) {
                try validator.nestingError(byte_offset, chromatogramChildOutOfOrderMessage(slot));
                return;
            }
            state.last_child_slot = @intFromEnum(slot);
        }
    }

    fn noteBinaryDataArrayListChild(validator: *StructuralValidator, byte_offset: u64) !void {
        if (validator.spectrum != null) {
            try validator.noteSpectrumChild(byte_offset, .binary_data_array_list);
            return;
        }
        if (validator.chromatogram != null) {
            try validator.noteChromatogramChild(byte_offset, .binary_data_array_list);
        }
    }

    fn noteComponentChild(validator: *StructuralValidator, byte_offset: u64, slot: ComponentChildSlot) !void {
        if (validator.component_list) |*state| {
            if (state.count_state.depth + 1 != validator.depth + 1) return;

            state.count_state.actual_count += 1;
            switch (slot) {
                .source => state.source_count += 1,
                .analyzer => state.analyzer_count += 1,
                .detector => state.detector_count += 1,
            }

            if (state.last_child_slot > @intFromEnum(slot)) {
                try validator.nestingError(byte_offset, componentChildOutOfOrderMessage(slot));
                return;
            }
            state.last_child_slot = @intFromEnum(slot);
        }
    }

    fn finishComponentList(validator: *StructuralValidator, element_depth: usize) !void {
        if (validator.component_list) |state| {
            if (state.count_state.depth == element_depth) {
                if (state.count_state.declared_count != state.count_state.actual_count) {
                    try validator.countError(state.count_state.byte_offset, "componentList count does not match actual component elements");
                }
                if (state.source_count == 0) {
                    try validator.appendDiagnostic(.{ .severity = .@"error", .rule = RuleId.mzml_structure_missing_child, .location = .{ .byte_offset = state.count_state.byte_offset }, .path = validator.path, .message = "componentList must contain at least 1 source element" });
                }
                if (state.analyzer_count == 0) {
                    try validator.appendDiagnostic(.{ .severity = .@"error", .rule = RuleId.mzml_structure_missing_child, .location = .{ .byte_offset = state.count_state.byte_offset }, .path = validator.path, .message = "componentList must contain at least 1 analyzer element" });
                }
                if (state.detector_count == 0) {
                    try validator.appendDiagnostic(.{ .severity = .@"error", .rule = RuleId.mzml_structure_missing_child, .location = .{ .byte_offset = state.count_state.byte_offset }, .path = validator.path, .message = "componentList must contain at least 1 detector element" });
                }
            }
        }
        validator.component_list = null;
    }

    fn initListCountState(
        validator: *StructuralValidator,
        start: StartElement,
        element_depth: usize,
        label: []const u8,
        child_label: []const u8,
        min_count: usize,
    ) !?ListCountState {
        const declared_count = try validator.parseCountAttribute(start, label) orelse return null;
        return .{
            .byte_offset = start.byte_offset,
            .depth = element_depth,
            .declared_count = declared_count,
            .min_count = min_count,
            .label = label,
            .child_label = child_label,
        };
    }

    fn parseCountAttribute(validator: *StructuralValidator, start: StartElement, label: []const u8) !?usize {
        const value = start.attr("count") orelse return null;
        if (std.mem.eql(u8, label, "scanWindowList")) {
            const signed = parseSchemaInt(value) orelse return null;
            if (signed >= 0) return @intCast(signed);
            try validator.countError(start.byte_offset, "scanWindowList count must not be negative");
            return null;
        }
        return parseNonNegativeInteger(value);
    }

    fn bumpListItemCount(validator: *StructuralValidator, state: *?ListCountState, element_depth: usize) void {
        _ = validator;
        if (state.*) |*active| {
            if (active.depth + 1 == element_depth) {
                active.actual_count += 1;
            }
        }
    }

    fn finishListCount(validator: *StructuralValidator, state: *?ListCountState, element_depth: usize) !void {
        if (state.*) |active| {
            if (active.depth == element_depth) {
                if (active.declared_count != active.actual_count) {
                    try validator.countError(active.byte_offset, countMismatchMessage(active));
                }
                if (active.actual_count < active.min_count) {
                    try validator.countError(active.byte_offset, minimumCountMessage(active));
                }
            }
        }
        state.* = null;
    }

    fn recordTopLevelElement(
        validator: *StructuralValidator,
        byte_offset: u64,
        element_depth: usize,
        seen: *bool,
        element_name: []const u8,
        slot: TopLevelSlot,
    ) !void {
        if (element_depth != validator.topLevelChildDepth()) {
            try validator.nestingError(byte_offset, topLevelDirectChildMessage(element_name));
            return;
        }

        if (seen.*) {
            const slot_bit = @as(u32, 1) << @as(u5, @truncate(@intFromEnum(slot)));
            if (validator.dup_reported_mask & slot_bit == 0) {
                try validator.nestingError(byte_offset, duplicateTopLevelMessage(element_name));
                validator.dup_reported_mask |= slot_bit;
            }
            return;
        }

        if (@intFromEnum(slot) < validator.last_top_level_slot) {
            try validator.nestingError(byte_offset, outOfOrderTopLevelMessage(element_name));
            seen.* = true;
            return;
        }

        seen.* = true;
        validator.last_top_level_slot = @intFromEnum(slot);
    }

    fn reportMissingTopLevelChildren(validator: *StructuralValidator) !void {
        if (!validator.root_valid) return;

        try validator.reportMissingTopLevelChild(validator.cv_list_seen, "mzML is missing required child cvList");
        try validator.reportMissingTopLevelChild(validator.file_description_seen, "mzML is missing required child fileDescription");
        try validator.reportMissingTopLevelChild(validator.software_list_seen, "mzML is missing required child softwareList");
        try validator.reportMissingTopLevelChild(validator.instrument_configuration_list_seen, "mzML is missing required child instrumentConfigurationList");
        try validator.reportMissingTopLevelChild(validator.data_processing_list_seen, "mzML is missing required child dataProcessingList");
    }

    fn reportMissingTopLevelChild(validator: *StructuralValidator, seen: bool, message: []const u8) !void {
        if (seen) return;

        try validator.appendDiagnostic(.{
            .severity = .@"error",
            .rule = RuleId.mzml_structure_missing_child,
            .location = .{ .byte_offset = validator.root_byte_offset },
            .path = validator.path,
            .message = message,
        });
    }

    fn topLevelChildDepth(validator: *StructuralValidator) usize {
        return if (validator.mzml_depth) |depth| depth + 1 else 2;
    }

    fn isWithinMzmlStartScope(validator: *StructuralValidator) bool {
        if (!validator.root_valid) return false;
        if (validator.mzml_depth == null) return false;
        return validator.depth >= validator.mzml_depth.?;
    }

    fn isWithinMzmlEndScope(validator: *StructuralValidator, element_depth: usize) bool {
        if (!validator.root_valid) return false;
        if (validator.mzml_depth == null) return false;
        return element_depth >= validator.mzml_depth.?;
    }

    fn validateAttributes(validator: *StructuralValidator, start: StartElement, tag: ElementId) !bool {
        var nilled = false;

        for (start.attributes) |attribute| {
            if (attribute.is_namespace_declaration) continue;
            if (attribute.name.namespace_uri) |namespace_uri| {
                if (tag == .indexListOffset and
                    std.mem.eql(u8, namespace_uri, xml_schema_instance_namespace) and
                    std.mem.eql(u8, attribute.name.local_name, "nil"))
                {
                    const value = trimSchemaWhitespace(attribute.value);
                    if (std.mem.eql(u8, value, "true") or std.mem.eql(u8, value, "1")) {
                        nilled = true;
                    } else if (!std.mem.eql(u8, value, "false") and !std.mem.eql(u8, value, "0")) {
                        try validator.attributeError(attribute.byte_offset, "xsi:nil must be true, false, 1, or 0");
                    }
                }
                continue;
            }
            if (attribute.name.prefix != null) continue;

            const spec = attributeSpec(tag, attribute.name.local_name) orelse {
                try validator.attributeError(attribute.byte_offset, "mzML element has an unknown unqualified attribute");
                continue;
            };
            try validator.validateAttributeValue(attribute, spec, start.name.local_name);
        }

        try validator.validateRequiredAttributes(start, tag);

        return nilled;
    }

    fn validateAttributeValue(validator: *StructuralValidator, attribute: Attribute, spec: AttributeSpec, element_name: []const u8) !void {
        const value = attribute.value;
        const valid = switch (spec.kind) {
            .string, .any_uri => true,
            .id, .id_ref => isNcName(value),
            .non_negative_integer => parseNonNegativeInteger(value) != null,
            .int => parseSchemaInt(value) != null,
            .date_time => isSchemaDateTime(value),
            .double => isSchemaDouble(value),
            .spectrum_id => isSpectrumId(value),
        };
        if (valid) return;

        if (std.mem.eql(u8, attribute.name.local_name, "count")) {
            try validator.countError(attribute.byte_offset, invalidCountMessage(element_name));
            return;
        }

        if (spec.kind == .id_ref and trimSchemaWhitespace(value).len == 0) {
            try validator.appendDiagnostic(.{
                .severity = .@"error",
                .rule = RuleId.mzml_ref_empty,
                .location = .{ .byte_offset = attribute.byte_offset },
                .path = validator.path,
                .message = "reference value is empty",
            });
            return;
        }

        const message = switch (spec.kind) {
            .string, .any_uri => unreachable,
            .id => "ID attribute must be an XML NCName",
            .id_ref => "reference attribute must be an XML NCName",
            .non_negative_integer => "attribute must be a non-negative integer within the supported range",
            .int => "attribute must be a 32-bit integer",
            .date_time => "attribute must be an XML Schema dateTime",
            .double => "attribute must be an XML Schema double",
            .spectrum_id => "spectrum id must match the native identifier pattern",
        };
        try validator.attributeError(attribute.byte_offset, message);
    }

    fn validateRequiredAttributes(validator: *StructuralValidator, start: StartElement, tag: ElementId) !void {
        switch (tag) {
            .mzML => try validator.requireSchemaAttribute(start, "version", "mzML is missing required attribute version", false),
            .cvList => try validator.requireSchemaAttribute(start, "count", "cvList is missing required attribute count", false),
            .cv => {
                try validator.requireSchemaAttribute(start, "id", "cv is missing required attribute id", false);
                try validator.requireSchemaAttribute(start, "fullName", "cv is missing required attribute fullName", false);
                try validator.requireSchemaAttribute(start, "URI", "cv is missing required attribute URI", false);
            },
            .sourceFileList => try validator.requireSchemaAttribute(start, "count", "sourceFileList is missing required attribute count", false),
            .sourceFile => {
                try validator.requireSchemaAttribute(start, "id", "sourceFile is missing required attribute id", false);
                try validator.requireSchemaAttribute(start, "name", "sourceFile is missing required attribute name", false);
                try validator.requireSchemaAttribute(start, "location", "sourceFile is missing required attribute location", false);
            },
            .referenceableParamGroupList => try validator.requireSchemaAttribute(start, "count", "referenceableParamGroupList is missing required attribute count", false),
            .referenceableParamGroup => try validator.requireSchemaAttribute(start, "id", "referenceableParamGroup is missing required attribute id", false),
            .referenceableParamGroupRef => try validator.requireSchemaAttribute(start, "ref", "referenceableParamGroupRef is missing required attribute ref", true),
            .cvParam => {
                try validator.requireSchemaAttribute(start, "cvRef", "cvParam is missing required attribute cvRef", true);
                try validator.requireSchemaAttribute(start, "accession", "cvParam is missing required attribute accession", false);
                try validator.requireSchemaAttribute(start, "name", "cvParam is missing required attribute name", false);
            },
            .userParam => try validator.requireSchemaAttribute(start, "name", "userParam is missing required attribute name", false),
            .sampleList => try validator.requireSchemaAttribute(start, "count", "sampleList is missing required attribute count", false),
            .sample => try validator.requireSchemaAttribute(start, "id", "sample is missing required attribute id", false),
            .instrumentConfigurationList => try validator.requireSchemaAttribute(start, "count", "instrumentConfigurationList is missing required attribute count", false),
            .source => try validator.requireSchemaAttribute(start, "order", "source is missing required attribute order", false),
            .analyzer => try validator.requireSchemaAttribute(start, "order", "analyzer is missing required attribute order", false),
            .detector => try validator.requireSchemaAttribute(start, "order", "detector is missing required attribute order", false),
            .componentList => try validator.requireSchemaAttribute(start, "count", "componentList is missing required attribute count", false),
            .instrumentConfiguration => try validator.requireSchemaAttribute(start, "id", "instrumentConfiguration is missing required attribute id", false),
            .softwareRef => try validator.requireSchemaAttribute(start, "ref", "softwareRef is missing required attribute ref", true),
            .softwareList => try validator.requireSchemaAttribute(start, "count", "softwareList is missing required attribute count", false),
            .software => {
                try validator.requireSchemaAttribute(start, "id", "software is missing required attribute id", false);
                try validator.requireSchemaAttribute(start, "version", "software is missing required attribute version", false);
            },
            .dataProcessingList => try validator.requireSchemaAttribute(start, "count", "dataProcessingList is missing required attribute count", false),
            .dataProcessing => try validator.requireSchemaAttribute(start, "id", "dataProcessing is missing required attribute id", false),
            .processingMethod => {
                try validator.requireSchemaAttribute(start, "order", "processingMethod is missing required attribute order", false);
                try validator.requireSchemaAttribute(start, "softwareRef", "processingMethod is missing required attribute softwareRef", true);
            },
            .scanSettingsList => try validator.requireSchemaAttribute(start, "count", "scanSettingsList is missing required attribute count", false),
            .scanSettings => try validator.requireSchemaAttribute(start, "id", "scanSettings is missing required attribute id", false),
            .targetList => try validator.requireSchemaAttribute(start, "count", "targetList is missing required attribute count", false),
            .run => {
                try validator.requireSchemaAttribute(start, "id", "run is missing required attribute id", false);
                try validator.requireSchemaAttribute(start, "defaultInstrumentConfigurationRef", "run is missing required attribute defaultInstrumentConfigurationRef", true);
            },
            .sourceFileRef => try validator.requireSchemaAttribute(start, "ref", "sourceFileRef is missing required attribute ref", true),
            .sourceFileRefList => try validator.requireSchemaAttribute(start, "count", "sourceFileRefList is missing required attribute count", false),
            .spectrumList => {
                try validator.requireSchemaAttribute(start, "count", "spectrumList is missing required attribute count", false);
                try validator.requireSchemaAttribute(start, "defaultDataProcessingRef", "spectrumList is missing required attribute defaultDataProcessingRef", true);
            },
            .scanWindowList => try validator.requireSchemaAttribute(start, "count", "scanWindowList is missing required attribute count", false),
            .scanList => try validator.requireSchemaAttribute(start, "count", "scanList is missing required attribute count", false),
            .precursorList => try validator.requireSchemaAttribute(start, "count", "precursorList is missing required attribute count", false),
            .selectedIonList => try validator.requireSchemaAttribute(start, "count", "selectedIonList is missing required attribute count", false),
            .productList => try validator.requireSchemaAttribute(start, "count", "productList is missing required attribute count", false),
            .binaryDataArrayList => try validator.requireSchemaAttribute(start, "count", "binaryDataArrayList is missing required attribute count", false),
            .binaryDataArray => try validator.requireSchemaAttribute(start, "encodedLength", "binaryDataArray is missing required attribute encodedLength", false),
            .spectrum => {
                try validator.requireSchemaAttribute(start, "id", "spectrum is missing required attribute id", false);
                try validator.requireSchemaAttribute(start, "index", "spectrum is missing required attribute index", false);
                try validator.requireSchemaAttribute(start, "defaultArrayLength", "spectrum is missing required attribute defaultArrayLength", false);
            },
            .chromatogramList => {
                try validator.requireSchemaAttribute(start, "count", "chromatogramList is missing required attribute count", false);
                try validator.requireSchemaAttribute(start, "defaultDataProcessingRef", "chromatogramList is missing required attribute defaultDataProcessingRef", true);
            },
            .chromatogram => {
                try validator.requireSchemaAttribute(start, "id", "chromatogram is missing required attribute id", false);
                try validator.requireSchemaAttribute(start, "index", "chromatogram is missing required attribute index", false);
                try validator.requireSchemaAttribute(start, "defaultArrayLength", "chromatogram is missing required attribute defaultArrayLength", false);
            },
            .indexList => try validator.requireSchemaAttribute(start, "count", "indexList is missing required attribute count", false),
            .index => try validator.requireSchemaAttribute(start, "name", "index is missing required attribute name", false),
            .offset => try validator.requireSchemaAttribute(start, "idRef", "offset is missing required attribute idRef", false),
            else => {},
        }
    }

    fn requireSchemaAttribute(validator: *StructuralValidator, start: StartElement, name: []const u8, message: []const u8, reference: bool) !void {
        if (start.attr(name) != null) return;
        if (reference) {
            try validator.appendDiagnostic(.{
                .severity = .@"error",
                .rule = RuleId.mzml_ref_missing,
                .location = .{ .byte_offset = start.byte_offset },
                .path = validator.path,
                .message = message,
            });
            return;
        }
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

    fn countError(validator: *StructuralValidator, byte_offset: u64, message: []const u8) !void {
        try validator.appendDiagnostic(.{
            .severity = .@"error",
            .rule = RuleId.mzml_structure_count,
            .location = .{ .byte_offset = byte_offset },
            .path = validator.path,
            .message = message,
        });
    }

    fn nestingError(validator: *StructuralValidator, byte_offset: u64, message: []const u8) !void {
        @branchHint(.cold);
        try validator.appendDiagnostic(.{
            .severity = .@"error",
            .rule = RuleId.mzml_structure_nesting,
            .location = .{ .byte_offset = byte_offset },
            .path = validator.path,
            .message = message,
        });
    }

    fn appendDiagnostic(validator: *StructuralValidator, item: Diagnostic) !void {
        @branchHint(.cold);
        _ = try validator.diagnostics.append(validator.allocator, item);
    }
};

const xml_schema_instance_namespace = "http://www.w3.org/2001/XMLSchema-instance";

fn attributeSpec(tag: ElementId, name: []const u8) ?AttributeSpec {
    if (std.mem.eql(u8, name, "count")) {
        return switch (tag) {
            .scanWindowList => .{ .kind = .int },
            .binaryDataArrayList,
            .chromatogramList,
            .componentList,
            .cvList,
            .dataProcessingList,
            .indexList,
            .instrumentConfigurationList,
            .precursorList,
            .productList,
            .referenceableParamGroupList,
            .sampleList,
            .scanList,
            .scanSettingsList,
            .selectedIonList,
            .softwareList,
            .sourceFileList,
            .sourceFileRefList,
            .spectrumList,
            .targetList,
            => .{ .kind = .non_negative_integer },
            else => null,
        };
    }

    if (std.mem.eql(u8, name, "id")) {
        return switch (tag) {
            .cv, .dataProcessing, .instrumentConfiguration, .referenceableParamGroup, .run, .sample, .scanSettings, .software, .sourceFile => .{ .kind = .id },
            .spectrum => .{ .kind = .spectrum_id },
            .chromatogram => .{ .kind = .string },
            .mzML => .{ .kind = .string },
            else => null,
        };
    }

    return switch (tag) {
        .mzML => if (std.mem.eql(u8, name, "accession"))
            .{ .kind = .string }
        else if (std.mem.eql(u8, name, "version"))
            .{ .kind = .string }
        else
            null,
        .cv => if (std.mem.eql(u8, name, "fullName"))
            .{ .kind = .string }
        else if (std.mem.eql(u8, name, "version"))
            .{ .kind = .string }
        else if (std.mem.eql(u8, name, "URI"))
            .{ .kind = .any_uri }
        else
            null,
        .sourceFile => if (std.mem.eql(u8, name, "name"))
            .{ .kind = .string }
        else if (std.mem.eql(u8, name, "location"))
            .{ .kind = .any_uri }
        else
            null,
        .referenceableParamGroupRef, .softwareRef, .sourceFileRef => if (std.mem.eql(u8, name, "ref"))
            .{ .kind = .id_ref }
        else
            null,
        .cvParam => paramAttributeSpec(name, true),
        .userParam => paramAttributeSpec(name, false),
        .sample => if (std.mem.eql(u8, name, "name")) .{ .kind = .string } else null,
        .source, .analyzer, .detector => if (std.mem.eql(u8, name, "order")) .{ .kind = .int } else null,
        .instrumentConfiguration => if (std.mem.eql(u8, name, "scanSettingsRef")) .{ .kind = .id_ref } else null,
        .software => if (std.mem.eql(u8, name, "version")) .{ .kind = .string } else null,
        .processingMethod => if (std.mem.eql(u8, name, "order"))
            .{ .kind = .non_negative_integer }
        else if (std.mem.eql(u8, name, "softwareRef"))
            .{ .kind = .id_ref }
        else
            null,
        .run => if (std.mem.eql(u8, name, "defaultInstrumentConfigurationRef"))
            .{ .kind = .id_ref }
        else if (std.mem.eql(u8, name, "defaultSourceFileRef") or std.mem.eql(u8, name, "sampleRef"))
            .{ .kind = .id_ref }
        else if (std.mem.eql(u8, name, "startTimeStamp"))
            .{ .kind = .date_time }
        else
            null,
        .spectrumList, .chromatogramList => if (std.mem.eql(u8, name, "defaultDataProcessingRef")) .{ .kind = .id_ref } else null,
        .scan => if (std.mem.eql(u8, name, "spectrumRef") or std.mem.eql(u8, name, "externalSpectrumID"))
            .{ .kind = .string }
        else if (std.mem.eql(u8, name, "sourceFileRef") or std.mem.eql(u8, name, "instrumentConfigurationRef"))
            .{ .kind = .id_ref }
        else
            null,
        .precursor => if (std.mem.eql(u8, name, "spectrumRef") or std.mem.eql(u8, name, "externalSpectrumID"))
            .{ .kind = .string }
        else if (std.mem.eql(u8, name, "sourceFileRef"))
            .{ .kind = .id_ref }
        else
            null,
        .binaryDataArray => if (std.mem.eql(u8, name, "arrayLength"))
            .{ .kind = .non_negative_integer }
        else if (std.mem.eql(u8, name, "dataProcessingRef"))
            .{ .kind = .id_ref }
        else if (std.mem.eql(u8, name, "encodedLength"))
            .{ .kind = .non_negative_integer }
        else
            null,
        .spectrum => spectrumAttributeSpec(name),
        .chromatogram => chromatogramAttributeSpec(name),
        .index => if (std.mem.eql(u8, name, "name")) .{ .kind = .string } else null,
        .offset => if (std.mem.eql(u8, name, "idRef"))
            .{ .kind = .string }
        else if (std.mem.eql(u8, name, "spotID"))
            .{ .kind = .string }
        else if (std.mem.eql(u8, name, "scanTime"))
            .{ .kind = .double }
        else
            null,
        else => null,
    };
}

fn paramAttributeSpec(name: []const u8, cv_param: bool) ?AttributeSpec {
    if (cv_param and std.mem.eql(u8, name, "cvRef")) return .{ .kind = .id_ref };
    if (cv_param and std.mem.eql(u8, name, "accession")) return .{ .kind = .string };
    if (std.mem.eql(u8, name, "name")) return .{ .kind = .string };
    if (std.mem.eql(u8, name, "value") or
        std.mem.eql(u8, name, "unitAccession") or
        std.mem.eql(u8, name, "unitName") or
        (!cv_param and std.mem.eql(u8, name, "type"))) return .{ .kind = .string };
    if (std.mem.eql(u8, name, "unitCvRef")) return .{ .kind = .id_ref };
    return null;
}

fn spectrumAttributeSpec(name: []const u8) ?AttributeSpec {
    if (std.mem.eql(u8, name, "spotID")) return .{ .kind = .string };
    if (std.mem.eql(u8, name, "index")) return .{ .kind = .non_negative_integer };
    if (std.mem.eql(u8, name, "defaultArrayLength")) return .{ .kind = .int };
    if (std.mem.eql(u8, name, "dataProcessingRef") or std.mem.eql(u8, name, "sourceFileRef")) return .{ .kind = .id_ref };
    return null;
}

fn chromatogramAttributeSpec(name: []const u8) ?AttributeSpec {
    if (std.mem.eql(u8, name, "index")) return .{ .kind = .non_negative_integer };
    if (std.mem.eql(u8, name, "defaultArrayLength")) return .{ .kind = .int };
    if (std.mem.eql(u8, name, "dataProcessingRef")) return .{ .kind = .id_ref };
    return null;
}

fn trimSchemaWhitespace(value: []const u8) []const u8 {
    return std.mem.trim(u8, value, " \t\r\n");
}

fn parseNonNegativeInteger(value: []const u8) ?usize {
    var token = trimSchemaWhitespace(value);
    if (token.len > 0 and token[0] == '+') token = token[1..];
    if (token.len == 0) return null;
    return std.fmt.parseUnsigned(usize, token, 10) catch null;
}

fn parseSchemaInt(value: []const u8) ?i32 {
    const token = trimSchemaWhitespace(value);
    if (token.len == 0) return null;
    return std.fmt.parseInt(i32, token, 10) catch null;
}

fn isNcName(value: []const u8) bool {
    const token = trimSchemaWhitespace(value);
    if (token.len == 0 or std.mem.indexOfScalar(u8, token, ':') != null) return false;
    xml_characters.validateQName(token) catch return false;
    return true;
}

fn isSpectrumId(value: []const u8) bool {
    if (value.len == 0 or value[0] == ' ' or value[value.len - 1] == ' ') return false;
    var token_start: usize = 0;
    for (value, 0..) |byte, index| {
        if (byte == '\t' or byte == '\r' or byte == '\n') return false;
        if (byte != ' ') continue;
        if (!isSpectrumIdToken(value[token_start..index])) return false;
        token_start = index + 1;
    }
    return isSpectrumIdToken(value[token_start..]);
}

fn isSpectrumIdToken(token: []const u8) bool {
    const equals = std.mem.indexOfScalar(u8, token, '=') orelse return false;
    return equals > 0 and equals + 1 < token.len;
}

pub fn isSchemaDouble(value: []const u8) bool {
    const token = trimSchemaWhitespace(value);
    if (std.mem.eql(u8, token, "INF") or
        std.mem.eql(u8, token, "-INF") or
        std.mem.eql(u8, token, "NaN")) return true;

    var index: usize = 0;
    if (index < token.len and (token[index] == '+' or token[index] == '-')) index += 1;
    var integer_digits: usize = 0;
    while (index < token.len and std.ascii.isDigit(token[index])) : (index += 1) integer_digits += 1;
    var fraction_digits: usize = 0;
    if (index < token.len and token[index] == '.') {
        index += 1;
        while (index < token.len and std.ascii.isDigit(token[index])) : (index += 1) fraction_digits += 1;
    }
    if (integer_digits == 0 and fraction_digits == 0) return false;
    if (index < token.len and (token[index] == 'e' or token[index] == 'E')) {
        index += 1;
        if (index < token.len and (token[index] == '+' or token[index] == '-')) index += 1;
        const exponent_start = index;
        while (index < token.len and std.ascii.isDigit(token[index])) : (index += 1) {}
        if (index == exponent_start) return false;
    }
    return index == token.len;
}

pub fn isSchemaDateTime(value: []const u8) bool {
    const token = trimSchemaWhitespace(value);
    var index: usize = 0;
    if (index < token.len and token[index] == '-') index += 1;

    const year_start = index;
    while (index < token.len and std.ascii.isDigit(token[index])) : (index += 1) {}
    const year_digits = token[year_start..index];
    if (year_digits.len < 4 or allZero(year_digits)) return false;
    if (year_digits.len > 4 and year_digits[0] == '0') return false;
    const year = year_digits;
    if (!takeByte(token, &index, '-')) return false;
    const month = takeTwoDigits(token, &index) orelse return false;
    if (!takeByte(token, &index, '-')) return false;
    const day = takeTwoDigits(token, &index) orelse return false;
    if (!takeByte(token, &index, 'T')) return false;
    const hour = takeTwoDigits(token, &index) orelse return false;
    if (!takeByte(token, &index, ':')) return false;
    const minute = takeTwoDigits(token, &index) orelse return false;
    if (!takeByte(token, &index, ':')) return false;
    const second = takeTwoDigits(token, &index) orelse return false;

    var fraction_nonzero = false;
    if (index < token.len and token[index] == '.') {
        index += 1;
        const fraction_start = index;
        while (index < token.len and std.ascii.isDigit(token[index])) : (index += 1) {
            fraction_nonzero = fraction_nonzero or token[index] != '0';
        }
        if (index == fraction_start) return false;
    }

    if (month < 1 or month > 12 or day < 1 or day > daysInMonth(month, year)) return false;
    if (hour > 24 or minute > 59 or second > 59) return false;
    if (hour == 24 and (minute != 0 or second != 0 or fraction_nonzero)) return false;

    if (index == token.len) return true;
    if (token[index] == 'Z') return index + 1 == token.len;
    if (token[index] != '+' and token[index] != '-') return false;
    index += 1;
    const timezone_hour = takeTwoDigits(token, &index) orelse return false;
    if (!takeByte(token, &index, ':')) return false;
    const timezone_minute = takeTwoDigits(token, &index) orelse return false;
    if (timezone_hour > 14 or timezone_minute > 59) return false;
    if (timezone_hour == 14 and timezone_minute != 0) return false;
    return index == token.len;
}

fn takeByte(value: []const u8, index: *usize, expected: u8) bool {
    if (index.* >= value.len or value[index.*] != expected) return false;
    index.* += 1;
    return true;
}

fn takeTwoDigits(value: []const u8, index: *usize) ?u8 {
    if (index.* + 2 > value.len) return null;
    const first = value[index.*];
    const second = value[index.* + 1];
    if (!std.ascii.isDigit(first) or !std.ascii.isDigit(second)) return null;
    index.* += 2;
    return (first - '0') * 10 + second - '0';
}

fn allZero(value: []const u8) bool {
    for (value) |byte| if (byte != '0') return false;
    return true;
}

fn daysInMonth(month: u8, leading_year_digits: []const u8) u8 {
    return switch (month) {
        2 => if (isLeapYear(leading_year_digits)) 29 else 28,
        4, 6, 9, 11 => 30,
        else => 31,
    };
}

fn isLeapYear(leading_year_digits: []const u8) bool {
    var year_mod_400: u16 = 0;
    for (leading_year_digits) |byte| year_mod_400 = (year_mod_400 * 10 + byte - '0') % 400;
    return year_mod_400 % 4 == 0 and (year_mod_400 % 100 != 0 or year_mod_400 == 0);
}

fn isAllowedParent(child: ElementId, parent: ElementId) bool {
    return switch (child) {
        .unknown, .indexedmzML => false,
        .mzML => parent == .indexedmzML,
        .cvList, .fileDescription, .referenceableParamGroupList, .sampleList, .softwareList, .scanSettingsList, .instrumentConfigurationList, .dataProcessingList, .run => parent == .mzML,
        .cv => parent == .cvList,
        .fileContent, .sourceFileList, .contact => parent == .fileDescription,
        .sourceFile => parent == .sourceFileList,
        .referenceableParamGroup => parent == .referenceableParamGroupList,
        .sample => parent == .sampleList,
        .software => parent == .softwareList,
        .scanSettings => parent == .scanSettingsList,
        .sourceFileRefList, .targetList => parent == .scanSettings,
        .sourceFileRef => parent == .sourceFileRefList,
        .target => parent == .targetList,
        .instrumentConfiguration => parent == .instrumentConfigurationList,
        .componentList, .softwareRef => parent == .instrumentConfiguration,
        .source, .analyzer, .detector => parent == .componentList,
        .dataProcessing => parent == .dataProcessingList,
        .processingMethod => parent == .dataProcessing,
        .spectrumList, .chromatogramList => parent == .run,
        .spectrum => parent == .spectrumList,
        .chromatogram => parent == .chromatogramList,
        .scanList, .precursorList, .productList, .binaryDataArrayList => parent == .spectrum or
            (child == .binaryDataArrayList and parent == .chromatogram),
        .scan => parent == .scanList,
        .scanWindowList => parent == .scan,
        .scanWindow => parent == .scanWindowList,
        .precursor => parent == .precursorList or parent == .chromatogram,
        .isolationWindow => parent == .precursor or parent == .product,
        .selectedIonList, .activation => parent == .precursor,
        .selectedIon => parent == .selectedIonList,
        .product => parent == .productList or parent == .chromatogram,
        .binaryDataArray => parent == .binaryDataArrayList,
        .binary => parent == .binaryDataArray,
        .referenceableParamGroupRef => isParamGroupParent(parent),
        .cvParam, .userParam => isParamGroupParent(parent) or parent == .referenceableParamGroup,
        .indexList, .indexListOffset, .fileChecksum => parent == .indexedmzML,
        .index => parent == .indexList,
        .offset => parent == .index,
    };
}

fn isParamGroupParent(tag: ElementId) bool {
    return switch (tag) {
        .fileContent,
        .contact,
        .sourceFile,
        .sample,
        .software,
        .scanSettings,
        .instrumentConfiguration,
        .source,
        .analyzer,
        .detector,
        .processingMethod,
        .run,
        .target,
        .scanList,
        .scan,
        .scanWindow,
        .spectrum,
        .isolationWindow,
        .selectedIon,
        .activation,
        .binaryDataArray,
        .chromatogram,
        => true,
        else => false,
    };
}

fn paramGroupChildPhase(parent: ElementId, child: ElementId) ?u8 {
    if (parent == .referenceableParamGroup) {
        return switch (child) {
            .cvParam => 1,
            .userParam => 2,
            else => null,
        };
    }
    if (!isParamGroupParent(parent)) return null;
    return switch (child) {
        .referenceableParamGroupRef => 1,
        .cvParam => 2,
        .userParam => 3,
        else => 4,
    };
}

fn invalidParentMessage(child: ElementId, parent: ElementId) []const u8 {
    if (parent == .indexedmzML) return "element is not allowed as a direct child of indexedmzML";
    if (child == .unknown) return "unrecognized element in mzML scope";
    if (child == .binaryDataArrayList) return "binaryDataArrayList must be a child of spectrum or chromatogram";
    if (child == .indexList or child == .indexListOffset or child == .fileChecksum) return "index metadata must be a direct child of indexedmzML";
    return "mzML element is not allowed under its parent";
}

fn topLevelDirectChildMessage(element_name: []const u8) []const u8 {
    if (std.mem.eql(u8, element_name, "cvList")) return "cvList must be a direct child of mzML";
    if (std.mem.eql(u8, element_name, "fileDescription")) return "fileDescription must be a direct child of mzML";
    if (std.mem.eql(u8, element_name, "referenceableParamGroupList")) return "referenceableParamGroupList must be a direct child of mzML";
    if (std.mem.eql(u8, element_name, "sampleList")) return "sampleList must be a direct child of mzML";
    if (std.mem.eql(u8, element_name, "softwareList")) return "softwareList must be a direct child of mzML";
    if (std.mem.eql(u8, element_name, "scanSettingsList")) return "scanSettingsList must be a direct child of mzML";
    if (std.mem.eql(u8, element_name, "instrumentConfigurationList")) return "instrumentConfigurationList must be a direct child of mzML";
    if (std.mem.eql(u8, element_name, "run")) return "run must be a direct child of mzML";
    return "dataProcessingList must be a direct child of mzML";
}

fn duplicateTopLevelMessage(element_name: []const u8) []const u8 {
    if (std.mem.eql(u8, element_name, "cvList")) return "mzML must not contain more than one cvList";
    if (std.mem.eql(u8, element_name, "fileDescription")) return "mzML must not contain more than one fileDescription";
    if (std.mem.eql(u8, element_name, "referenceableParamGroupList")) return "mzML must not contain more than one referenceableParamGroupList";
    if (std.mem.eql(u8, element_name, "sampleList")) return "mzML must not contain more than one sampleList";
    if (std.mem.eql(u8, element_name, "softwareList")) return "mzML must not contain more than one softwareList";
    if (std.mem.eql(u8, element_name, "scanSettingsList")) return "mzML must not contain more than one scanSettingsList";
    if (std.mem.eql(u8, element_name, "instrumentConfigurationList")) return "mzML must not contain more than one instrumentConfigurationList";
    if (std.mem.eql(u8, element_name, "run")) return "mzML must not contain more than one run";
    return "mzML must not contain more than one dataProcessingList";
}

fn outOfOrderTopLevelMessage(element_name: []const u8) []const u8 {
    if (std.mem.eql(u8, element_name, "cvList")) return "cvList appears out of order under mzML";
    if (std.mem.eql(u8, element_name, "fileDescription")) return "fileDescription appears out of order under mzML";
    if (std.mem.eql(u8, element_name, "referenceableParamGroupList")) return "referenceableParamGroupList appears out of order under mzML";
    if (std.mem.eql(u8, element_name, "sampleList")) return "sampleList appears out of order under mzML";
    if (std.mem.eql(u8, element_name, "softwareList")) return "softwareList appears out of order under mzML";
    if (std.mem.eql(u8, element_name, "scanSettingsList")) return "scanSettingsList appears out of order under mzML";
    if (std.mem.eql(u8, element_name, "instrumentConfigurationList")) return "instrumentConfigurationList appears out of order under mzML";
    if (std.mem.eql(u8, element_name, "run")) return "run appears out of order under mzML";
    return "dataProcessingList appears out of order under mzML";
}

fn invalidCountMessage(label: []const u8) []const u8 {
    if (std.mem.eql(u8, label, "cvList")) return "cvList count attribute must be a non-negative integer";
    if (std.mem.eql(u8, label, "sourceFileList")) return "sourceFileList count attribute must be a non-negative integer";
    if (std.mem.eql(u8, label, "sourceFileRefList")) return "sourceFileRefList count attribute must be a non-negative integer";
    if (std.mem.eql(u8, label, "targetList")) return "targetList count attribute must be a non-negative integer";
    if (std.mem.eql(u8, label, "indexList")) return "indexList count attribute must be a non-negative integer";
    if (std.mem.eql(u8, label, "referenceableParamGroupList")) return "referenceableParamGroupList count attribute must be a non-negative integer";
    if (std.mem.eql(u8, label, "sampleList")) return "sampleList count attribute must be a non-negative integer";
    if (std.mem.eql(u8, label, "softwareList")) return "softwareList count attribute must be a non-negative integer";
    if (std.mem.eql(u8, label, "scanSettingsList")) return "scanSettingsList count attribute must be a non-negative integer";
    if (std.mem.eql(u8, label, "componentList")) return "componentList count attribute must be a non-negative integer";
    if (std.mem.eql(u8, label, "instrumentConfigurationList")) return "instrumentConfigurationList count attribute must be a non-negative integer";
    if (std.mem.eql(u8, label, "dataProcessingList")) return "dataProcessingList count attribute must be a non-negative integer";
    if (std.mem.eql(u8, label, "precursorList")) return "precursorList count attribute must be a non-negative integer";
    if (std.mem.eql(u8, label, "productList")) return "productList count attribute must be a non-negative integer";
    if (std.mem.eql(u8, label, "spectrumList")) return "spectrumList count attribute must be a non-negative integer";
    if (std.mem.eql(u8, label, "chromatogramList")) return "chromatogramList count attribute must be a non-negative integer";
    if (std.mem.eql(u8, label, "scanList")) return "scanList count attribute must be a non-negative integer";
    if (std.mem.eql(u8, label, "scanWindowList")) return "scanWindowList count attribute must be a non-negative integer";
    if (std.mem.eql(u8, label, "selectedIonList")) return "selectedIonList count attribute must be a non-negative integer";
    return "binaryDataArrayList count attribute must be a non-negative integer";
}

fn countMismatchMessage(active: ListCountState) []const u8 {
    if (std.mem.eql(u8, active.label, "cvList")) return "cvList count does not match actual cv elements";
    if (std.mem.eql(u8, active.label, "sourceFileList")) return "sourceFileList count does not match actual sourceFile elements";
    if (std.mem.eql(u8, active.label, "sourceFileRefList")) return "sourceFileRefList count does not match actual sourceFileRef elements";
    if (std.mem.eql(u8, active.label, "targetList")) return "targetList count does not match actual target elements";
    if (std.mem.eql(u8, active.label, "indexList")) return "indexList count does not match actual index elements";
    if (std.mem.eql(u8, active.label, "referenceableParamGroupList")) return "referenceableParamGroupList count does not match actual referenceableParamGroup elements";
    if (std.mem.eql(u8, active.label, "sampleList")) return "sampleList count does not match actual sample elements";
    if (std.mem.eql(u8, active.label, "softwareList")) return "softwareList count does not match actual software elements";
    if (std.mem.eql(u8, active.label, "scanSettingsList")) return "scanSettingsList count does not match actual scanSettings elements";
    if (std.mem.eql(u8, active.label, "instrumentConfigurationList")) return "instrumentConfigurationList count does not match actual instrumentConfiguration elements";
    if (std.mem.eql(u8, active.label, "dataProcessingList")) return "dataProcessingList count does not match actual dataProcessing elements";
    if (std.mem.eql(u8, active.label, "spectrumList")) return "spectrumList count does not match actual spectrum elements";
    if (std.mem.eql(u8, active.label, "chromatogramList")) return "chromatogramList count does not match actual chromatogram elements";
    if (std.mem.eql(u8, active.label, "scanList")) return "scanList count does not match actual scan elements";
    if (std.mem.eql(u8, active.label, "precursorList")) return "precursorList count does not match actual precursor elements";
    if (std.mem.eql(u8, active.label, "productList")) return "productList count does not match actual product elements";
    if (std.mem.eql(u8, active.label, "scanWindowList")) return "scanWindowList count does not match actual scanWindow elements";
    if (std.mem.eql(u8, active.label, "selectedIonList")) return "selectedIonList count does not match actual selectedIon elements";
    return "binaryDataArrayList count does not match actual binaryDataArray elements";
}

fn minimumCountMessage(active: ListCountState) []const u8 {
    if (std.mem.eql(u8, active.label, "cvList")) return "cvList must contain at least 1 cv element";
    if (std.mem.eql(u8, active.label, "sourceFileList")) return "sourceFileList must contain at least 1 sourceFile element";
    if (std.mem.eql(u8, active.label, "targetList")) return "targetList must contain at least 1 target element";
    if (std.mem.eql(u8, active.label, "indexList")) return "indexList must contain at least 1 index element";
    if (std.mem.eql(u8, active.label, "referenceableParamGroupList")) return "referenceableParamGroupList must contain at least 1 referenceableParamGroup element";
    if (std.mem.eql(u8, active.label, "sampleList")) return "sampleList must contain at least 1 sample element";
    if (std.mem.eql(u8, active.label, "softwareList")) return "softwareList must contain at least 1 software element";
    if (std.mem.eql(u8, active.label, "scanSettingsList")) return "scanSettingsList must contain at least 1 scanSettings element";
    if (std.mem.eql(u8, active.label, "instrumentConfigurationList")) return "instrumentConfigurationList must contain at least 1 instrumentConfiguration element";
    if (std.mem.eql(u8, active.label, "dataProcessingList")) return "dataProcessingList must contain at least 1 dataProcessing element";
    if (std.mem.eql(u8, active.label, "chromatogramList")) return "chromatogramList must contain at least 1 chromatogram element";
    if (std.mem.eql(u8, active.label, "scanList")) return "scanList must contain at least 1 scan element";
    if (std.mem.eql(u8, active.label, "precursorList")) return "precursorList must contain at least 1 precursor element";
    if (std.mem.eql(u8, active.label, "productList")) return "productList must contain at least 1 product element";
    if (std.mem.eql(u8, active.label, "scanWindowList")) return "scanWindowList must contain at least 1 scanWindow element";
    if (std.mem.eql(u8, active.label, "selectedIonList")) return "selectedIonList must contain at least 1 selectedIon element";
    return "binaryDataArrayList must contain at least 2 binaryDataArray elements";
}

fn spectrumChildOutOfOrderMessage(slot: SpectrumChildSlot) []const u8 {
    return switch (slot) {
        .scan_list => "scanList appears out of order under spectrum",
        .precursor_list => "precursorList appears out of order under spectrum",
        .product_list => "productList appears out of order under spectrum",
        .binary_data_array_list => "binaryDataArrayList appears out of order under spectrum",
    };
}

fn chromatogramChildOutOfOrderMessage(slot: ChromatogramChildSlot) []const u8 {
    return switch (slot) {
        .precursor => "precursor appears out of order under chromatogram",
        .product => "product appears out of order under chromatogram",
        .binary_data_array_list => "binaryDataArrayList appears out of order under chromatogram",
    };
}

fn componentChildOutOfOrderMessage(slot: ComponentChildSlot) []const u8 {
    return switch (slot) {
        .source => "source appears out of order under componentList",
        .analyzer => "analyzer appears out of order under componentList",
        .detector => "detector appears out of order under componentList",
    };
}

fn indexedChildBeforeMzmlMessage(slot: IndexedChildSlot) []const u8 {
    return switch (slot) {
        .index_list => "indexList must appear after mzML",
        .index_list_offset => "indexListOffset must appear after mzML",
        .file_checksum => "fileChecksum must appear after mzML",
    };
}

fn duplicateIndexedChildMessage(slot: IndexedChildSlot) []const u8 {
    return switch (slot) {
        .index_list => "indexedmzML must not contain more than one indexList",
        .index_list_offset => "indexedmzML must not contain more than one indexListOffset",
        .file_checksum => "indexedmzML must not contain more than one fileChecksum",
    };
}

fn indexedChildOutOfOrderMessage(slot: IndexedChildSlot) []const u8 {
    return switch (slot) {
        .index_list => "indexList appears out of order under indexedmzML",
        .index_list_offset => "indexListOffset appears out of order under indexedmzML",
        .file_checksum => "fileChecksum appears out of order under indexedmzML",
    };
}

fn runStructuralValidationInto(
    allocator: std.mem.Allocator,
    io: std.Io,
    fixture: []const u8,
    diagnostics: *DiagnosticSink,
) !void {
    diagnostics.clearRetainingCapacity();
    var reader = std.Io.Reader.fixed(fixture);
    try StructuralValidator.validateReader(allocator, io, &reader, diagnostics, "fixture");
}

fn expectSingleStructuralDiagnostic(diagnostics: []const Diagnostic, expected_rule: []const u8, expected_message: ?[]const u8) !void {
    try std.testing.expectEqual(@as(usize, 1), diagnostics.len);
    try std.testing.expectEqualStrings(expected_rule, diagnostics[0].rule);
    if (expected_message) |message| {
        try std.testing.expectEqualStrings(message, diagnostics[0].message);
    }
}

fn readFixtureAlloc(allocator: std.mem.Allocator, io: std.Io, sub_path: []const u8) ![]u8 {
    return try std.Io.Dir.cwd().readFileAlloc(io, sub_path, allocator, .limited(64 * 1024));
}

fn minimalChromatogramMzml(comptime chromatogram_inner: []const u8) []const u8 {
    return "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">" ++
        "<cvList count=\"1\"><cv id=\"MS\" fullName=\"PSI-MS\" URI=\"https://example.invalid/psi-ms.obo\"/></cvList>" ++
        "<fileDescription><fileContent/></fileDescription>" ++
        "<softwareList count=\"1\"><software id=\"SW1\" version=\"1.0\"/></softwareList>" ++
        "<instrumentConfigurationList count=\"1\"><instrumentConfiguration id=\"IC1\"/></instrumentConfigurationList>" ++
        "<dataProcessingList count=\"1\"><dataProcessing id=\"DP1\"><processingMethod order=\"0\" softwareRef=\"SW1\"/></dataProcessing></dataProcessingList>" ++
        "<run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\">" ++
        "<chromatogramList count=\"1\" defaultDataProcessingRef=\"DP1\">" ++
        "<chromatogram index=\"0\" id=\"tic=1\" defaultArrayLength=\"1\">" ++
        chromatogram_inner ++
        "</chromatogram>" ++
        "</chromatogramList>" ++
        "</run>" ++
        "</mzML>";
}

fn minimalMzml(comptime file_content_inner: []const u8, comptime run_inner: []const u8) []const u8 {
    return "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">" ++
        "<cvList count=\"1\"><cv id=\"MS\" fullName=\"PSI-MS\" URI=\"https://example.invalid/psi-ms.obo\"/></cvList>" ++
        "<fileDescription><fileContent>" ++ file_content_inner ++ "</fileContent></fileDescription>" ++
        "<softwareList count=\"1\"><software id=\"SW1\" version=\"1.0\"/></softwareList>" ++
        "<instrumentConfigurationList count=\"1\"><instrumentConfiguration id=\"IC1\"/></instrumentConfigurationList>" ++
        "<dataProcessingList count=\"1\"><dataProcessing id=\"DP1\"><processingMethod order=\"0\" softwareRef=\"SW1\"/></dataProcessing></dataProcessingList>" ++
        "<run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\">" ++ run_inner ++ "</run>" ++
        "</mzML>";
}

// --- Unit Tests ---

// --- Valid Fixtures ---

test "structural validator accepts realistic one-spectrum mzML fixture" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try readFixtureAlloc(allocator, io, "fixtures/examples/mzml/single-spectrum-missing-cv-terms.mzML");
    defer allocator.free(fixture);

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "structural validator accepts indexed mzML PSI tiny fixture" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try readFixtureAlloc(allocator, io, "fixtures/mzml/valid/tiny.pwiz.1.1.mzML");
    defer allocator.free(fixture);

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "structural validator accepts valid chromatogram fixture" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = minimalChromatogramMzml(
        "<precursor><activation/></precursor>" ++
            "<product/>" ++
            "<binaryDataArrayList count=\"2\">" ++
            "<binaryDataArray encodedLength=\"8\"><binary>AAAAAA==</binary></binaryDataArray>" ++
            "<binaryDataArray encodedLength=\"8\"><binary>AAAAAA==</binary></binaryDataArray>" ++
            "</binaryDataArrayList>",
    );

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "structural validator cvParam with unknown intern id does not report unrecognized element" {
    const allocator = std.testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var validator = StructuralValidator.init(allocator, &diagnostics, null);
    defer validator.deinit();

    try validator.consumeStart(test_events.startUnknown("mzML", &.{test_events.attr("version", "1.1.0")}, 0));
    try validator.consumeStart(test_events.startUnknown("run", &.{test_events.attr("id", "run1")}, 10));
    try validator.consumeStart(test_events.startUnknown("spectrumList", &.{test_events.attr("count", "1")}, 20));
    try validator.consumeStart(test_events.startUnknown("spectrum", &.{ test_events.attr("index", "0"), test_events.attr("id", "s1"), test_events.attr("defaultArrayLength", "1") }, 30));
    try validator.consumeStart(test_events.startUnknown("cvParam", &.{test_events.attr("accession", "MS:1000576")}, 40));

    for (diagnostics.items) |diag| {
        try std.testing.expect(!std.mem.eql(u8, diag.message, "unrecognized element in mzML scope"));
    }
}

// --- Required Children and Attributes ---

test "structural validator reports missing required top-level mzML children" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture =
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">" ++
        "<run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\">" ++
        "<spectrumList count=\"0\" defaultDataProcessingRef=\"DP1\"/>" ++
        "</run>" ++
        "</mzML>";

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 5), diagnostics.items.len);
    try std.testing.expectEqualStrings("mzML is missing required child cvList", diagnostics.items[0].message);
    try std.testing.expectEqualStrings("mzML is missing required child fileDescription", diagnostics.items[1].message);
    try std.testing.expectEqualStrings("mzML is missing required child softwareList", diagnostics.items[2].message);
    try std.testing.expectEqualStrings("mzML is missing required child instrumentConfigurationList", diagnostics.items[3].message);
    try std.testing.expectEqualStrings("mzML is missing required child dataProcessingList", diagnostics.items[4].message);
}

test "structural validator reports missing required run and spectrumList attributes" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture =
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">" ++
        "<cvList count=\"1\"><cv id=\"MS\" fullName=\"PSI-MS\" URI=\"https://example.invalid/psi-ms.obo\"/></cvList>" ++
        "<fileDescription><fileContent/></fileDescription>" ++
        "<softwareList count=\"1\"><software id=\"SW1\" version=\"1.0\"/></softwareList>" ++
        "<instrumentConfigurationList count=\"1\"><instrumentConfiguration id=\"IC1\"/></instrumentConfigurationList>" ++
        "<dataProcessingList count=\"1\"><dataProcessing id=\"DP1\"><processingMethod order=\"0\" softwareRef=\"SW1\"/></dataProcessing></dataProcessingList>" ++
        "<run>" ++
        "<spectrumList count=\"1\">" ++
        "<spectrum index=\"0\" id=\"scan=1\" defaultArrayLength=\"1\">" ++
        "<binaryDataArrayList count=\"2\">" ++
        "<binaryDataArray encodedLength=\"8\"><binary>AAAAAA==</binary></binaryDataArray>" ++
        "<binaryDataArray encodedLength=\"8\"><binary>AAAAAA==</binary></binaryDataArray>" ++
        "</binaryDataArrayList>" ++
        "</spectrum>" ++
        "</spectrumList>" ++
        "</run>" ++
        "</mzML>";

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 3), diagnostics.items.len);
    try std.testing.expectEqualStrings("run is missing required attribute id", diagnostics.items[0].message);
    try std.testing.expectEqualStrings(RuleId.mzml_ref_missing, diagnostics.items[1].rule);
    try std.testing.expectEqualStrings("run is missing required attribute defaultInstrumentConfigurationRef", diagnostics.items[1].message);
    try std.testing.expectEqualStrings(RuleId.mzml_ref_missing, diagnostics.items[2].rule);
    try std.testing.expectEqualStrings("spectrumList is missing required attribute defaultDataProcessingRef", diagnostics.items[2].message);
}

test "structural validator reports missing required reference element attributes" {
    const allocator = std.testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var validator = StructuralValidator.init(allocator, &diagnostics, null);
    defer validator.deinit();

    try validator.consumeStart(test_events.startUnknown("mzML", &.{test_events.attr("version", "1.1.0")}, 0));
    try validator.consumeStart(test_events.startUnknown("scanSettingsList", &.{test_events.attr("count", "1")}, 10));
    try validator.consumeStart(test_events.startUnknown("scanSettings", &.{test_events.attr("id", "SS1")}, 20));
    try validator.consumeStart(test_events.startUnknown("referenceableParamGroupRef", &.{}, 30));
    try validator.consumeEnd(test_events.endUnknown("referenceableParamGroupRef"));
    try validator.consumeStart(test_events.startUnknown("sourceFileRefList", &.{test_events.attr("count", "1")}, 40));
    try validator.consumeStart(test_events.startUnknown("sourceFileRef", &.{}, 50));

    var source_file_missing = false;
    var param_group_missing = false;
    for (diagnostics.items) |item| {
        if (!std.mem.eql(u8, item.rule, RuleId.mzml_ref_missing)) continue;
        if (std.mem.eql(u8, item.message, "sourceFileRef is missing required attribute ref")) source_file_missing = true;
        if (std.mem.eql(u8, item.message, "referenceableParamGroupRef is missing required attribute ref")) param_group_missing = true;
    }
    try std.testing.expect(source_file_missing);
    try std.testing.expect(param_group_missing);
}

// --- Ordering and Nesting Rules ---

test "structural validator reports out of order top-level child" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture =
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">" ++
        "<cvList count=\"1\"><cv id=\"MS\" fullName=\"PSI-MS\" URI=\"https://example.invalid/psi-ms.obo\"/></cvList>" ++
        "<fileDescription><fileContent/></fileDescription>" ++
        "<softwareList count=\"1\"><software id=\"SW1\" version=\"1.0\"/></softwareList>" ++
        "<dataProcessingList count=\"1\"><dataProcessing id=\"DP1\"><processingMethod order=\"0\" softwareRef=\"SW1\"/></dataProcessing></dataProcessingList>" ++
        "<instrumentConfigurationList count=\"1\"><instrumentConfiguration id=\"IC1\"/></instrumentConfigurationList>" ++
        "<run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\">" ++
        "<spectrumList count=\"0\" defaultDataProcessingRef=\"DP1\"/>" ++
        "</run>" ++
        "</mzML>";

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_structure_nesting, diagnostics.items[0].rule);
    try std.testing.expectEqualStrings("instrumentConfigurationList appears out of order under mzML", diagnostics.items[0].message);
}

test "structural validator reports duplicate top-level child" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture =
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">" ++
        "<cvList count=\"1\"><cv id=\"MS\" fullName=\"PSI-MS\" URI=\"https://example.invalid/psi-ms.obo\"/></cvList>" ++
        "<fileDescription><fileContent/></fileDescription>" ++
        "<softwareList count=\"1\"><software id=\"SW1\" version=\"1.0\"/></softwareList>" ++
        "<softwareList count=\"1\"><software id=\"SW2\" version=\"1.0\"/></softwareList>" ++
        "<instrumentConfigurationList count=\"1\"><instrumentConfiguration id=\"IC1\"/></instrumentConfigurationList>" ++
        "<dataProcessingList count=\"1\"><dataProcessing id=\"DP1\"><processingMethod order=\"0\" softwareRef=\"SW1\"/></dataProcessing></dataProcessingList>" ++
        "<run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\">" ++
        "<spectrumList count=\"0\" defaultDataProcessingRef=\"DP1\"/>" ++
        "</run>" ++
        "</mzML>";

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_structure_nesting, diagnostics.items[0].rule);
    try std.testing.expectEqualStrings("mzML must not contain more than one softwareList", diagnostics.items[0].message);
}

test "structural validator reports spectrumList count mismatch" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture =
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">" ++
        "<cvList count=\"1\"><cv id=\"MS\" fullName=\"PSI-MS\" URI=\"https://example.invalid/psi-ms.obo\"/></cvList>" ++
        "<fileDescription><fileContent/></fileDescription>" ++
        "<softwareList count=\"1\"><software id=\"SW1\" version=\"1.0\"/></softwareList>" ++
        "<instrumentConfigurationList count=\"1\"><instrumentConfiguration id=\"IC1\"/></instrumentConfigurationList>" ++
        "<dataProcessingList count=\"1\"><dataProcessing id=\"DP1\"><processingMethod order=\"0\" softwareRef=\"SW1\"/></dataProcessing></dataProcessingList>" ++
        "<run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\">" ++
        "<spectrumList count=\"2\" defaultDataProcessingRef=\"DP1\">" ++
        "<spectrum index=\"0\" id=\"scan=1\" defaultArrayLength=\"1\">" ++
        "<binaryDataArrayList count=\"2\">" ++
        "<binaryDataArray encodedLength=\"8\"><binary>AAAAAA==</binary></binaryDataArray>" ++
        "<binaryDataArray encodedLength=\"8\"><binary>AAAAAA==</binary></binaryDataArray>" ++
        "</binaryDataArrayList>" ++
        "</spectrum>" ++
        "</spectrumList>" ++
        "</run>" ++
        "</mzML>";

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_structure_count, diagnostics.items[0].rule);
    try std.testing.expectEqualStrings("spectrumList count does not match actual spectrum elements", diagnostics.items[0].message);
}

test "structural validator reports top-level list count mismatch" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture =
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">" ++
        "<cvList count=\"1\"><cv id=\"MS\" fullName=\"PSI-MS\" URI=\"https://example.invalid/psi-ms.obo\"/></cvList>" ++
        "<fileDescription><fileContent/></fileDescription>" ++
        "<softwareList count=\"2\"><software id=\"SW1\" version=\"1.0\"/></softwareList>" ++
        "<instrumentConfigurationList count=\"1\"><instrumentConfiguration id=\"IC1\"/></instrumentConfigurationList>" ++
        "<dataProcessingList count=\"1\"><dataProcessing id=\"DP1\"><processingMethod order=\"0\" softwareRef=\"SW1\"/></dataProcessing></dataProcessingList>" ++
        "<run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\">" ++
        "<spectrumList count=\"0\" defaultDataProcessingRef=\"DP1\"/>" ++
        "</run>" ++
        "</mzML>";

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_structure_count, diagnostics.items[0].rule);
    try std.testing.expectEqualStrings("softwareList count does not match actual software elements", diagnostics.items[0].message);
}

test "structural validator reports malformed count attribute values" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture =
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">" ++
        "<cvList count=\"oops\"><cv id=\"MS\" fullName=\"PSI-MS\" URI=\"https://example.invalid/psi-ms.obo\"/></cvList>" ++
        "<fileDescription><fileContent/></fileDescription>" ++
        "<softwareList count=\"1\"><software id=\"SW1\" version=\"1.0\"/></softwareList>" ++
        "<instrumentConfigurationList count=\"1\"><instrumentConfiguration id=\"IC1\"/></instrumentConfigurationList>" ++
        "<dataProcessingList count=\"1\"><dataProcessing id=\"DP1\"><processingMethod order=\"0\" softwareRef=\"SW1\"/></dataProcessing></dataProcessingList>" ++
        "<run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\">" ++
        "<spectrumList count=\"0\" defaultDataProcessingRef=\"DP1\"/>" ++
        "</run>" ++
        "</mzML>";

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_structure_count, diagnostics.items[0].rule);
    try std.testing.expectEqualStrings("cvList count attribute must be a non-negative integer", diagnostics.items[0].message);
}

test "structural validator reports scanList minimum child violation" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture =
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">" ++
        "<cvList count=\"1\"><cv id=\"MS\" fullName=\"PSI-MS\" URI=\"https://example.invalid/psi-ms.obo\"/></cvList>" ++
        "<fileDescription><fileContent/></fileDescription>" ++
        "<softwareList count=\"1\"><software id=\"SW1\" version=\"1.0\"/></softwareList>" ++
        "<instrumentConfigurationList count=\"1\"><instrumentConfiguration id=\"IC1\"/></instrumentConfigurationList>" ++
        "<dataProcessingList count=\"1\"><dataProcessing id=\"DP1\"><processingMethod order=\"0\" softwareRef=\"SW1\"/></dataProcessing></dataProcessingList>" ++
        "<run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\">" ++
        "<spectrumList count=\"1\" defaultDataProcessingRef=\"DP1\">" ++
        "<spectrum index=\"0\" id=\"scan=1\" defaultArrayLength=\"1\">" ++
        "<scanList count=\"0\"/>" ++
        "<binaryDataArrayList count=\"2\">" ++
        "<binaryDataArray encodedLength=\"8\"><binary>AAAAAA==</binary></binaryDataArray>" ++
        "<binaryDataArray encodedLength=\"8\"><binary>AAAAAA==</binary></binaryDataArray>" ++
        "</binaryDataArrayList>" ++
        "</spectrum>" ++
        "</spectrumList>" ++
        "</run>" ++
        "</mzML>";

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_structure_count, diagnostics.items[0].rule);
    try std.testing.expectEqualStrings("scanList must contain at least 1 scan element", diagnostics.items[0].message);
}

test "structural validator reports binaryDataArrayList minimum child violation" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture =
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">" ++
        "<cvList count=\"1\"><cv id=\"MS\" fullName=\"PSI-MS\" URI=\"https://example.invalid/psi-ms.obo\"/></cvList>" ++
        "<fileDescription><fileContent/></fileDescription>" ++
        "<softwareList count=\"1\"><software id=\"SW1\" version=\"1.0\"/></softwareList>" ++
        "<instrumentConfigurationList count=\"1\"><instrumentConfiguration id=\"IC1\"/></instrumentConfigurationList>" ++
        "<dataProcessingList count=\"1\"><dataProcessing id=\"DP1\"><processingMethod order=\"0\" softwareRef=\"SW1\"/></dataProcessing></dataProcessingList>" ++
        "<run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\">" ++
        "<spectrumList count=\"1\" defaultDataProcessingRef=\"DP1\">" ++
        "<spectrum index=\"0\" id=\"scan=1\" defaultArrayLength=\"1\">" ++
        "<binaryDataArrayList count=\"1\">" ++
        "<binaryDataArray encodedLength=\"8\"><binary>AAAAAA==</binary></binaryDataArray>" ++
        "</binaryDataArrayList>" ++
        "</spectrum>" ++
        "</spectrumList>" ++
        "</run>" ++
        "</mzML>";

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_structure_count, diagnostics.items[0].rule);
    try std.testing.expectEqualStrings("binaryDataArrayList must contain at least 2 binaryDataArray elements", diagnostics.items[0].message);
}

test "structural validator reports optional top-level list minimum child violation" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture =
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">" ++
        "<cvList count=\"1\"><cv id=\"MS\" fullName=\"PSI-MS\" URI=\"https://example.invalid/psi-ms.obo\"/></cvList>" ++
        "<fileDescription><fileContent/></fileDescription>" ++
        "<softwareList count=\"1\"><software id=\"SW1\" version=\"1.0\"/></softwareList>" ++
        "<scanSettingsList count=\"0\"/>" ++
        "<instrumentConfigurationList count=\"1\"><instrumentConfiguration id=\"IC1\"/></instrumentConfigurationList>" ++
        "<dataProcessingList count=\"1\"><dataProcessing id=\"DP1\"><processingMethod order=\"0\" softwareRef=\"SW1\"/></dataProcessing></dataProcessingList>" ++
        "<run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\">" ++
        "<spectrumList count=\"0\" defaultDataProcessingRef=\"DP1\"/>" ++
        "</run>" ++
        "</mzML>";

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_structure_count, diagnostics.items[0].rule);
    try std.testing.expectEqualStrings("scanSettingsList must contain at least 1 scanSettings element", diagnostics.items[0].message);
}

test "structural validator reports wrong root namespace" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try readFixtureAlloc(allocator, io, "fixtures/examples/mzml/wrong-namespace.mzML");
    defer allocator.free(fixture);

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_structure_root, diagnostics.items[0].rule);
}

test "structural validator rejects a complete unqualified mzML document" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try readFixtureAlloc(allocator, io, "fixtures/examples/mzml/unqualified-complete.mzML");
    defer allocator.free(fixture);

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");

    try expectSingleStructuralDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_root,
        "root element must be mzML in the http://psi.hupo.org/ms/mzml namespace",
    );
}

test "structural validator does not accept a foreign required attribute" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try readFixtureAlloc(allocator, io, "fixtures/examples/mzml/foreign-required-attribute.mzML");
    defer allocator.free(fixture);

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");

    try expectSingleStructuralDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_attribute,
        "run is missing required attribute id",
    );
}

test "structural validator: accepts spectrum without optional binaryDataArrayList" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try readFixtureAlloc(allocator, io, "fixtures/examples/mzml/missing-binary-data-array-list.mzML");
    defer allocator.free(fixture);

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "structural validator reports mzml missing run child" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture =
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">" ++
        "<cvList count=\"1\"><cv id=\"MS\" fullName=\"PSI-MS\" URI=\"https://example.invalid/psi-ms.obo\"/></cvList>" ++
        "<fileDescription><fileContent/></fileDescription>" ++
        "<softwareList count=\"1\"><software id=\"SW1\" version=\"1.0\"/></softwareList>" ++
        "<instrumentConfigurationList count=\"1\"><instrumentConfiguration id=\"IC1\"/></instrumentConfigurationList>" ++
        "<dataProcessingList count=\"1\"><dataProcessing id=\"DP1\"><processingMethod order=\"0\" softwareRef=\"SW1\"/></dataProcessing></dataProcessingList>" ++
        "</mzML>";

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_structure_missing_child, diagnostics.items[0].rule);
    try std.testing.expectEqualStrings("mzML is missing required child run", diagnostics.items[0].message);
}

test "structural validator reports binaryDataArrayList nested directly under run" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture =
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">" ++
        "<cvList count=\"1\"><cv id=\"MS\" fullName=\"PSI-MS\" URI=\"https://example.invalid/psi-ms.obo\"/></cvList>" ++
        "<fileDescription><fileContent/></fileDescription>" ++
        "<softwareList count=\"1\"><software id=\"SW1\" version=\"1.0\"/></softwareList>" ++
        "<instrumentConfigurationList count=\"1\"><instrumentConfiguration id=\"IC1\"/></instrumentConfigurationList>" ++
        "<dataProcessingList count=\"1\"><dataProcessing id=\"DP1\"><processingMethod order=\"0\" softwareRef=\"SW1\"/></dataProcessing></dataProcessingList>" ++
        "<run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\">" ++
        "<binaryDataArrayList count=\"2\">" ++
        "<binaryDataArray encodedLength=\"8\"><binary>AAAAAA==</binary></binaryDataArray>" ++
        "<binaryDataArray encodedLength=\"8\"><binary>AAAAAA==</binary></binaryDataArray>" ++
        "</binaryDataArrayList>" ++
        "</run>" ++
        "</mzML>";

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_structure_nesting, diagnostics.items[0].rule);
    try std.testing.expectEqualStrings("binaryDataArrayList must be a child of spectrum or chromatogram", diagnostics.items[0].message);
}

test "structural validator reports chromatogram child ordering violations" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = minimalChromatogramMzml(
        "<product/>" ++
            "<precursor><activation/></precursor>" ++
            "<binaryDataArrayList count=\"2\">" ++
            "<binaryDataArray encodedLength=\"8\"><binary>AAAAAA==</binary></binaryDataArray>" ++
            "<binaryDataArray encodedLength=\"8\"><binary>AAAAAA==</binary></binaryDataArray>" ++
            "</binaryDataArrayList>",
    );

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try expectSingleStructuralDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_nesting,
        "precursor appears out of order under chromatogram",
    );
}

test "structural validator reports indexed wrapper child ordering violations" {
    const allocator = std.testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var validator = StructuralValidator.init(allocator, &diagnostics, null);
    defer validator.deinit();

    try validator.consumeStart(test_events.startInterned("indexedmzML", &.{}, 0));
    try validator.consumeStart(test_events.startInterned("mzML", &.{test_events.attr("version", "1.1.0")}, 10));
    try validator.consumeEnd(test_events.endInterned("mzML", 20));
    try validator.consumeStart(test_events.startInterned("indexListOffset", &.{}, 30));
    try validator.consumeEnd(test_events.endInterned("indexListOffset", 40));
    try validator.consumeStart(test_events.startInterned("indexList", &.{test_events.attr("count", "0")}, 50));

    try expectSingleStructuralDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_nesting,
        "indexList appears out of order under indexedmzML",
    );
}

test "structural validator reports index metadata before mzML" {
    const allocator = std.testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var validator = StructuralValidator.init(allocator, &diagnostics, null);
    defer validator.deinit();

    try validator.consumeStart(test_events.startInterned("indexedmzML", &.{}, 0));
    try validator.consumeStart(test_events.startInterned("indexList", &.{test_events.attr("count", "0")}, 10));

    try expectSingleStructuralDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_nesting,
        "indexList must appear after mzML",
    );
}

test "structural validator rejects index metadata inside plain mzML" {
    const allocator = std.testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var validator = StructuralValidator.init(allocator, &diagnostics, null);
    defer validator.deinit();

    try validator.consumeStart(test_events.startInterned("mzML", &.{test_events.attr("version", "1.1.0")}, 0));
    try validator.consumeStart(test_events.startInterned("indexList", &.{test_events.attr("count", "0")}, 10));

    try expectSingleStructuralDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_nesting,
        "index metadata must be a direct child of indexedmzML",
    );
}

test "structural validator rejects unexpected indexed wrapper children" {
    const allocator = std.testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var validator = StructuralValidator.init(allocator, &diagnostics, null);
    defer validator.deinit();

    try validator.consumeStart(test_events.startInterned("indexedmzML", &.{}, 0));
    try validator.consumeStart(test_events.startInterned("mzML", &.{test_events.attr("version", "1.1.0")}, 10));
    try validator.consumeEnd(test_events.endInterned("mzML", 20));
    try validator.consumeStart(test_events.startUnknown("unexpected", &.{}, 30));

    try expectSingleStructuralDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_nesting,
        "element is not allowed as a direct child of indexedmzML",
    );
}

test "structural validator: rejects duplicate mzML in indexed wrapper" {
    const allocator = std.testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var validator = StructuralValidator.init(allocator, &diagnostics, null);
    defer validator.deinit();

    try validator.consumeStart(test_events.startInterned("indexedmzML", &.{}, 0));
    try validator.consumeStart(test_events.startInterned("mzML", &.{test_events.attr("version", "1.1.0")}, 10));
    try validator.consumeEnd(test_events.endInterned("mzML", 20));
    try validator.consumeStart(test_events.startInterned("mzML", &.{test_events.attr("version", "1.1.0")}, 30));

    try expectSingleStructuralDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_nesting,
        "indexedmzML must not contain more than one mzML element",
    );
}

test "structural parent inventory: covers every shared content rule" {
    const allowed = [_]struct { child: ElementId, parent: ElementId }{
        .{ .child = .cv, .parent = .cvList },
        .{ .child = .fileContent, .parent = .fileDescription },
        .{ .child = .sourceFile, .parent = .sourceFileList },
        .{ .child = .referenceableParamGroup, .parent = .referenceableParamGroupList },
        .{ .child = .cvParam, .parent = .referenceableParamGroup },
        .{ .child = .referenceableParamGroupRef, .parent = .run },
        .{ .child = .sourceFileRef, .parent = .sourceFileRefList },
        .{ .child = .target, .parent = .targetList },
        .{ .child = .source, .parent = .componentList },
        .{ .child = .processingMethod, .parent = .dataProcessing },
        .{ .child = .spectrum, .parent = .spectrumList },
        .{ .child = .chromatogram, .parent = .chromatogramList },
        .{ .child = .scan, .parent = .scanList },
        .{ .child = .scanWindow, .parent = .scanWindowList },
        .{ .child = .precursor, .parent = .precursorList },
        .{ .child = .activation, .parent = .precursor },
        .{ .child = .product, .parent = .productList },
        .{ .child = .binaryDataArrayList, .parent = .chromatogram },
        .{ .child = .binary, .parent = .binaryDataArray },
        .{ .child = .index, .parent = .indexList },
        .{ .child = .offset, .parent = .index },
    };

    for (allowed) |pair| try std.testing.expect(isAllowedParent(pair.child, pair.parent));
    try std.testing.expect(!isAllowedParent(.cv, .mzML));
    try std.testing.expect(!isAllowedParent(.scan, .spectrum));
    try std.testing.expect(!isAllowedParent(.activation, .chromatogram));
    try std.testing.expect(!isAllowedParent(.binaryDataArray, .spectrum));
    try std.testing.expect(!isAllowedParent(.offset, .indexList));
}

test "structural parent inventory: gives every schema element a placement" {
    for (std.enums.values(ElementId)) |child| {
        if (child == .unknown or child == .indexedmzML) continue;

        var has_parent = false;
        for (std.enums.values(ElementId)) |parent| {
            has_parent = has_parent or isAllowedParent(child, parent);
        }
        try std.testing.expect(has_parent);
    }
}

test "structural validator: quarantines invalid subtrees from active list counts" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture =
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">" ++
        "<cvList count=\"1\"><fileDescription><cv id=\"bad\" fullName=\"bad\" URI=\"bad\"/></fileDescription><cv id=\"MS\" fullName=\"PSI-MS\" URI=\"valid\"/></cvList>" ++
        "<fileDescription><fileContent/></fileDescription>" ++
        "<softwareList count=\"1\"><software id=\"SW1\" version=\"1.0\"/></softwareList>" ++
        "<instrumentConfigurationList count=\"1\"><instrumentConfiguration id=\"IC1\"/></instrumentConfigurationList>" ++
        "<dataProcessingList count=\"1\"><dataProcessing id=\"DP1\"><processingMethod order=\"0\" softwareRef=\"SW1\"/></dataProcessing></dataProcessingList>" ++
        "<run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\"/>" ++
        "</mzML>";

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try expectSingleStructuralDiagnostic(diagnostics.items, RuleId.mzml_structure_nesting, "mzML element is not allowed under its parent");
}

test "structural validator: rejects foreign extension elements" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = minimalMzml("<ext:foreign xmlns:ext=\"urn:extension\"/>", "");

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try expectSingleStructuralDiagnostic(diagnostics.items, RuleId.mzml_structure_nesting, "unrecognized element in mzML scope");
}

test "structural validator: enforces inherited parameter ordering" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = minimalMzml("<userParam name=\"first\"/><cvParam cvRef=\"MS\" accession=\"MS:1\" name=\"late\"/>", "");

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try expectSingleStructuralDiagnostic(diagnostics.items, RuleId.mzml_structure_nesting, "parameter element appears out of order in mzML content");
}

test "structural validator: rejects text in element-only content" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = minimalMzml("illegal text", "");

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try expectSingleStructuralDiagnostic(diagnostics.items, RuleId.mzml_structure_nesting, "non-whitespace text is not allowed in element-only mzML content");
}

test "structural validator: allows text in indexed scalar content nodes" {
    const allocator = std.testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var validator = StructuralValidator.init(allocator, &diagnostics, null);
    defer validator.deinit();

    try validator.consumeStart(test_events.startInterned("indexedmzML", &.{}, 0));
    try validator.consumeStart(test_events.startInterned("mzML", &.{test_events.attr("version", "1.1.0")}, 10));
    try validator.consumeEnd(test_events.endInterned("mzML", 20));
    try validator.consumeStart(test_events.startInterned("indexList", &.{test_events.attr("count", "1")}, 30));
    try validator.consumeStart(test_events.startInterned("index", &.{test_events.attr("name", "spectrum")}, 40));
    try validator.consumeStart(test_events.startInterned("offset", &.{test_events.attr("idRef", "scan=1")}, 50));
    try validator.consumeText(test_events.text("123"));
    try validator.consumeEnd(test_events.endInterned("offset", 60));
    try validator.consumeEnd(test_events.endInterned("index", 70));
    try validator.consumeEnd(test_events.endInterned("indexList", 80));
    try validator.consumeStart(test_events.startInterned("indexListOffset", &.{}, 90));
    try validator.consumeText(test_events.text("456"));
    try validator.consumeEnd(test_events.endInterned("indexListOffset", 100));
    try validator.consumeStart(test_events.startInterned("fileChecksum", &.{}, 110));
    try validator.consumeText(test_events.text("abc"));

    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "structural validator: requires precursor activation" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = minimalChromatogramMzml(
        "<precursor/>" ++
            "<binaryDataArrayList count=\"2\">" ++
            "<binaryDataArray encodedLength=\"8\"><binary>AAAAAA==</binary></binaryDataArray>" ++
            "<binaryDataArray encodedLength=\"8\"><binary>AAAAAA==</binary></binaryDataArray>" ++
            "</binaryDataArrayList>",
    );

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try expectSingleStructuralDiagnostic(diagnostics.items, RuleId.mzml_structure_missing_child, "precursor is missing required child activation");
}

test "structural validator: requires one binary child per binaryDataArray" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = minimalMzml("", "<spectrumList count=\"1\" defaultDataProcessingRef=\"DP1\">" ++
        "<spectrum index=\"0\" id=\"scan=1\" defaultArrayLength=\"1\">" ++
        "<binaryDataArrayList count=\"2\">" ++
        "<binaryDataArray encodedLength=\"0\"/>" ++
        "<binaryDataArray encodedLength=\"8\"><binary>AAAAAA==</binary></binaryDataArray>" ++
        "</binaryDataArrayList></spectrum></spectrumList>");

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try expectSingleStructuralDiagnostic(diagnostics.items, RuleId.mzml_structure_missing_child, "binaryDataArray is missing required child binary");
}

test "structural validator: enforces nonempty precursor lists" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = minimalMzml("", "<spectrumList count=\"1\" defaultDataProcessingRef=\"DP1\">" ++
        "<spectrum index=\"0\" id=\"scan=1\" defaultArrayLength=\"0\"><precursorList count=\"0\"/></spectrum>" ++
        "</spectrumList>");

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try expectSingleStructuralDiagnostic(diagnostics.items, RuleId.mzml_structure_count, "precursorList must contain at least 1 precursor element");
}

test "structural validator: rejects duplicate scan window lists" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = minimalMzml("", "<spectrumList count=\"1\" defaultDataProcessingRef=\"DP1\">" ++
        "<spectrum index=\"0\" id=\"scan=1\" defaultArrayLength=\"0\">" ++
        "<scanList count=\"1\"><scan><scanWindowList count=\"1\"><scanWindow/></scanWindowList><scanWindowList count=\"1\"><scanWindow/></scanWindowList></scan></scanList>" ++
        "</spectrum></spectrumList>");

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try expectSingleStructuralDiagnostic(diagnostics.items, RuleId.mzml_structure_nesting, "scan must not contain more than one scanWindowList");
}

test "structural validator: rejects precursor child order" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = minimalMzml("", "<spectrumList count=\"1\" defaultDataProcessingRef=\"DP1\">" ++
        "<spectrum index=\"0\" id=\"scan=1\" defaultArrayLength=\"0\">" ++
        "<precursorList count=\"1\"><precursor><activation/><selectedIonList count=\"1\"><selectedIon/></selectedIonList></precursor></precursorList>" ++
        "</spectrum></spectrumList>");

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try expectSingleStructuralDiagnostic(diagnostics.items, RuleId.mzml_structure_nesting, "selectedIonList appears out of order under precursor");
}

test "structural validator: out-of-order precursor children remain seen" {
    const allocator = std.testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var validator = StructuralValidator.init(allocator, &diagnostics, null);
    defer validator.deinit();

    try validator.consumeStart(test_events.startInterned("mzML", &.{test_events.attr("version", "1.1.0")}, 0));
    try validator.consumeStart(test_events.startInterned("run", &.{ test_events.attr("id", "run-1"), test_events.attr("defaultInstrumentConfigurationRef", "IC1") }, 10));
    try validator.consumeStart(test_events.startInterned("spectrumList", &.{ test_events.attr("count", "1"), test_events.attr("defaultDataProcessingRef", "DP1") }, 20));
    try validator.consumeStart(test_events.startInterned("spectrum", &.{ test_events.attr("index", "0"), test_events.attr("id", "scan=1"), test_events.attr("defaultArrayLength", "0") }, 30));
    try validator.consumeStart(test_events.startInterned("precursorList", &.{test_events.attr("count", "1")}, 40));
    try validator.consumeStart(test_events.startInterned("precursor", &.{}, 50));
    try validator.consumeStart(test_events.startInterned("activation", &.{}, 60));
    try validator.consumeEnd(test_events.endInterned("activation", 70));
    try validator.consumeStart(test_events.startInterned("selectedIonList", &.{test_events.attr("count", "1")}, 80));
    try validator.consumeStart(test_events.startInterned("selectedIon", &.{}, 90));
    try validator.consumeEnd(test_events.endInterned("selectedIon", 100));
    try validator.consumeEnd(test_events.endInterned("selectedIonList", 110));
    try validator.consumeStart(test_events.startInterned("selectedIonList", &.{test_events.attr("count", "1")}, 120));

    try std.testing.expectEqual(@as(usize, 2), diagnostics.items.len);
    try std.testing.expectEqualStrings("selectedIonList appears out of order under precursor", diagnostics.items[0].message);
    try std.testing.expectEqualStrings("precursor must not contain more than one selectedIonList", diagnostics.items[1].message);
}

test "structural validator: enforces index list count and offset minimum" {
    const allocator = std.testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var validator = StructuralValidator.init(allocator, &diagnostics, null);
    defer validator.deinit();

    try validator.consumeStart(test_events.startInterned("indexedmzML", &.{}, 0));
    try validator.consumeStart(test_events.startInterned("mzML", &.{test_events.attr("version", "1.1.0")}, 10));
    try validator.consumeEnd(test_events.endInterned("mzML", 20));
    try validator.consumeStart(test_events.startInterned("indexList", &.{test_events.attr("count", "1")}, 30));
    try validator.consumeStart(test_events.startInterned("index", &.{test_events.attr("name", "spectrum")}, 40));
    try validator.consumeEnd(test_events.endInterned("index", 50));
    try validator.consumeEnd(test_events.endInterned("indexList", 60));

    try expectSingleStructuralDiagnostic(diagnostics.items, RuleId.mzml_structure_missing_child, "index must contain at least 1 offset element");
}

test "structural validator: out-of-order components remain counted" {
    const allocator = std.testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var validator = StructuralValidator.init(allocator, &diagnostics, null);
    defer validator.deinit();

    try validator.consumeStart(test_events.startInterned("mzML", &.{test_events.attr("version", "1.1.0")}, 0));
    try validator.consumeStart(test_events.startInterned("instrumentConfigurationList", &.{test_events.attr("count", "1")}, 10));
    try validator.consumeStart(test_events.startInterned("instrumentConfiguration", &.{test_events.attr("id", "IC1")}, 20));
    try validator.consumeStart(test_events.startInterned("componentList", &.{test_events.attr("count", "3")}, 30));
    try validator.consumeStart(test_events.startInterned("source", &.{test_events.attr("order", "1")}, 40));
    try validator.consumeEnd(test_events.endInterned("source", 50));
    try validator.consumeStart(test_events.startInterned("detector", &.{test_events.attr("order", "3")}, 60));
    try validator.consumeEnd(test_events.endInterned("detector", 70));
    try validator.consumeStart(test_events.startInterned("analyzer", &.{test_events.attr("order", "2")}, 80));
    try validator.consumeEnd(test_events.endInterned("analyzer", 90));
    try validator.consumeEnd(test_events.endInterned("componentList", 100));

    try expectSingleStructuralDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_nesting,
        "analyzer appears out of order under componentList",
    );
}

test "[unit]: missing binary metadata is rejected" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = minimalMzml("", "<spectrumList count=\"1\" defaultDataProcessingRef=\"DP1\">" ++
        "<spectrum index=\"0\" id=\"scan=1\" defaultArrayLength=\"0\">" ++
        "<binaryDataArrayList count=\"2\">" ++
        "<binaryDataArray><binary/></binaryDataArray>" ++
        "<binaryDataArray encodedLength=\"0\"><binary/></binaryDataArray>" ++
        "</binaryDataArrayList></spectrum></spectrumList>");

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");

    try expectSingleStructuralDiagnostic(diagnostics.items, RuleId.mzml_structure_attribute, "binaryDataArray is missing required attribute encodedLength");
}

test "[unit]: cvParam identity fields are required" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = minimalMzml("<cvParam value=\"\"/>", "");

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");

    try std.testing.expectEqual(@as(usize, 3), diagnostics.items.len);
    try std.testing.expectEqualStrings("cvParam is missing required attribute cvRef", diagnostics.items[0].message);
    try std.testing.expectEqualStrings("cvParam is missing required attribute accession", diagnostics.items[1].message);
    try std.testing.expectEqualStrings("cvParam is missing required attribute name", diagnostics.items[2].message);
}

test "[unit]: unknown unqualified attributes are rejected" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = minimalMzml("<cvParam xmlns:ext=\"urn:extension\" cvRef=\"MS\" accession=\"MS:1\" name=\"term\" ext:note=\"allowed\" bogus=\"rejected\"/>", "");

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");

    try expectSingleStructuralDiagnostic(diagnostics.items, RuleId.mzml_structure_attribute, "mzML element has an unknown unqualified attribute");
}

test "[unit]: structural attribute validator rejects empty typed required values" {
    const allocator = std.testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var validator = StructuralValidator.init(allocator, &diagnostics, null);
    defer validator.deinit();

    _ = try validator.validateAttributes(test_events.startInterned("run", &.{
        test_events.attr("id", ""),
        test_events.attr("defaultInstrumentConfigurationRef", "IC1"),
    }, 0), .run);

    try expectSingleStructuralDiagnostic(diagnostics.items, RuleId.mzml_structure_attribute, "ID attribute must be an XML NCName");

    diagnostics.clearRetainingCapacity();
    _ = try validator.validateAttributes(test_events.startInterned("run", &.{
        test_events.attr("id", "run-1"),
        test_events.attr("defaultInstrumentConfigurationRef", ""),
    }, 0), .run);

    try expectSingleStructuralDiagnostic(diagnostics.items, RuleId.mzml_ref_empty, "reference value is empty");

    diagnostics.clearRetainingCapacity();
    _ = try validator.validateAttributes(test_events.startInterned("cvList", &.{test_events.attr("count", "")}, 0), .cvList);

    try expectSingleStructuralDiagnostic(diagnostics.items, RuleId.mzml_structure_count, "cvList count attribute must be a non-negative integer");
}

test "[unit]: structural numeric attribute lexical forms cover boundaries" {
    var max_usize_buffer: [32]u8 = undefined;
    const max_usize = try std.fmt.bufPrint(&max_usize_buffer, "{d}", .{std.math.maxInt(usize)});

    try std.testing.expectEqual(@as(?usize, 0), parseNonNegativeInteger("0"));
    try std.testing.expectEqual(@as(?usize, 0), parseNonNegativeInteger(" +0 "));
    try std.testing.expectEqual(std.math.maxInt(usize), parseNonNegativeInteger(max_usize).?);
    try std.testing.expectEqual(@as(?usize, null), parseNonNegativeInteger("-1"));
    try std.testing.expectEqual(@as(?usize, null), parseNonNegativeInteger("1.0"));
    try std.testing.expectEqual(@as(?usize, null), parseNonNegativeInteger("9999999999999999999999999999999999999999"));

    try std.testing.expectEqual(@as(?i32, std.math.minInt(i32)), parseSchemaInt("-2147483648"));
    try std.testing.expectEqual(@as(?i32, std.math.maxInt(i32)), parseSchemaInt("+2147483647"));
    try std.testing.expectEqual(@as(?i32, null), parseSchemaInt("-2147483649"));
    try std.testing.expectEqual(@as(?i32, null), parseSchemaInt("2147483648"));
    try std.testing.expectEqual(@as(?i32, null), parseSchemaInt("1e2"));
}

test "[unit]: structural ID reference and spectrum lexical forms are exact" {
    try std.testing.expect(isNcName(" valid_id-1 "));
    try std.testing.expect(isNcName("\u{03b1}name"));
    try std.testing.expect(!isNcName(""));
    try std.testing.expect(!isNcName("1invalid"));
    try std.testing.expect(!isNcName("prefix:name"));

    try std.testing.expect(isSpectrumId("scan=1"));
    try std.testing.expect(isSpectrumId("controllerType=0 controllerNumber=1 scan=2"));
    try std.testing.expect(!isSpectrumId("scan="));
    try std.testing.expect(!isSpectrumId("scan=1  index=2"));
    try std.testing.expect(!isSpectrumId(" scan=1"));
    try std.testing.expect(!isSpectrumId("scan=1\tindex=2"));
}

test "[unit]: structural date and floating attribute lexical forms are exact" {
    try std.testing.expect(isSchemaDouble("0"));
    try std.testing.expect(isSchemaDouble("-.5E+2"));
    try std.testing.expect(isSchemaDouble("INF"));
    try std.testing.expect(isSchemaDouble("-INF"));
    try std.testing.expect(isSchemaDouble("NaN"));
    try std.testing.expect(!isSchemaDouble("+INF"));
    try std.testing.expect(!isSchemaDouble("."));
    try std.testing.expect(!isSchemaDouble("1e"));

    try std.testing.expect(isSchemaDateTime("2000-02-29T24:00:00Z"));
    try std.testing.expect(isSchemaDateTime("2026-07-18T12:34:56.125-07:00"));
    try std.testing.expect(isSchemaDateTime("-0001-01-01T00:00:00+14:00"));
    try std.testing.expect(!isSchemaDateTime("0000-01-01T00:00:00Z"));
    try std.testing.expect(!isSchemaDateTime("02026-01-01T00:00:00Z"));
    try std.testing.expect(!isSchemaDateTime("2023-02-29T00:00:00Z"));
    try std.testing.expect(!isSchemaDateTime("2026-01-01T24:00:00.1Z"));
    try std.testing.expect(!isSchemaDateTime("2026-01-01T00:00:00+14:01"));
}

test "[unit]: structural validator accepts only XML Schema boolean nil values" {
    const allocator = std.testing.allocator;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var validator = StructuralValidator.init(allocator, &diagnostics, null);
    defer validator.deinit();

    const true_nil = Attribute{
        .byte_offset = 5,
        .name = .{ .prefix = "xsi", .local_name = "nil", .namespace_uri = xml_schema_instance_namespace },
        .value = "1",
    };
    const nilled = try validator.validateAttributes(test_events.startInterned("indexListOffset", &.{true_nil}, 0), .indexListOffset);

    try std.testing.expect(nilled);
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);

    const invalid_nil = Attribute{
        .byte_offset = 5,
        .name = .{ .prefix = "xsi", .local_name = "nil", .namespace_uri = xml_schema_instance_namespace },
        .value = "yes",
    };
    _ = try validator.validateAttributes(test_events.startInterned("indexListOffset", &.{invalid_nil}, 0), .indexListOffset);

    try expectSingleStructuralDiagnostic(diagnostics.items, RuleId.mzml_structure_attribute, "xsi:nil must be true, false, 1, or 0");
}

test "structural validator repeated clean and broken runs do not accumulate diagnostics" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const clean_fixture = try readFixtureAlloc(allocator, io, "fixtures/examples/mzml/single-spectrum-missing-cv-terms.mzML");
    defer allocator.free(clean_fixture);
    const broken_fixture = try readFixtureAlloc(allocator, io, "fixtures/examples/mzml/wrong-namespace.mzML");
    defer allocator.free(broken_fixture);

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    for (0..24) |index| {
        const fixture = if (index % 2 == 0) clean_fixture else broken_fixture;
        try runStructuralValidationInto(allocator, io, fixture, &diagnostics);

        if (index % 2 == 0) {
            try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
        } else {
            try expectSingleStructuralDiagnostic(diagnostics.items, RuleId.mzml_structure_root, null);
        }
    }
}

test "structural validator propagates diagnostic allocation failure" {
    var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(std.testing.allocator);

    var validator = StructuralValidator.init(failing_allocator.allocator(), &diagnostics, "fixture");
    defer validator.deinit();

    try std.testing.expectError(error.OutOfMemory, validator.countError(0, "count mismatch"));
}

const test_events = @import("test_events.zig");
