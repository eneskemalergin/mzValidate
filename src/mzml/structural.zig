//! One-pass Phase 1 structural validation for mzML documents.

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

/// Namespace matched by the streaming mzML validators.
pub const mzml_namespace = "http://psi.hupo.org/ms/mzml";
const max_structural_token_bytes = 1024 * 1024;

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
    // Index and checksum elements are optional and appear after run.
    // They are validated at the structural level only for ordering and duplication;
    // deep index cross-checks live in the IndexValidator (index.zig).
    index_list = 10,
    index_list_offset = 11,
    file_checksum = 12,
};

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
    kind: ContainerKind,
    has_binary_data_array_list: bool = false,
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

pub const StructuralValidator = struct {
    allocator: std.mem.Allocator,
    diagnostics: *std.ArrayList(Diagnostic),
    path: ?[]const u8,

    // Structural validation retains only the current nesting depth, top-level ordering,
    // and active local container/list state needed to validate the current branch.
    // Completed spectra and chromatograms are discarded as soon as their end element is seen.
    depth: usize = 0,
    root_seen: bool = false,
    root_valid: bool = false,
    root_byte_offset: u64 = 0,
    indexed_mzml_depth: ?usize = null,
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
    /// Bitmask of TopLevelSlot values whose duplicate diagnostic has already
    /// been emitted.  Prevents N duplicates from producing N-1 error messages.
    dup_reported_mask: u32 = 0,

    run_seen: bool = false,
    run_depth: ?usize = null,
    run_byte_offset: ?u64 = null,
    run_has_spectrum_list: bool = false,
    run_has_chromatogram_list: bool = false,
    run_last_child_slot: u8 = 0,

    // Index and checksum elements (optional, post-run top-level children of mzML).
    index_list_seen: bool = false,
    index_list_offset_seen: bool = false,
    file_checksum_seen: bool = false,

    file_description: ?FileDescriptionState = null,

    cv_list: ?ListCountState = null,
    referenceable_param_group_list: ?ListCountState = null,
    sample_list: ?ListCountState = null,
    software_list: ?ListCountState = null,
    scan_settings_list: ?ListCountState = null,
    instrument_configuration_list: ?ListCountState = null,
    data_processing_list: ?ListCountState = null,
    source_file_list: ?ListCountState = null,
    component_list: ?ComponentListState = null,

    instrument_configuration: ?InstrumentConfigurationState = null,
    data_processing: ?DataProcessingState = null,

    spectrum_list_depth: ?usize = null,
    chromatogram_list_depth: ?usize = null,
    spectrum_list: ?ListCountState = null,
    chromatogram_list: ?ListCountState = null,
    scan_list: ?ListCountState = null,
    binary_data_array_list: ?ListCountState = null,

    spectrum: ?ContainerState = null,
    chromatogram: ?ContainerState = null,

    /// Creates a validator that appends structural diagnostics to the shared list.
    pub fn init(
        allocator: std.mem.Allocator,
        diagnostics: *std.ArrayList(Diagnostic),
        path: ?[]const u8,
    ) StructuralValidator {
        return .{
            .allocator = allocator,
            .diagnostics = diagnostics,
            .path = path,
        };
    }

    /// Structural validation does not own long-lived allocations today.
    pub fn deinit(validator: *StructuralValidator) void {
        _ = validator;
    }

    /// Runs the standalone structural validator over a reader-backed XML stream.
    pub fn validateReader(
        allocator: std.mem.Allocator,
        io: std.Io,
        reader: *std.Io.Reader,
        diagnostics: *std.ArrayList(Diagnostic),
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
        try validator.run(io, &parser);
    }

    /// Consumes one start-element event from the shared XML traversal.
    pub fn consumeStart(validator: *StructuralValidator, start: StartElement) !void {
        const element_depth = validator.depth + 1;
        try validator.handleStart(start, element_depth);
        validator.depth += 1;
    }

    /// Consumes one end-element event from the shared XML traversal.
    pub fn consumeEnd(validator: *StructuralValidator, end: EndElement) !void {
        const element_depth = validator.depth;
        try validator.handleEnd(end, element_depth);
        validator.depth -= 1;
    }

    /// Consumes one text event from the shared XML traversal.
    pub fn consumeText(validator: *StructuralValidator, text: xml_events.Text) !void {
        try validator.handleText(text.value, text.byte_offset);
    }

    /// Emits any root or container diagnostics that can only be decided at end of stream.
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
                .start_element => |start| try validator.consumeStart(start),
                .end_element => |end| try validator.consumeEnd(end),
                .text => |text| try validator.consumeText(text),
            }
        }
        try validator.finish();
    }

    fn handleStart(validator: *StructuralValidator, start: StartElement, element_depth: usize) !void {
        if (!validator.root_seen) {
            validator.root_seen = true;
            validator.root_byte_offset = start.byte_offset;
            if (start.name.matches(mzml_namespace, "indexedmzML")) {
                validator.indexed_mzml_depth = element_depth;
                return;
            }

            validator.root_valid = start.name.matches(mzml_namespace, "mzML");
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
                try validator.requireAttribute(start, "version", "mzML is missing required attribute version");
            }
            return;
        }

        if (!validator.root_valid and validator.indexed_mzml_depth != null and start.name.matches(mzml_namespace, "mzML")) {
            if (element_depth != validator.indexed_mzml_depth.? + 1) {
                try validator.nestingError(start.byte_offset, "mzML must be a direct child of indexedmzML");
                return;
            }
            validator.root_valid = true;
            validator.root_byte_offset = start.byte_offset;
            validator.mzml_depth = element_depth;
            try validator.requireAttribute(start, "version", "mzML is missing required attribute version");
            return;
        }

        if (!validator.isWithinMzmlStartScope()) return;

        if (start.name.matches(mzml_namespace, "cvList")) {
            try validator.recordTopLevelElement(start.byte_offset, element_depth, &validator.cv_list_seen, "cvList", .cv_list);
            try validator.requireAttribute(start, "count", "cvList is missing required attribute count");
            validator.cv_list = validator.initListCountState(start, element_depth, "cvList", "cv", 1);
            return;
        }

        if (start.name.matches(mzml_namespace, "fileDescription")) {
            try validator.recordTopLevelElement(start.byte_offset, element_depth, &validator.file_description_seen, "fileDescription", .file_description);
            validator.file_description = .{ .byte_offset = start.byte_offset, .depth = element_depth };
            return;
        }

        if (start.name.matches(mzml_namespace, "referenceableParamGroupList")) {
            try validator.recordTopLevelElement(start.byte_offset, element_depth, &validator.referenceable_param_group_list_seen, "referenceableParamGroupList", .referenceable_param_group_list);
            try validator.requireAttribute(start, "count", "referenceableParamGroupList is missing required attribute count");
            validator.referenceable_param_group_list = validator.initListCountState(start, element_depth, "referenceableParamGroupList", "referenceableParamGroup", 1);
            return;
        }

        if (start.name.matches(mzml_namespace, "sampleList")) {
            try validator.recordTopLevelElement(start.byte_offset, element_depth, &validator.sample_list_seen, "sampleList", .sample_list);
            try validator.requireAttribute(start, "count", "sampleList is missing required attribute count");
            validator.sample_list = validator.initListCountState(start, element_depth, "sampleList", "sample", 1);
            return;
        }

        if (start.name.matches(mzml_namespace, "softwareList")) {
            try validator.recordTopLevelElement(start.byte_offset, element_depth, &validator.software_list_seen, "softwareList", .software_list);
            try validator.requireAttribute(start, "count", "softwareList is missing required attribute count");
            validator.software_list = validator.initListCountState(start, element_depth, "softwareList", "software", 1);
            return;
        }

        if (start.name.matches(mzml_namespace, "scanSettingsList")) {
            try validator.recordTopLevelElement(start.byte_offset, element_depth, &validator.scan_settings_list_seen, "scanSettingsList", .scan_settings_list);
            try validator.requireAttribute(start, "count", "scanSettingsList is missing required attribute count");
            validator.scan_settings_list = validator.initListCountState(start, element_depth, "scanSettingsList", "scanSettings", 1);
            return;
        }

        if (start.name.matches(mzml_namespace, "instrumentConfigurationList")) {
            try validator.recordTopLevelElement(start.byte_offset, element_depth, &validator.instrument_configuration_list_seen, "instrumentConfigurationList", .instrument_configuration_list);
            try validator.requireAttribute(start, "count", "instrumentConfigurationList is missing required attribute count");
            validator.instrument_configuration_list = validator.initListCountState(start, element_depth, "instrumentConfigurationList", "instrumentConfiguration", 1);
            return;
        }

        if (start.name.matches(mzml_namespace, "dataProcessingList")) {
            try validator.recordTopLevelElement(start.byte_offset, element_depth, &validator.data_processing_list_seen, "dataProcessingList", .data_processing_list);
            try validator.requireAttribute(start, "count", "dataProcessingList is missing required attribute count");
            validator.data_processing_list = validator.initListCountState(start, element_depth, "dataProcessingList", "dataProcessing", 1);
            return;
        }

        if (start.name.matches(mzml_namespace, "run")) {
            if (element_depth != validator.topLevelChildDepth()) {
                try validator.nestingError(start.byte_offset, "run must be a direct child of mzML");
                return;
            }
            try validator.recordTopLevelElement(start.byte_offset, element_depth, &validator.run_seen, "run", .run);
            validator.run_seen = true;
            validator.run_depth = element_depth;
            validator.run_byte_offset = start.byte_offset;
            validator.run_has_spectrum_list = false;
            validator.run_has_chromatogram_list = false;
            validator.run_last_child_slot = 0;
            try validator.requireAttribute(start, "id", "run is missing required attribute id");
            try validator.requireAttribute(start, "defaultInstrumentConfigurationRef", "run is missing required attribute defaultInstrumentConfigurationRef");
            return;
        }

        // Index and checksum elements. These are optional post-run top-level children.
        // They must appear after <run> and follow their own ordering:
        //   indexList → indexListOffset → fileChecksum
        // Deep index content validation is done by IndexValidator (index.zig).

        if (start.name.matches(mzml_namespace, "indexList")) {
            if (!validator.run_seen) {
                try validator.nestingError(start.byte_offset, "indexList must appear after run");
                return;
            }
            try validator.recordTopLevelElement(start.byte_offset, element_depth, &validator.index_list_seen, "indexList", .index_list);
            try validator.requireAttribute(start, "count", "indexList is missing required attribute count");
            return;
        }

        if (start.name.matches(mzml_namespace, "indexListOffset")) {
            if (!validator.run_seen) {
                try validator.nestingError(start.byte_offset, "indexListOffset must appear after run");
                return;
            }
            try validator.recordTopLevelElement(start.byte_offset, element_depth, &validator.index_list_offset_seen, "indexListOffset", .index_list_offset);
            return;
        }

        if (start.name.matches(mzml_namespace, "fileChecksum")) {
            if (!validator.run_seen) {
                try validator.nestingError(start.byte_offset, "fileChecksum must appear after run");
                return;
            }
            try validator.recordTopLevelElement(start.byte_offset, element_depth, &validator.file_checksum_seen, "fileChecksum", .file_checksum);
            return;
        }

        if (start.name.matches(mzml_namespace, "fileContent")) {
            if (validator.file_description) |*state| {
                if (state.depth + 1 != element_depth) {
                    try validator.nestingError(start.byte_offset, "fileContent must be a direct child of fileDescription");
                } else {
                    if (state.has_file_content) {
                        try validator.nestingError(start.byte_offset, "fileDescription must not contain more than one fileContent");
                        return;
                    }
                    if (state.source_file_list_seen) {
                        try validator.nestingError(start.byte_offset, "fileContent appears out of order under fileDescription");
                        return;
                    }
                    state.has_file_content = true;
                }
            }
            return;
        }

        if (start.name.matches(mzml_namespace, "sourceFileList")) {
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
                }
            }
            try validator.requireAttribute(start, "count", "sourceFileList is missing required attribute count");
            validator.source_file_list = validator.initListCountState(start, element_depth, "sourceFileList", "sourceFile", 1);
            return;
        }

        if (start.name.matches(mzml_namespace, "sourceFile")) {
            validator.bumpListItemCount(&validator.source_file_list, element_depth);
            try validator.requireAttribute(start, "id", "sourceFile is missing required attribute id");
            try validator.requireAttribute(start, "name", "sourceFile is missing required attribute name");
            try validator.requireAttribute(start, "location", "sourceFile is missing required attribute location");
            return;
        }

        if (start.name.matches(mzml_namespace, "spectrumList")) {
            try validator.noteRunChild(start.byte_offset, .spectrum_list);
            if (validator.run_depth != element_depth - 1) {
                try validator.nestingError(start.byte_offset, "spectrumList must be a child of run");
            } else {
                validator.run_has_spectrum_list = true;
            }
            validator.spectrum_list_depth = element_depth;
            try validator.requireAttribute(start, "count", "spectrumList is missing required attribute count");
            try validator.requireAttribute(start, "defaultDataProcessingRef", "spectrumList is missing required attribute defaultDataProcessingRef");
            validator.spectrum_list = validator.initListCountState(start, element_depth, "spectrumList", "spectrum", 0);
            return;
        }

        if (start.name.matches(mzml_namespace, "chromatogramList")) {
            try validator.noteRunChild(start.byte_offset, .chromatogram_list);
            if (validator.run_depth != element_depth - 1) {
                try validator.nestingError(start.byte_offset, "chromatogramList must be a child of run");
            } else {
                validator.run_has_chromatogram_list = true;
            }
            validator.chromatogram_list_depth = element_depth;
            try validator.requireAttribute(start, "count", "chromatogramList is missing required attribute count");
            try validator.requireAttribute(start, "defaultDataProcessingRef", "chromatogramList is missing required attribute defaultDataProcessingRef");
            validator.chromatogram_list = validator.initListCountState(start, element_depth, "chromatogramList", "chromatogram", 1);
            return;
        }

        if (start.name.matches(mzml_namespace, "spectrum")) {
            validator.bumpListItemCount(&validator.spectrum_list, element_depth);
            if (validator.spectrum_list_depth != element_depth - 1) {
                try validator.nestingError(start.byte_offset, "spectrum must be a child of spectrumList");
            }
            validator.spectrum = .{ .byte_offset = start.byte_offset, .depth = element_depth, .kind = .spectrum };
            try validator.requireSpectrumLikeAttributes(start, .spectrum);
            return;
        }

        if (start.name.matches(mzml_namespace, "chromatogram")) {
            validator.bumpListItemCount(&validator.chromatogram_list, element_depth);
            if (validator.chromatogram_list_depth != element_depth - 1) {
                try validator.nestingError(start.byte_offset, "chromatogram must be a child of chromatogramList");
            }
            validator.chromatogram = .{ .byte_offset = start.byte_offset, .depth = element_depth, .kind = .chromatogram };
            try validator.requireSpectrumLikeAttributes(start, .chromatogram);
            return;
        }

        if (start.name.matches(mzml_namespace, "cv")) {
            validator.bumpListItemCount(&validator.cv_list, element_depth);
            try validator.requireAttribute(start, "id", "cv is missing required attribute id");
            try validator.requireAttribute(start, "fullName", "cv is missing required attribute fullName");
            try validator.requireAttribute(start, "URI", "cv is missing required attribute URI");
            return;
        }

        if (start.name.matches(mzml_namespace, "referenceableParamGroup")) {
            validator.bumpListItemCount(&validator.referenceable_param_group_list, element_depth);
            try validator.requireAttribute(start, "id", "referenceableParamGroup is missing required attribute id");
            return;
        }

        if (start.name.matches(mzml_namespace, "sample")) {
            validator.bumpListItemCount(&validator.sample_list, element_depth);
            try validator.requireAttribute(start, "id", "sample is missing required attribute id");
            return;
        }

        if (start.name.matches(mzml_namespace, "software")) {
            validator.bumpListItemCount(&validator.software_list, element_depth);
            try validator.requireAttribute(start, "id", "software is missing required attribute id");
            try validator.requireAttribute(start, "version", "software is missing required attribute version");
            return;
        }

        if (start.name.matches(mzml_namespace, "scanSettings")) {
            validator.bumpListItemCount(&validator.scan_settings_list, element_depth);
            try validator.requireAttribute(start, "id", "scanSettings is missing required attribute id");
            return;
        }

        if (start.name.matches(mzml_namespace, "instrumentConfiguration")) {
            validator.bumpListItemCount(&validator.instrument_configuration_list, element_depth);
            try validator.requireAttribute(start, "id", "instrumentConfiguration is missing required attribute id");
            validator.instrument_configuration = .{ .byte_offset = start.byte_offset, .depth = element_depth };
            return;
        }

        if (start.name.matches(mzml_namespace, "componentList")) {
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
            try validator.requireAttribute(start, "count", "componentList is missing required attribute count");
            const count_state = validator.initListCountState(start, element_depth, "componentList", "component", 3);
            if (count_state) |active| {
                validator.component_list = .{ .count_state = active };
            } else {
                validator.component_list = null;
            }
            return;
        }

        if (start.name.matches(mzml_namespace, "softwareRef")) {
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
            try validator.requireAttribute(start, "ref", "softwareRef is missing required attribute ref");
            return;
        }

        if (start.name.matches(mzml_namespace, "source")) {
            try validator.noteComponentChild(start.byte_offset, .source);
            try validator.requireAttribute(start, "order", "source is missing required attribute order");
            return;
        }

        if (start.name.matches(mzml_namespace, "analyzer")) {
            try validator.noteComponentChild(start.byte_offset, .analyzer);
            try validator.requireAttribute(start, "order", "analyzer is missing required attribute order");
            return;
        }

        if (start.name.matches(mzml_namespace, "detector")) {
            try validator.noteComponentChild(start.byte_offset, .detector);
            try validator.requireAttribute(start, "order", "detector is missing required attribute order");
            return;
        }

        if (start.name.matches(mzml_namespace, "dataProcessing")) {
            validator.bumpListItemCount(&validator.data_processing_list, element_depth);
            try validator.requireAttribute(start, "id", "dataProcessing is missing required attribute id");
            validator.data_processing = .{ .byte_offset = start.byte_offset, .depth = element_depth };
            return;
        }

        if (start.name.matches(mzml_namespace, "processingMethod")) {
            if (validator.data_processing) |*state| {
                if (state.depth + 1 != element_depth) {
                    try validator.nestingError(start.byte_offset, "processingMethod must be a direct child of dataProcessing");
                } else {
                    state.processing_method_seen = true;
                }
            }
            try validator.requireAttribute(start, "order", "processingMethod is missing required attribute order");
            try validator.requireAttribute(start, "softwareRef", "processingMethod is missing required attribute softwareRef");
            return;
        }

        if (start.name.matches(mzml_namespace, "scanList")) {
            if (validator.spectrum == null) {
                try validator.nestingError(start.byte_offset, "scanList must be a child of spectrum");
            }
            try validator.noteSpectrumChild(start.byte_offset, .scan_list);
            try validator.requireAttribute(start, "count", "scanList is missing required attribute count");
            validator.scan_list = validator.initListCountState(start, element_depth, "scanList", "scan", 1);
            return;
        }

        if (start.name.matches(mzml_namespace, "precursorList")) {
            if (validator.spectrum == null) {
                try validator.nestingError(start.byte_offset, "precursorList must be a child of spectrum");
            }
            try validator.noteSpectrumChild(start.byte_offset, .precursor_list);
            try validator.requireAttribute(start, "count", "precursorList is missing required attribute count");
            return;
        }

        if (start.name.matches(mzml_namespace, "productList")) {
            if (validator.spectrum == null) {
                try validator.nestingError(start.byte_offset, "productList must be a child of spectrum");
            }
            try validator.noteSpectrumChild(start.byte_offset, .product_list);
            try validator.requireAttribute(start, "count", "productList is missing required attribute count");
            return;
        }

        if (start.name.matches(mzml_namespace, "precursor")) {
            if (validator.chromatogram) |state| {
                if (state.depth + 1 == element_depth) {
                    try validator.noteChromatogramChild(start.byte_offset, .precursor);
                }
                return;
            }
            if (validator.spectrum != null) {
                return;
            }
            {
                try validator.nestingError(start.byte_offset, "precursor must be a child of chromatogram");
                return;
            }
        }

        if (start.name.matches(mzml_namespace, "product")) {
            if (validator.chromatogram) |state| {
                if (state.depth + 1 == element_depth) {
                    try validator.noteChromatogramChild(start.byte_offset, .product);
                }
                return;
            }
            if (validator.spectrum != null) {
                return;
            }
            {
                try validator.nestingError(start.byte_offset, "product must be a child of chromatogram");
                return;
            }
        }

        if (start.name.matches(mzml_namespace, "scan")) {
            validator.bumpListItemCount(&validator.scan_list, element_depth);
            return;
        }

        if (start.name.matches(mzml_namespace, "binaryDataArrayList")) {
            try validator.noteBinaryDataArrayListChild(start.byte_offset);
            try validator.requireAttribute(start, "count", "binaryDataArrayList is missing required attribute count");
            validator.binary_data_array_list = validator.initListCountState(start, element_depth, "binaryDataArrayList", "binaryDataArray", 2);

            if (validator.spectrum != null and validator.spectrum_list_depth != null and validator.spectrum_list_depth.? < element_depth) {
                validator.spectrum.?.has_binary_data_array_list = true;
                return;
            }
            if (validator.chromatogram != null and validator.chromatogram_list_depth != null and validator.chromatogram_list_depth.? < element_depth) {
                validator.chromatogram.?.has_binary_data_array_list = true;
                return;
            }

            try validator.nestingError(start.byte_offset, "binaryDataArrayList must be a child of spectrum or chromatogram");
            return;
        }

        if (start.name.matches(mzml_namespace, "binaryDataArray")) {
            validator.bumpListItemCount(&validator.binary_data_array_list, element_depth);
        }
    }

    fn handleEnd(validator: *StructuralValidator, end: EndElement, element_depth: usize) !void {
        if (!validator.isWithinMzmlEndScope(element_depth)) return;

        if (end.name.matches(mzml_namespace, "mzML") and validator.mzml_depth == element_depth) {
            validator.mzml_depth = null;
            return;
        }

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

        if (end.name.matches(mzml_namespace, "fileDescription")) {
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
            return;
        }

        if (end.name.matches(mzml_namespace, "cvList")) {
            try validator.finishListCount(&validator.cv_list, element_depth);
            return;
        }

        if (end.name.matches(mzml_namespace, "sourceFileList")) {
            try validator.finishListCount(&validator.source_file_list, element_depth);
            return;
        }

        if (end.name.matches(mzml_namespace, "referenceableParamGroupList")) {
            try validator.finishListCount(&validator.referenceable_param_group_list, element_depth);
            return;
        }

        if (end.name.matches(mzml_namespace, "sampleList")) {
            try validator.finishListCount(&validator.sample_list, element_depth);
            return;
        }

        if (end.name.matches(mzml_namespace, "softwareList")) {
            try validator.finishListCount(&validator.software_list, element_depth);
            return;
        }

        if (end.name.matches(mzml_namespace, "scanSettingsList")) {
            try validator.finishListCount(&validator.scan_settings_list, element_depth);
            return;
        }

        if (end.name.matches(mzml_namespace, "instrumentConfigurationList")) {
            try validator.finishListCount(&validator.instrument_configuration_list, element_depth);
            return;
        }

        if (end.name.matches(mzml_namespace, "componentList")) {
            try validator.finishComponentList(element_depth);
            return;
        }

        if (end.name.matches(mzml_namespace, "instrumentConfiguration")) {
            validator.instrument_configuration = null;
            return;
        }

        if (end.name.matches(mzml_namespace, "dataProcessingList")) {
            try validator.finishListCount(&validator.data_processing_list, element_depth);
            return;
        }

        if (end.name.matches(mzml_namespace, "dataProcessing")) {
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
            return;
        }

        if (end.name.matches(mzml_namespace, "spectrumList") and validator.spectrum_list_depth == element_depth) {
            try validator.finishListCount(&validator.spectrum_list, element_depth);
            validator.spectrum_list_depth = null;
            return;
        }

        if (end.name.matches(mzml_namespace, "chromatogramList") and validator.chromatogram_list_depth == element_depth) {
            try validator.finishListCount(&validator.chromatogram_list, element_depth);
            validator.chromatogram_list_depth = null;
            return;
        }

        if (end.name.matches(mzml_namespace, "scanList")) {
            try validator.finishListCount(&validator.scan_list, element_depth);
            return;
        }

        if (end.name.matches(mzml_namespace, "binaryDataArrayList")) {
            try validator.finishListCount(&validator.binary_data_array_list, element_depth);
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
            validator.spectrum.?.has_binary_data_array_list = true;
            return;
        }
        if (validator.chromatogram != null) {
            try validator.noteChromatogramChild(byte_offset, .binary_data_array_list);
            validator.chromatogram.?.has_binary_data_array_list = true;
        }
    }

    fn noteComponentChild(validator: *StructuralValidator, byte_offset: u64, slot: ComponentChildSlot) !void {
        if (validator.component_list) |*state| {
            if (state.count_state.depth + 1 != validator.depth + 1) return;

            if (state.last_child_slot > @intFromEnum(slot)) {
                try validator.nestingError(byte_offset, componentChildOutOfOrderMessage(slot));
                return;
            }
            state.last_child_slot = @intFromEnum(slot);
            state.count_state.actual_count += 1;

            switch (slot) {
                .source => state.source_count += 1,
                .analyzer => state.analyzer_count += 1,
                .detector => state.detector_count += 1,
            }
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
    ) ?ListCountState {
        const declared_count = validator.parseCountAttribute(start, label) orelse return null;
        return .{
            .byte_offset = start.byte_offset,
            .depth = element_depth,
            .declared_count = declared_count,
            .min_count = min_count,
            .label = label,
            .child_label = child_label,
        };
    }

    fn parseCountAttribute(validator: *StructuralValidator, start: StartElement, label: []const u8) ?usize {
        const value = attributeValue(start.attributes, "count") orelse return null;
        return std.fmt.parseUnsigned(usize, value, 10) catch {
            validator.countError(start.byte_offset, invalidCountMessage(label)) catch {};
            return null;
        };
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

fn attributeValue(attributes: []const Attribute, local_name: []const u8) ?[]const u8 {
    for (attributes) |attribute| {
        if (attribute.is_namespace_declaration) continue;
        if (std.mem.eql(u8, attribute.name.local_name, local_name)) return attribute.value;
    }
    return null;
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
    return "binaryDataArrayList count attribute must be a non-negative integer";
}

fn countMismatchMessage(active: ListCountState) []const u8 {
    if (std.mem.eql(u8, active.label, "cvList")) return "cvList count does not match actual cv elements";
    if (std.mem.eql(u8, active.label, "sourceFileList")) return "sourceFileList count does not match actual sourceFile elements";
    if (std.mem.eql(u8, active.label, "referenceableParamGroupList")) return "referenceableParamGroupList count does not match actual referenceableParamGroup elements";
    if (std.mem.eql(u8, active.label, "sampleList")) return "sampleList count does not match actual sample elements";
    if (std.mem.eql(u8, active.label, "softwareList")) return "softwareList count does not match actual software elements";
    if (std.mem.eql(u8, active.label, "scanSettingsList")) return "scanSettingsList count does not match actual scanSettings elements";
    if (std.mem.eql(u8, active.label, "instrumentConfigurationList")) return "instrumentConfigurationList count does not match actual instrumentConfiguration elements";
    if (std.mem.eql(u8, active.label, "dataProcessingList")) return "dataProcessingList count does not match actual dataProcessing elements";
    if (std.mem.eql(u8, active.label, "spectrumList")) return "spectrumList count does not match actual spectrum elements";
    if (std.mem.eql(u8, active.label, "chromatogramList")) return "chromatogramList count does not match actual chromatogram elements";
    if (std.mem.eql(u8, active.label, "scanList")) return "scanList count does not match actual scan elements";
    return "binaryDataArrayList count does not match actual binaryDataArray elements";
}

fn minimumCountMessage(active: ListCountState) []const u8 {
    if (std.mem.eql(u8, active.label, "cvList")) return "cvList must contain at least 1 cv element";
    if (std.mem.eql(u8, active.label, "sourceFileList")) return "sourceFileList must contain at least 1 sourceFile element";
    if (std.mem.eql(u8, active.label, "referenceableParamGroupList")) return "referenceableParamGroupList must contain at least 1 referenceableParamGroup element";
    if (std.mem.eql(u8, active.label, "sampleList")) return "sampleList must contain at least 1 sample element";
    if (std.mem.eql(u8, active.label, "softwareList")) return "softwareList must contain at least 1 software element";
    if (std.mem.eql(u8, active.label, "scanSettingsList")) return "scanSettingsList must contain at least 1 scanSettings element";
    if (std.mem.eql(u8, active.label, "instrumentConfigurationList")) return "instrumentConfigurationList must contain at least 1 instrumentConfiguration element";
    if (std.mem.eql(u8, active.label, "dataProcessingList")) return "dataProcessingList must contain at least 1 dataProcessing element";
    if (std.mem.eql(u8, active.label, "chromatogramList")) return "chromatogramList must contain at least 1 chromatogram element";
    if (std.mem.eql(u8, active.label, "scanList")) return "scanList must contain at least 1 scan element";
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

test "structural validator accepts indexed mzML PSI tiny fixture" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try readFixtureAlloc(allocator, io, "fixtures/mzml/valid/tiny.pwiz.1.1.mzML");
    defer allocator.free(fixture);

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "structural validator accepts valid chromatogram fixture" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = minimalChromatogramMzml(
        "<precursor/>" ++
            "<product/>" ++
            "<binaryDataArrayList count=\"2\">" ++
            "<binaryDataArray encodedLength=\"8\"><binary>AAAAAA==</binary></binaryDataArray>" ++
            "<binaryDataArray encodedLength=\"8\"><binary>AAAAAA==</binary></binaryDataArray>" ++
            "</binaryDataArrayList>",
    );

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

// Tests: required children and attributes.

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
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
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
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 3), diagnostics.items.len);
    try std.testing.expectEqualStrings("run is missing required attribute id", diagnostics.items[0].message);
    try std.testing.expectEqualStrings("run is missing required attribute defaultInstrumentConfigurationRef", diagnostics.items[1].message);
    try std.testing.expectEqualStrings("spectrumList is missing required attribute defaultDataProcessingRef", diagnostics.items[2].message);
}

// Tests: ordering and nesting rules.

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
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
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
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
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
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
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
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
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
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
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
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
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
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
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
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
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
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
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
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try std.testing.expectEqual(@as(usize, 2), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_structure_nesting, diagnostics.items[0].rule);
    try std.testing.expectEqualStrings("binaryDataArrayList must be a child of spectrum or chromatogram", diagnostics.items[0].message);
    try std.testing.expectEqualStrings(RuleId.mzml_structure_missing_child, diagnostics.items[1].rule);
    try std.testing.expectEqualStrings("run must contain spectrumList or chromatogramList", diagnostics.items[1].message);
}

test "structural validator reports chromatogram child ordering violations" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = minimalChromatogramMzml(
        "<product/>" ++
            "<precursor/>" ++
            "<binaryDataArrayList count=\"2\">" ++
            "<binaryDataArray encodedLength=\"8\"><binary>AAAAAA==</binary></binaryDataArray>" ++
            "<binaryDataArray encodedLength=\"8\"><binary>AAAAAA==</binary></binaryDataArray>" ++
            "</binaryDataArrayList>",
    );

    var reader = std.Io.Reader.fixed(fixture);
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    try StructuralValidator.validateReader(allocator, io, &reader, &diagnostics, "fixture");
    try expectSingleStructuralDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_nesting,
        "precursor appears out of order under chromatogram",
    );
}

test "structural validator repeated clean and broken runs do not accumulate diagnostics" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    const clean_fixture = try readFixtureAlloc(allocator, io, "fixtures/examples/mzml/clean-single-spectrum.mzML");
    defer allocator.free(clean_fixture);
    const broken_fixture = try readFixtureAlloc(allocator, io, "fixtures/examples/mzml/wrong-namespace.mzML");
    defer allocator.free(broken_fixture);

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    for (0..24) |index| {
        const fixture = if (index % 2 == 0) clean_fixture else broken_fixture;
        try runStructuralValidationInto(allocator, io, fixture, &diagnostics);

        // Assert.
        if (index % 2 == 0) {
            try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
        } else {
            try expectSingleStructuralDiagnostic(diagnostics.items, RuleId.mzml_structure_root, null);
        }
    }
}

fn runStructuralValidationInto(
    allocator: std.mem.Allocator,
    io: std.Io,
    fixture: []const u8,
    diagnostics: *std.ArrayList(Diagnostic),
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
