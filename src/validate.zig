//! Entry points for running validation against files or streams.
//!
//! Three I/O paths:
//!   checkPath                  -> explicit mmap or bounded stream, selected by options.
//!   checkSlice                 -> caller provides contiguous bytes, slice parser.
//!   checkReader                -> caller provides a stream, reader parser.
//!
//! All validators (structural, binary, index, semantic) run in one
//! forward pass over the event stream. Validator-owned state is bounded per
//! phase: parser buffers, one active binary workspace, index tables, and the
//! semantic CV/ref tracker. A path never falls back to a file-sized heap buffer.

const std = @import("std");
const binary = @import("mzml/binary.zig");
const diagnostic = @import("diagnostic.zig");
const elements = @import("mzml/elements.zig");
const mzml_index = @import("mzml/index.zig");
const obo_parser = @import("obo/parser.zig");
const rule_engine = @import("obo/rule_engine.zig");
const semantic = @import("mzml/semantic.zig");
const structural = @import("mzml/structural.zig");
const xml_events = @import("xml/events.zig");
const xml_parser = @import("xml/parser.zig");
const xml_parse_errors = @import("xml/parse_errors.zig");

const Attribute = xml_events.Attribute;
const Diagnostic = diagnostic.Diagnostic;
const DiagnosticSink = diagnostic.DiagnosticSink;
const FailureReason = diagnostic.FailureReason;
const FileResult = diagnostic.FileResult;
const RuleId = diagnostic.RuleId;
const ValidationStage = diagnostic.ValidationStage;
const max_validation_token_bytes = 1024 * 1024;
const stream_input_buffer_bytes = 64 * 1024;

// --- Public entry points ---

/// Requested input source mode. Mmap requires a stable regular file.
pub const InputMode = enum {
    stream,
    mmap,
};

/// Per-run flags for `checkPath`, `checkSlice`, and `checkReader`.
pub const CheckOptions = struct {
    skip_binary: bool = false,
    skip_index: bool = false,
    skip_semantic: bool = false,
    input_mode: InputMode = .mmap,
    memory_limit: ?usize = null,
    mmap: bool = false,
    max_binary_size: ?usize = null,
    resource_limits: diagnostic.ResourceLimits = .{},
    obo_path: ?[]const u8 = null,
};

const CatalogFailure = struct {
    reason: FailureReason,
    rule: []const u8,
    message: []const u8,
};

const SemanticCatalog = struct {
    cv_table: obo_parser.CvTable,
    rule_engine: rule_engine.RuleEngine,

    fn deinit(catalog: *SemanticCatalog) void {
        catalog.rule_engine.deinit();
        catalog.cv_table.deinit();
    }
};

/// Invocation-owned immutable options and semantic resources.
pub const InvocationContext = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    options: CheckOptions,
    catalog: ?SemanticCatalog = null,
    catalog_failure: ?CatalogFailure = null,

    /// Builds the semantic catalog once. A catalog failure is retained as fixed
    /// metadata so file validation can stop before opening an input.
    pub fn init(allocator: std.mem.Allocator, io: std.Io, options: CheckOptions) InvocationContext {
        var context = InvocationContext{
            .allocator = allocator,
            .io = io,
            .options = options,
        };
        if (!options.skip_semantic) context.buildCatalog();
        return context;
    }

    pub fn deinit(context: *InvocationContext) void {
        if (context.catalog) |*catalog| catalog.deinit();
        context.* = undefined;
    }

    /// Validates one path using this invocation's immutable resources.
    pub fn validateOne(
        context: *InvocationContext,
        diagnostics: *DiagnosticSink,
        path: []const u8,
    ) FileResult {
        diagnostics.configureFromResourceLimits(context.options.resource_limits);
        if (context.catalog_failure != null) return context.catalogFailureResult(diagnostics, path);

        var result = FileResult.init(enabledStages(context.options));
        const diagnostic_mark = diagnostics.mark();
        checkPathInternal(context, diagnostics, path, &result) catch |err| {
            recordUnhandledFailure(&result, err, path);
        };
        result.finalizeSink(diagnostics, diagnostic_mark);
        return result;
    }

    pub fn checkPathResult(
        context: *InvocationContext,
        diagnostics: *DiagnosticSink,
        path: []const u8,
    ) FileResult {
        return context.validateOne(diagnostics, path);
    }

    pub fn checkSliceResult(
        context: *InvocationContext,
        bytes: []const u8,
        diagnostics: *DiagnosticSink,
        path: []const u8,
        file_bytes: ?[]const u8,
    ) FileResult {
        diagnostics.configureFromResourceLimits(context.options.resource_limits);
        if (context.catalog_failure != null) return context.catalogFailureResult(diagnostics, path);

        var result = FileResult.init(enabledStages(context.options));
        const diagnostic_mark = diagnostics.mark();
        result.completeStage(.input);
        runValidation(context, diagnostics, path, file_bytes, .{ .slice = bytes }, &result, null, null) catch |err| {
            recordUnhandledFailure(&result, err, path);
        };
        result.finalizeSink(diagnostics, diagnostic_mark);
        return result;
    }

    pub fn checkReaderResult(
        context: *InvocationContext,
        reader: *std.Io.Reader,
        diagnostics: *DiagnosticSink,
        path: []const u8,
        file_bytes: ?[]const u8,
    ) FileResult {
        diagnostics.configureFromResourceLimits(context.options.resource_limits);
        if (context.catalog_failure != null) return context.catalogFailureResult(diagnostics, path);

        var result = FileResult.init(enabledStages(context.options));
        const diagnostic_mark = diagnostics.mark();
        result.completeStage(.input);
        runValidation(context, diagnostics, path, file_bytes, .{ .reader = reader }, &result, null, null) catch |err| {
            recordUnhandledFailure(&result, err, path);
        };
        result.finalizeSink(diagnostics, diagnostic_mark);
        return result;
    }

    fn buildCatalog(context: *InvocationContext) void {
        const options = context.options;
        const obo_text: ?[]const u8 = if (options.obo_path) |obo_path| blk: {
            const cwd = std.Io.Dir.cwd();
            const text = cwd.readFileAlloc(context.io, obo_path, context.allocator, .limited(50 * 1024 * 1024)) catch |err| {
                context.catalog_failure = .{
                    .reason = if (err == error.OutOfMemory) .allocation else if (err == error.StreamTooLong) .resource else .catalog,
                    .rule = RuleId.runtime_file_open,
                    .message = "unable to read OBO file",
                };
                break :blk null;
            };
            break :blk text;
        } else @embedFile("data/psi-ms.obo");
        const text = obo_text orelse return;
        defer if (options.obo_path != null) context.allocator.free(text);

        var table = obo_parser.CvTable.initWithLimits(context.allocator, text, options.resource_limits) catch |err| {
            context.catalog_failure = .{
                .reason = if (err == error.OutOfMemory) .allocation else .catalog,
                .rule = RuleId.runtime_file_open,
                .message = if (err == error.OutOfMemory) "unable to allocate OBO state" else obo_parser.parseErrorMessage(err),
            };
            return;
        };

        var engine = rule_engine.RuleEngine.init(context.allocator, @embedFile("data/ms-mapping.xml")) catch |err| {
            table.deinit();
            context.catalog_failure = .{
                .reason = if (err == error.OutOfMemory) .allocation else .catalog,
                .rule = RuleId.runtime_file_open,
                .message = if (err == error.OutOfMemory) "unable to allocate mapping state" else "unable to parse mapping rules",
            };
            return;
        };

        if (engine.firstMissingVocabularyTerm(&table) != null) {
            engine.deinit();
            table.deinit();
            context.catalog_failure = .{
                .reason = .catalog,
                .rule = RuleId.runtime_catalog,
                .message = "embedded mapping policy is incompatible with the selected OBO vocabulary",
            };
            return;
        }

        context.catalog = .{ .cv_table = table, .rule_engine = engine };
    }

    fn catalogFailureResult(
        context: *InvocationContext,
        diagnostics: *DiagnosticSink,
        path: []const u8,
    ) FileResult {
        var result = FileResult.init(enabledStages(context.options));
        const diagnostic_mark = diagnostics.mark();
        result.beginStage(.semantic);
        const failure = context.catalog_failure.?;
        appendFailureDiagnostic(
            context.allocator,
            diagnostics,
            &result,
            .semantic,
            failure.reason,
            .{
                .severity = .@"error",
                .rule = failure.rule,
                .path = path,
                .message = failure.message,
            },
        ) catch |err| recordUnhandledFailure(&result, err, path);
        result.finalizeSink(diagnostics, diagnostic_mark);
        return result;
    }
};

/// Returned by legacy `check*` wrappers when no normal diagnostic could be stored.
pub const ValidationError = error{
    ValidationIncomplete,
};

/// Validates an mzML file on disk using the requested input mode.
pub fn checkPath(
    allocator: std.mem.Allocator,
    io: std.Io,
    diagnostics: *DiagnosticSink,
    path: []const u8,
    options: CheckOptions,
) ValidationError!void {
    const result = checkPathResult(allocator, io, diagnostics, path, options);
    if (result.needsEmergencyDiagnostic()) return error.ValidationIncomplete;
}

/// Validates one path and returns completion metadata independent of diagnostics storage.
pub fn checkPathResult(
    allocator: std.mem.Allocator,
    io: std.Io,
    diagnostics: *DiagnosticSink,
    path: []const u8,
    options: CheckOptions,
) FileResult {
    var context = InvocationContext.init(allocator, io, options);
    defer context.deinit();
    return context.validateOne(diagnostics, path);
}

fn checkPathInternal(
    context: *InvocationContext,
    diagnostics: *DiagnosticSink,
    path: []const u8,
    result: *FileResult,
) !void {
    result.beginStage(.input);
    const cwd = std.Io.Dir.cwd();
    const path_stat = cwd.statFile(context.io, path, .{}) catch {
        try appendFailureDiagnostic(
            context.allocator,
            diagnostics,
            result,
            .input,
            .input,
            .{
                .severity = .@"error",
                .rule = RuleId.runtime_file_open,
                .path = path,
                .message = "unable to stat input file",
            },
        );
        return;
    };
    if (path_stat.kind != .file) {
        try appendFailureDiagnostic(
            context.allocator,
            diagnostics,
            result,
            .input,
            .input,
            .{
                .severity = .@"error",
                .rule = RuleId.runtime_file_open,
                .path = path,
                .message = "input path is not a regular file",
            },
        );
        return;
    }
    var file = cwd.openFile(context.io, path, .{}) catch {
        try appendFailureDiagnostic(
            context.allocator,
            diagnostics,
            result,
            .input,
            .input,
            .{
                .severity = .@"error",
                .rule = RuleId.runtime_file_open,
                .path = path,
                .message = "unable to open input file",
            },
        );
        return;
    };
    defer file.close(context.io);

    const opened_stat = file.stat(context.io) catch {
        try appendFailureDiagnostic(
            context.allocator,
            diagnostics,
            result,
            .input,
            .input,
            .{
                .severity = .@"error",
                .rule = RuleId.runtime_file_open,
                .path = path,
                .message = "unable to stat opened input file",
            },
        );
        return;
    };
    if (!sameFileStat(path_stat, opened_stat)) {
        try appendFileStabilityDiagnostic(context, diagnostics, result, path, "input changed before validation started");
        return;
    }

    switch (context.options.input_mode) {
        .mmap => try checkPathMapped(context, file, opened_stat, diagnostics, path, result, std.Io.File.MemoryMap.create),
        .stream => try checkPathStream(context, file, opened_stat, diagnostics, path, result),
    }
}

fn checkPathMapped(
    context: *InvocationContext,
    file: std.Io.File,
    initial_stat: std.Io.File.Stat,
    diagnostics: *DiagnosticSink,
    path: []const u8,
    result: *FileResult,
    comptime map_create: anytype,
) !void {
    const len = std.math.cast(usize, initial_stat.size) orelse {
        try appendFailureDiagnostic(
            context.allocator,
            diagnostics,
            result,
            .input,
            .resource,
            .{
                .severity = .@"error",
                .rule = RuleId.runtime_file_open,
                .path = path,
                .message = "input file is too large for this platform",
            },
        );
        return;
    };

    var mm = map_create(context.io, file, .{
        .len = len,
        .protection = .{ .read = true },
        .populate = false,
    }) catch {
        try appendModeFailureDiagnostic(context, diagnostics, result, path, "requested mmap input mode is unavailable");
        return;
    };
    if (mm.section == null) {
        mm.destroy(context.io);
        try appendModeFailureDiagnostic(context, diagnostics, result, path, "requested mmap input mode is unavailable");
        return;
    }

    var map_destroyed = false;
    defer if (!map_destroyed) mm.destroy(context.io);

    const index_bytes = if (context.options.skip_index) null else mm.memory;
    result.completeStage(.input);
    try runValidation(context, diagnostics, path, index_bytes, .{ .slice = mm.memory }, result, null, null);
    mm.destroy(context.io);
    map_destroyed = true;
    try checkFileStability(context, file, initial_stat, diagnostics, path, result);
}

fn checkPathStream(
    context: *InvocationContext,
    file: std.Io.File,
    initial_stat: std.Io.File.Stat,
    diagnostics: *DiagnosticSink,
    path: []const u8,
    result: *FileResult,
) !void {
    var input_buffer: [stream_input_buffer_bytes]u8 = undefined;
    var file_reader = file.readerStreaming(context.io, &input_buffer);

    result.completeStage(.input);
    try runValidation(context, diagnostics, path, null, .{ .reader = &file_reader.interface }, result, file, initial_stat.size);
    try checkFileStability(context, file, initial_stat, diagnostics, path, result);
}

fn sameFileStat(first: std.Io.File.Stat, second: std.Io.File.Stat) bool {
    return first.kind == second.kind and
        first.inode == second.inode and
        first.size == second.size and
        std.meta.eql(first.mtime, second.mtime) and
        std.meta.eql(first.ctime, second.ctime);
}

fn checkFileStability(
    context: *InvocationContext,
    file: std.Io.File,
    initial_stat: std.Io.File.Stat,
    diagnostics: *DiagnosticSink,
    path: []const u8,
    result: *FileResult,
) !void {
    const final_file_stat = file.stat(context.io) catch {
        try appendFileStabilityDiagnostic(context, diagnostics, result, path, "unable to stat input after validation");
        return;
    };
    const final_path_stat = std.Io.Dir.cwd().statFile(context.io, path, .{}) catch {
        try appendFileStabilityDiagnostic(context, diagnostics, result, path, "unable to stat input path after validation");
        return;
    };
    if (!sameFileStat(initial_stat, final_file_stat) or !sameFileStat(initial_stat, final_path_stat)) {
        try appendFileStabilityDiagnostic(context, diagnostics, result, path, "input file changed during validation");
    }
}

fn appendFileStabilityDiagnostic(
    context: *InvocationContext,
    diagnostics: *DiagnosticSink,
    result: *FileResult,
    path: []const u8,
    message: []const u8,
) !void {
    try appendFailureDiagnostic(
        context.allocator,
        diagnostics,
        result,
        .input,
        .file_stability,
        .{
            .severity = .@"error",
            .rule = RuleId.runtime_file_stability,
            .path = path,
            .message = message,
        },
    );
}

fn appendModeFailureDiagnostic(
    context: *InvocationContext,
    diagnostics: *DiagnosticSink,
    result: *FileResult,
    path: []const u8,
    message: []const u8,
) !void {
    try appendFailureDiagnostic(
        context.allocator,
        diagnostics,
        result,
        .input,
        .input,
        .{
            .severity = .@"error",
            .rule = RuleId.runtime_input_mode,
            .path = path,
            .message = message,
        },
    );
}

// --- Validation core ---

const ParserSource = union(enum) {
    reader: *std.Io.Reader,
    slice: []const u8,
};

/// Validates mzML from a caller-owned contiguous byte slice.
pub fn checkSlice(
    allocator: std.mem.Allocator,
    io: std.Io,
    bytes: []const u8,
    diagnostics: *DiagnosticSink,
    path: []const u8,
    options: CheckOptions,
    file_bytes: ?[]const u8,
) ValidationError!void {
    const result = checkSliceResult(allocator, io, bytes, diagnostics, path, options, file_bytes);
    if (result.needsEmergencyDiagnostic()) return error.ValidationIncomplete;
}

/// Validates a contiguous input and returns completion metadata.
pub fn checkSliceResult(
    allocator: std.mem.Allocator,
    io: std.Io,
    bytes: []const u8,
    diagnostics: *DiagnosticSink,
    path: []const u8,
    options: CheckOptions,
    file_bytes: ?[]const u8,
) FileResult {
    var context = InvocationContext.init(allocator, io, options);
    defer context.deinit();
    return context.checkSliceResult(bytes, diagnostics, path, file_bytes);
}

/// Validates mzML from a streaming `std.Io.Reader` (stdin, pipes).
pub fn checkReader(
    allocator: std.mem.Allocator,
    io: std.Io,
    reader: *std.Io.Reader,
    diagnostics: *DiagnosticSink,
    path: []const u8,
    options: CheckOptions,
    file_bytes: ?[]const u8,
) ValidationError!void {
    const result = checkReaderResult(allocator, io, reader, diagnostics, path, options, file_bytes);
    if (result.needsEmergencyDiagnostic()) return error.ValidationIncomplete;
}

/// Validates a reader input and returns completion metadata.
pub fn checkReaderResult(
    allocator: std.mem.Allocator,
    io: std.Io,
    reader: *std.Io.Reader,
    diagnostics: *DiagnosticSink,
    path: []const u8,
    options: CheckOptions,
    file_bytes: ?[]const u8,
) FileResult {
    var context = InvocationContext.init(allocator, io, options);
    defer context.deinit();
    return context.checkReaderResult(reader, diagnostics, path, file_bytes);
}

fn runValidation(
    context: *InvocationContext,
    diagnostics: *DiagnosticSink,
    path: []const u8,
    file_bytes: ?[]const u8,
    source: ParserSource,
    result: *FileResult,
    stream_file: ?std.Io.File,
    stream_size: ?u64,
) !void {

    // Bounded validator state: parser stacks, structural state, and one
    // binary workspace. The slice source itself may be file-sized.
    result.beginStage(.parser);
    const token_buffer = try context.allocator.alloc(u8, max_validation_token_bytes);
    defer {
        result.resource_usage.parser_current_bytes = token_buffer.len;
        result.resource_usage.parser_peak_bytes = token_buffer.len;
        context.allocator.free(token_buffer);
    }

    var attributes: [64]Attribute = undefined;
    var namespace_bindings: [32]xml_parser.NamespaceBinding = undefined;
    var namespace_bytes: [2048]u8 = undefined;
    var element_stack: [128]xml_parser.ElementFrame = undefined;
    var element_bytes: [4096]u8 = undefined;

    const parser_buffers = xml_parser.Buffers{
        .token = token_buffer,
        .attributes = &attributes,
        .namespace_bindings = &namespace_bindings,
        .namespace_bytes = &namespace_bytes,
        .element_stack = &element_stack,
        .element_bytes = &element_bytes,
    };

    var parser = switch (source) {
        .reader => |reader| xml_parser.Parser.init(reader, parser_buffers),
        .slice => |bytes| xml_parser.Parser.initSlice(bytes, parser_buffers),
    };

    var structural_validator = structural.StructuralValidator.init(context.allocator, diagnostics, path);
    defer structural_validator.deinit();

    var binary_validator = if (context.options.skip_binary) null else binary.BinaryValidator{
        .allocator = context.allocator,
        .diagnostics = diagnostics,
        .path = path,
        .limits = context.options.resource_limits,
        .max_binary_size = context.options.max_binary_size,
    };
    defer if (binary_validator) |*validator| {
        result.resource_usage.binary_scratch_current_bytes = validator.scratch_current_bytes;
        result.resource_usage.binary_scratch_peak_bytes = validator.scratch_peak_bytes;
        validator.deinit();
    };

    var index_validator = if (context.options.skip_index) null else mzml_index.IndexValidator.initWithLimits(context.allocator, diagnostics, path, context.options.resource_limits);
    defer if (index_validator) |*validator| {
        result.resource_usage.index_current_bytes = validator.index_state_current_bytes;
        result.resource_usage.index_peak_bytes = validator.index_state_peak_bytes;
        validator.deinit();
    };
    if (index_validator) |*validator| {
        switch (source) {
            .slice => |bytes| {
                validator.input_size = bytes.len;
            },
            .reader => {},
        }
        if (stream_file) |file| validator.setStreamSource(context.io, file, stream_size orelse return error.InputOutput);
        if (file_bytes) |bytes| validator.beginOnlineSha(bytes);
    }

    var semantic_validator: ?semantic.SemanticValidator = null;
    defer if (semantic_validator) |*v| v.deinit();
    defer if (semantic_validator) |*v| {
        const usage = v.resourceUsage();
        result.resource_usage.semantic_current_bytes = usage.semantic_current_bytes;
        result.resource_usage.semantic_peak_bytes = usage.semantic_peak_bytes;
        result.resource_usage.semantic_declaration_bytes = usage.semantic_declaration_bytes;
        result.resource_usage.semantic_unresolved_bytes = usage.semantic_unresolved_bytes;
        result.resource_usage.semantic_scope_bytes = usage.semantic_scope_bytes;
        result.resource_usage.semantic_param_group_bytes = usage.semantic_param_group_bytes;
        result.resource_usage.semantic_declaration_peak_bytes = usage.semantic_declaration_peak_bytes;
        result.resource_usage.semantic_unresolved_peak_bytes = usage.semantic_unresolved_peak_bytes;
        result.resource_usage.semantic_scope_peak_bytes = usage.semantic_scope_peak_bytes;
        result.resource_usage.semantic_param_group_peak_bytes = usage.semantic_param_group_peak_bytes;
    };
    if (!context.options.skip_semantic) {
        result.beginStage(.semantic);
        if (context.catalog) |*catalog| {
            semantic_validator = semantic.SemanticValidator.initWithLimits(
                context.allocator,
                &catalog.cv_table,
                &catalog.rule_engine,
                diagnostics,
                path,
                context.options.resource_limits,
            );
        } else {
            try appendFailureDiagnostic(
                context.allocator,
                diagnostics,
                result,
                .semantic,
                .catalog,
                .{
                    .severity = .@"error",
                    .rule = RuleId.runtime_catalog,
                    .path = path,
                    .message = "semantic catalog is unavailable",
                },
            );
            return;
        }
    }
    var element_depth: usize = 0;
    const active = elements.activeMask(context.options.skip_binary, context.options.skip_index, context.options.skip_semantic);
    const fuse_index_semantic = index_validator != null or semantic_validator != null;

    while (true) {
        result.beginStage(.parser);
        const maybe_event = parser.next() catch |err| {
            const message = xml_parse_errors.parseErrorMessage(err);
            try appendFailureDiagnostic(
                context.allocator,
                diagnostics,
                result,
                .parser,
                .parser,
                .{
                    .severity = .@"error",
                    .rule = RuleId.mzml_structure_xml,
                    .location = .{ .byte_offset = parser.byteOffset() },
                    .path = path,
                    .message = message,
                },
            );
            return;
        };
        const event = maybe_event orelse {
            result.completeStage(.parser);
            if (semantic_validator) |*sv| {
                result.beginStage(.semantic);
                try sv.finish();
                result.completeStage(.semantic);
            }
            if (index_validator) |*iv| {
                result.beginStage(.index);
                try iv.finish(file_bytes);
                result.completeStage(.index);
            }
            break;
        };

        switch (event) {
            .start_element => |start| {
                element_depth += 1;
                result.beginStage(.structural);
                try structural_validator.consumeStart(start);
                if (binary_validator) |*validator| {
                    result.beginStage(.binary);
                    try validator.consumeStart(start);
                }
                if (fuse_index_semantic) {
                    const needed = elements.startMask(start.resolvedId()).intersect(active);
                    if (needed.index) {
                        if (index_validator) |*validator| {
                            result.beginStage(.index);
                            try validator.consumeStart(start, element_depth);
                        }
                    }
                    if (needed.semantic) {
                        if (semantic_validator) |*validator| {
                            result.beginStage(.semantic);
                            try validator.consumeStart(start);
                        }
                    }
                }
            },
            .end_element => |end| {
                result.beginStage(.structural);
                try structural_validator.consumeEnd(end);
                if (binary_validator) |*validator| {
                    result.beginStage(.binary);
                    try validator.consumeEnd(end);
                }
                if (fuse_index_semantic) {
                    const needed = elements.endMask(end.resolvedId()).intersect(active);
                    if (needed.index) {
                        if (index_validator) |*validator| {
                            result.beginStage(.index);
                            try validator.consumeEnd(end, element_depth);
                        }
                    }
                    if (needed.semantic) {
                        if (semantic_validator) |*validator| {
                            result.beginStage(.semantic);
                            try validator.consumeEnd(end);
                        }
                    }
                }
                element_depth -= 1;
            },
            .text => |text| {
                result.beginStage(.structural);
                if (structural_validator.depth == 0) {
                    try structural_validator.consumeText(text);
                }
                if (binary_validator) |*validator| {
                    if (validator.wantsText()) {
                        result.beginStage(.binary);
                        try validator.consumeText(text);
                    }
                }
                if (index_validator) |*validator| {
                    if (validator.wantsText()) {
                        result.beginStage(.index);
                        try validator.consumeText(text);
                    }
                }
            },
        }
        if (index_validator) |*validator| {
            result.beginStage(.index);
            validator.feedShaExclusive(parser.byteOffset() + 1);
        }
    }

    result.beginStage(.structural);
    try structural_validator.finish();
    result.completeStage(.structural);
    if (binary_validator) |*validator| {
        result.beginStage(.binary);
        try validator.finish();
        result.completeStage(.binary);
    }
}

fn enabledStages(options: CheckOptions) diagnostic.StageMask {
    var stages = diagnostic.stageBit(.input) | diagnostic.stageBit(.parser) | diagnostic.stageBit(.structural);
    if (!options.skip_binary) stages |= diagnostic.stageBit(.binary);
    if (!options.skip_index) stages |= diagnostic.stageBit(.index);
    if (!options.skip_semantic) stages |= diagnostic.stageBit(.semantic);
    return stages;
}

fn recordUnhandledFailure(result: *FileResult, err: anyerror, path: []const u8) void {
    const reason: FailureReason = if (err == error.OutOfMemory)
        .allocation
    else if (err == error.ResourceLimitExceeded)
        .resource
    else
        .unknown;
    result.recordEmergencyFailure(result.active_stage, reason, path);
}

fn appendFailureDiagnostic(
    allocator: std.mem.Allocator,
    diagnostics: *DiagnosticSink,
    result: *FileResult,
    stage: ValidationStage,
    reason: FailureReason,
    item: Diagnostic,
) !void {
    const emitted = diagnostics.append(allocator, item) catch |err| {
        result.recordEmergencyFailure(stage, .allocation, item.path);
        return err;
    };
    result.recordFailure(stage, reason, item.rule, item.message, item.location, item.path, emitted);
    if (!emitted) result.failure_diagnostic_counted = true;
}

fn expectAllocationFailuresIncomplete(
    bytes: []const u8,
    options: CheckOptions,
    file_bytes: ?[]const u8,
    sampled: bool,
) !void {
    var baseline_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var baseline_diagnostics: DiagnosticSink = .empty;
    const baseline = checkSliceResult(
        baseline_allocator.allocator(),
        std.testing.io,
        bytes,
        &baseline_diagnostics,
        "allocation-failure.mzML",
        options,
        file_bytes,
    );
    baseline_diagnostics.deinit(baseline_allocator.allocator());
    try std.testing.expectEqual(baseline_allocator.allocated_bytes, baseline_allocator.freed_bytes);
    try std.testing.expectEqual(diagnostic.CompletionState.complete, baseline.completion);

    const allocation_count = baseline_allocator.alloc_index;
    for (0..allocation_count) |fail_index| {
        if (sampled and fail_index != 0 and fail_index != allocation_count / 2 and fail_index + 1 != allocation_count) continue;
        var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
        var diagnostics: DiagnosticSink = .empty;
        const result = checkSliceResult(
            failing_allocator.allocator(),
            std.testing.io,
            bytes,
            &diagnostics,
            "allocation-failure.mzML",
            options,
            file_bytes,
        );
        const induced = failing_allocator.has_induced_failure;
        diagnostics.deinit(failing_allocator.allocator());

        try std.testing.expectEqual(failing_allocator.allocated_bytes, failing_allocator.freed_bytes);
        if (induced) {
            const failure = result.first_failure orelse return error.TestUnexpectedResult;
            try std.testing.expectEqual(diagnostic.CompletionState.incomplete, result.completion);
            try std.testing.expectEqual(diagnostic.FailureReason.allocation, failure.reason);
            try std.testing.expect(result.status() != .clean);
        } else {
            try std.testing.expectEqual(diagnostic.CompletionState.complete, result.completion);
        }
    }
}

// --- Unit tests ---

// Tests: file and reader entry points.

test "checkPath_missingFile_reportsOpenError" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    try checkPath(allocator, io, &diagnostics, "definitely-missing-file.mzML", .{});

    // Assert.
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqual(diagnostic.Severity.@"error", diagnostics.items[0].severity);
    try std.testing.expectEqualStrings(RuleId.runtime_file_open, diagnostics.items[0].rule);
}

test "checkPath_streamMode_usesBoundedReaderPath" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try std.Io.Dir.cwd().readFileAlloc(
        io,
        "fixtures/examples/mzml/single-spectrum-missing-cv-terms.mzML",
        allocator,
        .limited(64 * 1024),
    );
    defer allocator.free(fixture);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    const path = try stageFixtureInTempDir(allocator, io, &temp_dir, "stream.mzML", fixture);
    defer allocator.free(path);

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    const result = checkPathResult(allocator, io, &diagnostics, path, .{
        .skip_binary = true,
        .skip_index = true,
        .skip_semantic = true,
        .input_mode = .stream,
    });

    try std.testing.expectEqual(diagnostic.CompletionState.complete, result.completion);
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "explicit mmap failure_reports_mode_error_without_fallback" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    try temp_dir.dir.writeFile(io, .{ .sub_path = "mmap-failure.mzML", .data = "<mzML/>" });
    const path = try tempFixturePath(allocator, temp_dir.sub_path[0..], "mmap-failure.mzML");
    defer allocator.free(path);

    var context = InvocationContext.init(allocator, io, .{
        .skip_binary = true,
        .skip_index = true,
        .skip_semantic = true,
        .input_mode = .mmap,
    });
    defer context.deinit();

    var file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    const initial_stat = try file.stat(io);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var result = FileResult.init(enabledStages(context.options));
    result.beginStage(.input);

    try checkPathMapped(
        &context,
        file,
        initial_stat,
        &diagnostics,
        path,
        &result,
        forcedMemoryMapFailure,
    );
    result.finalize(diagnostics.items);

    try std.testing.expectEqual(diagnostic.CompletionState.incomplete, result.completion);
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.runtime_input_mode, diagnostics.items[0].rule);
}

test "file stability check_rejects_changed_file" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    try temp_dir.dir.writeFile(io, .{ .sub_path = "changed.mzML", .data = "x" });
    const path = try tempFixturePath(allocator, temp_dir.sub_path[0..], "changed.mzML");
    defer allocator.free(path);

    var file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    const initial_stat = try file.stat(io);
    try temp_dir.dir.writeFile(io, .{ .sub_path = "changed.mzML", .data = "changed" });

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var context = InvocationContext.init(allocator, io, .{ .skip_semantic = true });
    defer context.deinit();
    var result = FileResult.init(enabledStages(context.options));

    try checkFileStability(&context, file, initial_stat, &diagnostics, path, &result);
    result.finalize(diagnostics.items);

    try std.testing.expectEqual(diagnostic.CompletionState.incomplete, result.completion);
    try std.testing.expectEqualStrings(RuleId.runtime_file_stability, diagnostics.items[0].rule);
}

test "mapped validation_rejects_truncation_after_mapping" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml = "<?xml version=\"1.0\"?><mzML xmlns=\"http://psi.hupo.org/ms/mzml\"/>";

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    try temp_dir.dir.writeFile(io, .{ .sub_path = "mapped-truncated.mzML", .data = xml });
    const path = try tempFixturePath(allocator, temp_dir.sub_path[0..], "mapped-truncated.mzML");
    defer allocator.free(path);

    var context = InvocationContext.init(allocator, io, .{
        .skip_binary = true,
        .skip_index = true,
        .skip_semantic = true,
    });
    defer context.deinit();
    var file = try std.Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
    defer file.close(io);
    const initial_stat = try file.stat(io);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var result = FileResult.init(enabledStages(context.options));
    result.beginStage(.input);

    try checkPathMapped(
        &context,
        file,
        initial_stat,
        &diagnostics,
        path,
        &result,
        mapThenTruncate,
    );
    result.finalize(diagnostics.items);

    try std.testing.expectEqual(diagnostic.CompletionState.incomplete, result.completion);
    var found_stability_failure = false;
    for (diagnostics.items) |item| {
        if (std.mem.eql(u8, item.rule, RuleId.runtime_file_stability)) {
            found_stability_failure = true;
            break;
        }
    }
    try std.testing.expect(found_stability_failure);
}

test "checkPath_existingFile_runsStructuralValidationWhenSkippingBinary" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/examples/mzml/single-spectrum-missing-cv-terms.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();

    const path = try stageFixtureInTempDir(allocator, io, &temp_dir, "sample.mzML", fixture);
    defer allocator.free(path);

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    try checkPath(allocator, io, &diagnostics, path, .{ .skip_binary = true, .skip_semantic = true });

    // Assert.
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "checkPath_existingFile_reportsCleanResultWhenStructureAndBinaryPass" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/examples/mzml/single-spectrum-missing-cv-terms.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();

    const path = try stageFixtureInTempDir(allocator, io, &temp_dir, "sample.mzML", fixture);
    defer allocator.free(path);

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    try checkPath(allocator, io, &diagnostics, path, .{ .skip_semantic = true });

    // Assert.
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

// Tests: indexed and corpus fixtures.

test "checkPath_indexedMzMLFixture_runsStructuralValidationWhenSkippingBinary" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/valid/tiny.pwiz.1.1.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();

    const path = try stageFixtureInTempDir(allocator, io, &temp_dir, "tiny-indexed.mzML", fixture);
    defer allocator.free(path);

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    try checkPath(allocator, io, &diagnostics, path, .{ .skip_binary = true, .skip_semantic = true, .skip_index = true });

    // Assert.
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "checkPath_largeIndexedMzMLFixture_runsStructuralValidationWhenSkippingBinary" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    try checkPath(allocator, io, &diagnostics, "fixtures/mzml/valid/small.pwiz.1.1.mzML", .{ .skip_binary = true, .skip_semantic = true, .skip_index = true });

    // Assert.
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "checkPath_indexedMzMLFixture_runsStructuralWhenSkippingIndex" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    // Act. Skip index because the pwiz fixture has a bad checksum.
    // Index SHA-1 verification is tested separately with correct fixtures.
    try checkPath(allocator, io, &diagnostics, "fixtures/mzml/valid/tiny.pwiz.1.1.mzML", .{ .skip_binary = true, .skip_semantic = true, .skip_index = true });

    // Assert.
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "checkPath_semantic_end_to_end" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    const result = checkPathResult(allocator, io, &diagnostics, "fixtures/mzml/valid/tiny.pwiz.1.1.mzML", .{ .skip_binary = true, .skip_index = true });

    try std.testing.expect(diagnostics.items.len > 0);
    try std.testing.expect(result.resource_usage.semantic_peak_bytes > 0);
    try std.testing.expect(result.resource_usage.semantic_declaration_peak_bytes > 0);
    var has_cv_diag = false;
    for (diagnostics.items) |d| {
        if (std.mem.startsWith(u8, d.rule, "mzml.cv.") or std.mem.startsWith(u8, d.rule, "mzml.ref.")) {
            has_cv_diag = true;
            break;
        }
    }
    try std.testing.expect(has_cv_diag);
}

test "checkSliceResult_semantic_limit_is_incomplete" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml = spectrumListMzml("<spectrumList count=\"0\" defaultDataProcessingRef=\"DP1\"/>");

    var context = InvocationContext.init(allocator, io, .{
        .skip_binary = true,
        .skip_index = true,
        .resource_limits = .{ .max_semantic_bytes = 1 },
    });
    defer context.deinit();
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    const result = context.checkSliceResult(xml, &diagnostics, "semantic-limit.mzML", null);

    try std.testing.expectEqual(diagnostic.CompletionState.incomplete, result.completion);
    try std.testing.expectEqual(diagnostic.FailureReason.resource, result.first_failure.?.reason);
    try std.testing.expectEqualStrings(RuleId.runtime_semantic_limit, diagnostics.items[0].rule);
}

test "checkPath_indexed_fixture_runs_mapping_rules" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, "fixtures/mzml/adversarial/indexed-mapping-missing.mzML", .{
        .skip_binary = true,
        .skip_index = true,
    });

    var found_required_mapping_error = false;
    for (diagnostics.items) |item| {
        if (std.mem.eql(u8, item.rule, RuleId.mzml_cv_required)) {
            found_required_mapping_error = true;
            break;
        }
    }
    try std.testing.expect(found_required_mapping_error);
}

test "checkPath_nonempty_binary_without_array_length_is_incomplete" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    const result = checkPathResult(allocator, io, &diagnostics, "fixtures/mzml/adversarial/missing-default-array-length.mzML", .{
        .skip_index = true,
        .skip_semantic = true,
    });

    try std.testing.expectEqual(diagnostic.CompletionState.incomplete, result.completion);
    try std.testing.expectEqual(diagnostic.ValidationStage.binary, result.first_failure.?.stage);
    try std.testing.expectEqual(diagnostic.FailureReason.resource, result.first_failure.?.reason);

    var found_binary_diagnostic = false;
    for (diagnostics.items) |item| {
        if (std.mem.eql(u8, item.rule, RuleId.mzml_binary_length_mismatch) and
            std.mem.eql(u8, item.message, "non-empty binary payload is missing required defaultArrayLength"))
        {
            found_binary_diagnostic = true;
            break;
        }
    }
    try std.testing.expect(found_binary_diagnostic);
}

test "checkPath_missing_required_reference_emits_reference_rule" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, "fixtures/mzml/adversarial/missing-required-reference.mzML", .{
        .skip_binary = true,
        .skip_index = true,
        .skip_semantic = true,
    });

    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_ref_missing, diagnostics.items[0].rule);
    try std.testing.expectEqualStrings("run is missing required attribute defaultInstrumentConfigurationRef", diagnostics.items[0].message);
}

test "checkPath_indexedMzMLFixture_skipIndexSkipsIndexChecks" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    try checkPath(allocator, io, &diagnostics, "fixtures/mzml/valid/tiny.pwiz.1.1.mzML", .{ .skip_binary = true, .skip_index = true, .skip_semantic = true });

    // Assert.
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "checkPath_indexedSha_stream_noChecksumError" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange. Build a file with a correct SHA-1 embedded in fileChecksum.
    // The hash must cover everything up to the hex content, which is:
    // prefix (= content up to and including the newline after </indexListOffset>)
    // + indent (= "  ") + "<fileChecksum>".
    const prefix =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" ++
        "<indexedmzML xmlns=\"http://psi.hupo.org/ms/mzml\">\n" ++
        "  <mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">\n" ++
        "    <cvList count=\"1\"><cv id=\"MS\" fullName=\"PSI-MS\" URI=\"\"/></cvList>\n" ++
        "    <fileDescription><fileContent/></fileDescription>\n" ++
        "    <softwareList count=\"1\"><software id=\"sw\" version=\"1.0\"/></softwareList>\n" ++
        "    <instrumentConfigurationList count=\"1\"><instrumentConfiguration id=\"ic\"/></instrumentConfigurationList>\n" ++
        "    <dataProcessingList count=\"1\"><dataProcessing id=\"dp\"><processingMethod order=\"0\" softwareRef=\"sw\"/></dataProcessing></dataProcessingList>\n" ++
        "    <run id=\"r\" defaultInstrumentConfigurationRef=\"ic\">\n" ++
        "      <spectrumList count=\"0\" defaultDataProcessingRef=\"dp\"/>\n" ++
        "    </run>\n" ++
        "  </mzML>\n" ++
        "  <indexList count=\"1\"><index name=\"spectrum\"/></indexList>\n" ++
        "  <indexListOffset>10</indexListOffset>\n";
    var sha_ctx = std.crypto.hash.Sha1.init(.{});
    sha_ctx.update(prefix);
    sha_ctx.update("  <fileChecksum>");
    var raw: [20]u8 = undefined;
    sha_ctx.final(&raw);
    const hex = std.fmt.bytesToHex(raw, .lower);

    const xml = try indexedMzmlWithSha(allocator, &hex);
    defer allocator.free(xml);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    try temp_dir.dir.writeFile(io, .{ .sub_path = "valid-sha.mzML", .data = xml });
    const path = try tempFixturePath(allocator, temp_dir.sub_path[0..], "valid-sha.mzML");
    defer allocator.free(path);

    // Act. Stream path: checksum is recomputed from the seekable source.
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    const result = checkPathResult(allocator, io, &diagnostics, path, .{
        .skip_binary = true,
        .skip_semantic = true,
        .input_mode = .stream,
    });

    // Assert. No checksum error.
    for (diagnostics.items) |d| {
        if (std.mem.eql(u8, d.rule, RuleId.mzml_index_checksum)) {
            return error.TestUnexpectedChecksumError;
        }
    }
    try std.testing.expect(result.resource_usage.index_peak_bytes > 0);
}

test "checkPath_indexedSha_mmap_noChecksumError" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange. Same fixture, explicit mmap path.
    const prefix =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" ++
        "<indexedmzML xmlns=\"http://psi.hupo.org/ms/mzml\">\n" ++
        "  <mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">\n" ++
        "    <cvList count=\"1\"><cv id=\"MS\" fullName=\"PSI-MS\" URI=\"\"/></cvList>\n" ++
        "    <fileDescription><fileContent/></fileDescription>\n" ++
        "    <softwareList count=\"1\"><software id=\"sw\" version=\"1.0\"/></softwareList>\n" ++
        "    <instrumentConfigurationList count=\"1\"><instrumentConfiguration id=\"ic\"/></instrumentConfigurationList>\n" ++
        "    <dataProcessingList count=\"1\"><dataProcessing id=\"dp\"><processingMethod order=\"0\" softwareRef=\"sw\"/></dataProcessing></dataProcessingList>\n" ++
        "    <run id=\"r\" defaultInstrumentConfigurationRef=\"ic\">\n" ++
        "      <spectrumList count=\"0\" defaultDataProcessingRef=\"dp\"/>\n" ++
        "    </run>\n" ++
        "  </mzML>\n" ++
        "  <indexList count=\"1\"><index name=\"spectrum\"/></indexList>\n" ++
        "  <indexListOffset>10</indexListOffset>\n";
    var sha_ctx = std.crypto.hash.Sha1.init(.{});
    sha_ctx.update(prefix);
    sha_ctx.update("  <fileChecksum>");
    var raw: [20]u8 = undefined;
    sha_ctx.final(&raw);
    const hex = std.fmt.bytesToHex(raw, .lower);
    const xml = try indexedMzmlWithSha(allocator, &hex);
    defer allocator.free(xml);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    try temp_dir.dir.writeFile(io, .{ .sub_path = "valid-sha-mmap.mzML", .data = xml });
    const path = try tempFixturePath(allocator, temp_dir.sub_path[0..], "valid-sha-mmap.mzML");
    defer allocator.free(path);

    // Act. Explicit mmap.
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    try checkPath(allocator, io, &diagnostics, path, .{
        .skip_binary = true,
        .skip_semantic = true,
        .mmap = true,
    });

    // Assert. No checksum error.
    for (diagnostics.items) |d| {
        if (std.mem.eql(u8, d.rule, RuleId.mzml_index_checksum)) {
            return error.TestUnexpectedChecksumError;
        }
    }
}

test "checkPath_indexedSha_skipIndex_noShaCheck" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange. Same fixture, skip-index path.
    const prefix =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" ++
        "<indexedmzML xmlns=\"http://psi.hupo.org/ms/mzml\">\n" ++
        "  <mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">\n" ++
        "    <cvList count=\"1\"><cv id=\"MS\" fullName=\"PSI-MS\" URI=\"\"/></cvList>\n" ++
        "    <fileDescription><fileContent/></fileDescription>\n" ++
        "    <softwareList count=\"1\"><software id=\"sw\" version=\"1.0\"/></softwareList>\n" ++
        "    <instrumentConfigurationList count=\"1\"><instrumentConfiguration id=\"ic\"/></instrumentConfigurationList>\n" ++
        "    <dataProcessingList count=\"1\"><dataProcessing id=\"dp\"><processingMethod order=\"0\" softwareRef=\"sw\"/></dataProcessing></dataProcessingList>\n" ++
        "    <run id=\"r\" defaultInstrumentConfigurationRef=\"ic\">\n" ++
        "      <spectrumList count=\"0\" defaultDataProcessingRef=\"dp\"/>\n" ++
        "    </run>\n" ++
        "  </mzML>\n" ++
        "  <indexList count=\"1\"><index name=\"spectrum\"/></indexList>\n" ++
        "  <indexListOffset>10</indexListOffset>\n";
    var sha_ctx = std.crypto.hash.Sha1.init(.{});
    sha_ctx.update(prefix);
    sha_ctx.update("  <fileChecksum>");
    var raw: [20]u8 = undefined;
    sha_ctx.final(&raw);
    const hex = std.fmt.bytesToHex(raw, .lower);
    const xml = try indexedMzmlWithSha(allocator, &hex);
    defer allocator.free(xml);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    try temp_dir.dir.writeFile(io, .{ .sub_path = "skip-sha.mzML", .data = xml });
    const path = try tempFixturePath(allocator, temp_dir.sub_path[0..], "skip-sha.mzML");
    defer allocator.free(path);

    // Act. Skip-index: pure streaming, no SHA-1 at all.
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    try checkPath(allocator, io, &diagnostics, path, .{
        .skip_binary = true,
        .skip_semantic = true,
        .skip_index = true,
    });

    // Assert. No index work at all.
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "checkPath_indexedSha_corruptedChecksum_detected" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange. Same fixture but with deliberately wrong SHA-1 (all zeros).
    const bad_hex = "0000000000000000000000000000000000000000";
    const xml = try indexedMzmlWithSha(allocator, bad_hex);
    defer allocator.free(xml);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    try temp_dir.dir.writeFile(io, .{ .sub_path = "bad-sha.mzML", .data = xml });
    const path = try tempFixturePath(allocator, temp_dir.sub_path[0..], "bad-sha.mzML");
    defer allocator.free(path);

    // Act.
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    try checkPath(allocator, io, &diagnostics, path, .{
        .skip_binary = true,
        .skip_semantic = true,
        .input_mode = .stream,
    });

    // Assert. The wrong checksum must produce a mismatch diagnostic.
    var found = false;
    for (diagnostics.items) |d| {
        if (std.mem.eql(u8, d.rule, RuleId.mzml_index_checksum)) {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}

test "checkPath_indexedSha_nonIndexed_noShaAttempted" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange. A non-indexed file (no indexList). Index validation runs but
    // sees no index elements, so no SHA-1 is attempted.
    const xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" ++
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">\n" ++
        "  <cvList count=\"1\"><cv id=\"MS\" fullName=\"PSI-MS\" URI=\"\"/></cvList>\n" ++
        "  <fileDescription><fileContent/></fileDescription>\n" ++
        "  <softwareList count=\"1\"><software id=\"sw\" version=\"1.0\"/></softwareList>\n" ++
        "  <instrumentConfigurationList count=\"1\"><instrumentConfiguration id=\"ic\"/></instrumentConfigurationList>\n" ++
        "  <dataProcessingList count=\"1\"><dataProcessing id=\"dp\"><processingMethod order=\"0\" softwareRef=\"sw\"/></dataProcessing></dataProcessingList>\n" ++
        "  <run id=\"r\" defaultInstrumentConfigurationRef=\"ic\">\n" ++
        "    <spectrumList count=\"0\" defaultDataProcessingRef=\"dp\"/>\n" ++
        "  </run>\n" ++
        "</mzML>\n";

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    try temp_dir.dir.writeFile(io, .{ .sub_path = "non-indexed.mzML", .data = xml });
    const path = try tempFixturePath(allocator, temp_dir.sub_path[0..], "non-indexed.mzML");
    defer allocator.free(path);

    // Act.
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    try checkPath(allocator, io, &diagnostics, path, .{
        .skip_binary = true,
        .skip_semantic = true,
    });

    // Assert. Clean. No SHA-1 check because no index elements.
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "checkPath_indexed_skipIndex_noSha1Check" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    // Act. Skip-index path: pure streaming, no SHA-1.
    try checkPath(allocator, io, &diagnostics, "fixtures/mzml/valid/tiny.pwiz.1.1.mzML", .{
        .skip_binary = true,
        .skip_semantic = true,
        .skip_index = true,
    });

    // Assert. No index work done, no SHA-1 check.
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "checkPath_indexed_missingChecksum_noError" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange. A minimal indexed mzML without a fileChecksum element.
    // The spec allows indexed mzML without checksum.
    const xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" ++
        "<indexedmzML xmlns=\"http://psi.hupo.org/ms/mzml\">\n" ++
        "  <mzML version=\"1.1.0\">\n" ++
        "    <run id=\"r\" defaultInstrumentConfigurationRef=\"ic\">\n" ++
        "      <spectrumList count=\"0\" defaultDataProcessingRef=\"dp\"/>\n" ++
        "    </run>\n" ++
        "  </mzML>\n" ++
        "  <indexList count=\"1\">\n" ++
        "    <index name=\"spectrum\">\n" ++
        "      <offset idRef=\"s1\">0</offset>\n" ++
        "    </index>\n" ++
        "  </indexList>\n" ++
        "  <indexListOffset>250</indexListOffset>\n" ++
        "</indexedmzML>\n";

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    try temp_dir.dir.writeFile(io, .{ .sub_path = "no-checksum.mzML", .data = xml });

    const path = try tempFixturePath(allocator, temp_dir.sub_path[0..], "no-checksum.mzML");
    defer allocator.free(path);

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    try checkPath(allocator, io, &diagnostics, path, .{
        .skip_binary = true,
        .skip_semantic = true,
    });

    // Assert. No checksum error (no fileChecksum element found).
    for (diagnostics.items) |d| {
        if (std.mem.eql(u8, d.rule, RuleId.mzml_index_checksum)) {
            return error.TestUnexpectedChecksumError;
        }
    }
}

test "checkPath_mmap_flag_onMissingFileReportsOpenError" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    // Act. The open fails before input-mode selection starts.
    try checkPath(allocator, io, &diagnostics, "definitely-missing.mzML", .{ .mmap = true });

    // Assert. Report the file-open error, not a memory-map error.
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.runtime_file_open, diagnostics.items[0].rule);
}

test "checkPath_validMzMLCorpus_runsStructuralValidationWhenSkippingBinary" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const root = "fixtures/mzml/valid";

    // Act.
    const fixture_count = try expectCorpusDiagnostics(
        allocator,
        io,
        root,
        .{ .skip_binary = true, .skip_semantic = true, .skip_index = true },
        .clean,
    );

    // Assert.
    try std.testing.expect(fixture_count > 0);
}

// Tests: synthetic large streaming input.

test "checkPath_syntheticLargeMzMLFixture_runsCleanInOnePass" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const spectrum_count = 2048;

    // Arrange.
    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    const written_len = try writeSyntheticLargeMzmlFixture(io, &temp_dir, "synthetic-large.mzML", spectrum_count);
    try std.testing.expect(written_len > 1024 * 1024);

    const path = try tempFixturePath(allocator, temp_dir.sub_path[0..], "synthetic-large.mzML");
    defer allocator.free(path);

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    try checkPath(allocator, io, &diagnostics, path, .{ .skip_semantic = true });

    // Assert.
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "checkPath_stream_largeBinaryText_fixture_reportsLengthMismatch" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, "fixtures/mzml/adversarial/large-binary-text.mzML", .{
        .input_mode = .stream,
        .skip_semantic = true,
    });

    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_binary_length_mismatch,
        "decoded array length does not match defaultArrayLength",
    );
}

test "writeSyntheticLargeMzmlFixture_writes_expected_streamed_shape" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const spectrum_count = 3;

    // Arrange.
    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();

    // Act.
    const written_len = try writeSyntheticLargeMzmlFixture(io, &temp_dir, "synthetic-shape.mzML", spectrum_count);
    const path = try tempFixturePath(allocator, temp_dir.sub_path[0..], "synthetic-shape.mzML");
    defer allocator.free(path);
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(128 * 1024));
    defer allocator.free(fixture);

    // Assert.
    try std.testing.expectEqual(fixture.len, written_len);
    try std.testing.expect(std.mem.startsWith(u8, fixture, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<mzML "));
    try std.testing.expect(std.mem.indexOf(u8, fixture, "<spectrumList count=\"3\" defaultDataProcessingRef=\"DP1\">") != null);
    try std.testing.expect(std.mem.indexOf(u8, fixture, "<spectrum index=\"0\" id=\"scan=1\" defaultArrayLength=\"1\">") != null);
    try std.testing.expect(std.mem.indexOf(u8, fixture, "<spectrum index=\"2\" id=\"scan=3\" defaultArrayLength=\"1\">") != null);
    try std.testing.expectEqual(@as(usize, spectrum_count * 2), std.mem.count(u8, fixture, "<binary>AAAAAA==</binary>"));
    try std.testing.expect(std.mem.endsWith(u8, fixture, "    </spectrumList>\n  </run>\n</mzML>\n"));
}

// Tests: adversarial public reader API.

test "checkReader_truncated_xml_reports_exact_structure_xml_diagnostic" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" ++
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\"><run";

    // Arrange.
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-truncated.mzML", .{ .skip_semantic = true }, null);

    // Assert.
    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_xml,
        "unexpected end of XML input",
    );
}

test "checkReader_truncated_xml_returns_incomplete_file_result" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" ++
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\"><run";

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    const result = checkReaderResult(allocator, io, &reader, &diagnostics, "inline-truncated.mzML", .{
        .skip_binary = true,
        .skip_semantic = true,
    }, null);

    try std.testing.expectEqual(diagnostic.CompletionState.incomplete, result.completion);
    try std.testing.expectEqual(diagnostic.ValidationStage.parser, result.first_failure.?.stage);
    try std.testing.expectEqual(diagnostic.FailureReason.parser, result.first_failure.?.reason);
    try std.testing.expectEqual(diagnostic.stageBit(.input), result.completed_stages);
    try std.testing.expectEqual(@as(u8, 2), diagnostic.exitCodeForResults(&.{result}));
}

test "checkReader_clean_input_returns_complete_file_result" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml = spectrumListMzml("<spectrumList count=\"0\" defaultDataProcessingRef=\"DP1\"/>");

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    const result = checkReaderResult(allocator, io, &reader, &diagnostics, "inline-clean.mzML", .{
        .skip_binary = true,
        .skip_index = true,
        .skip_semantic = true,
    }, null);

    try std.testing.expectEqual(diagnostic.CompletionState.complete, result.completion);
    try std.testing.expectEqual(result.enabled_stages, result.completed_stages);
    try std.testing.expectEqual(diagnostic.ResultStatus.clean, result.status());
    try std.testing.expectEqual(@as(usize, max_validation_token_bytes), result.resource_usage.parser_current_bytes);
    try std.testing.expectEqual(@as(usize, max_validation_token_bytes), result.resource_usage.parser_peak_bytes);
}

test "checkReader_out_of_memory_returns_incomplete_file_result" {
    const io = std.testing.io;

    var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(std.testing.allocator);
    var reader = std.Io.Reader.fixed("<mzML/>");

    const result = checkReaderResult(failing_allocator.allocator(), io, &reader, &diagnostics, "inline-oom.mzML", .{
        .skip_binary = true,
        .skip_index = true,
        .skip_semantic = true,
    }, null);

    try std.testing.expectEqual(diagnostic.CompletionState.incomplete, result.completion);
    try std.testing.expectEqual(diagnostic.FailureReason.allocation, result.first_failure.?.reason);
    try std.testing.expect(result.needsEmergencyDiagnostic());
    try std.testing.expectEqual(@as(usize, 1), result.totals.errors);
}

test "required-state allocation failures stay incomplete and leak-free" {
    const semantic_xml = spectrumListMzml("<spectrumList count=\"0\" defaultDataProcessingRef=\"DP1\"/>");
    try expectAllocationFailuresIncomplete(semantic_xml, .{
        .skip_binary = true,
        .skip_index = true,
        .skip_semantic = true,
    }, null, false);

    const index_fixture = try std.Io.Dir.cwd().readFileAlloc(
        std.testing.io,
        "fixtures/mzml/valid/tiny.pwiz.1.1.mzML",
        std.testing.allocator,
        .limited(256 * 1024),
    );
    defer std.testing.allocator.free(index_fixture);
    try expectAllocationFailuresIncomplete(index_fixture, .{
        .skip_binary = true,
        .skip_semantic = true,
    }, index_fixture, false);

    try expectAllocationFailuresIncomplete(semantic_xml, .{
        .skip_binary = true,
        .skip_index = true,
    }, null, true);
}

test "failure diagnostic allocation uses the fixed emergency result" {
    const xml = "<?xml version=\"1.0\"?><mzML><run";
    var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 1 });
    var diagnostics: DiagnosticSink = .empty;

    const result = checkSliceResult(failing_allocator.allocator(), std.testing.io, xml, &diagnostics, "diagnostic-oom.mzML", .{
        .skip_binary = true,
        .skip_index = true,
        .skip_semantic = true,
    }, null);
    diagnostics.deinit(failing_allocator.allocator());

    try std.testing.expect(failing_allocator.has_induced_failure);
    try std.testing.expectEqual(failing_allocator.allocated_bytes, failing_allocator.freed_bytes);
    try std.testing.expectEqual(diagnostic.CompletionState.incomplete, result.completion);
    try std.testing.expect(result.first_failure.?.stage == .parser or result.first_failure.?.stage == .structural);
    try std.testing.expectEqual(diagnostic.FailureReason.allocation, result.first_failure.?.reason);
    try std.testing.expectEqualStrings(diagnostic.RuleId.runtime_incomplete, result.first_failure.?.rule);
    try std.testing.expect(result.diagnostics_truncated);
    try std.testing.expect(result.needsEmergencyDiagnostic());
}

test "checkPath_missing_catalog_returns_incomplete_file_result" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    const result = checkPathResult(allocator, io, &diagnostics, "fixtures/mzml/valid/tiny.pwiz.1.1.mzML", .{
        .skip_binary = true,
        .skip_index = true,
        .obo_path = "definitely-missing.obo",
    });

    try std.testing.expectEqual(diagnostic.CompletionState.incomplete, result.completion);
    try std.testing.expectEqual(diagnostic.FailureReason.catalog, result.first_failure.?.reason);
    try std.testing.expectEqual(@as(u8, 2), diagnostic.exitCodeForResults(&.{result}));
}

test "InvocationContext_owns_catalog_across_multiple_paths" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    try temp_dir.dir.writeFile(io, .{
        .sub_path = "psi-ms.obo",
        .data = @embedFile("data/psi-ms.obo"),
    });
    const obo_path = try tempFixturePath(allocator, temp_dir.sub_path[0..], "psi-ms.obo");
    defer allocator.free(obo_path);

    var context = InvocationContext.init(allocator, io, .{
        .skip_binary = true,
        .skip_index = true,
        .obo_path = obo_path,
    });
    defer context.deinit();
    try std.testing.expect(context.catalog != null);
    try temp_dir.dir.deleteFile(io, "psi-ms.obo");

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    const first = context.validateOne(&diagnostics, "fixtures/mzml/valid/tiny.pwiz.1.1.mzML");
    diagnostics.clearRetainingCapacity();
    const second = context.validateOne(&diagnostics, "fixtures/mzml/valid/small.pwiz.1.1.mzML");

    try std.testing.expectEqual(diagnostic.CompletionState.complete, first.completion);
    try std.testing.expectEqual(diagnostic.CompletionState.complete, second.completion);
    try std.testing.expect(context.catalog != null);
}

test "checkPath_incompatible_custom_vocabulary_is_non_clean" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    const result = checkPathResult(allocator, io, &diagnostics, "fixtures/mzml/valid/tiny.pwiz.1.1.mzML", .{
        .skip_binary = true,
        .skip_index = true,
        .obo_path = "fixtures/obo/adversarial/custom-namespace.obo",
    });

    try std.testing.expectEqual(diagnostic.CompletionState.incomplete, result.completion);
    try std.testing.expectEqual(diagnostic.ValidationStage.semantic, result.first_failure.?.stage);
    try std.testing.expectEqual(diagnostic.FailureReason.catalog, result.first_failure.?.reason);
    try std.testing.expectEqualStrings(RuleId.runtime_catalog, result.first_failure.?.rule);
}

test "checkPath_invalid_zlib_returns_complete_result_with_error" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    const result = checkPathResult(allocator, io, &diagnostics, "fixtures/mzml/invalid/invalid-zlib.mzML", .{
        .skip_semantic = true,
    });

    try std.testing.expectEqual(diagnostic.CompletionState.complete, result.completion);
    try std.testing.expectEqual(diagnostic.ResultStatus.errors_present, result.status());
    try std.testing.expectEqualStrings(RuleId.mzml_binary_decompress, diagnostics.items[0].rule);
    try std.testing.expect(result.resource_usage.binary_scratch_peak_bytes > 0);
}

test "checkPath_resource_limit_returns_incomplete_resource_result" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    const result = checkPathResult(allocator, io, &diagnostics, "fixtures/mzml/adversarial/huge-count.mzML", .{
        .skip_binary = true,
        .skip_semantic = true,
    });

    try std.testing.expectEqual(diagnostic.CompletionState.incomplete, result.completion);
    try std.testing.expectEqual(diagnostic.FailureReason.resource, result.first_failure.?.reason);
    var found_limit = false;
    for (diagnostics.items) |item| {
        if (std.mem.eql(u8, item.rule, RuleId.mzml_index_offset_list)) {
            found_limit = true;
            break;
        }
    }
    try std.testing.expect(found_limit);
}

test "checkSlice_index_state_limit_returns_incomplete_resource_result" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try std.Io.Dir.cwd().readFileAlloc(
        io,
        "fixtures/mzml/valid/tiny.pwiz.1.1.mzML",
        allocator,
        .limited(64 * 1024),
    );
    defer allocator.free(fixture);

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    const result = checkSliceResult(allocator, io, fixture, &diagnostics, "tiny-index-limit.mzML", .{
        .skip_binary = true,
        .skip_semantic = true,
        .resource_limits = .{ .max_index_state_bytes = 1 },
    }, fixture);

    try std.testing.expectEqual(diagnostic.CompletionState.incomplete, result.completion);
    try std.testing.expectEqual(diagnostic.ValidationStage.index, result.first_failure.?.stage);
    try std.testing.expectEqual(diagnostic.FailureReason.resource, result.first_failure.?.reason);
}

test "checkReader_legacy_wrapper_rejects_unreported_oom" {
    const io = std.testing.io;

    var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(std.testing.allocator);
    var reader = std.Io.Reader.fixed("<mzML/>");

    try std.testing.expectError(error.ValidationIncomplete, checkReader(failing_allocator.allocator(), io, &reader, &diagnostics, "inline-oom.mzML", .{
        .skip_binary = true,
        .skip_index = true,
        .skip_semantic = true,
    }, null));
}

test "checkReader_broken_attribute_quote_reports_malformed_xml_diagnostic" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" ++
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\"><run id=\"broken></run></mzML>";

    // Arrange.
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-broken-quote.mzML", .{ .skip_binary = true, .skip_semantic = true }, null);

    // Assert.
    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_xml,
        "unexpected end of XML input",
    );
}

test "checkReader_mismatched_end_tag_reports_malformed_xml_diagnostic" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml = spectrumListMzml(
        "<spectrumList count=\"1\" defaultDataProcessingRef=\"DP1\">" ++
            "<spectrum index=\"0\" id=\"scan=1\" defaultArrayLength=\"1\">" ++
            "<scanList count=\"1\"><scan></scanList>" ++
            "</spectrum>" ++
            "</spectrumList>",
    );

    // Arrange.
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-mismatched-end-tag.mzML", .{ .skip_binary = true, .skip_semantic = true }, null);

    // Assert.
    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_xml,
        "closing tag does not match the most recent opening tag",
    );
}

test "checkReader_invalid_utf8_reports_exact_structure_xml_diagnostic" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml = spectrumListMzml(
        "<spectrumList count=\"1\" defaultDataProcessingRef=\"DP1\">" ++
            "<spectrum index=\"0\" id=\"scan=1\" defaultArrayLength=\"1\">" ++
            "<scanList count=\"1\"><scan>\xc0</scan></scanList>" ++
            "<binaryDataArrayList count=\"2\">" ++
            "<binaryDataArray encodedLength=\"8\"><binary>AAAAAA==</binary></binaryDataArray>" ++
            "<binaryDataArray encodedLength=\"8\"><binary>AAAAAA==</binary></binaryDataArray>" ++
            "</binaryDataArrayList>" ++
            "</spectrum>" ++
            "</spectrumList>",
    );

    // Arrange.
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-invalid-utf8.mzML", .{ .skip_binary = true, .skip_semantic = true }, null);

    // Assert.
    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_xml,
        "invalid UTF-8 in XML input",
    );
}

test "checkReader_wrong_namespace_reports_root_rule_not_generic_xml_failure" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" ++
        "<mzML xmlns=\"urn:not-mzml\" version=\"1.1.0\">\n" ++
        "  <run id=\"run-1\">\n" ++
        "    <spectrumList count=\"0\" defaultDataProcessingRef=\"DP1\"/>\n" ++
        "  </run>\n" ++
        "</mzML>\n";

    // Arrange.
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-wrong-namespace.mzML", .{ .skip_binary = true, .skip_semantic = true }, null);

    // Assert.
    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_root,
        "root element must be mzML in the http://psi.hupo.org/ms/mzml namespace",
    );
}

test "checkReader_text_before_root_reports_structure_xml_diagnostic" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml =
        "junk before root\n" ++
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" ++
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">\n" ++
        "  <run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\">\n" ++
        "    <spectrumList count=\"0\" defaultDataProcessingRef=\"DP1\"/>\n" ++
        "  </run>\n" ++
        "</mzML>\n";

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    try checkReader(allocator, io, &reader, &diagnostics, "inline-text-before-root.mzML", .{ .skip_binary = true, .skip_semantic = true, .skip_index = true }, null);

    var found = false;
    for (diagnostics.items) |d| {
        if (std.mem.eql(u8, d.rule, RuleId.mzml_structure_xml) and
            std.mem.eql(u8, d.message, "text outside the mzML root element is not allowed"))
        {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}

test "checkReader_prefixed_psi_namespace_root_runs_clean_when_skipping_binary" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" ++
        "<ms:mzML xmlns:ms=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">\n" ++
        "  <ms:cvList count=\"1\"><ms:cv id=\"MS\" fullName=\"PSI-MS\" URI=\"https://example.invalid/psi-ms.obo\"/></ms:cvList>\n" ++
        "  <ms:fileDescription><ms:fileContent/></ms:fileDescription>\n" ++
        "  <ms:softwareList count=\"1\"><ms:software id=\"SW1\" version=\"1.0\"/></ms:softwareList>\n" ++
        "  <ms:instrumentConfigurationList count=\"1\"><ms:instrumentConfiguration id=\"IC1\"/></ms:instrumentConfigurationList>\n" ++
        "  <ms:dataProcessingList count=\"1\"><ms:dataProcessing id=\"DP1\"><ms:processingMethod order=\"0\" softwareRef=\"SW1\"/></ms:dataProcessing></ms:dataProcessingList>\n" ++
        "  <ms:run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\">\n" ++
        "    <ms:spectrumList count=\"0\" defaultDataProcessingRef=\"DP1\"/>\n" ++
        "  </ms:run>\n" ++
        "</ms:mzML>\n";

    // Arrange.
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-prefixed-root.mzML", .{ .skip_binary = true, .skip_semantic = true }, null);

    // Assert.
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "checkPath_chromatogram_binary_error_reports_exact_rule_without_spectrum_index" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    const fixture = chromatogramMzmlWithPayloads("%%%%", "AAAAAA==");

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    const path = try stageFixtureInTempDir(allocator, io, &temp_dir, "chromatogram-invalid-base64.mzML", fixture);
    defer allocator.free(path);

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    try checkPath(allocator, io, &diagnostics, path, .{ .skip_semantic = true });

    // Assert.
    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_binary_base64,
        "binary payload is not valid base64",
    );
    try std.testing.expectEqual(@as(?usize, null), diagnostics.items[0].location.spectrum_index);
}

fn forcedMemoryMapFailure(
    io: std.Io,
    file: std.Io.File,
    options: std.Io.File.MemoryMap.CreateOptions,
) std.Io.File.MemoryMap.CreateError!std.Io.File.MemoryMap {
    _ = io;
    _ = file;
    _ = options;
    return error.AccessDenied;
}

fn mapThenTruncate(
    io: std.Io,
    file: std.Io.File,
    options: std.Io.File.MemoryMap.CreateOptions,
) std.Io.File.MemoryMap.CreateError!std.Io.File.MemoryMap {
    var mm = try std.Io.File.MemoryMap.create(io, file, options);
    file.setLength(io, 1) catch {
        mm.destroy(io);
        return error.AccessDenied;
    };
    return mm;
}

test "checkReader_repeated_clean_runs_do_not_accumulate_state" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" ++
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">\n" ++
        "  <cvList count=\"1\"><cv id=\"MS\" fullName=\"Proteomics Standards Initiative Mass Spectrometry Ontology\" version=\"4.1.0\" URI=\"https://raw.githubusercontent.com/HUPO-PSI/psi-ms-CV/master/psi-ms.obo\"/></cvList>\n" ++
        "  <fileDescription><fileContent><cvParam cvRef=\"MS\" accession=\"MS:1000579\" name=\"MS1 spectrum\"/></fileContent></fileDescription>\n" ++
        "  <softwareList count=\"1\"><software id=\"SW1\" version=\"0.0.3\"><cvParam cvRef=\"MS\" accession=\"MS:1000531\" name=\"software\"/></software></softwareList>\n" ++
        "  <instrumentConfigurationList count=\"1\"><instrumentConfiguration id=\"IC1\"><componentList count=\"3\"><source order=\"1\"><cvParam cvRef=\"MS\" accession=\"MS:1000008\" name=\"ionization type\"/></source><analyzer order=\"2\"><cvParam cvRef=\"MS\" accession=\"MS:1000443\" name=\"mass analyzer type\"/></analyzer><detector order=\"3\"><cvParam cvRef=\"MS\" accession=\"MS:1000026\" name=\"detector type\"/></detector></componentList></instrumentConfiguration></instrumentConfigurationList>\n" ++
        "  <dataProcessingList count=\"1\"><dataProcessing id=\"DP1\"><processingMethod order=\"0\" softwareRef=\"SW1\"><cvParam cvRef=\"MS\" accession=\"MS:1000544\" name=\"Conversion to mzML\"/></processingMethod></dataProcessing></dataProcessingList>\n" ++
        "  <run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\"><spectrumList count=\"1\" defaultDataProcessingRef=\"DP1\"><spectrum index=\"0\" id=\"scan=1\" defaultArrayLength=\"1\"><scanList count=\"1\"><scan/></scanList><binaryDataArrayList count=\"2\"><binaryDataArray encodedLength=\"8\"><cvParam cvRef=\"MS\" accession=\"MS:1000521\" name=\"32-bit float\"/><cvParam cvRef=\"MS\" accession=\"MS:1000576\" name=\"no compression\"/><cvParam cvRef=\"MS\" accession=\"MS:1000514\" name=\"m/z array\" unitCvRef=\"MS\" unitAccession=\"MS:1000040\" unitName=\"m/z\"/><binary>AAAAAA==</binary></binaryDataArray><binaryDataArray encodedLength=\"8\"><cvParam cvRef=\"MS\" accession=\"MS:1000521\" name=\"32-bit float\"/><cvParam cvRef=\"MS\" accession=\"MS:1000576\" name=\"no compression\"/><cvParam cvRef=\"MS\" accession=\"MS:1000515\" name=\"intensity array\" unitCvRef=\"MS\" unitAccession=\"MS:1000131\" unitName=\"number of counts\"/><binary>AAAAAA==</binary></binaryDataArray></binaryDataArrayList></spectrum></spectrumList></run>\n" ++
        "</mzML>\n";

    // Arrange.
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    for (0..32) |_| {
        diagnostics.clearRetainingCapacity();
        var reader = std.Io.Reader.fixed(xml);
        try checkReader(allocator, io, &reader, &diagnostics, "inline-repeated-clean.mzML", .{ .skip_semantic = true }, null);

        // Assert.
        try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
    }
}

test "checkReader_empty_spectrum_list_is_clean_when_skipping_binary" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml = spectrumListMzml("<spectrumList count=\"0\" defaultDataProcessingRef=\"DP1\"/>");

    // Arrange.
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-empty-spectrum-list.mzML", .{ .skip_binary = true, .skip_semantic = true }, null);

    // Assert.
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "checkReader_multiple_spectra_are_clean_when_structure_is_valid" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml = spectrumListMzml(
        "<spectrumList count=\"2\" defaultDataProcessingRef=\"DP1\">" ++
            spectrumXml(0, true) ++
            spectrumXml(1, true) ++
            "</spectrumList>",
    );

    // Arrange.
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-multiple-spectra.mzML", .{ .skip_binary = true, .skip_semantic = true }, null);

    // Assert.
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "checkReader_missing_binary_data_array_list_reports_exact_structure_rule" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml = spectrumListMzml(
        "<spectrumList count=\"1\" defaultDataProcessingRef=\"DP1\">" ++
            "<spectrum index=\"0\" id=\"scan=1\" defaultArrayLength=\"1\">" ++
            "<scanList count=\"1\"><scan/></scanList>" ++
            "</spectrum>" ++
            "</spectrumList>",
    );

    // Arrange.
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-missing-binary-list.mzML", .{ .skip_binary = true, .skip_semantic = true }, null);

    // Assert.
    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_missing_child,
        "spectrum is missing required child binaryDataArrayList",
    );
}

test "checkReader_out_of_order_top_level_child_reports_exact_nesting_rule" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" ++
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">" ++
        "<cvList count=\"1\"><cv id=\"MS\" fullName=\"PSI-MS\" URI=\"https://example.invalid/psi-ms.obo\"/></cvList>" ++
        "<fileDescription><fileContent/></fileDescription>" ++
        "<softwareList count=\"1\"><software id=\"SW1\" version=\"1.0\"/></softwareList>" ++
        "<dataProcessingList count=\"1\"><dataProcessing id=\"DP1\"><processingMethod order=\"0\" softwareRef=\"SW1\"/></dataProcessing></dataProcessingList>" ++
        "<instrumentConfigurationList count=\"1\"><instrumentConfiguration id=\"IC1\"/></instrumentConfigurationList>" ++
        "<run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\"><spectrumList count=\"0\" defaultDataProcessingRef=\"DP1\"/></run>" ++
        "</mzML>";

    // Arrange.
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-out-of-order-top-level.mzML", .{ .skip_binary = true, .skip_semantic = true }, null);

    // Assert.
    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_nesting,
        "instrumentConfigurationList appears out of order under mzML",
    );
}

test "checkReader_oversized_attribute_maps_parser_limit_to_structure_xml_diagnostic" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    const xml = try oversizedAttributeValueMzml(allocator, max_validation_token_bytes + 1);
    defer allocator.free(xml);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-oversized-text.mzML", .{ .skip_binary = true, .skip_semantic = true }, null);

    // Assert.
    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_xml,
        "XML attribute exceeds the configured attribute limit",
    );
}

test "checkReader_excessive_attribute_count_maps_parser_limit_to_structure_xml_diagnostic" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    const xml = try tooManyAttributesXml(allocator, 65);
    defer allocator.free(xml);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-too-many-attributes.mzML", .{ .skip_binary = true, .skip_semantic = true }, null);

    // Assert.
    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_xml,
        "XML element has more attributes than the configured parser limit",
    );
}

test "checkReader_excessive_namespace_bindings_map_parser_limit_to_structure_xml_diagnostic" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    const xml = try tooManyNamespacesXml(allocator, 33);
    defer allocator.free(xml);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-too-many-namespaces.mzML", .{ .skip_binary = true, .skip_semantic = true }, null);

    // Assert.
    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_xml,
        "XML namespace bindings exceed the configured parser limit",
    );
}

test "checkReader_excessive_element_name_storage_maps_parser_limit_to_structure_xml_diagnostic" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const xml = try tooDeepXml(allocator, 129);
    defer allocator.free(xml);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    try checkReader(allocator, io, &reader, &diagnostics, "inline-too-deep.mzML", .{ .skip_binary = true, .skip_semantic = true }, null);

    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_xml,
        "XML element name storage exceeds the configured parser limit",
    );
}

test "checkPath_existingFile_reportsStructuralErrorWithoutBinaryNoise" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/examples/mzml/wrong-namespace.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();

    const path = try stageFixtureInTempDir(allocator, io, &temp_dir, "broken.mzML", fixture);
    defer allocator.free(path);

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    try checkPath(allocator, io, &diagnostics, path, .{ .skip_semantic = true });

    // Assert.
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqual(diagnostic.Severity.@"error", diagnostics.items[0].severity);
    try std.testing.expectEqualStrings(RuleId.mzml_structure_root, diagnostics.items[0].rule);
}

test "checkPath_existingFile_skips_binary_warning_when_structure_is_broken_and_skip_binary_is_enabled" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/examples/mzml/wrong-namespace.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();

    const path = try stageFixtureInTempDir(allocator, io, &temp_dir, "broken.mzML", fixture);
    defer allocator.free(path);

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    try checkPath(allocator, io, &diagnostics, path, .{ .skip_binary = true, .skip_semantic = true });

    // Assert.
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqual(diagnostic.Severity.@"error", diagnostics.items[0].severity);
    try std.testing.expectEqualStrings(RuleId.mzml_structure_root, diagnostics.items[0].rule);
}

// Tests: binary failure handling.

test "checkPath_corruptBinary_reportsBinaryDiagnostic" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/invalid/invalid-base64.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    const path = try stageFixtureInTempDir(allocator, io, &temp_dir, "corrupt-binary.mzML", fixture);
    defer allocator.free(path);

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    try checkPath(allocator, io, &diagnostics, path, .{ .skip_semantic = true });

    // Assert.
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_binary_base64, diagnostics.items[0].rule);
}

test "checkPath_corruptBinary_is_clean_when_skip_binary_is_enabled" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/invalid/invalid-base64.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    const path = try stageFixtureInTempDir(allocator, io, &temp_dir, "corrupt-binary.mzML", fixture);
    defer allocator.free(path);

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    try checkPath(allocator, io, &diagnostics, path, .{ .skip_binary = true, .skip_semantic = true });

    // Assert.
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "checkReader_empty_binary_payload_reports_exact_length_mismatch" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml = binarySpectrumListMzml("", "AAAAAA==", 1, "MS:1000576");

    // Arrange.
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-empty-binary.mzML", .{ .skip_semantic = true }, null);

    // Assert.
    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_binary_length_mismatch,
        "decoded array length does not match defaultArrayLength",
    );
}

test "checkReader_valid_zlib_payload_with_wrong_declared_length_reports_exact_length_mismatch" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml = binarySpectrumListMzml("eJxjYGBgAAAABAAB", "AAAAAAAAAAA=", 2, "MS:1000574");

    // Arrange.
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-zlib-length-mismatch.mzML", .{ .skip_semantic = true }, null);

    // Assert.
    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_binary_length_mismatch,
        "decoded array length does not match defaultArrayLength",
    );
}

test "checkPath_reports_conflictingCompression_fixture" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    try checkPath(allocator, io, &diagnostics, "fixtures/mzml/invalid/conflicting-compression.mzML", .{ .skip_semantic = true });
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_binary_compression, diagnostics.items[0].rule);
}

test "checkPath_reports_unsupportedCompression_fixture" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    try checkPath(allocator, io, &diagnostics, "fixtures/mzml/invalid/unsupported-compression.mzML", .{ .skip_semantic = true });

    // Assert.
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_binary_compression, diagnostics.items[0].rule);
}

// Tests: invalid fixture corpus behavior.

test "checkPath_invalidMzMLBinaryCorpus_reportsExactRulePerFixture" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const expectations = [_]InvalidBinaryExpectation{
        .{ .sub_path = "fixtures/mzml/invalid/conflicting-compression.mzML", .rule = RuleId.mzml_binary_compression, .message = "binaryDataArray declares conflicting compression terms" },
        .{ .sub_path = "fixtures/mzml/invalid/conflicting-precision.mzML", .rule = RuleId.mzml_binary_precision_mismatch, .message = "binaryDataArray declares conflicting 32-bit and 64-bit precision" },
        .{ .sub_path = "fixtures/mzml/invalid/invalid-base64.mzML", .rule = RuleId.mzml_binary_base64, .message = "binary payload is not valid base64" },
        .{ .sub_path = "fixtures/mzml/invalid/invalid-zlib.mzML", .rule = RuleId.mzml_binary_decompress, .message = "binary payload is not valid zlib data" },
        .{ .sub_path = "fixtures/mzml/invalid/unsupported-compression.mzML", .rule = RuleId.mzml_binary_compression, .message = "binaryDataArray declares unsupported compression terms" },
    };

    // Act.
    for (expectations) |expectation| {
        var diagnostics: DiagnosticSink = .empty;
        defer diagnostics.deinit(allocator);
        try checkPath(allocator, io, &diagnostics, expectation.sub_path, .{ .skip_semantic = true });

        // Assert.
        try expectSingleDiagnostic(diagnostics.items, expectation.rule, expectation.message);
    }
}

test "checkPath_invalidMzMLBinaryCorpus_is_clean_when_skip_binary_is_enabled" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const root = "fixtures/mzml/invalid";

    // Act.
    const fixture_count = try expectCorpusDiagnostics(
        allocator,
        io,
        root,
        .{ .skip_binary = true, .skip_semantic = true },
        .clean,
    );

    // Assert.
    try std.testing.expect(fixture_count > 0);
}

test "checkPath_repeated_clean_and_corrupt_runs_reset_diagnostics_between_invocations" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    const clean_fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/examples/mzml/single-spectrum-missing-cv-terms.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(clean_fixture);
    const corrupt_fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/invalid/invalid-base64.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(corrupt_fixture);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    const clean_path = try stageFixtureInTempDir(allocator, io, &temp_dir, "repeated-clean.mzML", clean_fixture);
    defer allocator.free(clean_path);
    const corrupt_path = try stageFixtureInTempDir(allocator, io, &temp_dir, "repeated-corrupt.mzML", corrupt_fixture);
    defer allocator.free(corrupt_path);

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    for (0..24) |index| {
        const path = if (index % 2 == 0) clean_path else corrupt_path;
        diagnostics.clearRetainingCapacity();
        try checkPath(allocator, io, &diagnostics, path, .{ .skip_semantic = true });

        // Assert.
        if (index % 2 == 0) {
            try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
        } else {
            try expectSingleDiagnostic(
                diagnostics.items,
                RuleId.mzml_binary_base64,
                "binary payload is not valid base64",
            );
        }
    }
}

// --- Test helpers ---

const CorpusExpectation = enum {
    clean,
    non_empty,
};

const InvalidBinaryExpectation = struct {
    sub_path: []const u8,
    rule: []const u8,
    message: []const u8,
};

fn stageFixtureInTempDir(
    allocator: std.mem.Allocator,
    io: std.Io,
    temp_dir: *std.testing.TmpDir,
    file_name: []const u8,
    fixture: []const u8,
) ![]u8 {
    try temp_dir.dir.writeFile(io, .{ .sub_path = file_name, .data = fixture });
    return tempFixturePath(allocator, temp_dir.sub_path[0..], file_name);
}

// Builds bytes of a minimal indexed mzML whose fileChecksum is correct
// for the content before the `<fileChecksum>` element.
fn indexedMzmlWithSha(allocator: std.mem.Allocator, sha_hex: []const u8) ![]u8 {
    const prefix =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" ++
        "<indexedmzML xmlns=\"http://psi.hupo.org/ms/mzml\">\n" ++
        "  <mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">\n" ++
        "    <cvList count=\"1\"><cv id=\"MS\" fullName=\"PSI-MS\" URI=\"\"/></cvList>\n" ++
        "    <fileDescription><fileContent/></fileDescription>\n" ++
        "    <softwareList count=\"1\"><software id=\"sw\" version=\"1.0\"/></softwareList>\n" ++
        "    <instrumentConfigurationList count=\"1\"><instrumentConfiguration id=\"ic\"/></instrumentConfigurationList>\n" ++
        "    <dataProcessingList count=\"1\"><dataProcessing id=\"dp\"><processingMethod order=\"0\" softwareRef=\"sw\"/></dataProcessing></dataProcessingList>\n" ++
        "    <run id=\"r\" defaultInstrumentConfigurationRef=\"ic\">\n" ++
        "      <spectrumList count=\"0\" defaultDataProcessingRef=\"dp\"/>\n" ++
        "    </run>\n" ++
        "  </mzML>\n" ++
        "  <indexList count=\"1\"><index name=\"spectrum\"/></indexList>\n" ++
        "  <indexListOffset>10</indexListOffset>\n";
    const indent = "  ";

    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(allocator);
    try buf.appendSlice(allocator, prefix);
    try buf.appendSlice(allocator, indent);
    try buf.appendSlice(allocator, "<fileChecksum>");
    try buf.appendSlice(allocator, sha_hex);
    try buf.appendSlice(allocator, "</fileChecksum>\n</indexedmzML>\n");
    return try buf.toOwnedSlice(allocator);
}

fn tempFixturePath(allocator: std.mem.Allocator, temp_sub_path: []const u8, file_name: []const u8) ![]u8 {
    return std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", temp_sub_path, file_name });
}

fn writeSyntheticLargeMzmlFixture(
    io: std.Io,
    temp_dir: *std.testing.TmpDir,
    file_name: []const u8,
    spectrum_count: usize,
) !usize {
    var file = try temp_dir.dir.createFile(io, file_name, .{});
    defer file.close(io);

    var writer_buffer: [4096]u8 = undefined;
    var file_writer = file.writer(io, &writer_buffer);
    const writer = &file_writer.interface;

    try writeSyntheticMzmlPreamble(writer, spectrum_count);
    for (0..spectrum_count) |index| {
        try writeSyntheticSpectrum(writer, index);
    }
    try writeSyntheticMzmlPostamble(writer);
    try writer.flush();

    return @intCast((try file.stat(io)).size);
}

fn expectCorpusDiagnostics(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    options: CheckOptions,
    expectation: CorpusExpectation,
) !usize {
    var corpus_dir = try std.Io.Dir.cwd().openDir(io, root, .{ .iterate = true });
    defer corpus_dir.close(io);

    var walker = try corpus_dir.walk(allocator);
    defer walker.deinit();

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var fixture_count: usize = 0;
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.path, ".mzML")) continue;

        const path = try std.fs.path.join(allocator, &.{ root, entry.path });
        defer allocator.free(path);

        diagnostics.clearRetainingCapacity();
        try checkPath(allocator, io, &diagnostics, path, options);

        switch (expectation) {
            .clean => {
                if (diagnostics.items.len != 0) {
                    std.debug.print(
                        "unexpected diagnostics for {s}: first rule={s} message={s}\n",
                        .{ path, diagnostics.items[0].rule, diagnostics.items[0].message },
                    );
                    return error.TestUnexpectedResult;
                }
            },
            .non_empty => {
                if (diagnostics.items.len == 0) {
                    std.debug.print("expected diagnostics for {s}, but run was clean\n", .{path});
                    return error.TestUnexpectedResult;
                }
            },
        }
        fixture_count += 1;
    }

    return fixture_count;
}

fn writeSyntheticMzmlPreamble(writer: *std.Io.Writer, spectrum_count: usize) !void {
    try writer.writeAll(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" ++
            "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">\n" ++
            "  <cvList count=\"1\">\n" ++
            "    <cv id=\"MS\" fullName=\"Proteomics Standards Initiative Mass Spectrometry Ontology\" version=\"4.1.0\" URI=\"https://raw.githubusercontent.com/HUPO-PSI/psi-ms-CV/master/psi-ms.obo\"/>\n" ++
            "  </cvList>\n" ++
            "  <fileDescription>\n" ++
            "    <fileContent>\n" ++
            "      <cvParam cvRef=\"MS\" accession=\"MS:1000579\" name=\"MS1 spectrum\"/>\n" ++
            "    </fileContent>\n" ++
            "  </fileDescription>\n" ++
            "  <softwareList count=\"1\">\n" ++
            "    <software id=\"SW1\" version=\"0.0.3\">\n" ++
            "      <cvParam cvRef=\"MS\" accession=\"MS:1000531\" name=\"software\"/>\n" ++
            "    </software>\n" ++
            "  </softwareList>\n" ++
            "  <instrumentConfigurationList count=\"1\">\n" ++
            "    <instrumentConfiguration id=\"IC1\">\n" ++
            "      <componentList count=\"3\">\n" ++
            "        <source order=\"1\">\n" ++
            "          <cvParam cvRef=\"MS\" accession=\"MS:1000008\" name=\"ionization type\"/>\n" ++
            "        </source>\n" ++
            "        <analyzer order=\"2\">\n" ++
            "          <cvParam cvRef=\"MS\" accession=\"MS:1000443\" name=\"mass analyzer type\"/>\n" ++
            "        </analyzer>\n" ++
            "        <detector order=\"3\">\n" ++
            "          <cvParam cvRef=\"MS\" accession=\"MS:1000026\" name=\"detector type\"/>\n" ++
            "        </detector>\n" ++
            "      </componentList>\n" ++
            "    </instrumentConfiguration>\n" ++
            "  </instrumentConfigurationList>\n" ++
            "  <dataProcessingList count=\"1\">\n" ++
            "    <dataProcessing id=\"DP1\">\n" ++
            "      <processingMethod order=\"0\" softwareRef=\"SW1\">\n" ++
            "        <cvParam cvRef=\"MS\" accession=\"MS:1000544\" name=\"Conversion to mzML\"/>\n" ++
            "      </processingMethod>\n" ++
            "    </dataProcessing>\n" ++
            "  </dataProcessingList>\n" ++
            "  <run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\">\n",
    );
    try writer.print("    <spectrumList count=\"{d}\" defaultDataProcessingRef=\"DP1\">\n", .{spectrum_count});
}

fn writeSyntheticSpectrum(writer: *std.Io.Writer, index: usize) !void {
    try writer.print(
        "      <spectrum index=\"{d}\" id=\"scan={d}\" defaultArrayLength=\"1\">\n" ++
            "        <scanList count=\"1\">\n" ++
            "          <scan/>\n" ++
            "        </scanList>\n" ++
            "        <binaryDataArrayList count=\"2\">\n" ++
            "          <binaryDataArray encodedLength=\"8\">\n" ++
            "            <cvParam cvRef=\"MS\" accession=\"MS:1000521\" name=\"32-bit float\"/>\n" ++
            "            <cvParam cvRef=\"MS\" accession=\"MS:1000576\" name=\"no compression\"/>\n" ++
            "            <cvParam cvRef=\"MS\" accession=\"MS:1000514\" name=\"m/z array\" unitCvRef=\"MS\" unitAccession=\"MS:1000040\" unitName=\"m/z\"/>\n" ++
            "            <binary>AAAAAA==</binary>\n" ++
            "          </binaryDataArray>\n" ++
            "          <binaryDataArray encodedLength=\"8\">\n" ++
            "            <cvParam cvRef=\"MS\" accession=\"MS:1000521\" name=\"32-bit float\"/>\n" ++
            "            <cvParam cvRef=\"MS\" accession=\"MS:1000576\" name=\"no compression\"/>\n" ++
            "            <cvParam cvRef=\"MS\" accession=\"MS:1000515\" name=\"intensity array\" unitCvRef=\"MS\" unitAccession=\"MS:1000131\" unitName=\"number of counts\"/>\n" ++
            "            <binary>AAAAAA==</binary>\n" ++
            "          </binaryDataArray>\n" ++
            "        </binaryDataArrayList>\n" ++
            "      </spectrum>\n",
        .{ index, index + 1 },
    );
}

fn writeSyntheticMzmlPostamble(writer: *std.Io.Writer) !void {
    try writer.writeAll(
        "    </spectrumList>\n" ++
            "  </run>\n" ++
            "</mzML>\n",
    );
}

fn chromatogramMzmlWithPayloads(comptime first_payload: []const u8, comptime second_payload: []const u8) []const u8 {
    return "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">" ++
        "<cvList count=\"1\"><cv id=\"MS\" fullName=\"PSI-MS\" URI=\"https://example.invalid/psi-ms.obo\"/></cvList>" ++
        "<fileDescription><fileContent/></fileDescription>" ++
        "<softwareList count=\"1\"><software id=\"SW1\" version=\"1.0\"/></softwareList>" ++
        "<instrumentConfigurationList count=\"1\"><instrumentConfiguration id=\"IC1\"/></instrumentConfigurationList>" ++
        "<dataProcessingList count=\"1\"><dataProcessing id=\"DP1\"><processingMethod order=\"0\" softwareRef=\"SW1\"/></dataProcessing></dataProcessingList>" ++
        "<run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\">" ++
        "<chromatogramList count=\"1\" defaultDataProcessingRef=\"DP1\">" ++
        "<chromatogram index=\"0\" id=\"tic=1\" defaultArrayLength=\"1\">" ++
        "<precursor/>" ++
        "<product/>" ++
        "<binaryDataArrayList count=\"2\">" ++
        "<binaryDataArray encodedLength=\"8\"><cvParam accession=\"MS:1000521\"/><cvParam accession=\"MS:1000576\"/><cvParam accession=\"MS:1000595\"/><binary>" ++ first_payload ++ "</binary></binaryDataArray>" ++
        "<binaryDataArray encodedLength=\"8\"><cvParam accession=\"MS:1000521\"/><cvParam accession=\"MS:1000576\"/><cvParam accession=\"MS:1000515\"/><binary>" ++ second_payload ++ "</binary></binaryDataArray>" ++
        "</binaryDataArrayList>" ++
        "</chromatogram>" ++
        "</chromatogramList>" ++
        "</run>" ++
        "</mzML>";
}

fn binarySpectrumListMzml(comptime payload: []const u8, comptime second_payload: []const u8, comptime default_array_length: usize, comptime compression_accession: []const u8) []const u8 {
    return spectrumListMzml(
        "<spectrumList count=\"1\" defaultDataProcessingRef=\"DP1\">" ++
            "<spectrum index=\"0\" id=\"scan=1\" defaultArrayLength=\"" ++ comptimeUnsigned(default_array_length) ++ "\">" ++
            "<scanList count=\"1\"><scan/></scanList>" ++
            "<binaryDataArrayList count=\"2\">" ++
            "<binaryDataArray encodedLength=\"" ++ comptimeUnsigned(payload.len) ++ "\">" ++
            "<cvParam accession=\"MS:1000521\"/>" ++
            "<cvParam accession=\"" ++ compression_accession ++ "\"/>" ++
            "<cvParam accession=\"MS:1000514\"/>" ++
            "<binary>" ++ payload ++ "</binary>" ++
            "</binaryDataArray>" ++
            "<binaryDataArray encodedLength=\"" ++ comptimeUnsigned(second_payload.len) ++ "\">" ++
            "<cvParam accession=\"MS:1000521\"/>" ++
            "<cvParam accession=\"MS:1000576\"/>" ++
            "<cvParam accession=\"MS:1000515\"/>" ++
            "<binary>" ++ second_payload ++ "</binary>" ++
            "</binaryDataArray>" ++
            "</binaryDataArrayList>" ++
            "</spectrum>" ++
            "</spectrumList>",
    );
}

fn spectrumListMzml(comptime spectrum_list_xml: []const u8) []const u8 {
    return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" ++
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\">" ++
        "<cvList count=\"1\"><cv id=\"MS\" fullName=\"PSI-MS\" URI=\"https://example.invalid/psi-ms.obo\"/></cvList>" ++
        "<fileDescription><fileContent/></fileDescription>" ++
        "<softwareList count=\"1\"><software id=\"SW1\" version=\"1.0\"/></softwareList>" ++
        "<instrumentConfigurationList count=\"1\"><instrumentConfiguration id=\"IC1\"/></instrumentConfigurationList>" ++
        "<dataProcessingList count=\"1\"><dataProcessing id=\"DP1\"><processingMethod order=\"0\" softwareRef=\"SW1\"/></dataProcessing></dataProcessingList>" ++
        "<run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\">" ++
        spectrum_list_xml ++
        "</run>" ++
        "</mzML>";
}

fn spectrumXml(comptime index: usize, comptime include_binary_list: bool) []const u8 {
    return if (include_binary_list)
        "<spectrum index=\"" ++ comptimeUnsigned(index) ++ "\" id=\"scan=" ++ comptimeUnsigned(index + 1) ++ "\" defaultArrayLength=\"1\">" ++
            "<scanList count=\"1\"><scan/></scanList>" ++
            "<binaryDataArrayList count=\"2\">" ++
            "<binaryDataArray encodedLength=\"8\"><binary>AAAAAA==</binary></binaryDataArray>" ++
            "<binaryDataArray encodedLength=\"8\"><binary>AAAAAA==</binary></binaryDataArray>" ++
            "</binaryDataArrayList>" ++
            "</spectrum>"
    else
        "<spectrum index=\"" ++ comptimeUnsigned(index) ++ "\" id=\"scan=" ++ comptimeUnsigned(index + 1) ++ "\" defaultArrayLength=\"1\">" ++
            "<scanList count=\"1\"><scan/></scanList>" ++
            "</spectrum>";
}

fn comptimeUnsigned(comptime value: usize) []const u8 {
    return std.fmt.comptimePrint("{d}", .{value});
}

fn expectSingleDiagnostic(diagnostics: []const Diagnostic, expected_rule: []const u8, expected_message: []const u8) !void {
    try std.testing.expectEqual(@as(usize, 1), diagnostics.len);
    try std.testing.expectEqualStrings(expected_rule, diagnostics[0].rule);
    try std.testing.expectEqualStrings(expected_message, diagnostics[0].message);
}

fn oversizedAttributeValueMzml(allocator: std.mem.Allocator, text_len: usize) ![]u8 {
    var xml: std.ArrayList(u8) = .empty;
    errdefer xml.deinit(allocator);

    try xml.appendSlice(allocator, "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\"><run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\"><blob value=\"");
    try xml.resize(allocator, xml.items.len + text_len);
    @memset(xml.items[xml.items.len - text_len ..], 'a');
    try xml.appendSlice(allocator, "\"/></run></mzML>");
    return try xml.toOwnedSlice(allocator);
}

fn tooManyAttributesXml(allocator: std.mem.Allocator, attribute_count: usize) ![]u8 {
    var xml: std.ArrayList(u8) = .empty;
    errdefer xml.deinit(allocator);

    try xml.appendSlice(allocator, "<root");
    for (0..attribute_count) |index| {
        const fragment = try std.fmt.allocPrint(allocator, " a{d}=\"x\"", .{index});
        defer allocator.free(fragment);
        try xml.appendSlice(allocator, fragment);
    }
    try xml.appendSlice(allocator, "/>");
    return try xml.toOwnedSlice(allocator);
}

fn tooManyNamespacesXml(allocator: std.mem.Allocator, namespace_count: usize) ![]u8 {
    var xml: std.ArrayList(u8) = .empty;
    errdefer xml.deinit(allocator);

    try xml.appendSlice(allocator, "<root");
    for (0..namespace_count) |index| {
        const fragment = try std.fmt.allocPrint(allocator, " xmlns:p{d}=\"urn:{d}\"", .{ index, index });
        defer allocator.free(fragment);
        try xml.appendSlice(allocator, fragment);
    }
    try xml.appendSlice(allocator, "/>");
    return try xml.toOwnedSlice(allocator);
}

fn tooDeepXml(allocator: std.mem.Allocator, depth: usize) ![]u8 {
    var xml: std.ArrayList(u8) = .empty;
    errdefer xml.deinit(allocator);

    try xml.appendSlice(allocator, "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\"><run id=\"run-1\" defaultInstrumentConfigurationRef=\"IC1\">");
    for (0..depth) |_| {
        try xml.appendSlice(allocator, "<cvParam>");
    }
    for (0..depth) |_| {
        try xml.appendSlice(allocator, "</cvParam>");
    }
    try xml.appendSlice(allocator, "</run></mzML>");
    return try xml.toOwnedSlice(allocator);
}
