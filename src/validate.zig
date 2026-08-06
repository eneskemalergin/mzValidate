//! Entry points for running validation against files or streams.
//!
//! Coordinates slice, reader, and regular-file validation.
//!
//! Parser and validators share one primary event pass. Regular files use bounded stream
//! input with file-stability checks around validation.

const std = @import("std");
const binary = @import("mzml/binary.zig");
const diagnostic = @import("diagnostic.zig");
const elements = @import("mzml/elements.zig");
const mzml_index = @import("mzml/index.zig");
const obo_parser = @import("obo/parser.zig");
const progress = @import("progress.zig");
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
/// Synchronous, caller-owned byte-progress callback for regular-file validation.
pub const ProgressObserver = progress.Observer;
const max_validation_token_bytes = 1024 * 1024;
const stream_input_buffer_bytes = 64 * 1024;

// --- Public entry points ---

/// Per-run flags for `checkPath`, `checkSlice`, and `checkReader`.
/// `obo_path` is borrowed only while an invocation context is initialized.
pub const CheckOptions = struct {
    skip_binary: bool = false,
    skip_index: bool = false,
    skip_semantic: bool = false,
    max_binary_size: ?usize = null,
    resource_limits: diagnostic.ResourceLimits = .{},
    obo_path: ?[]const u8 = null,
};

/// Invocation-owned heap capacity shared by every file checked through one context.
/// Counts are allocator-requested bytes; allocator metadata and external library
/// state remain visible only in process RSS.
pub const InvocationResourceUsage = struct {
    obo_source_peak_bytes: usize = 0,
    catalog_current_bytes: usize = 0,
    catalog_peak_bytes: usize = 0,
    /// Construction peak while a custom source and the growing catalog overlap.
    peak_bytes: usize = 0,
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
/// The allocator and I/O handle must outlive the context; returned file results do not.
pub const InvocationContext = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    options: CheckOptions,
    catalog: ?SemanticCatalog = null,
    catalog_failure: ?CatalogFailure = null,
    resource_usage: InvocationResourceUsage = .{},

    /// Builds the semantic catalog once. A catalog failure is retained as fixed
    /// metadata so file validation can stop before opening an input.
    pub fn init(allocator: std.mem.Allocator, io: std.Io, options: CheckOptions) InvocationContext {
        var context = InvocationContext{
            .allocator = allocator,
            .io = io,
            .options = options,
        };
        if (!options.skip_semantic) context.buildCatalog();
        context.options.obo_path = null;
        return context;
    }

    pub fn deinit(context: *InvocationContext) void {
        if (context.catalog) |*catalog| catalog.deinit();
        context.* = undefined;
    }

    /// Returns shared invocation capacity without charging it to each file result.
    pub fn resourceUsage(context: *const InvocationContext) InvocationResourceUsage {
        var usage = context.resource_usage;
        if (context.catalog) |*catalog| {
            usage.catalog_current_bytes = catalog.cv_table.currentBytes();
            usage.catalog_peak_bytes = catalog.cv_table.peakBytes();
            usage.peak_bytes = std.math.add(
                usize,
                usage.obo_source_peak_bytes,
                usage.catalog_peak_bytes,
            ) catch std.math.maxInt(usize);
        }
        return usage;
    }

    /// Validates one path using this invocation's immutable resources.
    /// Diagnostics borrow their string fields; the returned result owns its metadata.
    pub fn validateOne(
        context: *InvocationContext,
        diagnostics: *DiagnosticSink,
        path: []const u8,
    ) FileResult {
        return context.validateOneMode(false, diagnostics, path, {});
    }

    /// Validates one regular-file path while synchronously reporting bounded byte progress.
    pub fn validateOneWithProgress(
        context: *InvocationContext,
        diagnostics: *DiagnosticSink,
        path: []const u8,
        observer: ProgressObserver,
    ) FileResult {
        return context.validateOneMode(true, diagnostics, path, observer);
    }

    fn validateOneMode(
        context: *InvocationContext,
        comptime report_progress: bool,
        diagnostics: *DiagnosticSink,
        path: []const u8,
        observer: if (report_progress) ProgressObserver else void,
    ) FileResult {
        diagnostics.configureFromResourceLimits(context.options.resource_limits);
        if (context.catalog_failure != null) return context.catalogFailureResult(diagnostics, path);

        var result = FileResult.init(enabledStages(context.options));
        const diagnostic_mark = diagnostics.mark();
        checkPathInternal(report_progress, context, diagnostics, path, &result, observer) catch |err| {
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
            const text = cwd.readFileAlloc(
                context.io,
                obo_path,
                context.allocator,
                .limited(options.resource_limits.max_obo_source_bytes),
            ) catch |err| {
                const source_limit = err == error.StreamTooLong;
                context.catalog_failure = .{
                    .reason = if (err == error.OutOfMemory) .allocation else if (source_limit) .resource else .catalog,
                    .rule = if (source_limit) RuleId.runtime_catalog_limit else RuleId.runtime_file_open,
                    .message = if (source_limit) "custom OBO source exceeds the configured size limit" else "unable to read OBO file",
                };
                break :blk null;
            };
            context.resource_usage.obo_source_peak_bytes = text.len;
            context.resource_usage.peak_bytes = text.len;
            break :blk text;
        } else @embedFile("data/psi-ms.obo");
        const text = obo_text orelse return;
        defer if (options.obo_path != null) context.allocator.free(text);

        var table = obo_parser.CvTable.initWithLimits(context.allocator, text, options.resource_limits) catch |err| {
            const catalog_limit = err == error.ResourceLimitExceeded;
            context.catalog_failure = .{
                .reason = if (catalog_limit) .resource else if (err == error.OutOfMemory) .allocation else .catalog,
                .rule = if (catalog_limit) RuleId.runtime_catalog_limit else RuleId.runtime_catalog,
                .message = if (err == error.OutOfMemory) "unable to allocate OBO state" else obo_parser.parseErrorMessage(err),
            };
            return;
        };

        var engine = rule_engine.RuleEngine.init(table.catalogAllocator(), @embedFile("data/ms-mapping.xml")) catch |err| {
            const catalog_limit = table.limitExceeded();
            context.recordCatalogUsage(&table);
            table.deinit();
            context.resource_usage.catalog_current_bytes = 0;
            context.catalog_failure = .{
                .reason = if (catalog_limit) .resource else if (err == error.OutOfMemory) .allocation else .catalog,
                .rule = if (catalog_limit) RuleId.runtime_catalog_limit else RuleId.runtime_catalog,
                .message = if (catalog_limit)
                    "semantic catalog exceeds the configured memory limit"
                else if (err == error.OutOfMemory)
                    "unable to allocate mapping state"
                else
                    "unable to parse mapping rules",
            };
            return;
        };

        if (engine.firstMissingVocabularyTerm(&table) != null) {
            context.recordCatalogUsage(&table);
            engine.deinit();
            table.deinit();
            context.resource_usage.catalog_current_bytes = 0;
            context.catalog_failure = .{
                .reason = .catalog,
                .rule = RuleId.runtime_catalog,
                .message = "embedded mapping policy is incompatible with the selected OBO vocabulary",
            };
            return;
        }

        context.catalog = .{ .cv_table = table, .rule_engine = engine };
    }

    fn recordCatalogUsage(context: *InvocationContext, table: *const obo_parser.CvTable) void {
        context.resource_usage.catalog_current_bytes = table.currentBytes();
        context.resource_usage.catalog_peak_bytes = table.peakBytes();
        context.resource_usage.peak_bytes = std.math.add(
            usize,
            context.resource_usage.obo_source_peak_bytes,
            context.resource_usage.catalog_peak_bytes,
        ) catch std.math.maxInt(usize);
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

/// Validates an mzML file on disk using bounded stream input.
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
    comptime report_progress: bool,
    context: *InvocationContext,
    diagnostics: *DiagnosticSink,
    path: []const u8,
    result: *FileResult,
    observer: if (report_progress) ProgressObserver else void,
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

    try checkPathStream(report_progress, context, file, opened_stat, diagnostics, path, result, observer);
}

fn checkPathStream(
    comptime report_progress: bool,
    context: *InvocationContext,
    file: std.Io.File,
    initial_stat: std.Io.File.Stat,
    diagnostics: *DiagnosticSink,
    path: []const u8,
    result: *FileResult,
    observer: if (report_progress) ProgressObserver else void,
) !void {
    var input_buffer: [stream_input_buffer_bytes]u8 = undefined;
    var file_reader = file.readerStreaming(context.io, &input_buffer);

    result.completeStage(.input);
    try runValidationMode(report_progress, context, diagnostics, path, null, .{ .reader = &file_reader.interface }, result, file, initial_stat.size, observer);
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
/// `bytes` and optional `file_bytes` are borrowed for the duration of the call.
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
/// `file_bytes` is the complete borrowed source when indexed checks need it.
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
    return runValidationMode(false, context, diagnostics, path, file_bytes, source, result, stream_file, stream_size, {});
}

fn runValidationMode(
    comptime report_progress: bool,
    context: *InvocationContext,
    diagnostics: *DiagnosticSink,
    path: []const u8,
    file_bytes: ?[]const u8,
    source: ParserSource,
    result: *FileResult,
    stream_file: ?std.Io.File,
    stream_size: ?u64,
    observer: if (report_progress) ProgressObserver else void,
) !void {
    result.beginStage(.parser);
    // Parser token slices borrow caller-owned storage until the next event.
    // Allocate the fixed bound once per file so every event reuses it without
    // event-level allocation or parser API complexity.
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
    var parse_progress: if (report_progress) progress.Reporter else void = if (report_progress)
        progress.Reporter.init(observer, .parse, stream_size orelse return error.InputOutput)
    else {};

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
                if (err == error.ReadFailed) .input else .parser,
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
        if (comptime report_progress) {
            parse_progress.checkpoint(parser.byteOffset() +| 1);
        }
        const event = maybe_event orelse {
            if (comptime report_progress) parse_progress.complete();
            result.completeStage(.parser);
            if (semantic_validator) |*sv| {
                result.beginStage(.semantic);
                try sv.finish();
                result.completeStage(.semantic);
            }
            if (index_validator) |*iv| {
                result.beginStage(.index);
                (if (comptime report_progress)
                    iv.finishWithProgress(file_bytes, observer)
                else
                    iv.finish(file_bytes)) catch |err| {
                    if (err == error.InputIntegrityUnavailable) {
                        try appendFailureDiagnostic(
                            context.allocator,
                            diagnostics,
                            result,
                            .index,
                            .input,
                            .{
                                .severity = .@"error",
                                .rule = RuleId.mzml_index_checksum,
                                .path = path,
                                .message = "file bytes unavailable; SHA-1 and truncation checks cannot be verified",
                            },
                        );
                        return;
                    }
                    return err;
                };
                result.completeStage(.index);
            }
            break;
        };

        switch (event) {
            .start_element => |start| {
                element_depth = std.math.add(usize, element_depth, 1) catch return error.ResourceLimitExceeded;
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
                element_depth = std.math.sub(usize, element_depth, 1) catch return error.ResourceLimitExceeded;
            },
            .text => |text| {
                result.beginStage(.structural);
                try structural_validator.consumeText(text);
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
            const exclusive_end = std.math.add(u64, parser.byteOffset(), 1) catch return error.ResourceLimitExceeded;
            validator.maybeFeedShaExclusive(exclusive_end);
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
    else if (err == error.InputOutput)
        .input
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

test "[unit]: path progress reports monotonic parse and checksum bytes" {
    const Recorder = struct {
        updates: [8]progress.Update = undefined,
        len: usize = 0,

        fn observe(context: *anyopaque, update: progress.Update) void {
            const recorder: *@This() = @ptrCast(@alignCast(context));
            recorder.updates[recorder.len] = update;
            recorder.len += 1;
        }
    };

    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const path = "fixtures/mzml/valid/small.pwiz.1.1.mzML";
    const stat = try std.Io.Dir.cwd().statFile(io, path, .{});
    var recorder = Recorder{};
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var context = InvocationContext.init(allocator, io, .{ .skip_semantic = true });
    defer context.deinit();

    _ = context.validateOneWithProgress(&diagnostics, path, .{
        .context = &recorder,
        .update_fn = Recorder.observe,
    });

    var parse_bytes: u64 = 0;
    var checksum_bytes: u64 = 0;
    var saw_parse = false;
    var saw_checksum = false;
    for (recorder.updates[0..recorder.len]) |update| {
        try std.testing.expectEqual(stat.size, update.total_bytes);
        switch (update.phase) {
            .parse => {
                try std.testing.expect(!saw_checksum);
                try std.testing.expect(update.completed_bytes >= parse_bytes);
                parse_bytes = update.completed_bytes;
                saw_parse = true;
            },
            .checksum => {
                try std.testing.expect(update.completed_bytes >= checksum_bytes);
                checksum_bytes = update.completed_bytes;
                saw_checksum = true;
            },
        }
    }
    try std.testing.expect(saw_parse);
    try std.testing.expect(saw_checksum);
    try std.testing.expectEqual(stat.size, parse_bytes);
    try std.testing.expectEqual(stat.size, checksum_bytes);
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

const FailingInputReader = struct {
    reader: std.Io.Reader,
    buffer: [1]u8 = undefined,

    fn init(failing: *FailingInputReader) void {
        failing.reader = .{
            .vtable = &.{ .stream = stream },
            .buffer = &failing.buffer,
            .seek = 0,
            .end = 0,
        };
    }

    fn stream(_: *std.Io.Reader, _: *std.Io.Writer, _: std.Io.Limit) std.Io.Reader.StreamError!usize {
        return error.ReadFailed;
    }
};

// --- Unit Tests ---

test "path check: reports a missing file" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, "definitely-missing-file.mzML", .{});

    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqual(diagnostic.Severity.@"error", diagnostics.items[0].severity);
    try std.testing.expectEqualStrings(RuleId.runtime_file_open, diagnostics.items[0].rule);
}

test "path check: uses bounded stream input" {
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
    });

    try std.testing.expectEqual(diagnostic.CompletionState.complete, result.completion);
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "slice result owns failure metadata after borrowed inputs expire" {
    var bytes = [_]u8{ '<', 'm', 'z', 'M', 'L' };
    var path = [_]u8{ 'b', 'o', 'r', 'r', 'o', 'w', 'e', 'd', '.', 'm', 'z', 'M', 'L' };
    var diagnostics = DiagnosticSink.init(.{ .retain_details = false });
    defer diagnostics.deinit(std.testing.allocator);

    const result = checkSliceResult(
        std.testing.allocator,
        std.testing.io,
        &bytes,
        &diagnostics,
        &path,
        .{ .skip_binary = true, .skip_index = true, .skip_semantic = true },
        null,
    );
    @memset(&bytes, 'x');
    @memset(&path, 'x');

    const failure = result.first_failure.?;
    try std.testing.expectEqualStrings(RuleId.mzml_structure_xml, failure.rule());
    try std.testing.expectEqualStrings("borrowed.mzML", failure.path().?);
    try std.testing.expectEqual(diagnostic.CompletionState.incomplete, result.completion);
    try std.testing.expect(result.needsEmergencyDiagnostic());
    try std.testing.expect(!result.failure_diagnostic_emitted);
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
    try std.testing.expectEqual(diagnostic.Totals{ .errors = 1 }, diagnostics.totals);
    try std.testing.expectEqual(diagnostic.Totals{}, diagnostics.dropped);
}

test "[unit]: legacy slice wrapper reports intentionally non-retained failure detail" {
    var diagnostics = DiagnosticSink.init(.{ .retain_details = false });
    defer diagnostics.deinit(std.testing.allocator);

    try std.testing.expectError(error.ValidationIncomplete, checkSlice(
        std.testing.allocator,
        std.testing.io,
        "<mzML",
        &diagnostics,
        "non-retaining-slice.mzML",
        .{ .skip_binary = true, .skip_index = true, .skip_semantic = true },
        null,
    ));

    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
    try std.testing.expectEqual(diagnostic.Totals{ .errors = 1 }, diagnostics.totals);
}

test "[unit]: legacy reader wrapper reports intentionally non-retained failure detail" {
    var diagnostics = DiagnosticSink.init(.{ .retain_details = false });
    defer diagnostics.deinit(std.testing.allocator);
    var reader = std.Io.Reader.fixed("<mzML");

    try std.testing.expectError(error.ValidationIncomplete, checkReader(
        std.testing.allocator,
        std.testing.io,
        &reader,
        &diagnostics,
        "non-retaining-reader.mzML",
        .{ .skip_binary = true, .skip_index = true, .skip_semantic = true },
        null,
    ));

    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
    try std.testing.expectEqual(diagnostic.Totals{ .errors = 1 }, diagnostics.totals);
}

test "[unit]: legacy path wrapper reports intentionally non-retained failure detail" {
    var diagnostics = DiagnosticSink.init(.{ .retain_details = false });
    defer diagnostics.deinit(std.testing.allocator);

    try std.testing.expectError(error.ValidationIncomplete, checkPath(
        std.testing.allocator,
        std.testing.io,
        &diagnostics,
        "fixtures/mzml/does-not-exist-aud15.mzML",
        .{ .skip_binary = true, .skip_index = true, .skip_semantic = true },
    ));

    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
    try std.testing.expectEqual(diagnostic.Totals{ .errors = 1 }, diagnostics.totals);
}

test "path check: rejects a changed file" {
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

test "path check: validates structure when binary checks are skipped" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/examples/mzml/single-spectrum-missing-cv-terms.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();

    const path = try stageFixtureInTempDir(allocator, io, &temp_dir, "sample.mzML", fixture);
    defer allocator.free(path);

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, path, .{ .skip_binary = true, .skip_semantic = true });

    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "path check: reports a clean file when structure and binary pass" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/examples/mzml/single-spectrum-missing-cv-terms.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();

    const path = try stageFixtureInTempDir(allocator, io, &temp_dir, "sample.mzML", fixture);
    defer allocator.free(path);

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, path, .{ .skip_semantic = true });

    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "path check: reports indexed fixture URI deviations when binary checks are skipped" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/valid/tiny.pwiz.1.1.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();

    const path = try stageFixtureInTempDir(allocator, io, &temp_dir, "tiny-indexed.mzML", fixture);
    defer allocator.free(path);

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, path, .{ .skip_binary = true, .skip_semantic = true, .skip_index = true });

    try expectTinyUriDiagnostics(diagnostics.items);
}

test "path check: validates the larger indexed fixture structure" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, "fixtures/mzml/valid/small.pwiz.1.1.mzML", .{ .skip_binary = true, .skip_semantic = true, .skip_index = true });

    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "path check: keeps structural URI findings when index checks are disabled" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    // Skip index because the pwiz fixture has a bad checksum.
    // Index SHA-1 verification is tested separately with correct fixtures.
    try checkPath(allocator, io, &diagnostics, "fixtures/mzml/valid/tiny.pwiz.1.1.mzML", .{ .skip_binary = true, .skip_semantic = true, .skip_index = true });

    try expectTinyUriDiagnostics(diagnostics.items);
}

test "path check: runs semantic validation end to end" {
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

test "slice result: reports a semantic resource limit" {
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
    try std.testing.expectEqual(diagnostic.stageBit(.input), result.completed_stages);
    try std.testing.expect(result.enabled_stages & diagnostic.stageBit(.semantic) != 0);
    try std.testing.expectEqual(diagnostic.ValidationStage.semantic, result.first_failure.?.stage);
    try std.testing.expectEqual(diagnostic.FailureReason.resource, result.first_failure.?.reason);
    try std.testing.expectEqual(diagnostic.Totals{ .errors = 2 }, result.totals);
    try std.testing.expectEqualStrings(RuleId.runtime_semantic_limit, diagnostics.items[0].rule);
}

test "path check: runs mapping rules for an indexed fixture" {
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

test "path result: missing array length is complete with an error" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    const result = checkPathResult(allocator, io, &diagnostics, "fixtures/mzml/adversarial/missing-default-array-length.mzML", .{
        .skip_index = true,
        .skip_semantic = true,
    });

    try std.testing.expectEqual(diagnostic.CompletionState.complete, result.completion);
    try std.testing.expectEqual(result.enabled_stages, result.completed_stages);
    try std.testing.expectEqual(@as(?diagnostic.FirstFailure, null), result.first_failure);
    try std.testing.expectEqual(diagnostic.ResultStatus.errors_present, result.status());
    try std.testing.expectEqual(diagnostic.count(diagnostics.items), result.totals);
    try std.testing.expectEqual(@as(usize, 0), result.totals.info);
    try std.testing.expectEqual(@as(usize, 0), result.totals.warnings);
    try std.testing.expect(result.totals.errors >= 2);

    var binary_diagnostic_count: usize = 0;
    for (diagnostics.items) |item| {
        if (std.mem.eql(u8, item.rule, RuleId.mzml_binary_length_mismatch) and
            std.mem.eql(u8, item.message, "non-empty binary payload is missing required defaultArrayLength"))
        {
            binary_diagnostic_count += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 2), binary_diagnostic_count);
}

test "path check: reports a missing required reference" {
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

test "path check: skips index checks for indexed input" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, "fixtures/mzml/valid/tiny.pwiz.1.1.mzML", .{ .skip_binary = true, .skip_index = true, .skip_semantic = true });

    try expectTinyUriDiagnostics(diagnostics.items);
}

test "path check: validates a stream SHA-1 checksum" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // The digest covers the bytes through the opening fileChecksum tag.
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
        "  <indexList count=\"1\"><index name=\"spectrum\"><offset idRef=\"scan=1\">0</offset></index></indexList>\n" ++
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

    // Stream path: checksum is recomputed from the seekable source.
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    const result = checkPathResult(allocator, io, &diagnostics, path, .{
        .skip_binary = true,
        .skip_semantic = true,
    });

    for (diagnostics.items) |d| {
        if (std.mem.eql(u8, d.rule, RuleId.mzml_index_checksum)) {
            return error.TestUnexpectedChecksumError;
        }
    }
    try std.testing.expect(result.resource_usage.index_peak_bytes > 0);
}

test "path check: accepts a complete checksum start tag" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const checksum_start_tag = "<fileChecksum data-origin=\"test\" >";
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
        "  <indexList count=\"1\"><index name=\"spectrum\"><offset idRef=\"scan=1\">0</offset></index></indexList>\n" ++
        "  <indexListOffset>10</indexListOffset>\n";
    var sha_ctx = std.crypto.hash.Sha1.init(.{});
    sha_ctx.update(prefix);
    sha_ctx.update("  ");
    sha_ctx.update(checksum_start_tag);
    var raw: [20]u8 = undefined;
    sha_ctx.final(&raw);
    const hex = std.fmt.bytesToHex(raw, .lower);
    const xml = try indexedMzmlWithShaTag(allocator, checksum_start_tag, &hex);
    defer allocator.free(xml);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    try temp_dir.dir.writeFile(io, .{ .sub_path = "complete-start-tag-sha.mzML", .data = xml });
    const path = try tempFixturePath(allocator, temp_dir.sub_path[0..], "complete-start-tag-sha.mzML");
    defer allocator.free(path);

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    try checkPath(allocator, io, &diagnostics, path, .{
        .skip_binary = true,
        .skip_semantic = true,
    });

    for (diagnostics.items) |d| {
        if (std.mem.eql(u8, d.rule, RuleId.mzml_index_checksum)) {
            return error.TestUnexpectedChecksumError;
        }
    }
}

test "path check: skips SHA-1 when index checks are disabled" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

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
        "  <indexList count=\"1\"><index name=\"spectrum\"><offset idRef=\"scan=1\">0</offset></index></indexList>\n" ++
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

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    try checkPath(allocator, io, &diagnostics, path, .{
        .skip_binary = true,
        .skip_semantic = true,
        .skip_index = true,
    });

    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "path check: detects a corrupt SHA-1 checksum" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const bad_hex = "0000000000000000000000000000000000000000";
    const xml = try indexedMzmlWithSha(allocator, bad_hex);
    defer allocator.free(xml);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    try temp_dir.dir.writeFile(io, .{ .sub_path = "bad-sha.mzML", .data = xml });
    const path = try tempFixturePath(allocator, temp_dir.sub_path[0..], "bad-sha.mzML");
    defer allocator.free(path);

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    try checkPath(allocator, io, &diagnostics, path, .{
        .skip_binary = true,
        .skip_semantic = true,
    });

    var found = false;
    for (diagnostics.items) |d| {
        if (std.mem.eql(u8, d.rule, RuleId.mzml_index_checksum)) {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}

test "path check: does not hash non-indexed input" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // A non-indexed file (no indexList). Index validation runs but
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

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    try checkPath(allocator, io, &diagnostics, path, .{
        .skip_binary = true,
        .skip_semantic = true,
    });

    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "path check: skips SHA-1 for an indexed fixture when requested" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, "fixtures/mzml/valid/tiny.pwiz.1.1.mzML", .{
        .skip_binary = true,
        .skip_semantic = true,
        .skip_index = true,
    });

    try expectTinyUriDiagnostics(diagnostics.items);
}

test "path check: missing required indexed checksum is structural, not a SHA mismatch" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // The indexed 1.1.3 schema requires fileChecksum. Structural validation
    // owns the missing child; the index validator must not invent a checksum
    // mismatch when there is no declared digest to recompute.
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

    try checkPath(allocator, io, &diagnostics, path, .{
        .skip_binary = true,
        .skip_semantic = true,
    });

    var saw_missing_checksum = false;
    for (diagnostics.items) |d| {
        if (std.mem.eql(u8, d.rule, RuleId.mzml_index_checksum)) {
            return error.TestUnexpectedChecksumError;
        }
        if (std.mem.eql(u8, d.rule, RuleId.mzml_structure_missing_child) and
            std.mem.eql(u8, d.message, "indexedmzML is missing required child fileChecksum"))
        {
            saw_missing_checksum = true;
        }
    }
    try std.testing.expect(saw_missing_checksum);
}

test "path check: validates the conforming fixture corpus and preserves visible URI deviations" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const root = "fixtures/mzml/valid";

    const fixture_count = try expectCorpusDiagnostics(
        allocator,
        io,
        root,
        .{ .skip_binary = true, .skip_semantic = true, .skip_index = true },
        .valid_with_uri_compat,
    );

    try std.testing.expect(fixture_count > 0);
}

test "path check: validates a large synthetic mzML stream" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const spectrum_count = 2048;

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    const written_len = try writeSyntheticLargeMzmlFixture(io, &temp_dir, "synthetic-large.mzML", spectrum_count);
    try std.testing.expect(written_len > 1024 * 1024);

    const path = try tempFixturePath(allocator, temp_dir.sub_path[0..], "synthetic-large.mzML");
    defer allocator.free(path);

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, path, .{ .skip_semantic = true });

    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "path check: reports a binary length mismatch in stream mode" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, "fixtures/mzml/adversarial/large-binary-text.mzML", .{
        .skip_semantic = true,
    });

    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_binary_length_mismatch,
        "decoded array length does not match defaultArrayLength",
    );
}

test "synthetic fixture: writes the expected streamed shape" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const spectrum_count = 3;

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();

    const written_len = try writeSyntheticLargeMzmlFixture(io, &temp_dir, "synthetic-shape.mzML", spectrum_count);
    const path = try tempFixturePath(allocator, temp_dir.sub_path[0..], "synthetic-shape.mzML");
    defer allocator.free(path);
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(128 * 1024));
    defer allocator.free(fixture);

    try std.testing.expectEqual(fixture.len, written_len);
    try std.testing.expect(std.mem.startsWith(u8, fixture, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<mzML "));
    try std.testing.expect(std.mem.indexOf(u8, fixture, "<spectrumList count=\"3\" defaultDataProcessingRef=\"DP1\">") != null);
    try std.testing.expect(std.mem.indexOf(u8, fixture, "<spectrum index=\"0\" id=\"scan=1\" defaultArrayLength=\"1\">") != null);
    try std.testing.expect(std.mem.indexOf(u8, fixture, "<spectrum index=\"2\" id=\"scan=3\" defaultArrayLength=\"1\">") != null);
    try std.testing.expectEqual(@as(usize, spectrum_count * 2), std.mem.count(u8, fixture, "<binary>AAAAAA==</binary>"));
    try std.testing.expect(std.mem.endsWith(u8, fixture, "    </spectrumList>\n  </run>\n</mzML>\n"));
}

test "reader check: reports truncated XML" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" ++
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\"><run";

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    try checkReader(allocator, io, &reader, &diagnostics, "inline-truncated.mzML", .{ .skip_semantic = true }, null);

    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_xml,
        "unexpected end of XML input",
    );
}

test "reader result: marks truncated XML incomplete" {
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
    try std.testing.expectEqual(@as(u8, 3), diagnostic.exitCodeForResults(&.{result}));
}

test "[unit]: reader I/O failure is classified as an input failure" {
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(std.testing.allocator);
    var failing_reader: FailingInputReader = undefined;
    failing_reader.init();

    const result = checkReaderResult(
        std.testing.allocator,
        std.testing.io,
        &failing_reader.reader,
        &diagnostics,
        "unreadable.mzML",
        .{ .skip_binary = true, .skip_index = true, .skip_semantic = true },
        null,
    );

    try std.testing.expectEqual(diagnostic.CompletionState.incomplete, result.completion);
    try std.testing.expectEqual(diagnostic.ValidationStage.parser, result.first_failure.?.stage);
    try std.testing.expectEqual(diagnostic.FailureReason.input, result.first_failure.?.reason);
    try expectSingleDiagnostic(diagnostics.items, RuleId.mzml_structure_xml, "failed while reading XML input");
}

test "[unit]: index I/O failure is classified as an input failure" {
    var result = FileResult.init(diagnostic.stageBit(.index));
    result.beginStage(.index);

    recordUnhandledFailure(&result, error.InputOutput, "unreadable-index.mzML");
    result.finalize(&.{});

    try std.testing.expectEqual(diagnostic.CompletionState.incomplete, result.completion);
    try std.testing.expectEqual(diagnostic.ValidationStage.index, result.first_failure.?.stage);
    try std.testing.expectEqual(diagnostic.FailureReason.input, result.first_failure.?.reason);
}

test "reader result: marks clean input complete" {
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

test "reader result: indexed input without integrity source is incomplete" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture = try std.Io.Dir.cwd().readFileAlloc(
        io,
        "fixtures/mzml/valid/tiny.pwiz.1.1.mzML",
        allocator,
        .limited(256 * 1024),
    );
    defer allocator.free(fixture);

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(fixture);

    const result = checkReaderResult(allocator, io, &reader, &diagnostics, "indexed-reader.mzML", .{
        .skip_binary = true,
        .skip_semantic = true,
    }, null);

    try std.testing.expectEqual(diagnostic.CompletionState.incomplete, result.completion);
    try std.testing.expectEqual(diagnostic.ValidationStage.index, result.first_failure.?.stage);
    try std.testing.expectEqual(diagnostic.FailureReason.input, result.first_failure.?.reason);
    try std.testing.expect((result.completed_stages & diagnostic.stageBit(.index)) == 0);

    var found_integrity_failure = false;
    for (diagnostics.items) |item| {
        if (std.mem.eql(u8, item.rule, RuleId.mzml_index_checksum)) {
            found_integrity_failure = true;
            try std.testing.expectEqual(diagnostic.Severity.@"error", item.severity);
        }
    }
    try std.testing.expect(found_integrity_failure);
}

test "reader result: marks allocation failure incomplete" {
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

test "required state: allocation failures stay incomplete and leak-free" {
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

test "[unit]: binary and index allocation failures stay incomplete and leak-free" {
    const xml = binarySpectrumListMzml(
        "eJxjYGBgAAAABAAB",
        "AAAAAA==",
        1,
        "MS:1000574",
        "zlib compression",
    );
    try expectAllocationFailuresIncomplete(xml, .{
        .skip_semantic = true,
    }, xml, false);
}

fn fuzzValidationCleanup(_: void, smith: *std.testing.Smith) !void {
    const seed = comptime binarySpectrumListMzml(
        "eJxjYGBgAAAABAAB",
        "AAAAAA==",
        1,
        "MS:1000574",
        "zlib compression",
    );
    var mutated: [seed.len]u8 = undefined;
    @memcpy(&mutated, seed);

    var edits: [24]u8 = undefined;
    const edit_len: usize = smith.slice(&edits);
    var index: usize = 0;
    while (index + 1 < edit_len) : (index += 2) {
        mutated[edits[index] % mutated.len] ^= edits[index + 1];
    }
    const len: usize = smith.valueRangeAtMost(u16, 0, @intCast(seed.len));

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(std.testing.allocator);
    _ = checkSliceResult(
        std.testing.allocator,
        std.testing.io,
        mutated[0..len],
        &diagnostics,
        "fuzz.mzML",
        .{ .skip_semantic = true },
        null,
    );
}

test "[unit]: streaming validation mutation cleanup is leak-free" {
    try std.testing.fuzz({}, fuzzValidationCleanup, .{
        .corpus = &.{ "", "truncate", "byte-edit", "binary" },
    });
}

test "[unit]: forward-reference allocation failures remain incomplete" {
    const xml = spectrumListMzml(
        "<spectrumList count=\"2\" defaultDataProcessingRef=\"DP1\">" ++
            "<spectrum index=\"0\" id=\"scan=1\" defaultArrayLength=\"0\">" ++
            "<scanList count=\"1\"><scan spectrumRef=\"scan=2\"/></scanList></spectrum>" ++
            "<spectrum index=\"1\" id=\"scan=2\" defaultArrayLength=\"0\"/>" ++
            "</spectrumList>",
    );
    var context = InvocationContext.init(std.testing.allocator, std.testing.io, .{
        .skip_binary = true,
        .skip_index = true,
    });
    defer context.deinit();

    var baseline_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var baseline_diagnostics: DiagnosticSink = .empty;
    context.allocator = baseline_allocator.allocator();
    const baseline = context.checkSliceResult(xml, &baseline_diagnostics, "forward-allocation.mzML", null);
    context.allocator = std.testing.allocator;
    baseline_diagnostics.deinit(baseline_allocator.allocator());
    try std.testing.expectEqual(diagnostic.CompletionState.complete, baseline.completion);
    try std.testing.expectEqual(baseline_allocator.allocated_bytes, baseline_allocator.freed_bytes);

    for (0..baseline_allocator.alloc_index) |fail_index| {
        var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
        var diagnostics: DiagnosticSink = .empty;
        context.allocator = failing_allocator.allocator();
        const result = context.checkSliceResult(xml, &diagnostics, "forward-allocation.mzML", null);
        context.allocator = std.testing.allocator;
        const induced = failing_allocator.has_induced_failure;
        diagnostics.deinit(failing_allocator.allocator());

        try std.testing.expectEqual(failing_allocator.allocated_bytes, failing_allocator.freed_bytes);
        if (induced) {
            try std.testing.expectEqual(diagnostic.CompletionState.incomplete, result.completion);
            try std.testing.expectEqual(diagnostic.FailureReason.allocation, result.first_failure.?.reason);
            try std.testing.expect(result.status() != .clean);
        } else {
            try std.testing.expectEqual(diagnostic.CompletionState.complete, result.completion);
        }
    }
}

test "failure diagnostics: allocation failure uses emergency metadata" {
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
    const failure = result.first_failure.?;
    try std.testing.expectEqualStrings(diagnostic.RuleId.runtime_incomplete, failure.rule());
    try std.testing.expect(result.diagnostics_truncated);
    try std.testing.expect(result.needsEmergencyDiagnostic());
}

test "path result: missing catalog is incomplete" {
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
    try std.testing.expectEqual(@as(u8, 3), diagnostic.exitCodeForResults(&.{result}));
}

test "invocation context: owns the catalog across multiple paths" {
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
    const initial_usage = context.resourceUsage();
    try std.testing.expectEqual(@as(usize, @embedFile("data/psi-ms.obo").len), initial_usage.obo_source_peak_bytes);
    try std.testing.expect(initial_usage.catalog_current_bytes > 0);
    try std.testing.expect(initial_usage.catalog_peak_bytes >= initial_usage.catalog_current_bytes);
    try std.testing.expectEqual(
        initial_usage.obo_source_peak_bytes + initial_usage.catalog_peak_bytes,
        initial_usage.peak_bytes,
    );
    try temp_dir.dir.deleteFile(io, "psi-ms.obo");

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    const first = context.validateOne(&diagnostics, "fixtures/mzml/valid/tiny.pwiz.1.1.mzML");
    diagnostics.clearRetainingCapacity();
    const second = context.validateOne(&diagnostics, "fixtures/mzml/valid/small.pwiz.1.1.mzML");

    try std.testing.expectEqual(diagnostic.CompletionState.complete, first.completion);
    try std.testing.expectEqual(diagnostic.CompletionState.complete, second.completion);
    try std.testing.expect(context.catalog != null);
    try std.testing.expectEqual(initial_usage, context.resourceUsage());
}

test "[unit]: invocation context file-local owners return to the catalog baseline" {
    var allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var context = InvocationContext.init(allocator.allocator(), std.testing.io, .{});
    var context_live = true;
    defer if (context_live) context.deinit();
    try std.testing.expect(context.catalog != null);

    const catalog_live_bytes = allocator.allocated_bytes - allocator.freed_bytes;
    const clean = spectrumListMzml("<spectrumList count=\"0\" defaultDataProcessingRef=\"DP1\"/>");
    const zlib = binarySpectrumListMzml(
        "eJxjYGBgAAAABAAB",
        "AAAAAA==",
        1,
        "MS:1000574",
        "zlib compression",
    );
    const malformed = "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\"><run";
    const cases = [_][]const u8{
        clean,
        clean[0 .. clean.len - 7],
        zlib,
        malformed,
    };

    for (cases) |bytes| {
        var diagnostics: DiagnosticSink = .empty;
        _ = context.checkSliceResult(bytes, &diagnostics, "lifetime.mzML", null);
        diagnostics.deinit(allocator.allocator());
        try std.testing.expectEqual(
            catalog_live_bytes,
            allocator.allocated_bytes - allocator.freed_bytes,
        );
    }

    context.deinit();
    context_live = false;
    try std.testing.expectEqual(allocator.allocated_bytes, allocator.freed_bytes);
}

test "[unit]: embedded semantic catalog reports shared invocation capacity" {
    var context = InvocationContext.init(std.testing.allocator, std.testing.io, .{});
    defer context.deinit();

    const usage = context.resourceUsage();
    try std.testing.expect(context.catalog != null);
    try std.testing.expectEqual(@as(usize, 0), usage.obo_source_peak_bytes);
    try std.testing.expect(usage.catalog_current_bytes > 0);
    try std.testing.expect(usage.catalog_peak_bytes >= usage.catalog_current_bytes);
    try std.testing.expectEqual(usage.catalog_peak_bytes, usage.peak_bytes);
    try std.testing.expect(usage.peak_bytes <= context.options.resource_limits.max_obo_catalog_bytes);
}

test "[unit]: mapping growth at the shared catalog limit is an incomplete resource failure" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const obo_path = "fixtures/obo/adversarial/custom-namespace.obo";
    const obo_text = try std.Io.Dir.cwd().readFileAlloc(io, obo_path, allocator, .limited(64 * 1024));
    defer allocator.free(obo_text);
    var table = try obo_parser.CvTable.init(allocator, obo_text);
    const obo_peak_bytes = table.peakBytes();
    table.deinit();

    var context = InvocationContext.init(allocator, io, .{
        .skip_binary = true,
        .skip_index = true,
        .resource_limits = .{ .max_obo_catalog_bytes = obo_peak_bytes },
        .obo_path = obo_path,
    });
    defer context.deinit();
    try std.testing.expect(context.catalog == null);
    try std.testing.expectEqual(diagnostic.FailureReason.resource, context.catalog_failure.?.reason);
    try std.testing.expectEqualStrings(
        "semantic catalog exceeds the configured memory limit",
        context.catalog_failure.?.message,
    );
    const usage = context.resourceUsage();
    try std.testing.expectEqual(@as(usize, 0), usage.catalog_current_bytes);
    try std.testing.expectEqual(obo_peak_bytes, usage.catalog_peak_bytes);
    try std.testing.expectEqual(obo_text.len, usage.obo_source_peak_bytes);

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    const result = context.validateOne(&diagnostics, "fixtures/mzml/valid/tiny.pwiz.1.1.mzML");
    try std.testing.expectEqual(diagnostic.CompletionState.incomplete, result.completion);
    try std.testing.expectEqual(diagnostic.FailureReason.resource, result.first_failure.?.reason);
}

test "path check: rejects an incompatible custom vocabulary" {
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
    const failure = result.first_failure.?;
    try std.testing.expectEqualStrings(RuleId.runtime_catalog, failure.rule());
}

test "path check: reports a malformed custom vocabulary as a catalog failure" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    const result = checkPathResult(allocator, io, &diagnostics, "fixtures/mzml/valid/tiny.pwiz.1.1.mzML", .{
        .skip_binary = true,
        .skip_index = true,
        .obo_path = "fixtures/obo/adversarial/duplicate-ids.obo",
    });

    try std.testing.expectEqual(diagnostic.CompletionState.incomplete, result.completion);
    try std.testing.expectEqual(diagnostic.FailureReason.catalog, result.first_failure.?.reason);
    const failure = result.first_failure.?;
    try std.testing.expectEqualStrings(RuleId.runtime_catalog, failure.rule());
}

test "[unit]: custom OBO catalog limit is an incomplete resource failure" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    const result = checkPathResult(allocator, io, &diagnostics, "fixtures/mzml/valid/tiny.pwiz.1.1.mzML", .{
        .skip_binary = true,
        .skip_index = true,
        .resource_limits = .{ .max_obo_catalog_bytes = 1 },
        .obo_path = "fixtures/obo/adversarial/custom-namespace.obo",
    });

    try std.testing.expectEqual(diagnostic.CompletionState.incomplete, result.completion);
    try std.testing.expectEqual(diagnostic.FailureReason.resource, result.first_failure.?.reason);
    try std.testing.expect(result.status() != .clean);
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.runtime_catalog_limit, diagnostics.items[0].rule);
    try std.testing.expectEqualStrings(
        "OBO catalog exceeds the configured memory limit",
        diagnostics.items[0].message,
    );
}

test "[unit]: custom OBO source limit is an incomplete resource failure" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    var context = InvocationContext.init(allocator, io, .{
        .skip_binary = true,
        .skip_index = true,
        .resource_limits = .{ .max_obo_source_bytes = 1 },
        .obo_path = "fixtures/obo/adversarial/custom-namespace.obo",
    });
    defer context.deinit();
    const result = context.validateOne(&diagnostics, "fixtures/mzml/valid/tiny.pwiz.1.1.mzML");

    try std.testing.expectEqual(diagnostic.CompletionState.incomplete, result.completion);
    try std.testing.expectEqual(diagnostic.ValidationStage.semantic, result.first_failure.?.stage);
    try std.testing.expectEqual(diagnostic.FailureReason.resource, result.first_failure.?.reason);
    try std.testing.expectEqualStrings(RuleId.runtime_catalog_limit, result.first_failure.?.rule());
    try std.testing.expectEqualStrings(
        "custom OBO source exceeds the configured size limit",
        result.first_failure.?.message(),
    );
    try std.testing.expectEqual(@as(usize, 0), context.resourceUsage().peak_bytes);
}

test "path result: invalid zlib is complete with an error" {
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

test "path result: resource limit is incomplete" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    const result = checkPathResult(allocator, io, &diagnostics, "fixtures/mzml/adversarial/huge-count.mzML", .{
        .skip_binary = true,
        .skip_semantic = true,
    });

    try std.testing.expectEqual(diagnostic.CompletionState.incomplete, result.completion);
    try std.testing.expectEqual(diagnostic.stageBit(.input), result.completed_stages);
    try std.testing.expect(result.enabled_stages & diagnostic.stageBit(.index) != 0);
    try std.testing.expectEqual(diagnostic.ValidationStage.index, result.first_failure.?.stage);
    try std.testing.expectEqual(diagnostic.FailureReason.resource, result.first_failure.?.reason);
    try std.testing.expect(result.totals.errors > 0);
    var found_limit = false;
    for (diagnostics.items) |item| {
        if (std.mem.eql(u8, item.rule, RuleId.mzml_index_offset_list)) {
            found_limit = true;
            break;
        }
    }
    try std.testing.expect(found_limit);
}

test "slice result: index state limit is incomplete" {
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

test "reader wrapper: reports an allocation failure" {
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

test "reader check: reports a broken attribute quote" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" ++
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\"><run id=\"broken></run></mzML>";

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    try checkReader(allocator, io, &reader, &diagnostics, "inline-broken-quote.mzML", .{ .skip_binary = true, .skip_semantic = true }, null);

    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_xml,
        "character is not permitted by the XML version",
    );
}

test "[unit]: malformed spectrum index has one structural diagnostic" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml = spectrumListMzml(
        "<spectrumList count=\"1\" defaultDataProcessingRef=\"DP1\">" ++
            "<spectrum index=\"invalid\" id=\"scan=1\" defaultArrayLength=\"0\"/>" ++
            "</spectrumList>",
    );

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    try checkReader(allocator, io, &reader, &diagnostics, "inline-invalid-index.mzML", .{ .skip_index = true, .skip_semantic = true }, null);

    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_attribute,
        "attribute must be a non-negative integer within the supported range",
    );
}

test "[unit]: overflowing defaultArrayLength stays a complete structural error" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const mz_array =
        "<binaryDataArray encodedLength=\"8\">" ++
        "<cvParam cvRef=\"MS\" accession=\"MS:1000521\" name=\"32-bit float\"/>" ++
        "<cvParam cvRef=\"MS\" accession=\"MS:1000576\" name=\"no compression\"/>" ++
        "<cvParam cvRef=\"MS\" accession=\"MS:1000514\" name=\"m/z array\"/>" ++
        "<binary>AAAAAA==</binary>" ++
        "</binaryDataArray>";
    const intensity_array =
        "<binaryDataArray encodedLength=\"8\">" ++
        "<cvParam cvRef=\"MS\" accession=\"MS:1000521\" name=\"32-bit float\"/>" ++
        "<cvParam cvRef=\"MS\" accession=\"MS:1000576\" name=\"no compression\"/>" ++
        "<cvParam cvRef=\"MS\" accession=\"MS:1000515\" name=\"intensity array\"/>" ++
        "<binary>AAAAAA==</binary>" ++
        "</binaryDataArray>";
    const xml = spectrumListMzml(
        "<spectrumList count=\"1\" defaultDataProcessingRef=\"DP1\">" ++
            "<spectrum index=\"0\" id=\"scan=1\" defaultArrayLength=\"2147483648\">" ++
            "<binaryDataArrayList count=\"2\">" ++ mz_array ++ intensity_array ++ "</binaryDataArrayList>" ++
            "</spectrum></spectrumList>",
    );

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    const result = checkReaderResult(allocator, io, &reader, &diagnostics, "inline-overflowing-array-length.mzML", .{ .skip_index = true, .skip_semantic = true }, null);

    try std.testing.expectEqual(diagnostic.CompletionState.complete, result.completion);
    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_attribute,
        "attribute must be a 32-bit integer",
    );
}

test "reader check: reports a mismatched end tag" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml = spectrumListMzml(
        "<spectrumList count=\"1\" defaultDataProcessingRef=\"DP1\">" ++
            "<spectrum index=\"0\" id=\"scan=1\" defaultArrayLength=\"1\">" ++
            "<scanList count=\"1\"><scan></scanList>" ++
            "</spectrum>" ++
            "</spectrumList>",
    );

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    try checkReader(allocator, io, &reader, &diagnostics, "inline-mismatched-end-tag.mzML", .{ .skip_binary = true, .skip_semantic = true }, null);

    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_xml,
        "closing tag does not match the most recent opening tag",
    );
}

test "reader check: reports invalid UTF-8" {
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

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    try checkReader(allocator, io, &reader, &diagnostics, "inline-invalid-utf8.mzML", .{ .skip_binary = true, .skip_semantic = true }, null);

    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_xml,
        "invalid UTF-8 in XML input",
    );
}

test "reader check: reports the wrong root namespace" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" ++
        "<mzML xmlns=\"urn:not-mzml\" version=\"1.1.0\">\n" ++
        "  <run id=\"run-1\">\n" ++
        "    <spectrumList count=\"0\" defaultDataProcessingRef=\"DP1\"/>\n" ++
        "  </run>\n" ++
        "</mzML>\n";

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    try checkReader(allocator, io, &reader, &diagnostics, "inline-wrong-namespace.mzML", .{ .skip_binary = true, .skip_semantic = true }, null);

    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_root,
        "root element must be mzML in the http://psi.hupo.org/ms/mzml namespace",
    );
}

test "reader check: reports text before the root" {
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

    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_xml,
        "malformed XML input",
    );
}

test "reader check: accepts a prefixed PSI namespace" {
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

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    try checkReader(allocator, io, &reader, &diagnostics, "inline-prefixed-root.mzML", .{ .skip_binary = true, .skip_semantic = true }, null);

    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "path check: reports chromatogram binary errors without a spectrum index" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const fixture = chromatogramMzmlWithPayloads("%%%%%%%%", "AAAAAA==");

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    const path = try stageFixtureInTempDir(allocator, io, &temp_dir, "chromatogram-invalid-base64.mzML", fixture);
    defer allocator.free(path);

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, path, .{ .skip_semantic = true });

    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_binary_base64,
        "binary payload is not valid base64",
    );
    try std.testing.expectEqual(@as(?usize, null), diagnostics.items[0].location.spectrum_index);
}

test "reader check: repeated clean runs do not accumulate state" {
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

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    for (0..32) |_| {
        diagnostics.clearRetainingCapacity();
        var reader = std.Io.Reader.fixed(xml);
        try checkReader(allocator, io, &reader, &diagnostics, "inline-repeated-clean.mzML", .{ .skip_semantic = true }, null);

        try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
    }
}

test "reader check: accepts an empty spectrum list" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml = spectrumListMzml("<spectrumList count=\"0\" defaultDataProcessingRef=\"DP1\"/>");

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    try checkReader(allocator, io, &reader, &diagnostics, "inline-empty-spectrum-list.mzML", .{ .skip_binary = true, .skip_semantic = true }, null);

    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "reader check: accepts multiple valid spectra" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml = spectrumListMzml(
        "<spectrumList count=\"2\" defaultDataProcessingRef=\"DP1\">" ++
            spectrumXml(0, true) ++
            spectrumXml(1, true) ++
            "</spectrumList>",
    );

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    try checkReader(allocator, io, &reader, &diagnostics, "inline-multiple-spectra.mzML", .{ .skip_binary = true, .skip_semantic = true }, null);

    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "[unit]: indexed duplicate ids remain errors when semantic validation is skipped" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const mzml = spectrumListMzml(
        "<spectrumList count=\"2\" defaultDataProcessingRef=\"DP1\">" ++
            "<spectrum index=\"0\" id=\"scan=1\" defaultArrayLength=\"0\"><scanList count=\"1\"><scan/></scanList></spectrum>" ++
            "<spectrum index=\"1\" id=\"scan=1\" defaultArrayLength=\"0\"><scanList count=\"1\"><scan/></scanList></spectrum>" ++
            "</spectrumList>",
    );
    const mzml_start = std.mem.indexOfScalar(u8, mzml, '\n').? + 1;
    var xml: std.ArrayList(u8) = .empty;
    defer xml.deinit(allocator);
    try xml.appendSlice(allocator, "<indexedmzML xmlns=\"http://psi.hupo.org/ms/mzml\">");
    try xml.appendSlice(allocator, mzml[mzml_start..]);
    const spectrum_offset = std.mem.indexOf(u8, xml.items, "<spectrum index=\"0\"").?;
    const index_list_offset = xml.items.len;
    const index_xml = try std.fmt.allocPrint(
        allocator,
        "<indexList count=\"1\"><index name=\"spectrum\"><offset idRef=\"scan=1\">{d}</offset></index></indexList>" ++
            "<indexListOffset>{d}</indexListOffset><fileChecksum>",
        .{ spectrum_offset, index_list_offset },
    );
    defer allocator.free(index_xml);
    try xml.appendSlice(allocator, index_xml);
    var sha = std.crypto.hash.Sha1.init(.{});
    sha.update(xml.items);
    var digest: [20]u8 = undefined;
    sha.final(&digest);
    const checksum = std.fmt.bytesToHex(digest, .lower);
    try xml.appendSlice(allocator, &checksum);
    try xml.appendSlice(allocator, "</fileChecksum></indexedmzML>");

    for ([_]bool{ true, false }) |skip_semantic| {
        var diagnostics: DiagnosticSink = .empty;
        defer diagnostics.deinit(allocator);

        const result = checkSliceResult(allocator, io, xml.items, &diagnostics, "duplicate-indexable-id.mzML", .{
            .skip_binary = true,
            .skip_semantic = skip_semantic,
        }, xml.items);

        var index_duplicate_count: usize = 0;
        var semantic_duplicate_count: usize = 0;
        for (diagnostics.items) |item| {
            if (std.mem.eql(u8, item.rule, RuleId.mzml_index_duplicate_id)) index_duplicate_count += 1;
            if (std.mem.eql(u8, item.rule, RuleId.mzml_ref_duplicate_id)) semantic_duplicate_count += 1;
        }
        try std.testing.expectEqual(diagnostic.CompletionState.complete, result.completion);
        try std.testing.expectEqual(@as(usize, 1), index_duplicate_count);
        try std.testing.expectEqual(@as(usize, if (skip_semantic) 0 else 1), semantic_duplicate_count);
        if (skip_semantic) try std.testing.expectEqual(@as(usize, 1), result.totals.errors);
    }
}

test "reader check: accepts a spectrum without optional binary array list" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml = spectrumListMzml(
        "<spectrumList count=\"1\" defaultDataProcessingRef=\"DP1\">" ++
            "<spectrum index=\"0\" id=\"scan=1\" defaultArrayLength=\"1\">" ++
            "<scanList count=\"1\"><scan/></scanList>" ++
            "</spectrum>" ++
            "</spectrumList>",
    );

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    try checkReader(allocator, io, &reader, &diagnostics, "inline-missing-binary-list.mzML", .{ .skip_binary = true, .skip_semantic = true }, null);

    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "reader check: forwards element content text to structural validation" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml = spectrumListMzml(
        "<spectrumList count=\"1\" defaultDataProcessingRef=\"DP1\">" ++
            "<spectrum index=\"0\" id=\"scan=1\" defaultArrayLength=\"0\">" ++
            "<scanList count=\"1\"><scan>illegal text</scan></scanList>" ++
            "</spectrum></spectrumList>",
    );

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    try checkReader(allocator, io, &reader, &diagnostics, "inline-element-text.mzML", .{ .skip_binary = true, .skip_semantic = true }, null);

    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_nesting,
        "non-whitespace text is not allowed in element-only mzML content",
    );
}

test "reader check: reports an out-of-order top-level child" {
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

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    try checkReader(allocator, io, &reader, &diagnostics, "inline-out-of-order-top-level.mzML", .{ .skip_binary = true, .skip_semantic = true }, null);

    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_nesting,
        "instrumentConfigurationList appears out of order under mzML",
    );
}

test "reader check: reports an oversized attribute" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const xml = try oversizedAttributeValueMzml(allocator, max_validation_token_bytes + 1);
    defer allocator.free(xml);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    try checkReader(allocator, io, &reader, &diagnostics, "inline-oversized-text.mzML", .{ .skip_binary = true, .skip_semantic = true }, null);

    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_xml,
        "XML attribute exceeds the configured attribute limit",
    );
}

test "reader check: reports too many attributes" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const xml = try tooManyAttributesXml(allocator, 65);
    defer allocator.free(xml);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    try checkReader(allocator, io, &reader, &diagnostics, "inline-too-many-attributes.mzML", .{ .skip_binary = true, .skip_semantic = true }, null);

    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_xml,
        "XML element has more attributes than the configured parser limit",
    );
}

test "reader check: reports too many namespace bindings" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const xml = try tooManyNamespacesXml(allocator, 33);
    defer allocator.free(xml);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    try checkReader(allocator, io, &reader, &diagnostics, "inline-too-many-namespaces.mzML", .{ .skip_binary = true, .skip_semantic = true }, null);

    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_xml,
        "XML namespace bindings exceed the configured parser limit",
    );
}

test "reader check: reports excessive element-name storage" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const xml = try tooDeepXml(allocator, 129);
    defer allocator.free(xml);
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    try checkReader(allocator, io, &reader, &diagnostics, "inline-too-deep.mzML", .{ .skip_binary = true, .skip_semantic = true }, null);

    var found_limit = false;
    for (diagnostics.items) |item| {
        if (std.mem.eql(u8, item.rule, RuleId.mzml_structure_xml) and
            std.mem.eql(u8, item.message, "XML element name storage exceeds the configured parser limit"))
        {
            found_limit = true;
        }
    }
    try std.testing.expect(found_limit);
}

test "path check: reports a structural error without binary noise" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/examples/mzml/wrong-namespace.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();

    const path = try stageFixtureInTempDir(allocator, io, &temp_dir, "broken.mzML", fixture);
    defer allocator.free(path);

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, path, .{ .skip_semantic = true });

    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqual(diagnostic.Severity.@"error", diagnostics.items[0].severity);
    try std.testing.expectEqualStrings(RuleId.mzml_structure_root, diagnostics.items[0].rule);
}

test "path check: skips binary checks after a structural failure" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/examples/mzml/wrong-namespace.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();

    const path = try stageFixtureInTempDir(allocator, io, &temp_dir, "broken.mzML", fixture);
    defer allocator.free(path);

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, path, .{ .skip_binary = true, .skip_semantic = true });

    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqual(diagnostic.Severity.@"error", diagnostics.items[0].severity);
    try std.testing.expectEqualStrings(RuleId.mzml_structure_root, diagnostics.items[0].rule);
}

test "path check: reports corrupt binary data" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/invalid/invalid-base64.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    const path = try stageFixtureInTempDir(allocator, io, &temp_dir, "corrupt-binary.mzML", fixture);
    defer allocator.free(path);

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, path, .{ .skip_semantic = true });

    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_binary_base64, diagnostics.items[0].rule);
}

test "path check: is clean when corrupt binary checks are disabled" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/invalid/invalid-base64.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    const path = try stageFixtureInTempDir(allocator, io, &temp_dir, "corrupt-binary.mzML", fixture);
    defer allocator.free(path);

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, path, .{ .skip_binary = true, .skip_semantic = true });

    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "reader check: reports an empty binary length mismatch" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml = binarySpectrumListMzml("", "AAAAAA==", 1, "MS:1000576", "no compression");

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    try checkReader(allocator, io, &reader, &diagnostics, "inline-empty-binary.mzML", .{ .skip_semantic = true }, null);

    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_binary_length_mismatch,
        "decoded array length does not match defaultArrayLength",
    );
}

test "reader check: reports a zlib length mismatch" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml = binarySpectrumListMzml("eJxjYGBgAAAABAAB", "AAAAAAAAAAA=", 2, "MS:1000574", "zlib compression");

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    try checkReader(allocator, io, &reader, &diagnostics, "inline-zlib-length-mismatch.mzML", .{ .skip_semantic = true }, null);

    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_binary_length_mismatch,
        "decoded array length does not match defaultArrayLength",
    );
}

test "path check: reports conflicting compression terms" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);

    try checkPath(allocator, io, &diagnostics, "fixtures/mzml/invalid/conflicting-compression.mzML", .{ .skip_semantic = true });
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_binary_compression, diagnostics.items[0].rule);
}

test "path check: reports unsupported compression" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var diagnostics: DiagnosticSink = .empty;
    defer diagnostics.deinit(allocator);
    try checkPath(allocator, io, &diagnostics, "fixtures/mzml/invalid/unsupported-compression.mzML", .{ .skip_semantic = true });

    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_binary_compression, diagnostics.items[0].rule);
}

test "path check: reports the expected rule for each invalid binary fixture" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const expectations = [_]InvalidBinaryExpectation{
        .{ .sub_path = "fixtures/mzml/invalid/conflicting-compression.mzML", .rule = RuleId.mzml_binary_compression, .message = "binaryDataArray declares conflicting compression terms" },
        .{ .sub_path = "fixtures/mzml/invalid/conflicting-precision.mzML", .rule = RuleId.mzml_binary_type_mismatch, .message = "binaryDataArray declares more than one binary datatype" },
        .{ .sub_path = "fixtures/mzml/invalid/invalid-base64.mzML", .rule = RuleId.mzml_binary_base64, .message = "binary payload is not valid base64" },
        .{ .sub_path = "fixtures/mzml/invalid/invalid-zlib.mzML", .rule = RuleId.mzml_binary_decompress, .message = "binary payload is not valid zlib data" },
        .{ .sub_path = "fixtures/mzml/invalid/unsupported-compression.mzML", .rule = RuleId.mzml_binary_compression, .message = "binaryDataArray declares unsupported compression terms" },
    };

    for (expectations) |expectation| {
        var diagnostics: DiagnosticSink = .empty;
        defer diagnostics.deinit(allocator);
        try checkPath(allocator, io, &diagnostics, expectation.sub_path, .{ .skip_semantic = true });

        try expectSingleDiagnostic(diagnostics.items, expectation.rule, expectation.message);
    }
}

test "path check: invalid binary fixtures are clean when binary checks are disabled" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const root = "fixtures/mzml/invalid";

    const fixture_count = try expectCorpusDiagnostics(
        allocator,
        io,
        root,
        .{ .skip_binary = true, .skip_semantic = true },
        .clean,
    );

    try std.testing.expect(fixture_count > 0);
}

test "path check: repeated clean and corrupt runs reset diagnostics" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

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

    for (0..24) |index| {
        const path = if (index % 2 == 0) clean_path else corrupt_path;
        diagnostics.clearRetainingCapacity();
        try checkPath(allocator, io, &diagnostics, path, .{ .skip_semantic = true });

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

// --- Test Helpers ---

const CorpusExpectation = enum {
    clean,
    non_empty,
    valid_with_uri_compat,
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

fn indexedMzmlWithSha(allocator: std.mem.Allocator, sha_hex: []const u8) ![]u8 {
    return indexedMzmlWithShaTag(allocator, "<fileChecksum>", sha_hex);
}

fn indexedMzmlWithShaTag(
    allocator: std.mem.Allocator,
    checksum_start_tag: []const u8,
    sha_hex: []const u8,
) ![]u8 {
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
        "  <indexList count=\"1\"><index name=\"spectrum\"><offset idRef=\"scan=1\">0</offset></index></indexList>\n" ++
        "  <indexListOffset>10</indexListOffset>\n";
    const indent = "  ";

    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(allocator);
    try buf.appendSlice(allocator, prefix);
    try buf.appendSlice(allocator, indent);
    try buf.appendSlice(allocator, checksum_start_tag);
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
            .valid_with_uri_compat => {
                if (std.mem.eql(u8, entry.path, "tiny.pwiz.1.1.mzML")) {
                    try expectTinyUriDiagnostics(diagnostics.items);
                } else if (diagnostics.items.len != 0) {
                    std.debug.print(
                        "unexpected diagnostics for {s}: first rule={s} message={s}\n",
                        .{ path, diagnostics.items[0].rule, diagnostics.items[0].message },
                    );
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
        "<precursor><activation/></precursor>" ++
        "<product/>" ++
        "<binaryDataArrayList count=\"2\">" ++
        "<binaryDataArray encodedLength=\"8\"><cvParam cvRef=\"MS\" accession=\"MS:1000521\" name=\"32-bit float\"/><cvParam cvRef=\"MS\" accession=\"MS:1000576\" name=\"no compression\"/><cvParam cvRef=\"MS\" accession=\"MS:1000595\" name=\"time array\"/><binary>" ++ first_payload ++ "</binary></binaryDataArray>" ++
        "<binaryDataArray encodedLength=\"8\"><cvParam cvRef=\"MS\" accession=\"MS:1000521\" name=\"32-bit float\"/><cvParam cvRef=\"MS\" accession=\"MS:1000576\" name=\"no compression\"/><cvParam cvRef=\"MS\" accession=\"MS:1000515\" name=\"intensity array\"/><binary>" ++ second_payload ++ "</binary></binaryDataArray>" ++
        "</binaryDataArrayList>" ++
        "</chromatogram>" ++
        "</chromatogramList>" ++
        "</run>" ++
        "</mzML>";
}

fn binarySpectrumListMzml(
    comptime payload: []const u8,
    comptime second_payload: []const u8,
    comptime default_array_length: usize,
    comptime compression_accession: []const u8,
    comptime compression_name: []const u8,
) []const u8 {
    return spectrumListMzml(
        "<spectrumList count=\"1\" defaultDataProcessingRef=\"DP1\">" ++
            "<spectrum index=\"0\" id=\"scan=1\" defaultArrayLength=\"" ++ comptimeUnsigned(default_array_length) ++ "\">" ++
            "<scanList count=\"1\"><scan/></scanList>" ++
            "<binaryDataArrayList count=\"2\">" ++
            "<binaryDataArray encodedLength=\"" ++ comptimeUnsigned(payload.len) ++ "\">" ++
            "<cvParam cvRef=\"MS\" accession=\"MS:1000521\" name=\"32-bit float\"/>" ++
            "<cvParam cvRef=\"MS\" accession=\"" ++ compression_accession ++ "\" name=\"" ++ compression_name ++ "\"/>" ++
            "<cvParam cvRef=\"MS\" accession=\"MS:1000514\" name=\"m/z array\"/>" ++
            "<binary>" ++ payload ++ "</binary>" ++
            "</binaryDataArray>" ++
            "<binaryDataArray encodedLength=\"" ++ comptimeUnsigned(second_payload.len) ++ "\">" ++
            "<cvParam cvRef=\"MS\" accession=\"MS:1000521\" name=\"32-bit float\"/>" ++
            "<cvParam cvRef=\"MS\" accession=\"MS:1000576\" name=\"no compression\"/>" ++
            "<cvParam cvRef=\"MS\" accession=\"MS:1000515\" name=\"intensity array\"/>" ++
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

fn expectTinyUriDiagnostics(diagnostics: []const Diagnostic) !void {
    try std.testing.expectEqual(@as(usize, 3), diagnostics.len);
    for (diagnostics) |item| {
        try std.testing.expectEqualStrings(RuleId.mzml_structure_attribute, item.rule);
        try std.testing.expectEqualStrings("attribute must be an XML Schema anyURI", item.message);
    }
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
