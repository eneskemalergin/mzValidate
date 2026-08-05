//! Shared diagnostic records, bounded sinks, and completion state.
//!
//! Rule IDs and exit-code mappings are stable output contracts.

const std = @import("std");

/// mzML namespace URI, shared across all mzML validators.
pub const mzml_namespace = "http://psi.hupo.org/ms/mzml";

/// Stable rule IDs emitted in diagnostics and serialized output.
///
/// Naming convention: `domain.category.slug`. The slug appears verbatim in JSON
/// so it is a breaking change to rename or remove an existing entry.
pub const RuleId = struct {
    pub const runtime_file_open = "runtime.file-open";
    pub const runtime_file_stability = "runtime.file-stability";
    pub const runtime_catalog = "runtime.catalog";
    pub const runtime_catalog_limit = "runtime.catalog-limit";
    pub const runtime_semantic_limit = "runtime.semantic-limit";
    pub const runtime_diagnostics_truncated = "runtime.diagnostics-truncated";
    pub const runtime_incomplete = "runtime.incomplete";
    pub const runtime_stub = "runtime.stub";

    pub const mzml_structure_root = "mzml.structure.root";
    pub const mzml_structure_xml = "mzml.structure.xml";
    pub const mzml_structure_nesting = "mzml.structure.nesting";
    pub const mzml_structure_attribute = "mzml.structure.attribute";
    pub const mzml_structure_count = "mzml.structure.count";
    pub const mzml_structure_missing_child = "mzml.structure.missing-child";
    pub const mzml_binary_base64 = "mzml.binary.base64";
    pub const mzml_binary_compression = "mzml.binary.compression";
    pub const mzml_binary_decompress = "mzml.binary.decompress";
    pub const mzml_binary_length_mismatch = "mzml.binary.length-mismatch";
    pub const mzml_binary_precision_mismatch = "mzml.binary.precision-mismatch";
    pub const mzml_binary_oversized = "mzml.binary.oversized";
    pub const mzml_binary_type_mismatch = "mzml.binary.type-mismatch";
    pub const mzml_binary_default_array = "mzml.binary.default-array";

    /// Declared indexListOffset does not match the actual byte offset of indexList.
    pub const mzml_index_offset_list = "mzml.index.offset-list";
    /// Index offset does not match the recorded spectrum/chromatogram position,
    /// or references a non-existent element.
    pub const mzml_index_offset = "mzml.index.offset";
    /// An indexed spectrum or chromatogram ID repeats within its element kind.
    pub const mzml_index_duplicate_id = "mzml.index.duplicate-id";
    /// Index offset points past the end of the file (truncated file).
    pub const mzml_index_truncated = "mzml.index.truncated";
    /// fileChecksum SHA-1 text is invalid, non-canonical, or does not match.
    pub const mzml_index_checksum = "mzml.index.checksum";

    /// CV accession does not exist in the controlled vocabulary.
    pub const mzml_cv_accession = "mzml.cv.accession";
    /// CV term is obsolete and has been replaced.
    pub const mzml_cv_obsolete = "mzml.cv.obsolete";
    /// cvRef does not match the term's declared namespace.
    pub const mzml_cv_namespace = "mzml.cv.namespace";
    /// A required CV term name is empty.
    pub const mzml_cv_name = "mzml.cv.name";
    /// A present CV term name does not match the catalog name or a synonym.
    pub const mzml_cv_name_mismatch = "mzml.cv.name-mismatch";
    /// A declared external ontology is not bundled, so its accessions were not checked.
    pub const mzml_cv_unverified_namespace = "mzml.cv.unverified-namespace";
    /// Unit term accession is not recognised.
    pub const mzml_cv_unit = "mzml.cv.unit";
    /// CV value is missing, invalid, unsupported, or present without a datatype contract.
    pub const mzml_cv_value = "mzml.cv.value";
    /// A required CV term is missing from an element.
    pub const mzml_cv_required = "mzml.cv.required";
    /// A recommended CV term is missing from an element.
    pub const mzml_cv_recommended = "mzml.cv.recommended";
    /// A CV term is not allowed at its mapped element location, or no location
    /// mapping covers the element.
    pub const mzml_cv_location = "mzml.cv.location";
    /// Mutually exclusive CV terms appear on the same element.
    pub const mzml_cv_contradiction = "mzml.cv.contradiction";
    /// CV ancestry traversal reached its configured bound.
    pub const mzml_cv_ancestry_limit = "mzml.cv.ancestry-limit";
    /// Non-repeatable CV term appears more than once on the same element.
    pub const mzml_cv_term_repeat = "mzml.cv.term-repeat";
    /// A source file lacks the CV terms required by the default mzML object rule.
    pub const mzml_cv_source_file = "mzml.cv.source-file";
    /// A *Ref attribute does not resolve to any declared id.
    pub const mzml_ref_unresolved = "mzml.ref.unresolved";
    /// A reference attribute is present but has an empty value.
    pub const mzml_ref_empty = "mzml.ref.empty";
    /// A reference resolves to an id declared by the wrong mzML element type.
    pub const mzml_ref_wrong_target = "mzml.ref.wrong-target";
    /// Two or more elements share the same id.
    pub const mzml_ref_duplicate_id = "mzml.ref.duplicate-id";
    /// A required *Ref attribute is missing on an element.
    pub const mzml_ref_missing = "mzml.ref.missing";
    /// Local and external spectrum reference attributes form an invalid combination.
    pub const mzml_ref_spectrum_form = "mzml.ref.spectrum-form";
};

const emergency_failure_message = "validation stopped before all enabled stages completed";
pub const first_failure_rule_capacity = 64;
pub const first_failure_message_capacity = 512;
pub const first_failure_path_capacity = std.Io.Dir.max_path_bytes;

/// Shared input-derived limits used by validators in one check.
pub const ResourceLimits = struct {
    max_binary_encoded_bytes: usize = 256 * 1024 * 1024,
    max_binary_decoded_bytes: usize = 256 * 1024 * 1024,
    max_binary_scratch_bytes: usize = 256 * 1024 * 1024,
    max_binary_materialized_bytes: usize = 8 * 1024 * 1024,
    max_index_entries: usize = 1_000_000,
    max_index_state_bytes: usize = 256 * 1024 * 1024,
    max_index_id_ref_bytes: usize = 4096,
    max_index_offset_text_bytes: usize = 64,
    max_index_list_offset_text_bytes: usize = 64,
    max_file_checksum_text_bytes: usize = 64,
    max_obo_line_bytes: usize = 1024 * 1024,
    max_obo_xref_accession_bytes: usize = 128,
    max_obo_source_bytes: usize = 50 * 1024 * 1024,
    max_obo_catalog_bytes: usize = 64 * 1024 * 1024,
    max_semantic_bytes: usize = 64 * 1024 * 1024,
    max_diagnostics: usize = 4096,
    max_rendered_bytes: usize = 4 * 1024 * 1024,
};

/// Classifies diagnostics so CLI exit codes and renderers stay consistent.
pub const Severity = enum {
    info,
    warning,
    @"error",

    pub fn label(severity: Severity) []const u8 {
        return switch (severity) {
            .info => "info",
            .warning => "warning",
            .@"error" => "error",
        };
    }
};

/// Carries optional source coordinates for a diagnostic.
pub const Location = struct {
    byte_offset: ?u64 = null,
    spectrum_index: ?usize = null,

    fn isEmpty(location: Location) bool {
        return location.byte_offset == null and location.spectrum_index == null;
    }

    fn eql(left: Location, right: Location) bool {
        return left.byte_offset == right.byte_offset and left.spectrum_index == right.spectrum_index;
    }
};

pub const max_diagnostic_example_locations = 3;

const aggregation_linear_group_limit = 32;
const aggregation_metadata_first_block_len = 8;
const aggregation_metadata_block_len = 64;
const group_index_empty = std.math.maxInt(usize);
const diagnostic_fixed_rendered_bytes = 192;
const grouped_diagnostic_fixed_rendered_bytes = 640;

const EncodedLocation = struct {
    byte_offset: u64 = 0,
    spectrum_index: usize = 0,
};

const AggregationMetadata = struct {
    locations: [max_diagnostic_example_locations - 1]EncodedLocation = @splat(.{}),
    byte_offset_mask: u8 = 0,
    spectrum_index_mask: u8 = 0,
    count: u8 = 0,

    fn location(metadata: *const AggregationMetadata, index: usize) Location {
        std.debug.assert(index < metadata.count);
        const bit = @as(u8, 1) << @intCast(index);
        return .{
            .byte_offset = if (metadata.byte_offset_mask & bit != 0)
                metadata.locations[index].byte_offset
            else
                null,
            .spectrum_index = if (metadata.spectrum_index_mask & bit != 0)
                metadata.locations[index].spectrum_index
            else
                null,
        };
    }

    fn addLocation(metadata: *AggregationMetadata, primary: Location, location_value: Location) void {
        if (location_value.isEmpty() or primary.eql(location_value)) return;
        for (0..metadata.count) |index| {
            if (metadata.location(index).eql(location_value)) return;
        }
        if (metadata.count == metadata.locations.len) return;

        const index: usize = metadata.count;
        const bit = @as(u8, 1) << @intCast(index);
        if (location_value.byte_offset) |byte_offset| {
            metadata.locations[index].byte_offset = byte_offset;
            metadata.byte_offset_mask |= bit;
        }
        if (location_value.spectrum_index) |spectrum_index| {
            metadata.locations[index].spectrum_index = spectrum_index;
            metadata.spectrum_index_mask |= bit;
        }
        metadata.count += 1;
    }
};

/// Describes one validation finding group. String fields borrow caller-owned storage.
pub const Diagnostic = struct {
    severity: Severity,
    rule: []const u8,
    location: Location = .{},
    path: ?[]const u8 = null,
    message: []const u8,
    occurrences: usize = 1,
    aggregation: ?*AggregationMetadata = null,

    pub fn exampleLocationCount(item: Diagnostic) usize {
        const additional_count = if (item.aggregation) |metadata| metadata.count else 0;
        return @intFromBool(!item.location.isEmpty()) + additional_count;
    }

    pub fn exampleLocation(item: Diagnostic, index: usize) Location {
        std.debug.assert(index < item.exampleLocationCount());
        if (!item.location.isEmpty()) {
            if (index == 0) return item.location;
            return item.aggregation.?.location(index - 1);
        }
        return item.aggregation.?.location(index);
    }

    fn addOccurrence(item: *Diagnostic, location: Location) void {
        item.occurrences = saturatingAdd(item.occurrences, 1);
        const metadata = item.aggregation orelse return;
        if (location.isEmpty()) return;
        if (item.location.isEmpty()) {
            item.location = location;
            return;
        }
        metadata.addLocation(item.location, location);
    }
};

/// Per-file borrowed detail with bounded retention and complete severity totals.
pub const DiagnosticSink = struct {
    items: []Diagnostic = &.{},
    capacity: usize = 0,
    totals: Totals = .{},
    dropped: Totals = .{},
    retained_bytes: usize = 0,
    aggregation_blocks: std.ArrayList([]AggregationMetadata) = .empty,
    aggregation_count: usize = 0,
    group_index: []usize = &.{},
    group_index_disabled: bool = false,
    peak_allocated_bytes: usize = 0,
    peak_aggregation_metadata_bytes: usize = 0,
    peak_group_index_bytes: usize = 0,
    limits: Limits = .{},
    configured: bool = false,

    /// The byte limit uses a conservative escaped-output estimate.
    pub const Limits = struct {
        max_diagnostics: usize = 4096,
        max_rendered_bytes: usize = 4 * 1024 * 1024,
        retain_details: bool = true,
        aggregate_occurrences: bool = false,
    };

    /// Snapshot used to calculate totals for one validation scope.
    pub const Mark = struct {
        totals: Totals,
        dropped: Totals,
    };

    /// Zero-allocation sink using default limits until explicitly configured.
    pub const empty: DiagnosticSink = .{ .configured = false };

    /// Creates a sink with explicit retention limits.
    pub fn init(limits: Limits) DiagnosticSink {
        return .{ .limits = limits, .configured = true };
    }

    /// Applies shared limits only to a sink that has not been explicitly configured.
    pub fn configureFromResourceLimits(sink: *DiagnosticSink, resource_limits: ResourceLimits) void {
        if (sink.configured) return;
        sink.limits.max_diagnostics = resource_limits.max_diagnostics;
        sink.limits.max_rendered_bytes = resource_limits.max_rendered_bytes;
        sink.configured = true;
    }

    /// Counts every item and retains detail when configured to do so and within limits.
    /// Returns true only when the item is retained. Intentional non-retention does
    /// not increment `dropped`; allocation failures propagate.
    pub fn append(sink: *DiagnosticSink, allocator: std.mem.Allocator, item: Diagnostic) !bool {
        if (!sink.limits.retain_details) {
            sink.addTotal(item.severity);
            return false;
        }
        var group_hash: ?u64 = null;
        if (sink.limits.aggregate_occurrences) {
            const existing_index = if (sink.group_index.len > 0) indexed: {
                const hash = diagnosticGroupHash(&item);
                group_hash = hash;
                break :indexed sink.findIndexedGroup(&item, hash);
            } else sink.findLinearGroup(&item);
            if (existing_index) |index| {
                const retained = &sink.items[index];
                retained.addOccurrence(item.location);
                sink.addTotal(item.severity);
                return true;
            }
        }
        const item_bytes = diagnosticBytes(item, sink.limits.aggregate_occurrences);
        const count_limit = sink.items.len >= sink.limits.max_diagnostics;
        const next_bytes = std.math.add(usize, sink.retained_bytes, item_bytes) catch {
            sink.addDropped(item.severity);
            return false;
        };
        if (count_limit or next_bytes > sink.limits.max_rendered_bytes) {
            sink.addDropped(item.severity);
            return false;
        }

        const requested = std.math.add(usize, sink.items.len, 1) catch {
            sink.addDropped(item.severity);
            return false;
        };
        if (sink.limits.aggregate_occurrences and !sink.group_index_disabled) {
            sink.prepareGroupIndex(allocator, requested);
        }
        try sink.ensureTotalCapacity(allocator, requested);
        const aggregation = if (sink.limits.aggregate_occurrences)
            try sink.allocateAggregationMetadata(allocator)
        else
            null;
        const index = sink.items.len;
        sink.items.len = requested;
        sink.items[index] = item;
        sink.items[index].occurrences = 1;
        sink.items[index].aggregation = aggregation;
        if (sink.group_index.len > 0) {
            sink.insertGroupIndex(group_hash orelse diagnosticGroupHash(&sink.items[index]), index);
        }
        sink.retained_bytes = next_bytes;
        sink.updateAllocationPeaks();
        sink.addTotal(item.severity);
        return true;
    }

    /// Grows the retained-detail buffer without exceeding max_diagnostics.
    pub fn ensureTotalCapacity(sink: *DiagnosticSink, allocator: std.mem.Allocator, requested: usize) !void {
        if (requested <= sink.capacity) return;
        if (requested > sink.limits.max_diagnostics) return error.OutOfMemory;

        const growth = std.math.add(usize, sink.capacity, sink.capacity / 2) catch std.math.maxInt(usize);
        const grown = if (sink.capacity < 8) 8 else growth;
        const new_capacity = @min(sink.limits.max_diagnostics, @max(requested, grown));
        const old_memory = if (sink.capacity == 0) sink.items[0..0] else sink.items.ptr[0..sink.capacity];
        const old_len = sink.items.len;
        if (sink.capacity > 0) {
            if (allocator.remap(old_memory, new_capacity)) |new_items| {
                sink.items = new_items[0..old_len];
                sink.capacity = new_items.len;
                sink.updateAllocationPeaks();
                return;
            }
        }

        const new_items = try allocator.alloc(Diagnostic, new_capacity);
        sink.peak_allocated_bytes = @max(
            sink.peak_allocated_bytes,
            saturatingAdd(sink.allocatedBytes(), saturatingMul(new_capacity, @sizeOf(Diagnostic))),
        );
        @memcpy(new_items[0..sink.items.len], sink.items);
        if (sink.capacity > 0) allocator.free(old_memory);
        sink.items = new_items[0..old_len];
        sink.capacity = new_capacity;
        sink.updateAllocationPeaks();
    }

    /// Releases retained detail and resets the sink to its unconfigured state.
    pub fn deinit(sink: *DiagnosticSink, allocator: std.mem.Allocator) void {
        if (sink.capacity > 0) allocator.free(sink.items.ptr[0..sink.capacity]);
        for (sink.aggregation_blocks.items) |block| allocator.free(block);
        sink.aggregation_blocks.deinit(allocator);
        if (sink.group_index.len > 0) allocator.free(sink.group_index);
        sink.* = .empty;
    }

    /// Clears detail and totals while retaining the allocated buffer and limits.
    pub fn clearRetainingCapacity(sink: *DiagnosticSink) void {
        sink.items.len = 0;
        sink.totals = .{};
        sink.dropped = .{};
        sink.retained_bytes = 0;
        sink.aggregation_count = 0;
        if (sink.group_index.len > 0) @memset(sink.group_index, group_index_empty);
    }

    fn allocateAggregationMetadata(
        sink: *DiagnosticSink,
        allocator: std.mem.Allocator,
    ) !*AggregationMetadata {
        const block_index, const item_index = if (sink.aggregation_count < aggregation_metadata_first_block_len)
            .{ 0, sink.aggregation_count }
        else adjusted: {
            const adjusted_count = sink.aggregation_count - aggregation_metadata_first_block_len;
            break :adjusted .{
                1 + adjusted_count / aggregation_metadata_block_len,
                adjusted_count % aggregation_metadata_block_len,
            };
        };
        if (block_index == sink.aggregation_blocks.items.len) {
            const block_len: usize = if (block_index == 0)
                aggregation_metadata_first_block_len
            else
                aggregation_metadata_block_len;
            const block = try allocator.alloc(AggregationMetadata, block_len);
            const block_bytes = saturatingMul(block_len, @sizeOf(AggregationMetadata));
            sink.peak_aggregation_metadata_bytes = @max(
                sink.peak_aggregation_metadata_bytes,
                saturatingAdd(sink.aggregationMetadataCapacityBytes(), block_bytes),
            );
            sink.peak_allocated_bytes = @max(
                sink.peak_allocated_bytes,
                saturatingAdd(sink.allocatedBytes(), block_bytes),
            );
            errdefer allocator.free(block);
            try sink.aggregation_blocks.append(allocator, block);
        }
        const metadata = &sink.aggregation_blocks.items[block_index][item_index];
        metadata.* = .{};
        sink.aggregation_count += 1;
        return metadata;
    }

    fn findLinearGroup(sink: *const DiagnosticSink, item: *const Diagnostic) ?usize {
        for (sink.items, 0..) |*retained, index| {
            if (sameDiagnosticGroup(retained, item)) return index;
        }
        return null;
    }

    fn findIndexedGroup(sink: *const DiagnosticSink, item: *const Diagnostic, hash: u64) ?usize {
        var slot = @as(usize, @truncate(hash)) & (sink.group_index.len - 1);
        while (true) {
            const item_index = sink.group_index[slot];
            if (item_index == group_index_empty) return null;
            if (sameDiagnosticGroup(&sink.items[item_index], item)) return item_index;
            slot = (slot + 1) & (sink.group_index.len - 1);
        }
    }

    fn disableGroupIndex(sink: *DiagnosticSink, allocator: std.mem.Allocator) void {
        if (sink.group_index.len > 0) allocator.free(sink.group_index);
        sink.group_index = &.{};
        sink.group_index_disabled = true;
    }

    fn prepareGroupIndex(
        sink: *DiagnosticSink,
        allocator: std.mem.Allocator,
        requested_groups: usize,
    ) void {
        sink.ensureGroupIndexCapacity(allocator, requested_groups) catch {
            sink.disableGroupIndex(allocator);
        };
    }

    fn ensureGroupIndexCapacity(
        sink: *DiagnosticSink,
        allocator: std.mem.Allocator,
        requested_groups: usize,
    ) !void {
        if (sink.group_index.len == 0 and requested_groups < aggregation_linear_group_limit) return;
        const required_slots = std.math.mul(usize, requested_groups, 2) catch return error.OutOfMemory;
        if (required_slots <= sink.group_index.len) return;

        var new_len: usize = aggregation_linear_group_limit * 2;
        while (new_len < required_slots) {
            new_len = std.math.mul(usize, new_len, 2) catch return error.OutOfMemory;
        }
        const new_index = try allocator.alloc(usize, new_len);
        const new_index_bytes = saturatingMul(new_len, @sizeOf(usize));
        sink.peak_group_index_bytes = @max(
            sink.peak_group_index_bytes,
            saturatingAdd(sink.groupIndexCapacityBytes(), new_index_bytes),
        );
        sink.peak_allocated_bytes = @max(
            sink.peak_allocated_bytes,
            saturatingAdd(sink.allocatedBytes(), new_index_bytes),
        );
        @memset(new_index, group_index_empty);
        const old_index = sink.group_index;
        sink.group_index = new_index;
        for (sink.items, 0..) |*retained, index| {
            sink.insertGroupIndex(diagnosticGroupHash(retained), index);
        }
        if (old_index.len > 0) allocator.free(old_index);
    }

    fn insertGroupIndex(sink: *DiagnosticSink, hash: u64, item_index: usize) void {
        var slot = @as(usize, @truncate(hash)) & (sink.group_index.len - 1);
        while (sink.group_index[slot] != group_index_empty) {
            slot = (slot + 1) & (sink.group_index.len - 1);
        }
        sink.group_index[slot] = item_index;
    }

    fn diagnosticCapacityBytes(sink: *const DiagnosticSink) usize {
        return saturatingMul(sink.capacity, @sizeOf(Diagnostic));
    }

    fn aggregationMetadataCapacityBytes(sink: *const DiagnosticSink) usize {
        var bytes = saturatingMul(sink.aggregation_blocks.capacity, @sizeOf([]AggregationMetadata));
        for (sink.aggregation_blocks.items) |block| {
            bytes = saturatingAdd(bytes, saturatingMul(block.len, @sizeOf(AggregationMetadata)));
        }
        return bytes;
    }

    fn groupIndexCapacityBytes(sink: *const DiagnosticSink) usize {
        return saturatingMul(sink.group_index.len, @sizeOf(usize));
    }

    pub fn allocatedBytes(sink: *const DiagnosticSink) usize {
        return saturatingAdd(
            sink.diagnosticCapacityBytes(),
            saturatingAdd(sink.aggregationMetadataCapacityBytes(), sink.groupIndexCapacityBytes()),
        );
    }

    pub fn peakAllocatedBytes(sink: *const DiagnosticSink) usize {
        return sink.peak_allocated_bytes;
    }

    fn updateAllocationPeaks(sink: *DiagnosticSink) void {
        sink.peak_allocated_bytes = @max(sink.peak_allocated_bytes, sink.allocatedBytes());
        sink.peak_aggregation_metadata_bytes = @max(
            sink.peak_aggregation_metadata_bytes,
            sink.aggregationMetadataCapacityBytes(),
        );
        sink.peak_group_index_bytes = @max(sink.peak_group_index_bytes, sink.groupIndexCapacityBytes());
    }

    pub fn mark(sink: *const DiagnosticSink) Mark {
        return .{ .totals = sink.totals, .dropped = sink.dropped };
    }

    pub fn totalsSince(sink: *const DiagnosticSink, mark_value: Mark) Totals {
        return subtractTotals(sink.totals, mark_value.totals);
    }

    pub fn droppedSince(sink: *const DiagnosticSink, mark_value: Mark) Totals {
        return subtractTotals(sink.dropped, mark_value.dropped);
    }

    pub fn truncatedSince(sink: *const DiagnosticSink, mark_value: Mark) bool {
        const dropped = sink.droppedSince(mark_value);
        return dropped.info != 0 or dropped.warnings != 0 or dropped.errors != 0;
    }

    fn addTotal(sink: *DiagnosticSink, severity: Severity) void {
        switch (severity) {
            .info => sink.totals.info = saturatingAdd(sink.totals.info, 1),
            .warning => sink.totals.warnings = saturatingAdd(sink.totals.warnings, 1),
            .@"error" => sink.totals.errors = saturatingAdd(sink.totals.errors, 1),
        }
    }

    fn addDropped(sink: *DiagnosticSink, severity: Severity) void {
        switch (severity) {
            .info => sink.dropped.info = saturatingAdd(sink.dropped.info, 1),
            .warning => sink.dropped.warnings = saturatingAdd(sink.dropped.warnings, 1),
            .@"error" => sink.dropped.errors = saturatingAdd(sink.dropped.errors, 1),
        }
        sink.addTotal(severity);
    }
};

fn sameDiagnosticGroup(left: *const Diagnostic, right: *const Diagnostic) bool {
    return left.severity == right.severity and
        std.mem.eql(u8, left.rule, right.rule) and
        optionalStringEql(left.path, right.path) and
        std.mem.eql(u8, left.message, right.message);
}

fn diagnosticGroupHash(item: *const Diagnostic) u64 {
    var hash: u64 = 0xcbf29ce484222325;
    hashByte(&hash, @intFromEnum(item.severity));
    hashSlice(&hash, item.rule);
    if (item.path) |path| {
        hashByte(&hash, 1);
        hashSlice(&hash, path);
    } else {
        hashByte(&hash, 0);
    }
    hashSlice(&hash, item.message);
    return hash;
}

fn hashSlice(hash: *u64, value: []const u8) void {
    for (value) |byte| hashByte(hash, byte);
    hashByte(hash, 0xff);
}

fn hashByte(hash: *u64, byte: u8) void {
    hash.* = (hash.* ^ byte) *% 0x100000001b3;
}

fn optionalStringEql(left: ?[]const u8, right: ?[]const u8) bool {
    if (left) |left_value| {
        if (right) |right_value| return std.mem.eql(u8, left_value, right_value);
        return false;
    }
    return right == null;
}

fn diagnosticBytes(item: Diagnostic, grouped: bool) usize {
    var bytes: usize = if (grouped)
        grouped_diagnostic_fixed_rendered_bytes
    else
        diagnostic_fixed_rendered_bytes;
    bytes = saturatingAdd(bytes, saturatingMul(item.rule.len, 6));
    bytes = saturatingAdd(bytes, saturatingMul(item.message.len, 6));
    if (item.path) |path| bytes = saturatingAdd(bytes, saturatingMul(path.len, 6));
    return bytes;
}

fn saturatingAdd(left: usize, right: usize) usize {
    return std.math.add(usize, left, right) catch std.math.maxInt(usize);
}

fn saturatingMul(left: usize, right: usize) usize {
    return std.math.mul(usize, left, right) catch std.math.maxInt(usize);
}

fn subtractTotals(current: Totals, previous: Totals) Totals {
    return .{
        .info = current.info -| previous.info,
        .warnings = current.warnings -| previous.warnings,
        .errors = current.errors -| previous.errors,
    };
}

pub const CompletionState = enum {
    complete,
    incomplete,

    pub fn label(state: CompletionState) []const u8 {
        return switch (state) {
            .complete => "complete",
            .incomplete => "incomplete",
        };
    }
};

pub const ValidationStage = enum(u3) {
    input,
    parser,
    structural,
    binary,
    index,
    semantic,

    pub fn label(stage: ValidationStage) []const u8 {
        return switch (stage) {
            .input => "input",
            .parser => "parser",
            .structural => "structural",
            .binary => "binary",
            .index => "index",
            .semantic => "semantic",
        };
    }
};

pub const StageMask = u8;

/// Returns the mask bit assigned to a validation stage.
pub fn stageBit(stage: ValidationStage) StageMask {
    return @as(StageMask, 1) << @intFromEnum(stage);
}

pub const FailureReason = enum {
    input,
    parser,
    allocation,
    resource,
    catalog,
    decompression,
    file_stability,
    output,
    unknown,

    pub fn label(reason: FailureReason) []const u8 {
        return switch (reason) {
            .input => "input",
            .parser => "parser",
            .allocation => "allocation",
            .resource => "resource",
            .catalog => "catalog",
            .decompression => "decompression",
            .file_stability => "file-stability",
            .output => "output",
            .unknown => "unknown",
        };
    }
};

/// Tracks aggregate counts so renderers and exit-code mapping share one source of truth.
pub const Totals = struct {
    info: usize = 0,
    warnings: usize = 0,
    errors: usize = 0,
};

/// Per-file owner measurements captured before validation state is released.
/// Parser bytes cover the eager caller-owned token buffer. Binary scratch bytes
/// cover allocator-owned compressed, flate, and libdeflate output capacities;
/// the opaque allocation owned by libdeflate's decompressor is external and
/// excluded because its ABI does not expose an allocation size. Diagnostic
/// bytes cover retained records plus aggregation metadata and the group index
/// at file finalization. Aggregation subfields expose those side allocations.
pub const ResourceUsage = struct {
    parser_current_bytes: usize = 0,
    parser_peak_bytes: usize = 0,
    binary_scratch_current_bytes: usize = 0,
    binary_scratch_peak_bytes: usize = 0,
    index_current_bytes: usize = 0,
    index_peak_bytes: usize = 0,
    semantic_current_bytes: usize = 0,
    semantic_peak_bytes: usize = 0,
    semantic_declaration_bytes: usize = 0,
    semantic_unresolved_bytes: usize = 0,
    semantic_scope_bytes: usize = 0,
    semantic_param_group_bytes: usize = 0,
    semantic_declaration_peak_bytes: usize = 0,
    semantic_unresolved_peak_bytes: usize = 0,
    semantic_scope_peak_bytes: usize = 0,
    semantic_param_group_peak_bytes: usize = 0,
    diagnostic_current_bytes: usize = 0,
    diagnostic_peak_bytes: usize = 0,
    diagnostic_group_metadata_current_bytes: usize = 0,
    diagnostic_group_metadata_peak_bytes: usize = 0,
    diagnostic_group_index_current_bytes: usize = 0,
    diagnostic_group_index_peak_bytes: usize = 0,
};

fn BoundedFailureText(comptime capacity: usize) type {
    return struct {
        bytes: [capacity]u8 = undefined,
        len: usize = 0,
        truncated: bool = false,

        fn init(value: []const u8) @This() {
            var text: @This() = .{};
            text.len = @min(value.len, capacity);
            @memcpy(text.bytes[0..text.len], value[0..text.len]);
            text.truncated = value.len > capacity;
            if (text.truncated and capacity >= 3) @memcpy(text.bytes[capacity - 3 ..], "...");
            return text;
        }

        fn slice(text: *const @This()) []const u8 {
            return text.bytes[0..text.len];
        }
    };
}

const FailureRule = BoundedFailureText(first_failure_rule_capacity);
const FailureMessage = BoundedFailureText(first_failure_message_capacity);
const FailurePath = BoundedFailureText(first_failure_path_capacity);

/// Fixed, allocation-free metadata for the first failure that stopped a file.
/// Text accessors borrow this record; the record itself owns each copied value.
pub const FirstFailure = struct {
    stage: ValidationStage,
    reason: FailureReason,
    rule_text: FailureRule,
    message_text: FailureMessage,
    location: Location = .{},
    path_text: ?FailurePath = null,

    fn init(
        stage: ValidationStage,
        reason: FailureReason,
        rule_value: []const u8,
        message_value: []const u8,
        location: Location,
        path_value: ?[]const u8,
    ) FirstFailure {
        return .{
            .stage = stage,
            .reason = reason,
            .rule_text = .init(rule_value),
            .message_text = .init(message_value),
            .location = location,
            .path_text = if (path_value) |value| .init(value) else null,
        };
    }

    /// Returns a slice owned by this failure record.
    pub fn rule(failure: *const FirstFailure) []const u8 {
        return failure.rule_text.slice();
    }

    /// Returns a slice owned by this failure record.
    pub fn message(failure: *const FirstFailure) []const u8 {
        return failure.message_text.slice();
    }

    /// Returns an optional slice owned by this failure record.
    pub fn path(failure: *const FirstFailure) ?[]const u8 {
        if (failure.path_text) |*text| return text.slice();
        return null;
    }

    /// Reports whether a source value exceeded the fixed emergency storage.
    pub fn metadataTruncated(failure: *const FirstFailure) bool {
        return failure.rule_text.truncated or
            failure.message_text.truncated or
            if (failure.path_text) |path_text| path_text.truncated else false;
    }
};

/// Owned per-file values independent of parser, input, and diagnostic lifetimes.
pub const FileResult = struct {
    completion: CompletionState = .incomplete,
    enabled_stages: StageMask = 0,
    completed_stages: StageMask = 0,
    totals: Totals = .{},
    resource_usage: ResourceUsage = .{},
    first_failure: ?FirstFailure = null,
    diagnostics_truncated: bool = false,
    dropped_diagnostics: Totals = .{},

    active_stage: ValidationStage = .input,
    failure_diagnostic_emitted: bool = false,
    failure_diagnostic_counted: bool = false,

    pub fn init(enabled_stages: StageMask) FileResult {
        return .{ .enabled_stages = enabled_stages };
    }

    pub fn beginStage(result: *FileResult, stage: ValidationStage) void {
        result.active_stage = stage;
    }

    pub fn completeStage(result: *FileResult, stage: ValidationStage) void {
        result.completed_stages |= stageBit(stage);
    }

    /// Stores the first failure without allocating or replacing an earlier failure.
    pub fn recordFailure(
        result: *FileResult,
        stage: ValidationStage,
        reason: FailureReason,
        rule: []const u8,
        message: []const u8,
        location: Location,
        path: ?[]const u8,
        diagnostic_emitted: bool,
    ) void {
        if (!diagnostic_emitted) result.diagnostics_truncated = true;
        if (result.first_failure != null) return;
        result.first_failure = .init(stage, reason, rule, message, location, path);
        result.failure_diagnostic_emitted = diagnostic_emitted;
        result.failure_diagnostic_counted = diagnostic_emitted;
    }

    pub fn recordEmergencyFailure(
        result: *FileResult,
        stage: ValidationStage,
        reason: FailureReason,
        path: ?[]const u8,
    ) void {
        result.recordFailure(stage, reason, RuleId.runtime_incomplete, emergency_failure_message, .{}, path, false);
    }

    pub fn finalize(result: *FileResult, diagnostics: []const Diagnostic) void {
        result.totals = count(diagnostics);
        result.finish();
    }

    pub fn finalizeSink(result: *FileResult, sink: *const DiagnosticSink, mark_value: DiagnosticSink.Mark) void {
        result.totals = sink.totalsSince(mark_value);
        result.dropped_diagnostics = sink.droppedSince(mark_value);
        result.diagnostics_truncated = result.diagnostics_truncated or sink.truncatedSince(mark_value);
        const capacity_bytes = sink.allocatedBytes();
        result.resource_usage.diagnostic_current_bytes = capacity_bytes;
        result.resource_usage.diagnostic_peak_bytes = sink.peak_allocated_bytes;
        const metadata_bytes = sink.aggregationMetadataCapacityBytes();
        result.resource_usage.diagnostic_group_metadata_current_bytes = metadata_bytes;
        result.resource_usage.diagnostic_group_metadata_peak_bytes = sink.peak_aggregation_metadata_bytes;
        const index_bytes = sink.groupIndexCapacityBytes();
        result.resource_usage.diagnostic_group_index_current_bytes = index_bytes;
        result.resource_usage.diagnostic_group_index_peak_bytes = sink.peak_group_index_bytes;
        result.finish();
    }

    fn finish(result: *FileResult) void {
        if (result.first_failure != null) {
            if (!result.failure_diagnostic_emitted and !result.failure_diagnostic_counted) {
                result.totals.errors = std.math.add(usize, result.totals.errors, 1) catch std.math.maxInt(usize);
            }
        }
        result.completion = if (result.first_failure == null and result.completed_stages == result.enabled_stages)
            .complete
        else
            .incomplete;
    }

    pub fn status(result: FileResult) ResultStatus {
        if (result.completion == .incomplete) return .errors_present;
        if (result.totals.errors > 0) return .errors_present;
        if (result.totals.warnings > 0) return .warnings_only;
        return .clean;
    }

    pub fn needsEmergencyDiagnostic(result: FileResult) bool {
        return result.first_failure != null and !result.failure_diagnostic_emitted;
    }
};

/// Distills a run into the three states the CLI cares about.
pub const ResultStatus = enum {
    clean,
    warnings_only,
    errors_present,

    pub fn label(status: ResultStatus) []const u8 {
        return switch (status) {
            .clean => "clean",
            .warnings_only => "warnings-only",
            .errors_present => "errors-present",
        };
    }
};

/// Aggregates fixed result metadata without retaining diagnostic detail.
pub const Summary = struct {
    totals: Totals = .{},
    completion: CompletionState = .complete,
    files: usize = 0,
    incomplete_files: usize = 0,
    diagnostics_truncated: bool = false,
    dropped_diagnostics: Totals = .{},
    first_failure: ?FirstFailure = null,
    first_emergency_failure: ?FirstFailure = null,
    emergency_failures: usize = 0,

    pub fn addResult(summary: *Summary, result: FileResult) void {
        summary.files = saturatingAdd(summary.files, 1);
        summary.totals.info = saturatingAdd(summary.totals.info, result.totals.info);
        summary.totals.warnings = saturatingAdd(summary.totals.warnings, result.totals.warnings);
        summary.totals.errors = saturatingAdd(summary.totals.errors, result.totals.errors);
        summary.dropped_diagnostics.info = saturatingAdd(
            summary.dropped_diagnostics.info,
            result.dropped_diagnostics.info,
        );
        summary.dropped_diagnostics.warnings = saturatingAdd(
            summary.dropped_diagnostics.warnings,
            result.dropped_diagnostics.warnings,
        );
        summary.dropped_diagnostics.errors = saturatingAdd(
            summary.dropped_diagnostics.errors,
            result.dropped_diagnostics.errors,
        );
        summary.diagnostics_truncated = summary.diagnostics_truncated or result.diagnostics_truncated;
        if (result.completion == .incomplete) {
            summary.completion = .incomplete;
            summary.incomplete_files = saturatingAdd(summary.incomplete_files, 1);
            if (summary.first_failure == null) summary.first_failure = result.first_failure;
        }
        if (result.needsEmergencyDiagnostic()) {
            summary.emergency_failures = saturatingAdd(summary.emergency_failures, 1);
            if (summary.first_emergency_failure == null) {
                summary.first_emergency_failure = result.first_failure;
            }
        }
    }

    pub fn status(summary: Summary) ResultStatus {
        if (summary.completion == .incomplete) return .errors_present;
        if (summary.totals.errors > 0) return .errors_present;
        if (summary.totals.warnings > 0) return .warnings_only;
        return .clean;
    }
};

/// Tallies diagnostics by severity for renderers and exit-code mapping.
pub fn count(diagnostics: []const Diagnostic) Totals {
    var totals: Totals = .{};
    for (diagnostics) |item| {
        switch (item.severity) {
            .info => totals.info = saturatingAdd(totals.info, item.occurrences),
            .warning => totals.warnings = saturatingAdd(totals.warnings, item.occurrences),
            .@"error" => totals.errors = saturatingAdd(totals.errors, item.occurrences),
        }
    }
    return totals;
}

/// Bundles severity counts with the derived run status.
pub fn summarize(diagnostics: []const Diagnostic) Summary {
    return .{ .totals = count(diagnostics) };
}

pub fn summarizeResults(results: []const FileResult) Summary {
    var summary: Summary = .{};
    for (results) |result| summary.addResult(result);
    return summary;
}

/// Maps diagnostics to the process exit code contract.
///
/// 0 = clean, 1 = warnings only, 2 = any errors present.
pub fn exitCode(diagnostics: []const Diagnostic) u8 {
    return switch (summarize(diagnostics).status()) {
        .clean => 0,
        .warnings_only => 1,
        .errors_present => 2,
    };
}

/// Maps per-file completion and severity results to the process exit code.
pub fn exitCodeForResults(results: []const FileResult) u8 {
    return exitCodeForSummary(summarizeResults(results));
}

/// Maps an incrementally aggregated invocation summary to the process exit code.
pub fn exitCodeForSummary(summary: Summary) u8 {
    return switch (summary.status()) {
        .clean => 0,
        .warnings_only => 1,
        .errors_present => 2,
    };
}

// --- Unit Tests ---

test "errors take precedence over warnings in exit codes" {
    const diagnostics = [_]Diagnostic{
        .{ .severity = .warning, .rule = RuleId.runtime_stub, .message = "stub" },
        .{ .severity = .@"error", .rule = RuleId.runtime_file_open, .message = "open failed" },
    };

    try std.testing.expectEqual(@as(u8, 2), exitCode(&diagnostics));
}

test "summary status follows diagnostic severity" {
    const clean_summary = summarize(&.{});

    try std.testing.expectEqual(ResultStatus.clean, clean_summary.status());

    const warning_diagnostics = [_]Diagnostic{
        .{ .severity = .warning, .rule = RuleId.runtime_stub, .message = "stub" },
    };
    try std.testing.expectEqual(ResultStatus.warnings_only, summarize(&warning_diagnostics).status());

    const error_diagnostics = [_]Diagnostic{
        .{ .severity = .@"error", .rule = RuleId.runtime_file_open, .message = "open failed" },
    };
    try std.testing.expectEqual(ResultStatus.errors_present, summarize(&error_diagnostics).status());
}

test "result summary aggregates file and truncation metadata" {
    var clean = FileResult.init(0);
    clean.finalize(&.{});
    var incomplete = FileResult.init(stageBit(.parser));
    incomplete.recordFailure(.parser, .parser, RuleId.mzml_structure_xml, "parser stopped", .{}, "bad.mzML", true);
    incomplete.totals = .{ .info = 2, .warnings = 1, .errors = 1 };
    incomplete.dropped_diagnostics = .{ .warnings = 1 };
    incomplete.diagnostics_truncated = true;
    incomplete.finish();

    const summary = summarizeResults(&.{ clean, incomplete });

    try std.testing.expectEqual(@as(usize, 2), summary.files);
    try std.testing.expectEqual(@as(usize, 1), summary.incomplete_files);
    try std.testing.expectEqual(Totals{ .info = 2, .warnings = 1, .errors = 1 }, summary.totals);
    try std.testing.expectEqual(Totals{ .warnings = 1 }, summary.dropped_diagnostics);
    try std.testing.expect(summary.diagnostics_truncated);
    const failure = summary.first_failure.?;
    try std.testing.expectEqualStrings(RuleId.mzml_structure_xml, failure.rule());
}

test "[unit]: result summary saturates invocation counts" {
    var summary = Summary{
        .totals = .{
            .info = std.math.maxInt(usize),
            .warnings = std.math.maxInt(usize),
            .errors = std.math.maxInt(usize),
        },
        .files = std.math.maxInt(usize),
        .incomplete_files = std.math.maxInt(usize),
        .emergency_failures = std.math.maxInt(usize),
        .dropped_diagnostics = .{
            .info = std.math.maxInt(usize),
            .warnings = std.math.maxInt(usize),
            .errors = std.math.maxInt(usize),
        },
    };
    var result = FileResult.init(stageBit(.input));
    result.recordEmergencyFailure(.input, .allocation, "input.mzML");
    result.finalize(&.{});

    summary.addResult(result);

    try std.testing.expectEqual(std.math.maxInt(usize), summary.files);
    try std.testing.expectEqual(std.math.maxInt(usize), summary.incomplete_files);
    try std.testing.expectEqual(std.math.maxInt(usize), summary.emergency_failures);
    try std.testing.expectEqual(std.math.maxInt(usize), summary.totals.info);
    try std.testing.expectEqual(std.math.maxInt(usize), summary.totals.warnings);
    try std.testing.expectEqual(std.math.maxInt(usize), summary.totals.errors);
    try std.testing.expectEqual(std.math.maxInt(usize), summary.dropped_diagnostics.info);
    try std.testing.expectEqual(std.math.maxInt(usize), summary.dropped_diagnostics.warnings);
    try std.testing.expectEqual(std.math.maxInt(usize), summary.dropped_diagnostics.errors);
    try std.testing.expect(summary.first_emergency_failure != null);
}

test "file result stays incomplete until every enabled stage completes" {
    var result = FileResult.init(stageBit(.input) | stageBit(.parser));

    result.completeStage(.input);
    result.finalize(&.{});

    try std.testing.expectEqual(CompletionState.incomplete, result.completion);
    try std.testing.expectEqual(@as(u8, 2), exitCodeForResults(&.{result}));
}

test "file result records first failure without normal diagnostic storage" {
    var result = FileResult.init(stageBit(.parser));

    result.recordFailure(.parser, .parser, RuleId.mzml_structure_xml, "parser stopped", .{}, "sample.mzML", false);
    result.finalize(&.{});

    try std.testing.expect(result.diagnostics_truncated);
    try std.testing.expectEqual(CompletionState.incomplete, result.completion);
    try std.testing.expect(result.needsEmergencyDiagnostic());
    try std.testing.expectEqual(@as(usize, 1), result.totals.errors);
    try std.testing.expectEqual(@as(u8, 2), exitCodeForResults(&.{result}));
}

test "file result marks the fixed emergency failure path" {
    var result = FileResult.init(stageBit(.semantic));

    result.recordEmergencyFailure(.semantic, .allocation, "sample.mzML");
    result.finalize(&.{});

    try std.testing.expect(result.diagnostics_truncated);
    try std.testing.expect(result.needsEmergencyDiagnostic());
    const failure = result.first_failure.?;
    try std.testing.expectEqualStrings(emergency_failure_message, failure.message());
}

test "file result owns first failure metadata" {
    var rule = [_]u8{ 't', 'e', 's', 't', '.', 'r', 'u', 'l', 'e' };
    var message = [_]u8{ 's', 't', 'o', 'p', 'p', 'e', 'd' };
    var path = [_]u8{ 'i', 'n', 'p', 'u', 't', '.', 'm', 'z', 'M', 'L' };
    var result = FileResult.init(stageBit(.parser));
    result.recordFailure(.parser, .parser, &rule, &message, .{}, &path, false);

    @memset(&rule, 'x');
    @memset(&message, 'x');
    @memset(&path, 'x');

    const failure = result.first_failure.?;
    try std.testing.expectEqualStrings("test.rule", failure.rule());
    try std.testing.expectEqualStrings("stopped", failure.message());
    try std.testing.expectEqualStrings("input.mzML", failure.path().?);
    try std.testing.expect(!failure.metadataTruncated());
}

test "first failure reports bounded metadata truncation" {
    var long_path: [first_failure_path_capacity + 1]u8 = @splat('a');
    var result = FileResult.init(stageBit(.input));
    result.recordFailure(.input, .input, RuleId.runtime_file_open, "open failed", .{}, &long_path, true);

    const failure = result.first_failure.?;
    const path = failure.path().?;
    try std.testing.expect(failure.metadataTruncated());
    try std.testing.expectEqual(first_failure_path_capacity, path.len);
    try std.testing.expectEqualStrings("...", path[path.len - 3 ..]);
}

test "diagnostic sink handles maximal configured capacity without arithmetic overflow" {
    var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var sink = DiagnosticSink.init(.{ .max_diagnostics = std.math.maxInt(usize) });
    defer sink.deinit(failing_allocator.allocator());

    try std.testing.expectError(
        error.OutOfMemory,
        sink.ensureTotalCapacity(failing_allocator.allocator(), std.math.maxInt(usize)),
    );
    try std.testing.expectEqual(@as(usize, 0), sink.capacity);
}

fn diagnosticGrowthAllocationCheck(allocator: std.mem.Allocator) !void {
    var sink: DiagnosticSink = .empty;
    defer sink.deinit(allocator);
    for (0..17) |index| {
        _ = try sink.append(allocator, .{
            .severity = if (index % 2 == 0) .warning else .@"error",
            .rule = "test.allocation",
            .message = "retained diagnostic",
        });
    }
}

test "[unit]: diagnostic sink cleans every growth allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        diagnosticGrowthAllocationCheck,
        .{},
    );
}

test "[unit]: diagnostic sink aggregates occurrences and bounds example locations" {
    var sink = DiagnosticSink.init(.{ .aggregate_occurrences = true });
    defer sink.deinit(std.testing.allocator);

    for (0..5) |index| {
        _ = try sink.append(std.testing.allocator, .{
            .severity = .@"error",
            .rule = "test.repeated",
            .path = "input.mzML",
            .location = .{ .byte_offset = index, .spectrum_index = index },
            .message = "repeated finding",
        });
    }

    try std.testing.expectEqual(@as(usize, 1), sink.items.len);
    try std.testing.expectEqual(@as(usize, 5), sink.items[0].occurrences);
    try std.testing.expectEqual(@as(usize, max_diagnostic_example_locations), sink.items[0].exampleLocationCount());
    try std.testing.expectEqual(@as(?u64, 0), sink.items[0].exampleLocation(0).byte_offset);
    try std.testing.expectEqual(@as(?u64, 2), sink.items[0].exampleLocation(2).byte_offset);
    try std.testing.expectEqual(@as(usize, 5), sink.totals.errors);
}

test "[unit]: diagnostic sink keeps distinct grouping keys separate" {
    var sink = DiagnosticSink.init(.{ .aggregate_occurrences = true });
    defer sink.deinit(std.testing.allocator);
    _ = try sink.append(std.testing.allocator, .{
        .severity = .warning,
        .rule = "test.rule",
        .path = "first.mzML",
        .message = "finding",
    });
    _ = try sink.append(std.testing.allocator, .{
        .severity = .warning,
        .rule = "test.rule",
        .path = "second.mzML",
        .message = "finding",
    });

    try std.testing.expectEqual(@as(usize, 2), sink.items.len);
}

test "[unit]: diagnostic grouping index preserves exact keys and bounded allocation" {
    const group_count = 128;
    var keys: [group_count][16]u8 = undefined;
    var lengths: [group_count]usize = undefined;
    var sink = DiagnosticSink.init(.{ .aggregate_occurrences = true });
    defer sink.deinit(std.testing.allocator);
    const mark_value = sink.mark();

    for (&keys, &lengths, 0..) |*key, *length, index| {
        const rendered = try std.fmt.bufPrint(key, "rule-{d}", .{index});
        length.* = rendered.len;
        _ = try sink.append(std.testing.allocator, .{
            .severity = .warning,
            .rule = key[0..length.*],
            .message = "indexed finding",
            .location = .{ .spectrum_index = index },
        });
    }
    for (&keys, lengths) |*key, length| {
        _ = try sink.append(std.testing.allocator, .{
            .severity = .warning,
            .rule = key[0..length],
            .message = "indexed finding",
        });
    }

    try std.testing.expect(sink.group_index.len >= group_count * 2);
    try std.testing.expectEqual(@as(usize, group_count), sink.items.len);
    for (sink.items) |item| try std.testing.expectEqual(@as(usize, 2), item.occurrences);
    try std.testing.expect(sink.allocatedBytes() <= 32 * 1024);

    var result = FileResult.init(stageBit(.input));
    result.completeStage(.input);
    result.finalizeSink(&sink, mark_value);
    try std.testing.expectEqual(sink.allocatedBytes(), result.resource_usage.diagnostic_current_bytes);
    try std.testing.expect(result.resource_usage.diagnostic_peak_bytes >= result.resource_usage.diagnostic_current_bytes);
    try std.testing.expectEqual(
        sink.aggregationMetadataCapacityBytes(),
        result.resource_usage.diagnostic_group_metadata_current_bytes,
    );
    try std.testing.expectEqual(
        sink.groupIndexCapacityBytes(),
        result.resource_usage.diagnostic_group_index_current_bytes,
    );
    try std.testing.expect(
        result.resource_usage.diagnostic_group_index_peak_bytes >=
            result.resource_usage.diagnostic_group_index_current_bytes,
    );
}

test "[unit]: optional grouping index failure keeps exact linear grouping" {
    var sink = DiagnosticSink.init(.{ .aggregate_occurrences = true });
    defer sink.deinit(std.testing.allocator);

    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{
        .fail_index = 0,
    });
    sink.prepareGroupIndex(failing.allocator(), aggregation_linear_group_limit);

    try std.testing.expect(sink.group_index_disabled);
    try std.testing.expectEqual(@as(usize, 0), sink.group_index.len);

    const item = Diagnostic{
        .severity = .warning,
        .rule = "fallback",
        .path = "test.mzML",
        .message = "same finding",
        .location = .{ .byte_offset = 1 },
    };
    _ = try sink.append(std.testing.allocator, item);
    _ = try sink.append(std.testing.allocator, item);

    try std.testing.expectEqual(@as(usize, 1), sink.items.len);
    try std.testing.expectEqual(@as(usize, 2), sink.items[0].occurrences);
}

test "[unit]: verbose diagnostic records do not allocate aggregation storage" {
    var sink = DiagnosticSink.init(.{});
    defer sink.deinit(std.testing.allocator);

    _ = try sink.append(std.testing.allocator, .{
        .severity = .info,
        .rule = "test.verbose",
        .message = "one occurrence",
    });

    try std.testing.expectEqual(@as(usize, 0), sink.aggregationMetadataCapacityBytes());
    try std.testing.expectEqual(@as(usize, 0), sink.groupIndexCapacityBytes());
    try std.testing.expect(@sizeOf(Diagnostic) <= 112);
}

test "[unit]: grouped rendered-byte estimate reserves complete group syntax" {
    var sink = DiagnosticSink.init(.{
        .aggregate_occurrences = true,
        .max_rendered_bytes = grouped_diagnostic_fixed_rendered_bytes - 1,
    });
    defer sink.deinit(std.testing.allocator);

    const retained = try sink.append(std.testing.allocator, .{
        .severity = .warning,
        .rule = "r",
        .message = "m",
    });

    try std.testing.expect(!retained);
    try std.testing.expectEqual(@as(usize, 0), sink.items.len);
    try std.testing.expectEqual(Totals{ .warnings = 1 }, sink.dropped);
}

test "[unit]: diagnostic sink preserves ownership when remap growth fails" {
    const backing = try std.testing.allocator.alloc(u8, 64 * 1024);
    defer std.testing.allocator.free(backing);
    var fixed = std.heap.FixedBufferAllocator.init(backing);
    var allocator = std.testing.FailingAllocator.init(fixed.allocator(), .{
        .resize_fail_index = 0,
    });
    try diagnosticGrowthAllocationCheck(allocator.allocator());
    try std.testing.expectEqual(allocator.allocated_bytes, allocator.freed_bytes);
}

test "[unit]: diagnostic sink keeps old storage when remap and fallback allocation fail" {
    const backing = try std.testing.allocator.alloc(u8, 64 * 1024);
    defer std.testing.allocator.free(backing);
    var fixed = std.heap.FixedBufferAllocator.init(backing);
    var allocator = std.testing.FailingAllocator.init(fixed.allocator(), .{
        .fail_index = 1,
        .resize_fail_index = 0,
    });
    {
        var sink: DiagnosticSink = .empty;
        defer sink.deinit(allocator.allocator());

        _ = try sink.append(allocator.allocator(), .{
            .severity = .warning,
            .rule = "test.first",
            .message = "retained",
        });
        while (sink.items.len < sink.capacity) {
            _ = try sink.append(allocator.allocator(), .{
                .severity = .warning,
                .rule = "test.fill",
                .message = "retained",
            });
        }
        const retained_len = sink.items.len;
        try std.testing.expectError(error.OutOfMemory, sink.append(allocator.allocator(), .{
            .severity = .@"error",
            .rule = "test.second",
            .message = "must fail",
        }));
        try std.testing.expect(allocator.has_induced_failure);
        try std.testing.expectEqual(retained_len, sink.items.len);
        try std.testing.expectEqualStrings("test.first", sink.items[0].rule);
    }
    try std.testing.expectEqual(allocator.allocated_bytes, allocator.freed_bytes);
}

test "diagnostic sink bounds detail while retaining complete totals" {
    var sink = DiagnosticSink.init(.{ .max_diagnostics = 2, .max_rendered_bytes = 4096 });
    defer sink.deinit(std.testing.allocator);

    const mark = sink.mark();
    _ = try sink.append(std.testing.allocator, .{ .severity = .info, .rule = "test.info", .message = "one" });
    _ = try sink.append(std.testing.allocator, .{ .severity = .warning, .rule = "test.warning", .message = "two" });
    _ = try sink.append(std.testing.allocator, .{ .severity = .@"error", .rule = "test.error", .message = "three" });

    try std.testing.expectEqual(@as(usize, 2), sink.items.len);
    try std.testing.expectEqual(Totals{ .info = 1, .warnings = 1, .errors = 1 }, sink.totalsSince(mark));
    try std.testing.expectEqual(Totals{ .info = 0, .warnings = 0, .errors = 1 }, sink.droppedSince(mark));

    var result = FileResult.init(stageBit(.input));
    result.completeStage(.input);
    result.finalizeSink(&sink, mark);
    try std.testing.expect(result.diagnostics_truncated);
    try std.testing.expectEqual(@as(usize, 1), result.dropped_diagnostics.errors);
    try std.testing.expectEqual(@as(usize, 1), result.totals.errors);
    try std.testing.expectEqual(sink.capacity * @sizeOf(Diagnostic), result.resource_usage.diagnostic_current_bytes);
    try std.testing.expectEqual(result.resource_usage.diagnostic_current_bytes, result.resource_usage.diagnostic_peak_bytes);
}

test "diagnostic sink can count without retaining detail" {
    var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var sink = DiagnosticSink.init(.{ .retain_details = false });
    defer sink.deinit(failing_allocator.allocator());

    try std.testing.expect(!try sink.append(failing_allocator.allocator(), .{
        .severity = .warning,
        .rule = "test.warning",
        .message = "counted",
    }));
    try std.testing.expectEqual(@as(usize, 0), sink.items.len);
    try std.testing.expectEqual(@as(usize, 0), sink.capacity);
    try std.testing.expectEqual(@as(usize, 0), sink.retained_bytes);
    try std.testing.expectEqual(Totals{ .warnings = 1 }, sink.totals);
    try std.testing.expectEqual(Totals{}, sink.dropped);
    try std.testing.expect(!failing_allocator.has_induced_failure);
}
