//! Public validation entry points for Phase 1 mzML checks.

const std = @import("std");
const binary = @import("mzml/binary.zig");
const diagnostic = @import("diagnostic.zig");
const hash_reader = @import("io/hash_reader.zig");
const mzml_index = @import("mzml/index.zig");
const structural = @import("mzml/structural.zig");
const xml_events = @import("xml/events.zig");
const xml_parser = @import("xml/parser.zig");

const Attribute = xml_events.Attribute;
const Diagnostic = diagnostic.Diagnostic;
const ParseError = xml_parser.ParseError;
const RuleId = diagnostic.RuleId;
const max_validation_token_bytes = 1024 * 1024;

/// Controls which validation layers run for a check command.
pub const CheckOptions = struct {
    skip_binary: bool = false,
    skip_index: bool = false,
    mmap: bool = false,
    max_binary_size: ?usize = null,
};

/// Opens a file and runs the shared validation flow for one input path.
pub fn checkPath(
    allocator: std.mem.Allocator,
    io: std.Io,
    diagnostics: *std.ArrayList(Diagnostic),
    path: []const u8,
    options: CheckOptions,
) !void {
    const cwd = std.Io.Dir.cwd();
    var file = cwd.openFile(io, path, .{}) catch {
        try diagnostics.append(allocator, .{
            .severity = .@"error",
            .rule = RuleId.runtime_file_open,
            .path = path,
            .message = "unable to open input file",
        });
        return;
    };
    defer file.close(io);

    if (options.mmap) {
        // Memory-map for random-access SHA-1 and truncation verification.
        const stat = file.stat(io) catch {
            try diagnostics.append(allocator, .{
                .severity = .@"error",
                .rule = RuleId.runtime_file_open,
                .path = path,
                .message = "unable to stat input file",
            });
            return;
        };
        const len = @as(usize, @intCast(stat.size));
        var mm = std.Io.File.MemoryMap.create(io, file, .{
            .len = len,
            .protection = .{ .read = true },
        }) catch {
            // Fall back to streaming if mmap is unavailable
            // (e.g. 32-bit address space, certain filesystems).
            var read_buffer: [4096]u8 = undefined;
            var reader = file.readerStreaming(io, &read_buffer);
            try checkReader(allocator, io, &reader.interface, diagnostics, path, options, null);
            return;
        };
        defer mm.destroy(io);

        var reader = std.Io.Reader.fixed(mm.memory);
        try checkReader(allocator, io, &reader, diagnostics, path, options, mm.memory);
    } else {
        var read_buffer: [4096]u8 = undefined;
        var reader = file.readerStreaming(io, &read_buffer);
        try checkReader(allocator, io, &reader.interface, diagnostics, path, options, null);
    }
}

/// Runs structural and binary validation over one reader-backed XML stream.
///
/// This is the public one-pass seam for library callers. It keeps parser state,
/// structural state, and at most one active binary workspace alive at a time.
pub fn checkReader(
    allocator: std.mem.Allocator,
    io: std.Io,
    reader: *std.Io.Reader,
    diagnostics: *std.ArrayList(Diagnostic),
    path: []const u8,
    options: CheckOptions,
    file_bytes: ?[]const u8,
) !void {
    _ = io;

    // Phase 1 keeps traversal state bounded: one shared token buffer, parser namespace
    // and element stacks, one structural validator for local container bookkeeping,
    // and at most one active binary array workspace for the current spectrum or
    // chromatogram. Memory therefore scales with parser limits and one in-flight array,
    // not with full document size or prior spectra.
    const token_buffer = try allocator.alloc(u8, max_validation_token_bytes);
    defer allocator.free(token_buffer);

    var attributes: [64]Attribute = undefined;
    var namespace_bindings: [32]xml_parser.NamespaceBinding = undefined;
    var namespace_bytes: [2048]u8 = undefined;
    var element_stack: [128]xml_parser.ElementFrame = undefined;
    var element_bytes: [4096]u8 = undefined;

    // When index validation is active and no file_bytes are available for
    // post-parse SHA-1, wrap the reader in a HashingReader that computes
    // SHA-1 incrementally during the streaming parse pass.
    // HashingReader is temporarily disabled for the streaming path.
    // TODO: re-enable when streaming SHA-1 verification is fully debugged.
    const hashing_reader: ?hash_reader.HashingReader = null;
    const effective_reader = reader;

    var parser = xml_parser.Parser.init(effective_reader, .{
        .token = token_buffer,
        .attributes = &attributes,
        .namespace_bindings = &namespace_bindings,
        .namespace_bytes = &namespace_bytes,
        .element_stack = &element_stack,
        .element_bytes = &element_bytes,
    });

    var structural_validator = structural.StructuralValidator.init(allocator, diagnostics, path);
    defer structural_validator.deinit();

    var binary_validator = if (options.skip_binary) null else binary.BinaryValidator{
        .allocator = allocator,
        .diagnostics = diagnostics,
        .path = path,
        .max_binary_size = options.max_binary_size,
    };
    defer if (binary_validator) |*validator| validator.deinit();

    var index_validator = if (options.skip_index) null else mzml_index.IndexValidator.init(allocator, diagnostics, path);
    defer if (index_validator) |*validator| validator.deinit();

    var element_depth: usize = 0;

    while (true) {
        const maybe_event = parser.next() catch |err| {
            try diagnostics.append(allocator, .{
                .severity = .@"error",
                .rule = RuleId.mzml_structure_xml,
                .location = .{ .byte_offset = parser.byteOffset() },
                .path = path,
                .message = parseErrorMessage(err),
            });
            return;
        };
        const event = maybe_event orelse {
            if (index_validator) |*iv| iv.finish(file_bytes);
            break;
        };

        switch (event) {
            .start_element => |start| {
                element_depth += 1;
                try structural_validator.consumeStart(start);
                if (binary_validator) |*validator| try validator.consumeStart(start);
                if (index_validator) |*validator| try validator.consumeStart(start, element_depth);

                // Pause SHA-1 hashing when <fileChecksum> is encountered.
                if (hashing_reader) |*hr| {
                    if (!hr.paused and std.mem.eql(u8, start.name.local_name, "fileChecksum")) {
                        hr.pause();
                    }
                }
            },
            .end_element => |end| {
                try structural_validator.consumeEnd(end);
                if (binary_validator) |*validator| try validator.consumeEnd(end);
                if (index_validator) |*validator| validator.consumeEnd(end, element_depth);
                element_depth -= 1;
            },
            .text => |text| {
                try structural_validator.consumeText(text);
                if (binary_validator) |*validator| try validator.consumeText(text);
                if (index_validator) |*validator| try validator.consumeText(text, element_depth);
            },
        }
    }

    try structural_validator.finish();
    if (binary_validator) |*validator| try validator.finish();

    // Compare computed SHA-1 against declared fileChecksum when using
    // streaming mode (HashingReader active, no mmap'd file_bytes).
    if (hashing_reader) |*hr| {
        if (index_validator) |*iv| {
            if (iv.declaredChecksum()) |declared| {
                const computed = hr.finalize();
                if (!std.mem.eql(u8, &computed, &declared)) {
                    try diagnostics.append(allocator, .{
                        .severity = .@"error",
                        .rule = RuleId.mzml_index_checksum,
                        .path = path,
                        .message = "fileChecksum SHA-1 does not match recomputed value",
                    });
                }
            }
        }
    }
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

// Tests: file and reader entry points.

test "checkPath_missingFile_reportsOpenError" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    try checkPath(allocator, io, &diagnostics, "definitely-missing-file.mzML", .{});

    // Assert.
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqual(diagnostic.Severity.@"error", diagnostics.items[0].severity);
    try std.testing.expectEqualStrings(RuleId.runtime_file_open, diagnostics.items[0].rule);
}

test "checkPath_existingFile_runsStructuralValidationWhenSkippingBinary" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/examples/mzml/clean-single-spectrum.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();

    const path = try stageFixtureInTempDir(allocator, io, &temp_dir, "sample.mzML", fixture);
    defer allocator.free(path);

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    try checkPath(allocator, io, &diagnostics, path, .{ .skip_binary = true });

    // Assert.
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "checkPath_existingFile_reportsCleanResultWhenStructureAndBinaryPass" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    const fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/examples/mzml/clean-single-spectrum.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(fixture);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();

    const path = try stageFixtureInTempDir(allocator, io, &temp_dir, "sample.mzML", fixture);
    defer allocator.free(path);

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    try checkPath(allocator, io, &diagnostics, path, .{});

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

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    try checkPath(allocator, io, &diagnostics, path, .{ .skip_binary = true });

    // Assert.
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "checkPath_largeIndexedMzMLFixture_runsStructuralValidationWhenSkippingBinary" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    try checkPath(allocator, io, &diagnostics, "fixtures/mzml/valid/small.pwiz.1.1.mzML", .{ .skip_binary = true });

    // Assert.
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "checkPath_indexedMzMLFixture_runsCleanWithIndexValidationEnabled" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    try checkPath(allocator, io, &diagnostics, "fixtures/mzml/valid/tiny.pwiz.1.1.mzML", .{ .skip_binary = true });

    // Assert.
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "checkPath_indexedMzMLFixture_skipIndexSkipsIndexChecks" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    try checkPath(allocator, io, &diagnostics, "fixtures/mzml/valid/tiny.pwiz.1.1.mzML", .{ .skip_binary = true, .skip_index = true });

    // Assert.
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "checkPath_mmap_runsCleanOnValidIndexedFixture" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    // Act — use mmap on a valid indexed fixture.
    try checkPath(allocator, io, &diagnostics, "fixtures/mzml/valid/tiny.pwiz.1.1.mzML", .{ .skip_binary = true, .mmap = true });

    // Assert — mmap should produce the same clean result as streaming.
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "checkPath_mmap_fallsBackToStreamingOnMissingFile" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    // Act — mmap on a missing file: openFile fails before mmap even starts.
    try checkPath(allocator, io, &diagnostics, "definitely-missing.mzML", .{ .mmap = true });

    // Assert — should report file open error, not mmap error.
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
        .{ .skip_binary = true },
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

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    try checkPath(allocator, io, &diagnostics, path, .{});

    // Assert.
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
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
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-truncated.mzML", .{}, null);

    // Assert.
    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_xml,
        "unexpected end of XML input",
    );
}

test "checkReader_broken_attribute_quote_reports_malformed_xml_diagnostic" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" ++
        "<mzML xmlns=\"http://psi.hupo.org/ms/mzml\" version=\"1.1.0\"><run id=\"broken></run></mzML>";

    // Arrange.
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-broken-quote.mzML", .{ .skip_binary = true }, null);

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
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-mismatched-end-tag.mzML", .{ .skip_binary = true }, null);

    // Assert.
    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_xml,
        "malformed XML input",
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
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-invalid-utf8.mzML", .{ .skip_binary = true }, null);

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
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-wrong-namespace.mzML", .{ .skip_binary = true }, null);

    // Assert.
    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_root,
        "root element must be mzML in the http://psi.hupo.org/ms/mzml namespace",
    );
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
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-prefixed-root.mzML", .{ .skip_binary = true }, null);

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

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    try checkPath(allocator, io, &diagnostics, path, .{});

    // Assert.
    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_binary_base64,
        "binary payload is not valid base64",
    );
    try std.testing.expectEqual(@as(?usize, null), diagnostics.items[0].location.spectrum_index);
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
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    for (0..32) |_| {
        diagnostics.clearRetainingCapacity();
        var reader = std.Io.Reader.fixed(xml);
        try checkReader(allocator, io, &reader, &diagnostics, "inline-repeated-clean.mzML", .{}, null);

        // Assert.
        try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
    }
}

test "checkReader_empty_spectrum_list_is_clean_when_skipping_binary" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml = spectrumListMzml("<spectrumList count=\"0\" defaultDataProcessingRef=\"DP1\"/>");

    // Arrange.
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-empty-spectrum-list.mzML", .{ .skip_binary = true }, null);

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
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-multiple-spectra.mzML", .{ .skip_binary = true }, null);

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
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-missing-binary-list.mzML", .{ .skip_binary = true }, null);

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
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-out-of-order-top-level.mzML", .{ .skip_binary = true }, null);

    // Assert.
    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_nesting,
        "instrumentConfigurationList appears out of order under mzML",
    );
}

test "checkReader_oversized_text_token_maps_parser_limit_to_structure_xml_diagnostic" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    const xml = try oversizedAttributeValueMzml(allocator, max_validation_token_bytes + 1);
    defer allocator.free(xml);
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-oversized-text.mzML", .{ .skip_binary = true }, null);

    // Assert.
    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_xml,
        "XML token exceeds the configured parser buffer",
    );
}

test "checkReader_excessive_attribute_count_maps_parser_limit_to_structure_xml_diagnostic" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    const xml = try tooManyAttributesXml(allocator, 65);
    defer allocator.free(xml);
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-too-many-attributes.mzML", .{ .skip_binary = true }, null);

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
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-too-many-namespaces.mzML", .{ .skip_binary = true }, null);

    // Assert.
    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_xml,
        "malformed XML input",
    );
}

test "checkReader_excessive_nesting_maps_parser_limit_to_structure_xml_diagnostic" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    const xml = try tooDeepXml(allocator, 129);
    defer allocator.free(xml);
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-too-deep.mzML", .{ .skip_binary = true }, null);

    // Assert.
    try expectSingleDiagnostic(
        diagnostics.items,
        RuleId.mzml_structure_xml,
        "malformed XML input",
    );
}

// Tests: structural failure handling.

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

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    try checkPath(allocator, io, &diagnostics, path, .{});

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

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    try checkPath(allocator, io, &diagnostics, path, .{ .skip_binary = true });

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

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    try checkPath(allocator, io, &diagnostics, path, .{});

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

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    try checkPath(allocator, io, &diagnostics, path, .{ .skip_binary = true });

    // Assert.
    try std.testing.expectEqual(@as(usize, 0), diagnostics.items.len);
}

test "checkReader_empty_binary_payload_reports_exact_length_mismatch" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const xml = binarySpectrumListMzml("", "AAAAAA==", 1, "MS:1000576");

    // Arrange.
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-empty-binary.mzML", .{}, null);

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
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);
    var reader = std.Io.Reader.fixed(xml);

    // Act.
    try checkReader(allocator, io, &reader, &diagnostics, "inline-zlib-length-mismatch.mzML", .{}, null);

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
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    try checkPath(allocator, io, &diagnostics, "fixtures/mzml/invalid/conflicting-compression.mzML", .{});

    // Assert.
    try std.testing.expectEqual(@as(usize, 1), diagnostics.items.len);
    try std.testing.expectEqualStrings(RuleId.mzml_binary_compression, diagnostics.items[0].rule);
}

test "checkPath_reports_unsupportedCompression_fixture" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    try checkPath(allocator, io, &diagnostics, "fixtures/mzml/invalid/unsupported-compression.mzML", .{});

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
        var diagnostics: std.ArrayList(Diagnostic) = .empty;
        defer diagnostics.deinit(allocator);
        try checkPath(allocator, io, &diagnostics, expectation.sub_path, .{});

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
        .{ .skip_binary = true },
        .clean,
    );

    // Assert.
    try std.testing.expect(fixture_count > 0);
}

test "checkPath_repeated_clean_and_corrupt_runs_reset_diagnostics_between_invocations" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Arrange.
    const clean_fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/examples/mzml/clean-single-spectrum.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(clean_fixture);
    const corrupt_fixture = try std.Io.Dir.cwd().readFileAlloc(io, "fixtures/mzml/invalid/invalid-base64.mzML", allocator, .limited(64 * 1024));
    defer allocator.free(corrupt_fixture);

    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();
    const clean_path = try stageFixtureInTempDir(allocator, io, &temp_dir, "repeated-clean.mzML", clean_fixture);
    defer allocator.free(clean_path);
    const corrupt_path = try stageFixtureInTempDir(allocator, io, &temp_dir, "repeated-corrupt.mzML", corrupt_fixture);
    defer allocator.free(corrupt_path);

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    // Act.
    for (0..24) |index| {
        const path = if (index % 2 == 0) clean_path else corrupt_path;
        diagnostics.clearRetainingCapacity();
        try checkPath(allocator, io, &diagnostics, path, .{});

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

    var diagnostics: std.ArrayList(Diagnostic) = .empty;
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
        try xml.appendSlice(allocator, "<n>");
    }
    for (0..depth) |_| {
        try xml.appendSlice(allocator, "</n>");
    }
    try xml.appendSlice(allocator, "</run></mzML>");
    return try xml.toOwnedSlice(allocator);
}
