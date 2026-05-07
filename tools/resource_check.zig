//! Resource profiling gate driven by zebrac peak RSS measurements.
//!
//! This tool generates synthetic mzML fixtures, benchmarks representative
//! workloads with `tools/zebrac`, and fails when peak RSS exceeds the defined
//! ceilings. It is intended to be run via `zig build resource-check`.

const std = @import("std");

const temp_root_rel = ".zig-cache/tmp/resource-check";
const zebrac_json_rel = ".zig-cache/zebrac-resource-check.json";

const Scenario = struct {
    name: []const u8,
    command: []const u8,
    max_peak_rss_bytes: u64,
};

const ZebracResults = struct {
    results: []const Result,

    const Result = struct {
        command: []const u8,
        peak_rss: Metric,
    };

    const Metric = struct {
        mean: u64,
        unit: []const u8,
    };
};

const SyntheticFixture = struct {
    spectrum_count: usize,
    floats_per_array: usize,
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const cwd = std.Io.Dir.cwd();

    const repo_root = try std.process.currentPathAlloc(io, gpa);
    defer gpa.free(repo_root);

    const zebrac_path = try std.fs.path.join(gpa, &.{ repo_root, "tools", "zebrac" });
    defer gpa.free(zebrac_path);
    const mzvalidate_path = try std.fs.path.join(gpa, &.{ repo_root, "zig-out", "bin", "mzValidate" });
    defer gpa.free(mzvalidate_path);
    const temp_root = try std.fs.path.join(gpa, &.{ repo_root, temp_root_rel });
    defer gpa.free(temp_root);
    const zebrac_json_path = try std.fs.path.join(gpa, &.{ repo_root, zebrac_json_rel });
    defer gpa.free(zebrac_json_path);
    const stream_fixture_path = try std.fs.path.join(gpa, &.{ repo_root, temp_root_rel, "stream-many-spectra.mzML" });
    defer gpa.free(stream_fixture_path);
    const large_array_fixture_path = try std.fs.path.join(gpa, &.{ repo_root, temp_root_rel, "large-array.mzML" });
    defer gpa.free(large_array_fixture_path);

    try ensureExecutableExists(io, zebrac_path, "tools/zebrac");
    try ensureExecutableExists(io, mzvalidate_path, "zig-out/bin/mzValidate");

    cwd.deleteTree(io, temp_root_rel) catch {};
    try cwd.createDirPath(io, temp_root_rel);

    try writeSyntheticFixture(io, cwd, temp_root_rel ++ "/stream-many-spectra.mzML", .{
        .spectrum_count = 8192,
        .floats_per_array = 1,
    });
    try writeSyntheticFixture(io, cwd, temp_root_rel ++ "/large-array.mzML", .{
        .spectrum_count = 48,
        .floats_per_array = 32 * 1024,
    });

    const scenarios = try buildScenarios(gpa, mzvalidate_path, stream_fixture_path, large_array_fixture_path);
    defer {
        for (scenarios) |scenario| gpa.free(scenario.command);
        gpa.free(scenarios);
    }

    try runZebrac(gpa, io, zebrac_path, zebrac_json_path, scenarios);
    const parsed = try parseZebracJson(gpa, io, cwd, zebrac_json_rel);
    defer parsed.deinit();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buffer);
    const stdout = &stdout_writer.interface;

    try stdout.writeAll("resource-check: peak RSS report\n");
    for (scenarios) |scenario| {
        const rss_bytes = findPeakRssBytes(parsed.value.results, scenario.command) orelse {
            try fail(io, "missing zebrac result for scenario: {s}\n", .{scenario.name});
        };
        try stdout.print(
            "  {s}: mean_peak_rss={d} bytes limit={d} bytes\n",
            .{ scenario.name, rss_bytes, scenario.max_peak_rss_bytes },
        );
        if (rss_bytes > scenario.max_peak_rss_bytes) {
            try fail(
                io,
                "resource gate failed for {s}: peak RSS {d} exceeds limit {d}\n",
                .{ scenario.name, rss_bytes, scenario.max_peak_rss_bytes },
            );
        }
    }
    try stdout.print("  zebrac_json: {s}\n", .{zebrac_json_path});
    try stdout.flush();
}

fn ensureExecutableExists(io: std.Io, absolute_path: []const u8, label: []const u8) !void {
    var file = std.Io.Dir.openFileAbsolute(io, absolute_path, .{}) catch {
        return error.FileNotFound;
    };
    defer file.close(io);
    _ = label;
}

fn buildScenarios(
    allocator: std.mem.Allocator,
    mzvalidate_path: []const u8,
    stream_fixture_path: []const u8,
    large_array_fixture_path: []const u8,
) ![]Scenario {
    var scenarios: std.ArrayList(Scenario) = .empty;
    errdefer {
        for (scenarios.items) |scenario| allocator.free(scenario.command);
        scenarios.deinit(allocator);
    }

    try scenarios.append(allocator, .{
        .name = "level1_stream_many_spectra",
        .command = try std.fmt.allocPrint(
            allocator,
            "{s} check {s} -summary -skip-binary",
            .{ mzvalidate_path, stream_fixture_path },
        ),
        .max_peak_rss_bytes = 16 * 1024 * 1024,
    });
    try scenarios.append(allocator, .{
        .name = "level1_stream_many_spectra_mmap",
        .command = try std.fmt.allocPrint(
            allocator,
            "{s} check {s} -summary -skip-binary -mmap",
            .{ mzvalidate_path, stream_fixture_path },
        ),
        .max_peak_rss_bytes = 64 * 1024 * 1024,
    });
    try scenarios.append(allocator, .{
        .name = "level2_stream_many_spectra",
        .command = try std.fmt.allocPrint(
            allocator,
            "{s} check {s} -summary",
            .{ mzvalidate_path, stream_fixture_path },
        ),
        .max_peak_rss_bytes = 16 * 1024 * 1024,
    });
    try scenarios.append(allocator, .{
        .name = "level2_stream_many_spectra_mmap",
        .command = try std.fmt.allocPrint(
            allocator,
            "{s} check {s} -summary -mmap",
            .{ mzvalidate_path, stream_fixture_path },
        ),
        .max_peak_rss_bytes = 64 * 1024 * 1024,
    });
    try scenarios.append(allocator, .{
        .name = "level2_large_array_workspace",
        .command = try std.fmt.allocPrint(
            allocator,
            "{s} check {s} -summary",
            .{ mzvalidate_path, large_array_fixture_path },
        ),
        .max_peak_rss_bytes = 24 * 1024 * 1024,
    });
    try scenarios.append(allocator, .{
        .name = "level2_invalid_zlib_error_path",
        .command = try std.fmt.allocPrint(
            allocator,
            "{s} check fixtures/mzml/invalid/invalid-zlib.mzML -summary",
            .{mzvalidate_path},
        ),
        .max_peak_rss_bytes = 16 * 1024 * 1024,
    });

    return try scenarios.toOwnedSlice(allocator);
}

fn runZebrac(
    allocator: std.mem.Allocator,
    io: std.Io,
    zebrac_path: []const u8,
    json_path: []const u8,
    scenarios: []const Scenario,
) !void {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);

    try argv.appendSlice(allocator, &.{
        zebrac_path,
        "-d",
        "200",
        "-i",
        "2",
        "-a",
        "2",
        "-w",
        "1",
        "-f",
        "--quiet",
        "--json",
        json_path,
    });
    for (scenarios) |scenario| {
        try argv.append(allocator, scenario.command);
    }

    const run_result = try std.process.run(allocator, io, .{
        .argv = argv.items,
        .stdout_limit = .limited(128 * 1024),
        .stderr_limit = .limited(128 * 1024),
    });
    defer allocator.free(run_result.stdout);
    defer allocator.free(run_result.stderr);

    switch (run_result.term) {
        .exited => |code| if (code != 0) {
            try fail(io, "zebrac failed with exit code {d}\n{s}{s}", .{ code, run_result.stdout, run_result.stderr });
        },
        else => try fail(io, "zebrac terminated abnormally\n{s}{s}", .{ run_result.stdout, run_result.stderr }),
    }
}

fn parseZebracJson(
    allocator: std.mem.Allocator,
    io: std.Io,
    cwd: std.Io.Dir,
    json_rel_path: []const u8,
) !std.json.Parsed(ZebracResults) {
    const json_text = try cwd.readFileAlloc(io, json_rel_path, allocator, .limited(512 * 1024));
    defer allocator.free(json_text);
    return std.json.parseFromSlice(ZebracResults, allocator, json_text, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
}

fn findPeakRssBytes(results: []const ZebracResults.Result, command: []const u8) ?u64 {
    for (results) |result| {
        if (!std.mem.eql(u8, result.command, command)) continue;
        if (!std.mem.eql(u8, result.peak_rss.unit, "bytes")) return null;
        return result.peak_rss.mean;
    }
    return null;
}

fn writeSyntheticFixture(
    io: std.Io,
    cwd: std.Io.Dir,
    sub_path: []const u8,
    fixture: SyntheticFixture,
) !void {
    var file = try cwd.createFile(io, sub_path, .{ .truncate = true });
    defer file.close(io);

    var writer_buffer: [4096]u8 = undefined;
    var file_writer = file.writer(io, &writer_buffer);
    const writer = &file_writer.interface;

    const payload = try encodedZeroFloatPayload(std.heap.page_allocator, fixture.floats_per_array);
    defer std.heap.page_allocator.free(payload);

    try writeSyntheticMzmlPreamble(writer, fixture.spectrum_count);
    for (0..fixture.spectrum_count) |index| {
        try writeSyntheticSpectrum(writer, index, fixture.floats_per_array, payload);
    }
    try writeSyntheticMzmlPostamble(writer);
    try writer.flush();
}

fn encodedZeroFloatPayload(allocator: std.mem.Allocator, float_count: usize) ![]u8 {
    const byte_len = float_count * @sizeOf(f32);
    const decoded = try allocator.alloc(u8, byte_len);
    defer allocator.free(decoded);
    @memset(decoded, 0);

    const encoded_len = std.base64.standard.Encoder.calcSize(decoded.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    _ = std.base64.standard.Encoder.encode(encoded, decoded);
    return encoded;
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

fn writeSyntheticSpectrum(
    writer: *std.Io.Writer,
    index: usize,
    float_count: usize,
    encoded_payload: []const u8,
) !void {
    const decoded_bytes = float_count * @sizeOf(f32);
    try writer.print(
        "      <spectrum index=\"{d}\" id=\"scan={d}\" defaultArrayLength=\"{d}\">\n" ++
            "        <scanList count=\"1\">\n" ++
            "          <scan/>\n" ++
            "        </scanList>\n" ++
            "        <binaryDataArrayList count=\"2\">\n" ++
            "          <binaryDataArray encodedLength=\"{d}\">\n" ++
            "            <cvParam cvRef=\"MS\" accession=\"MS:1000521\" name=\"32-bit float\"/>\n" ++
            "            <cvParam cvRef=\"MS\" accession=\"MS:1000576\" name=\"no compression\"/>\n" ++
            "            <cvParam cvRef=\"MS\" accession=\"MS:1000514\" name=\"m/z array\" unitCvRef=\"MS\" unitAccession=\"MS:1000040\" unitName=\"m/z\"/>\n" ++
            "            <binary>{s}</binary>\n" ++
            "          </binaryDataArray>\n" ++
            "          <binaryDataArray encodedLength=\"{d}\">\n" ++
            "            <cvParam cvRef=\"MS\" accession=\"MS:1000521\" name=\"32-bit float\"/>\n" ++
            "            <cvParam cvRef=\"MS\" accession=\"MS:1000576\" name=\"no compression\"/>\n" ++
            "            <cvParam cvRef=\"MS\" accession=\"MS:1000515\" name=\"intensity array\" unitCvRef=\"MS\" unitAccession=\"MS:1000131\" unitName=\"number of counts\"/>\n" ++
            "            <binary>{s}</binary>\n" ++
            "          </binaryDataArray>\n" ++
            "        </binaryDataArrayList>\n" ++
            "      </spectrum>\n",
        .{ index, index + 1, float_count, encoded_payload.len, encoded_payload, encoded_payload.len, encoded_payload },
    );
    _ = decoded_bytes;
}

fn writeSyntheticMzmlPostamble(writer: *std.Io.Writer) !void {
    try writer.writeAll(
        "    </spectrumList>\n" ++
            "  </run>\n" ++
            "</mzML>\n",
    );
}

fn fail(io: std.Io, comptime format: []const u8, args: anytype) !noreturn {
    var stderr_buffer: [1024]u8 = undefined;
    var stderr_writer = std.Io.File.stderr().writer(io, &stderr_buffer);
    try stderr_writer.interface.print(format, args);
    try stderr_writer.interface.flush();
    std.process.exit(2);
}
