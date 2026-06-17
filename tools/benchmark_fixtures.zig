//! Synthetic mzML fixtures for resource (RSS) benchmarks.

const std = @import("std");

pub const temp_root_rel = ".zig-cache/tmp/resource-check";
const stamp_name = "fixture-generation.txt";
const stamp_rel = temp_root_rel ++ "/" ++ stamp_name;
/// Bump when synthetic fixture shape changes so stale repo-local files are regenerated.
pub const generation: u32 = 1;

pub const SyntheticFixture = struct {
    spectrum_count: usize,
    floats_per_array: usize,
};

pub fn ensureSyntheticFixtures(io: std.Io, cwd: std.Io.Dir, allocator: std.mem.Allocator) !void {
    if (try fixturesAreCurrent(io, cwd)) return;

    cwd.deleteTree(io, temp_root_rel) catch {};
    try cwd.createDirPath(io, temp_root_rel);
    try writeSyntheticFixture(io, cwd, allocator, temp_root_rel ++ "/stream-many-spectra.mzML", .{
        .spectrum_count = 8192,
        .floats_per_array = 1,
    });
    try writeSyntheticFixture(io, cwd, allocator, temp_root_rel ++ "/large-array.mzML", .{
        .spectrum_count = 48,
        .floats_per_array = 32 * 1024,
    });
    try writeGenerationStamp(io, cwd);
}

fn fixturesAreCurrent(io: std.Io, cwd: std.Io.Dir) !bool {
    const stamp = cwd.readFileAlloc(io, stamp_rel, std.heap.page_allocator, .limited(32)) catch return false;
    defer std.heap.page_allocator.free(stamp);
    const trimmed = std.mem.trim(u8, stamp, " \t\r\n");
    if (!std.mem.eql(u8, trimmed, std.fmt.comptimePrint("{d}", .{generation}))) return false;

    const paths = [_][]const u8{
        temp_root_rel ++ "/stream-many-spectra.mzML",
        temp_root_rel ++ "/large-array.mzML",
    };
    for (paths) |path| {
        var file = cwd.openFile(io, path, .{}) catch return false;
        file.close(io);
    }
    return true;
}

fn writeGenerationStamp(io: std.Io, cwd: std.Io.Dir) !void {
    const text = try std.fmt.allocPrint(std.heap.page_allocator, "{d}\n", .{generation});
    defer std.heap.page_allocator.free(text);
    try cwd.writeFile(io, .{ .sub_path = stamp_rel, .data = text });
}

fn writeSyntheticFixture(
    io: std.Io,
    cwd: std.Io.Dir,
    allocator: std.mem.Allocator,
    sub_path: []const u8,
    fixture: SyntheticFixture,
) !void {
    var file = try cwd.createFile(io, sub_path, .{ .truncate = true });
    defer file.close(io);

    var writer_buffer: [4096]u8 = undefined;
    var file_writer = file.writer(io, &writer_buffer);
    const writer = &file_writer.interface;

    const payload = try encodedZeroFloatPayload(allocator, fixture.floats_per_array);
    defer allocator.free(payload);

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
}

fn writeSyntheticMzmlPostamble(writer: *std.Io.Writer) !void {
    try writer.writeAll(
        "    </spectrumList>\n" ++
            "  </run>\n" ++
            "</mzML>\n",
    );
}

test "generation stamp format" {
    try std.testing.expectEqualStrings("1", std.fmt.comptimePrint("{d}", .{generation}));
}
