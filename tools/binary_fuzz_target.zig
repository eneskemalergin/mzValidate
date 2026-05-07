const std = @import("std");
const mzvalidate = @import("mzvalidate");

const diagnostic = mzvalidate.diagnostic;
const binary = mzvalidate.mzml.binary;

const max_input_bytes = 1024 * 1024;
const payload_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=%$#@! ?\n\r\t";

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(allocator);
    defer allocator.free(args);

    if (args.len != 2) {
        try fail(io, "usage: binary_fuzz_target <input-path>", .{});
    }

    const input = try std.Io.Dir.cwd().readFileAlloc(io, args[1], allocator, .limited(max_input_bytes));
    defer allocator.free(input);

    try fuzzBinaryLayer(allocator, io, input);
}

fn fuzzBinaryLayer(allocator: std.mem.Allocator, io: std.Io, input: []const u8) !void {
    const payload = try mapPayloadToXmlSafeAlphabet(allocator, input);
    defer allocator.free(payload);

    const array_length = defaultArrayLength(input);
    try runScenario(allocator, io, payload, false, false, array_length);
    try runScenario(allocator, io, payload, false, true, array_length);
    try runScenario(allocator, io, payload, true, false, array_length);
    try runScenario(allocator, io, payload, true, true, array_length);
}

fn runScenario(
    allocator: std.mem.Allocator,
    io: std.Io,
    payload: []const u8,
    chromatogram: bool,
    zlib_compression: bool,
    array_length: usize,
) !void {
    const fixture = try fixtureDocument(allocator, payload, chromatogram, zlib_compression, array_length);
    defer allocator.free(fixture);

    var diagnostics: std.ArrayList(diagnostic.Diagnostic) = .empty;
    defer diagnostics.deinit(allocator);

    var fixed_reader = std.Io.Reader.fixed(fixture);
    try binary.BinaryValidator.validateReader(allocator, io, &fixed_reader, &diagnostics, null);
}

fn fixtureDocument(
    allocator: std.mem.Allocator,
    payload: []const u8,
    chromatogram: bool,
    zlib_compression: bool,
    array_length: usize,
) ![]u8 {
    const compression_accession = if (zlib_compression) "MS:1000574" else "MS:1000576";
    const array_kind = if (chromatogram) "MS:1000595" else "MS:1000514";
    const owner_id = if (chromatogram) "chrom0" else "scan=1";
    const valid_secondary_kind = if (chromatogram) "MS:1000595" else "MS:1000515";

    if (chromatogram) {
        return try std.fmt.allocPrint(allocator,
            \\<?xml version="1.0" encoding="UTF-8"?>
            \\<mzML xmlns="http://psi.hupo.org/ms/mzml" version="1.1.0">
            \\  <run id="run0">
            \\    <chromatogramList count="1">
            \\      <chromatogram index="0" id="{s}" defaultArrayLength="{d}">
            \\        <binaryDataArrayList count="2">
            \\          <binaryDataArray encodedLength="{d}">
            \\            <cvParam accession="MS:1000521" name="32-bit float"/>
            \\            <cvParam accession="{s}" name="array kind"/>
            \\            <cvParam accession="{s}" name="compression"/>
            \\            <binary>{s}</binary>
            \\          </binaryDataArray>
            \\          <binaryDataArray encodedLength="8">
            \\            <cvParam accession="MS:1000521" name="32-bit float"/>
            \\            <cvParam accession="{s}" name="array kind"/>
            \\            <cvParam accession="MS:1000576" name="no compression"/>
            \\            <binary>AAAAAA==</binary>
            \\          </binaryDataArray>
            \\        </binaryDataArrayList>
            \\      </chromatogram>
            \\    </chromatogramList>
            \\  </run>
            \\</mzML>
        , .{ owner_id, array_length, payload.len, array_kind, compression_accession, payload, valid_secondary_kind });
    }

    return try std.fmt.allocPrint(allocator,
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<mzML xmlns="http://psi.hupo.org/ms/mzml" version="1.1.0">
        \\  <run id="run0">
        \\    <spectrumList count="1">
        \\      <spectrum index="0" id="{s}" defaultArrayLength="{d}">
        \\        <binaryDataArrayList count="2">
        \\          <binaryDataArray encodedLength="{d}">
        \\            <cvParam accession="MS:1000521" name="32-bit float"/>
        \\            <cvParam accession="{s}" name="array kind"/>
        \\            <cvParam accession="{s}" name="compression"/>
        \\            <binary>{s}</binary>
        \\          </binaryDataArray>
        \\          <binaryDataArray encodedLength="8">
        \\            <cvParam accession="MS:1000521" name="32-bit float"/>
        \\            <cvParam accession="{s}" name="array kind"/>
        \\            <cvParam accession="MS:1000576" name="no compression"/>
        \\            <binary>AAAAAA==</binary>
        \\          </binaryDataArray>
        \\        </binaryDataArrayList>
        \\      </spectrum>
        \\    </spectrumList>
        \\  </run>
        \\</mzML>
    , .{ owner_id, array_length, payload.len, array_kind, compression_accession, payload, valid_secondary_kind });
}

fn defaultArrayLength(input: []const u8) usize {
    if (input.len == 0) return 1;
    return @as(usize, input[0] % 8) + 1;
}

fn mapPayloadToXmlSafeAlphabet(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const payload = try allocator.alloc(u8, input.len);
    for (input, 0..) |byte, index| {
        payload[index] = payload_alphabet[byte % payload_alphabet.len];
    }
    return payload;
}

fn fail(io: std.Io, comptime fmt: []const u8, args: anytype) !noreturn {
    var stderr_buffer: [1024]u8 = undefined;
    var stderr_file_writer: std.Io.File.Writer = .init(.stderr(), io, &stderr_buffer);
    const stderr = &stderr_file_writer.interface;

    try stderr.print(fmt, args);
    try stderr.print("\n", .{});
    try stderr.flush();
    std.process.exit(1);
}
