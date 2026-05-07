const std = @import("std");
const mzvalidate = @import("mzvalidate");

const xml_events = mzvalidate.xml.events;
const xml_parser = mzvalidate.xml.parser;

const max_input_bytes = 2 * 1024 * 1024;
const max_token_bytes = 1024 * 1024;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(allocator);
    defer allocator.free(args);

    if (args.len != 2) {
        try fail(io, "usage: xml_fuzz_target <input-path>", .{});
    }

    const input = try std.Io.Dir.cwd().readFileAlloc(io, args[1], allocator, .limited(max_input_bytes));
    defer allocator.free(input);

    try fuzzXml(allocator, input);
}

fn fuzzXml(allocator: std.mem.Allocator, input: []const u8) !void {
    const token_buffer = try allocator.alloc(u8, max_token_bytes);
    defer allocator.free(token_buffer);

    var attributes: [64]xml_events.Attribute = undefined;
    var namespace_bindings: [32]xml_parser.NamespaceBinding = undefined;
    var namespace_bytes: [2048]u8 = undefined;
    var element_stack: [128]xml_parser.ElementFrame = undefined;
    var element_bytes: [4096]u8 = undefined;

    var fixed_reader = std.Io.Reader.fixed(input);
    var parser = xml_parser.Parser.init(&fixed_reader, .{
        .token = token_buffer,
        .attributes = &attributes,
        .namespace_bindings = &namespace_bindings,
        .namespace_bytes = &namespace_bytes,
        .element_stack = &element_stack,
        .element_bytes = &element_bytes,
    });

    while (true) {
        _ = parser.next() catch |err| switch (err) {
            error.UnexpectedEof,
            error.MalformedXml,
            error.InvalidUtf8,
            error.TokenTooLong,
            error.TooManyAttributes,
            error.TooManyNamespaces,
            error.NamespaceStorageExceeded,
            error.ElementNestingTooDeep,
            error.ElementStorageExceeded,
            error.UnknownEntity,
            error.InvalidCharacterReference,
            error.UnsupportedMarkup,
            error.MismatchedEndTag,
            error.ReadFailed,
            => break,
        } orelse break;
    }
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
