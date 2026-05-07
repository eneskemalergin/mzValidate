//! A reader wrapper that computes SHA-1 of all bytes passing through it.
//!
//! Used for streaming SHA-1 verification when mmap is not available.
//! Wraps an inner `*std.Io.Reader` and feeds every byte read through
//! `std.crypto.hash.Sha1` until `pause()` is called.
//!
//! The hash reader holds a fixed-size internal staging buffer for
//! decoupling the inner reader's output from the parser's view of
//! `r.buffer`, preventing `@memcpy` alias panics that occur when
//! `defaultReadVec` backs the stream writer with `r.buffer`.
//!
//! The staging buffer size (`staging_size`) controls how many bytes
//! are read from the inner reader per `stream` call.  The default
//! value (8 KiB) is well above typical XML token sizes and provides
//! ample throughput for streaming validation.  Increasing it uses
//! more stack space without meaningful benefit since the parser
//! already limits per-call reads via its own buffering.

const std = @import("std");

pub const HashingReader = struct {
    /// Size of the internal staging buffer, in bytes.  This is the
    /// maximum amount of data read from the inner reader per single
    /// `stream` invocation.  Bumped only if profiling shows the
    /// default value to be a bottleneck in a specific deployment.
    pub const staging_size: usize = 8192;

    reader: std.Io.Reader,
    inner: *std.Io.Reader,
    sha_ctx: std.crypto.hash.Sha1,
    paused: bool,
    staging: [staging_size]u8,

    pub fn init(inner: *std.Io.Reader, read_buf: []u8) HashingReader {
        return .{
            .reader = .{
                .vtable = &VTABLE,
                .buffer = read_buf,
                .seek = 0,
                .end = 0,
            },
            .inner = inner,
            .sha_ctx = std.crypto.hash.Sha1.init(.{}),
            .paused = false,
            .staging = undefined,
        };
    }

    pub fn pause(hr: *HashingReader) void {
        hr.paused = true;
    }

    pub fn unpause(hr: *HashingReader) void {
        hr.paused = false;
    }

    pub fn finalize(hr: *HashingReader) [20]u8 {
        var result: [20]u8 = undefined;
        hr.sha_ctx.final(&result);
        return result;
    }

    fn streamFn(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const hr: *HashingReader = @fieldParentPtr("reader", r);

        // Read from inner reader into internal staging buffer.
        var temp_w = std.Io.Writer.fixed(&hr.staging);
        const max_to_read = if (limit == .unlimited) hr.staging.len else @min(@intFromEnum(limit), hr.staging.len);
        const n = hr.inner.stream(&temp_w, std.Io.Limit.limited(max_to_read)) catch |err| switch (err) {
            error.EndOfStream => return error.EndOfStream,
            else => |e| return e,
        };

        if (!hr.paused and n > 0) {
            hr.sha_ctx.update(hr.staging[0..n]);
        }

        // Forward to the real writer.  The staging buffer is separate from
        // r.buffer, so there is no alias even when defaultReadVec backs the
        // stream writer with r.buffer.  Do NOT touch r.seek/r.end here;
        // defaultReadVec / fillUnbuffered manage them.
        return w.write(hr.staging[0..n]) catch return error.WriteFailed;
    }

    const VTABLE = std.Io.Reader.VTable{
        .stream = streamFn,
    };
};

test "HashingReader: hashes inner reader data and forwards correctly" {
    const data = "hello world";
    var inner = std.Io.Reader.fixed(data);
    var read_buf: [8192]u8 = undefined;
    var hr = HashingReader.init(&inner, &read_buf);

    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    const n = try hr.reader.stream(&w, std.Io.Limit.limited(data.len));
    try std.testing.expectEqual(data.len, n);
    try std.testing.expectEqualStrings(data, out[0..n]);

    const digest = hr.finalize();
    var expected: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(data, &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &digest);
}

test "HashingReader: pause stops hashing" {
    const data = "hello";
    var inner = std.Io.Reader.fixed(data);
    var read_buf: [8192]u8 = undefined;
    var hr = HashingReader.init(&inner, &read_buf);

    hr.pause();

    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    _ = try hr.reader.stream(&w, std.Io.Limit.limited(data.len));

    const digest = hr.finalize();
    var expected: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash("", &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &digest);
}
