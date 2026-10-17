//! SHA-1 for indexed mzML checksums, through zmz (x86 SHA extensions when present).

const zmz = @import("zmz").mzml;

pub const Sha1 = struct {
    inner: zmz.sha1.Sha1 = .{},

    pub fn init() Sha1 {
        return .{};
    }

    pub fn update(hasher: *Sha1, bytes: []const u8) void {
        hasher.inner.update(bytes);
    }

    pub fn final(hasher: *Sha1, digest: *[20]u8) void {
        digest.* = hasher.inner.finalResult();
    }
};
