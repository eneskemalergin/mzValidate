# libdeflate - vendored decompress-only subset

## Upstream

<https://github.com/ebiggers/libdeflate>

Version: v1.25. License: MIT. See [`COPYING`](./COPYING).

## Why vendored

mzValidate validates zlib-compressed binary arrays in mzML files. libdeflate's decompressor is faster than `std.compress.flate.Decompress`, especially on CPUs with BMI2 runtime dispatch.

The vendored copy compiles directly into the binary via `addCSourceFile` in `build.zig`. This avoids depending on system `libdeflate.so` which may be missing, wrong version, or compiled without SIMD support.

## What was stripped

The full libdeflate distribution comes with compression, gzip, CRC32, and matchfinder code. mzValidate only needs zlib decompression. These components were removed:

- **DEFLATE compression** (not used)
- **Gzip compression and decompression** (not used)
- **Zlib compression** (not used)
- **CRC-32 checksum** (gzip-only)
- **Matchfinders** (compression-only)

These were kept: `deflate_decompress.c` (core engine), `zlib_decompress.c` (zlib wrapper), `adler32.c` (checksum), `utils.c` (alloc/free wrappers), `x86/cpu_features.c` (runtime BMI2 dispatch). ARM headers (`arm/cpu_features.h`, `arm/adler32_impl.h`) are retained so the build script can add `arm/cpu_features.c` when targeting aarch64.

## How it is used

`binary.zig` calls `libdeflate_zlib_decompress_ex()` with the complete zlib payload. This validates the zlib header and Adler-32 checksum; the consumed-input result is also checked so trailing bytes are rejected.

The decompressor handle is allocated once and reused across all binary arrays in a file.

## Build integration

Compiled from `build.zig`:

```zig
mod.addCSourceFile(.{ .file = b.path("vendor/libdeflate/lib/deflate_decompress.c"), .flags = &.{ opt, march } });
mod.addCSourceFile(.{ .file = b.path("vendor/libdeflate/lib/zlib_decompress.c"), .flags = &.{ opt, march } });
mod.addCSourceFile(.{ .file = b.path("vendor/libdeflate/lib/utils.c"), .flags = &.{ opt, march } });
mod.addCSourceFile(.{ .file = b.path("vendor/libdeflate/lib/x86/cpu_features.c"), .flags = &.{ opt, march } });
mod.addCSourceFile(.{ .file = b.path("vendor/libdeflate/lib/adler32.c"), .flags = &.{ opt, march, "-DLIBDEFLATE_ASSEMBLER_DOES_NOT_SUPPORT_AVX512VNNI" } });
```

The full git clone used for reference and regeneration is at [`tmp/libdeflate-git/`](../../tmp/libdeflate-git/).
