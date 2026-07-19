# Vendored libdeflate subset

## Snapshot

This directory is a self-contained, decompress-only snapshot of [libdeflate](https://github.com/ebiggers/libdeflate):

- upstream tag: `v1.25`
- upstream commit: `c8c56a20f8f621e6a966b716b31f1dedab6a41e3`
- verified against upstream: 2026-07-18
- license: MIT, preserved in [`COPYING`](./COPYING)

The retained upstream C files, headers, and license match that commit byte for byte. They have no local source modifications. This README is mzValidate-specific documentation and is not an upstream file.

## Contents

mzValidate keeps only the zlib decompression path and its dependencies:

- `deflate_decompress.c` for the core DEFLATE decoder
- `zlib_decompress.c` for the zlib wrapper
- `adler32.c` for checksum validation
- `utils.c` for allocator wrappers
- x86_64 and AArch64 CPU feature sources and required headers

Compression, gzip, CRC-32, matchfinder, program, test, build-system, CI, and release-support files are intentionally omitted because mzValidate does not compile or use them.

## Build integration

`build.zig` compiles the common decompression sources on every supported target. It adds `x86/cpu_features.c` on x86_64 and `arm/cpu_features.c` on AArch64. The default build links the target C runtime. `-Denable-libdeflate=false` omits the complete vendor integration and uses Zig's fallback decompressor.

`src/mzml/binary.zig` calls `libdeflate_zlib_decompress_ex()` with the complete zlib payload. libdeflate validates the zlib header and Adler-32 checksum, and mzValidate checks the consumed input length so trailing bytes are rejected. One decompressor handle is reused across arrays in a file.

On x86_64, `adler32.c` is compiled with `LIBDEFLATE_ASSEMBLER_DOES_NOT_SUPPORT_AVX512VNNI`. Zig 0.16.0's bundled Clang 21 fails to compile libdeflate v1.25's AVX512VNNI implementation because its target attribute does not enable the required `evex512` feature. The flag suppresses that implementation without modifying the upstream source files; the other x86 runtime-dispatch paths remain available.

The root project [`LICENSE`](../../LICENSE) and libdeflate's `COPYING` are distinct notices. Both are included in the package through `build.zig.zon`.

Vendor updates are deliberate source changes, not part of routine building or testing. When the snapshot is intentionally updated, record the new upstream tag and commit here, review the retained subset, and preserve `COPYING`.
