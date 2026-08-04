//! x86 SHA-extension compression written with Zig 0.16 inline assembly.
//!
//! The exported availability probe must pass before compression is called.

const V4u32 = @Vector(4, u32);
const V16u8 = @Vector(16, u8);

const CpuidLeaf = struct {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
};

fn available() bool {
    const maximum = cpuid(0, 0).eax;
    if (maximum < 7) return false;

    const basic = cpuid(1, 0);
    const structured = cpuid(7, 0);
    const has_ssse3 = basic.ecx & (@as(u32, 1) << 9) != 0;
    const has_sha = structured.ebx & (@as(u32, 1) << 29) != 0;
    return has_ssse3 and has_sha;
}

export fn mzv_sha1_x86_available() callconv(.c) c_int {
    return @intFromBool(available());
}

export fn mzv_sha1_x86_compress(
    state: *[5]u32,
    blocks: [*]const u8,
    block_count: usize,
) callconv(.c) void {
    if (block_count == 0) return;
    const byte_swap: V16u8 = .{ 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };

    asm volatile (
        \\mov %[blocks], %%r10
        \\mov %[count], %%r11
        \\movdqu (%[state]), %%xmm0
        \\movd 16(%[state]), %%xmm1
        \\movdqu (%%r10), %%xmm4
        \\pshufd $0x1b, %%xmm0, %%xmm0
        \\movdqu 16(%%r10), %%xmm5
        \\pshufd $0x1b, %%xmm1, %%xmm1
        \\movdqu 32(%%r10), %%xmm6
        \\pshufb %[swap], %%xmm4
        \\movdqu 48(%%r10), %%xmm7
        \\pshufb %[swap], %%xmm5
        \\pshufb %[swap], %%xmm6
        \\movdqa %%xmm1, %%xmm9
        \\pshufb %[swap], %%xmm7
        \\.p2align 4
        \\0:
        \\dec %%r11
        \\lea 64(%%r10), %%r8
        \\paddd %%xmm4, %%xmm1
        \\cmovne %%r8, %%r10
        \\movdqa %%xmm0, %%xmm8
        \\sha1msg1 %%xmm5, %%xmm4
        \\movdqa %%xmm0, %%xmm2
        \\sha1rnds4 $0, %%xmm1, %%xmm0
        \\sha1nexte %%xmm5, %%xmm2
        \\pxor %%xmm6, %%xmm4
        \\sha1msg1 %%xmm6, %%xmm5
        \\sha1msg2 %%xmm7, %%xmm4
        \\movdqa %%xmm0, %%xmm1
        \\sha1rnds4 $0, %%xmm2, %%xmm0
        \\sha1nexte %%xmm6, %%xmm1
        \\pxor %%xmm7, %%xmm5
        \\sha1msg2 %%xmm4, %%xmm5
        \\sha1msg1 %%xmm7, %%xmm6
        \\movdqa %%xmm0, %%xmm2
        \\sha1rnds4 $0, %%xmm1, %%xmm0
        \\sha1nexte %%xmm7, %%xmm2
        \\pxor %%xmm4, %%xmm6
        \\sha1msg1 %%xmm4, %%xmm7
        \\sha1msg2 %%xmm5, %%xmm6
        \\movdqa %%xmm0, %%xmm1
        \\sha1rnds4 $0, %%xmm2, %%xmm0
        \\sha1nexte %%xmm4, %%xmm1
        \\pxor %%xmm5, %%xmm7
        \\sha1msg2 %%xmm6, %%xmm7
        \\sha1msg1 %%xmm5, %%xmm4
        \\movdqa %%xmm0, %%xmm2
        \\sha1rnds4 $0, %%xmm1, %%xmm0
        \\sha1nexte %%xmm5, %%xmm2
        \\pxor %%xmm6, %%xmm4
        \\sha1msg1 %%xmm6, %%xmm5
        \\sha1msg2 %%xmm7, %%xmm4
        \\movdqa %%xmm0, %%xmm1
        \\sha1rnds4 $1, %%xmm2, %%xmm0
        \\sha1nexte %%xmm6, %%xmm1
        \\pxor %%xmm7, %%xmm5
        \\sha1msg2 %%xmm4, %%xmm5
        \\sha1msg1 %%xmm7, %%xmm6
        \\movdqa %%xmm0, %%xmm2
        \\sha1rnds4 $1, %%xmm1, %%xmm0
        \\sha1nexte %%xmm7, %%xmm2
        \\pxor %%xmm4, %%xmm6
        \\sha1msg1 %%xmm4, %%xmm7
        \\sha1msg2 %%xmm5, %%xmm6
        \\movdqa %%xmm0, %%xmm1
        \\sha1rnds4 $1, %%xmm2, %%xmm0
        \\sha1nexte %%xmm4, %%xmm1
        \\pxor %%xmm5, %%xmm7
        \\sha1msg2 %%xmm6, %%xmm7
        \\sha1msg1 %%xmm5, %%xmm4
        \\movdqa %%xmm0, %%xmm2
        \\sha1rnds4 $1, %%xmm1, %%xmm0
        \\sha1nexte %%xmm5, %%xmm2
        \\pxor %%xmm6, %%xmm4
        \\sha1msg1 %%xmm6, %%xmm5
        \\sha1msg2 %%xmm7, %%xmm4
        \\movdqa %%xmm0, %%xmm1
        \\sha1rnds4 $1, %%xmm2, %%xmm0
        \\sha1nexte %%xmm6, %%xmm1
        \\pxor %%xmm7, %%xmm5
        \\sha1msg2 %%xmm4, %%xmm5
        \\sha1msg1 %%xmm7, %%xmm6
        \\movdqa %%xmm0, %%xmm2
        \\sha1rnds4 $2, %%xmm1, %%xmm0
        \\sha1nexte %%xmm7, %%xmm2
        \\pxor %%xmm4, %%xmm6
        \\sha1msg1 %%xmm4, %%xmm7
        \\sha1msg2 %%xmm5, %%xmm6
        \\movdqa %%xmm0, %%xmm1
        \\sha1rnds4 $2, %%xmm2, %%xmm0
        \\sha1nexte %%xmm4, %%xmm1
        \\pxor %%xmm5, %%xmm7
        \\sha1msg2 %%xmm6, %%xmm7
        \\sha1msg1 %%xmm5, %%xmm4
        \\movdqa %%xmm0, %%xmm2
        \\sha1rnds4 $2, %%xmm1, %%xmm0
        \\sha1nexte %%xmm5, %%xmm2
        \\pxor %%xmm6, %%xmm4
        \\sha1msg1 %%xmm6, %%xmm5
        \\sha1msg2 %%xmm7, %%xmm4
        \\movdqa %%xmm0, %%xmm1
        \\sha1rnds4 $2, %%xmm2, %%xmm0
        \\sha1nexte %%xmm6, %%xmm1
        \\pxor %%xmm7, %%xmm5
        \\sha1msg2 %%xmm4, %%xmm5
        \\sha1msg1 %%xmm7, %%xmm6
        \\movdqa %%xmm0, %%xmm2
        \\sha1rnds4 $2, %%xmm1, %%xmm0
        \\sha1nexte %%xmm7, %%xmm2
        \\pxor %%xmm4, %%xmm6
        \\sha1msg1 %%xmm4, %%xmm7
        \\sha1msg2 %%xmm5, %%xmm6
        \\movdqa %%xmm0, %%xmm1
        \\sha1rnds4 $3, %%xmm2, %%xmm0
        \\sha1nexte %%xmm4, %%xmm1
        \\pxor %%xmm5, %%xmm7
        \\sha1msg2 %%xmm6, %%xmm7
        \\movdqu (%%r10), %%xmm4
        \\movdqa %%xmm0, %%xmm2
        \\sha1rnds4 $3, %%xmm1, %%xmm0
        \\sha1nexte %%xmm5, %%xmm2
        \\movdqu 16(%%r10), %%xmm5
        \\pshufb %[swap], %%xmm4
        \\movdqa %%xmm0, %%xmm1
        \\sha1rnds4 $3, %%xmm2, %%xmm0
        \\sha1nexte %%xmm6, %%xmm1
        \\movdqu 32(%%r10), %%xmm6
        \\pshufb %[swap], %%xmm5
        \\movdqa %%xmm0, %%xmm2
        \\sha1rnds4 $3, %%xmm1, %%xmm0
        \\sha1nexte %%xmm7, %%xmm2
        \\movdqu 48(%%r10), %%xmm7
        \\pshufb %[swap], %%xmm6
        \\movdqa %%xmm0, %%xmm1
        \\sha1rnds4 $3, %%xmm2, %%xmm0
        \\sha1nexte %%xmm9, %%xmm1
        \\pshufb %[swap], %%xmm7
        \\paddd %%xmm8, %%xmm0
        \\movdqa %%xmm1, %%xmm9
        \\jne 0b
        \\pshufd $0x1b, %%xmm0, %%xmm0
        \\pshufd $0x1b, %%xmm1, %%xmm1
        \\movdqu %%xmm0, (%[state])
        \\movd %%xmm1, 16(%[state])
        :
        : [state] "r" (state),
          [blocks] "r" (blocks),
          [count] "r" (block_count),
          [swap] "{xmm3}" (@as(V4u32, @bitCast(byte_swap))),
        : .{
          .cc = true,
          .memory = true,
          .r8 = true,
          .r10 = true,
          .r11 = true,
          .xmm0 = true,
          .xmm1 = true,
          .xmm2 = true,
          .xmm4 = true,
          .xmm5 = true,
          .xmm6 = true,
          .xmm7 = true,
          .xmm8 = true,
          .xmm9 = true,
        });
}

fn cpuid(leaf: u32, subleaf: u32) CpuidLeaf {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile ("cpuid"
        : [_] "={eax}" (eax),
          [_] "={ebx}" (ebx),
          [_] "={ecx}" (ecx),
          [_] "={edx}" (edx),
        : [_] "{eax}" (leaf),
          [_] "{ecx}" (subleaf),
    );
    return .{ .eax = eax, .ebx = ebx, .ecx = ecx, .edx = edx };
}
