// SPDX-License-Identifier: GPL-2.0-only

//! The three portable CRC32 table-lookup fallbacks -- the Rust bodies
//! behind `lib/crc/crc32-main.c`'s `crc32_le_base()`, `crc32_be_base()`
//! and `crc32c_base()`.
//!
//! Ported from `lib/crc/crc32-main.c` (6.18.49). Only these three
//! functions: `crc32-main.c` itself stays C, still `#include`s the real
//! `$(SRCARCH)/crc32.h` (x86: `lib/crc/x86/crc32.h`) under
//! `CONFIG_CRC32_ARCH`, and still exports `crc32_le()`/`crc32_be()`/
//! `crc32c()`/`crc32_optimizations()` unchanged. The arch dispatch code
//! (`crc32_le_arch()`/`crc32c_arch()` in that header) is real,
//! feature-detected SIMD assembly (`x86/crc32-pclmul.S`,
//! `x86/crc32c-3way.S`) wired through `static_branch`/`static_call` --
//! out of scope for this port, and it CALLS these three functions
//! directly as its own portable fallback (short buffers, FPU unusable,
//! or the CPU lacks the relevant instruction), so they have to keep
//! their exact names and signatures for that C code to keep linking
//! against them.
//!
//! # `crc32_le_base`/`crc32_be_base`/`crc32c_base` have no `EXPORT_SYMBOL`
//!
//! All three are `static inline` in the C -- internal to this file (and,
//! after this port, to the arch header it textually includes) only.
//! No MODVERSIONS CRC, no thunk needed: this file defines them directly
//! under their own names, the `lib/union_find` shape, matching
//! `lib/crc/crc16_rs.rs`'s own `crc16()` (which likewise owns a `static`
//! table nothing outside can see -- contrast `crc_ccitt_rs.rs`, whose
//! table IS an `EXPORT_SYMBOL` data symbol and stays in C for exactly
//! that reason).
//!
//! # The tables are derived, not transcribed
//!
//! `crc32table.h` doesn't ship in the tarball -- it's generated at build
//! time by `lib/crc/gen_crc32table.c`, run once with the real polynomials
//! from `include/linux/crc32poly.h`. Hand-copying its 768 `u32` literals
//! would be 768 chances for an unreviewable typo (see
//! `logs/porting-hazards.md`'s entry on this exact file: "the table has
//! to come from running the generator, not from transcription"). Instead,
//! [`build_table_le`]/[`build_table_be`] replicate
//! `gen_crc32table.c`'s own `crc32init_le_generic()`/`crc32init_be()`
//! algorithms line-for-line as `const fn`s, so a reviewer can diff this
//! file against that one directly rather than trust that some other
//! derivation produces the same table. Verified, not assumed: ran the
//! real, unmodified generator against this exact kernel's headers and
//! diffed all 768 values against what these `const fn`s produce before
//! writing this -- all three tables matched exactly (independently
//! reproduced by review: adversary, 2026-09-06, over 20,010 polynomials
//! including 20,000 random ones, an FNV hash over every entry). There is
//! no standing `port/test/crc32/` differential harness re-running this
//! check on every build -- `lib/libtest.c`'s `test_crc32()` is what runs
//! at every boot instead: the published catalogue check values (an
//! outside source, not our own table) plus a full 256-entry coverage
//! sweep of each table.
//!
//! Computed at compile time (`const fn`, landing in `.rodata`, no
//! initializer runs at boot), matching `crc16_rs.rs`'s own approach.
//!
//! # Recorded divergences (found by review: adversary, 2026-09-06)
//!
//! - The C's `static inline` becomes a global, out-of-line Rust function.
//!   On x86 this changes generated code on the CALLING side too:
//!   `crc32_be()` goes from an inlined byte loop to a real call per
//!   invocation, and so does `crc32_le()`'s short-buffer (<16 byte) path.
//!   Not vetoed -- correct and slower ships -- but recorded per the
//!   project's own rule, since an inlined-vs-called difference reads as a
//!   bug to someone who doesn't know it was deliberate.
//! - `gen_crc32table.c` emits all three tables `____cacheline_aligned`
//!   (64 bytes on x86). Reproduced with a `#[repr(align(64))]` newtype
//!   (`CacheAlignedTable`, below) rather than left at Rust's default
//!   4-byte array alignment -- confirmed in the compiled object before
//!   the fix (`.rodata` entry, `Al = 4`) and after (`Al = 64`).
//!
//! # Reachability beyond `lib/libtest.c`
//!
//! `lib/xz/xz_stream.h`'s `xz_crc32()` wraps `crc32_le()` for every xz
//! stream/block-header CRC check (`lib/xz/xz_dec_stream.c`), always on
//! 2- or 6-byte inputs -- under `CRC_PCLMUL`'s 16-byte SIMD threshold on
//! any x86_64 CPU, regardless of what instructions it has. So `xz_dec_run`
//! (`lib/libtest.c`) reaching `crc32_le_base()` is not incidental or
//! CPU-dependent; it is structurally guaranteed by xz's own format on
//! every xz stream the kernel ever parses. Confirmed by sabotage: XORing
//! one bit into `crc32_le_base`'s per-byte update broke `xz_dec_run`'s and
//! `unxz`'s own libtest vectors as well as the two direct `test_crc32()`
//! checks (see the commit history for the exact log lines).
//!
//! Replaces: the three `_base` functions in `lib/crc/crc32-main.c`.

/// `CRC32_POLY_LE`, `include/linux/crc32poly.h` -- the polynomial used by
/// `crc32_le()`.
const CRC32_POLY_LE: u32 = 0xedb8_8320;
/// `CRC32_POLY_BE`, `include/linux/crc32poly.h` -- the polynomial used by
/// `crc32_be()`.
const CRC32_POLY_BE: u32 = 0x04c1_1db7;
/// `CRC32C_POLY_LE`, `include/linux/crc32poly.h` -- the polynomial used by
/// `crc32c()`.
const CRC32C_POLY_LE: u32 = 0x82f6_3b78;

/// `crc32init_le_generic()`, `lib/crc/gen_crc32table.c`. Used for both
/// `crc32table_le` (with `CRC32_POLY_LE`) and `crc32ctable_le` (with
/// `CRC32C_POLY_LE`), same as the generator.
const fn build_table_le(polynomial: u32) -> [u32; 256] {
    let mut tab = [0u32; 256];
    let mut crc: u32 = 1;
    let mut i: usize = 128;

    while i > 0 {
        crc = (crc >> 1) ^ if crc & 1 != 0 { polynomial } else { 0 };
        let mut j = 0usize;
        while j < 256 {
            tab[i + j] = crc ^ tab[j];
            j += 2 * i;
        }
        i >>= 1;
    }
    tab
}

/// `crc32init_be()`, `lib/crc/gen_crc32table.c`.
const fn build_table_be(polynomial: u32) -> [u32; 256] {
    let mut tab = [0u32; 256];
    let mut crc: u32 = 0x8000_0000;
    let mut i: usize = 1;

    while i < 256 {
        crc = (crc << 1) ^ if crc & 0x8000_0000 != 0 { polynomial } else { 0 };
        let mut j = 0usize;
        while j < i {
            tab[i + j] = crc ^ tab[j];
            j += 1;
        }
        i <<= 1;
    }
    tab
}

/// `gen_crc32table.c` emits all three tables as
/// `static const u32 ____cacheline_aligned crc32table_*[256]` --
/// `____cacheline_aligned` is `__attribute__((aligned(SMP_CACHE_BYTES)))`,
/// 64 bytes on x86 (`include/vdso/cache.h`, `arch/x86/include/asm/cache.h`).
/// A plain `static [u32; 256]` lands at 4-byte alignment and can straddle an
/// extra cache line versus the C. Reproduced with a newtype rather than left
/// unaligned: found by review (adversary, 2026-09-06), confirmed by reading
/// the compiled object (`.rodata` entry, `Al = 4` before this fix).
#[repr(align(64))]
struct CacheAlignedTable([u32; 256]);

/// `crc32table_le`, `lib/crc/crc32table.h` (generated).
static CRC32TABLE_LE: CacheAlignedTable = CacheAlignedTable(build_table_le(CRC32_POLY_LE));
/// `crc32table_be`, `lib/crc/crc32table.h` (generated).
static CRC32TABLE_BE: CacheAlignedTable = CacheAlignedTable(build_table_be(CRC32_POLY_BE));
/// `crc32ctable_le`, `lib/crc/crc32table.h` (generated).
static CRC32CTABLE_LE: CacheAlignedTable = CacheAlignedTable(build_table_le(CRC32C_POLY_LE));

/// `crc32_le_base()`, `lib/crc/crc32-main.c`.
///
/// # Safety
/// `p` must be readable for `len` bytes. Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn crc32_le_base(crc: u32, p: *const u8, len: usize) -> u32 {
    // SAFETY: the caller guarantees `len` readable bytes at `p`.
    // `(NULL, 0)` is legal C and `from_raw_parts` forbids a null pointer.
    let buf: &[u8] = if len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(p, len) }
    };
    let mut crc = crc;
    for &b in buf {
        crc = (crc >> 8) ^ CRC32TABLE_LE.0[((crc & 255) ^ b as u32) as usize];
    }
    crc
}

/// `crc32_be_base()`, `lib/crc/crc32-main.c`.
///
/// # Safety
/// `p` must be readable for `len` bytes. Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn crc32_be_base(crc: u32, p: *const u8, len: usize) -> u32 {
    // SAFETY: the caller guarantees `len` readable bytes at `p`.
    // `(NULL, 0)` is legal C and `from_raw_parts` forbids a null pointer.
    let buf: &[u8] = if len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(p, len) }
    };
    let mut crc = crc;
    for &b in buf {
        crc = (crc << 8) ^ CRC32TABLE_BE.0[((crc >> 24) ^ b as u32) as usize];
    }
    crc
}

/// `crc32c_base()`, `lib/crc/crc32-main.c`.
///
/// # Safety
/// `p` must be readable for `len` bytes. Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn crc32c_base(crc: u32, p: *const u8, len: usize) -> u32 {
    // SAFETY: the caller guarantees `len` readable bytes at `p`.
    // `(NULL, 0)` is legal C and `from_raw_parts` forbids a null pointer.
    let buf: &[u8] = if len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(p, len) }
    };
    let mut crc = crc;
    for &b in buf {
        crc = (crc >> 8) ^ CRC32CTABLE_LE.0[((crc & 255) ^ b as u32) as usize];
    }
    crc
}
