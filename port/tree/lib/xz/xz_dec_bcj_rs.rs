// SPDX-License-Identifier: 0BSD

//! Branch/Call/Jump (BCJ) filter decoders for the XZ decompressor.
//!
//! Ported from `lib/xz/xz_dec_bcj.c` (6.18.49), which carries
//! `Authors: Lasse Collin <lasse.collin@tukaani.org>` and
//! `Igor Pavlov <https://7-zip.org/>` and is 0BSD.
//!
//! # Shape: no thunk, but the C file stays anyway
//!
//! `xz_dec_bcj_run()`, `xz_dec_bcj_reset()` and `xz_dec_bcj_create()` are
//! global but **not** `EXPORT_SYMBOL`'d, so they carry no MODVERSIONS CRC and
//! GOALS.md §1's entry-thunk constraint does not reach them. The first two are
//! defined here outright, under their own names, and `xz_dec_stream.c` links
//! straight to them.
//!
//! `xz_dec_bcj.c` still exists for two reasons, neither of them a thunk:
//!
//! 1. `lib/decompress_unxz.c:243` textually `#include`s it under
//!    `#ifdef STATIC` for the pre-boot decompressor, which has no Rust
//!    runtime. That branch is the original C, verbatim.
//! 2. `xz_dec_bcj_create()` is `kmalloc()`, and the matching
//!    `xz_dec_bcj_end(s)` in `xz_private.h` is a macro that expands to
//!    `kfree(s)` in *`xz_dec_stream.c`*. Both halves of that pair have to be
//!    the kernel's allocator, and `kmalloc` is a macro over a `static inline`
//!    with no linkable symbol. So `create` stays C — GOALS.md §1's second
//!    exception, "C that expresses something a Rust body cannot reach".
//!
//! **The C never sees this layout.** It asks [`rust_xz_dec_bcj_size`] how many
//! bytes to allocate and [`rust_xz_dec_bcj_init`] to fill them. There is one
//! definition of `struct xz_dec_bcj` in the built kernel and it is the one
//! below, so the two cannot drift.
//!
//! # Seven filters, not eight
//!
//! `CONFIG_XZ_DEC_IA64` has **no Kconfig stanza in 6.18** — it went with the
//! ia64 architecture, leaving only `# CONFIG_XZ_DEC_IA64 is not set` fossils
//! in old defconfigs. No kernel can enable it, so `bcj_ia64()` was unreachable
//! in every build; it survived only because `lib/xz/` is carried nearly
//! verbatim from Lasse Collin's XZ Embedded, which still supports Itanium.
//!
//! **It is now gone from this tree's C as well — Adam's call, 2026-09-03**, on
//! the standing goal of removing C wherever it can go. Measured, not assumed:
//! `.text`, `.rodata` and `.data` of `lib/xz/xz_dec_bcj.o` are byte-identical
//! on both configs before and after; only the debug info moved, because DWARF
//! had recorded the `BCJ_IA64` enumerator. Filter ID 6 is now rejected by
//! `xz_dec_bcj_reset()` like any other unsupported ID, in both languages.
//!
//! `port/pristine/lib/xz/xz_dec_bcj.c` still has it, and must: it is the
//! differential's oracle and has to stay as upstream ships it. The harness has
//! never defined `XZ_DEC_IA64`, so both arms compile the same seven filters.
//!
//! # Deliberate divergences, recorded so nobody fixes them back
//!
//! 1. **The filters take slices, and the bounds checks are real.** The C walks
//!    `uint8_t *buf` with an index it has reasoned safe. Here each filter takes
//!    `&mut [u8]` and indexes it, so a mistranscribed bound is a panic at the
//!    wrong access rather than a read past the caller's output buffer. The
//!    index arithmetic is transcribed one for one; only the checking is added.
//!    GOALS.md §5's three questions are all "no" — nothing outside observes a
//!    bounds check that never fires.
//!
//! 2. **`wrapping_*` wherever the C relies on unsigned wraparound**, with the
//!    invariant named in a `debug_assert!` where one exists.
//!    `CONFIG_RUST_OVERFLOW_CHECKS=y` on both configs, and every BCJ filter
//!    computes an address delta by subtracting a position from a value read
//!    out of attacker-supplied data. A plain `-` would turn ordinary input
//!    into a kernel panic inside a decompressor.
//!
//!    `bcj_x86`'s `prev_pos` is the sharp one: the C initialises it to
//!    `(size_t)-1` and then computes `i - prev_pos`, which is
//!    `i.wrapping_sub(usize::MAX)` — that is, `i + 1`. It is not an accident
//!    in the C and it is load-bearing on the first match and on the tail
//!    fix-up at the end of the function.
//!
//! 3. **`rust_xz_dec_bcj_init` writes every field; the C's `create` writes
//!    only `single_call`.** The rest is left uninitialised until
//!    `xz_dec_bcj_reset()`. Reading uninitialised memory is UB in Rust, and
//!    nothing outside can observe the difference because `xz_dec_stream.c`
//!    calls `xz_dec_bcj_reset()` (`:503`) before it ever sets `bcj_active` and
//!    reaches `xz_dec_bcj_run()` (`:226`).
//!
//! # What is NOT changed
//!
//! The filters are transcribed instruction for instruction, including the
//! places where the C's result depends on where a previous call stopped:
//! `s->pos` is the running offset every filter subtracts, and `x86_prev_mask`
//! is carried across calls. Chunk boundaries must not change the output, and
//! that is what the differential's chunking axis exists to check.
//!
//! Replaces: lib/xz/xz_dec_bcj.c

#![allow(clippy::needless_range_loop)]

use core::ffi::{c_int, c_uchar};

// ---------------------------------------------------------------------------
// The pieces of the XZ ABI this file touches. Both are the caller's, so
// GOALS.md §5's layout rule applies: these mirror include/linux/xz.h exactly.
// ---------------------------------------------------------------------------

/// `struct xz_buf`, `include/linux/xz.h`. Owned by the caller of
/// `xz_dec_run()`; only `out[out_pos..]`, `in_pos` and `out_pos` may be
/// modified, and `xz_dec_bcj_run()` additionally swaps `out`/`out_pos`/
/// `out_size` aside and back around one call into LZMA2.
#[repr(C)]
pub struct XzBuf {
    /// Beginning of the input buffer.
    pub input: *const c_uchar,
    /// Current position in the input buffer.
    pub in_pos: usize,
    /// Size of the input buffer.
    pub in_size: usize,
    /// Beginning of the output buffer.
    pub out: *mut c_uchar,
    /// Current position in the output buffer.
    pub out_pos: usize,
    /// Size of the output buffer.
    pub out_size: usize,
}

/// `struct xz_dec_lzma2`, opaque here exactly as it is in `xz_private.h`.
pub enum XzDecLzma2 {}

// `enum xz_ret`, include/linux/xz.h. Carried as c_int rather than as a
// `#[repr(C)] enum` on purpose: `xz_dec_lzma2_run()` is C, and a value outside
// the enumerators would be instant UB in a Rust enum while it is merely a
// number here.
/// `XZ_OK`.
const XZ_OK: c_int = 0;
/// `XZ_STREAM_END`.
const XZ_STREAM_END: c_int = 1;
/// `XZ_OPTIONS_ERROR`.
const XZ_OPTIONS_ERROR: c_int = 6;

// Filter IDs. These are the .xz format's, not ours: they appear in the block
// header of every BCJ-filtered stream.
//
// EACH ONE IS #[cfg]-GATED, and that is not decoration. Every CONFIG_XZ_DEC_*
// is `bool "..." if EXPERT / default y` in lib/xz/Kconfig, so switching one off
// is inside the supported config space -- and CONFIG_WERROR=y turns rustc's
// `constant is never used` into a build failure. Without these gates the port
// fails to build in a configuration the C builds fine, because a C enum
// constant never warns. Neither of this project's configs sets EXPERT, so this
// was invisible here; it was found by an adversarial subagent compiling the
// subsets rather than by anything the rig does.
/// x86 or x86-64.
#[cfg(CONFIG_XZ_DEC_X86)]
const BCJ_X86: u32 = 4;
/// PowerPC, big endian only.
#[cfg(CONFIG_XZ_DEC_POWERPC)]
const BCJ_POWERPC: u32 = 5;
/// ARM, little endian only.
#[cfg(CONFIG_XZ_DEC_ARM)]
const BCJ_ARM: u32 = 7;
/// ARM-Thumb, little endian only.
#[cfg(CONFIG_XZ_DEC_ARMTHUMB)]
const BCJ_ARMTHUMB: u32 = 8;
/// SPARC, big or little endian.
#[cfg(CONFIG_XZ_DEC_SPARC)]
const BCJ_SPARC: u32 = 9;
/// AArch64.
#[cfg(CONFIG_XZ_DEC_ARM64)]
const BCJ_ARM64: u32 = 10;
/// RV32GQC_Zfh, RV64GQC_Zfh.
#[cfg(CONFIG_XZ_DEC_RISCV)]
const BCJ_RISCV: u32 = 11;

/// `struct xz_dec_bcj`. Private to this file in the C and private to this
/// crate here; `xz_dec_stream.c` only ever holds the pointer.
#[repr(C)]
pub struct XzDecBcj {
    /// Type of the BCJ filter being used — one of the `BCJ_*` IDs above.
    kind: u32,
    /// Return value of the next filter in the chain, preserved across calls
    /// because the next filter must not be called again once it has returned
    /// `XZ_STREAM_END`.
    ret: c_int,
    /// True if we are operating in single-call mode.
    single_call: bool,
    /// Absolute position relative to the beginning of the uncompressed data in
    /// a single .xz Block. Only the lowest 32 bits matter.
    pos: u32,
    /// x86 filter state, carried across calls.
    x86_prev_mask: u32,
    /// Temporary space to hold `b->out` while it points at `temp_buf`.
    out: *mut c_uchar,
    /// Temporary space to hold `b->out_pos`.
    out_pos: usize,
    /// Temporary space to hold `b->out_size`.
    out_size: usize,
    /// Amount of already filtered data at the beginning of `temp_buf`.
    temp_filtered: usize,
    /// Total amount of data currently stored in `temp_buf`.
    temp_size: usize,
    /// A mix of filtered and unfiltered data. Big enough for
    /// Alignment + 2 * Look-ahead over every filter: the worst case is x86's
    /// 1 + 2*4 and IA-64's alignment of 16.
    temp_buf: [u8; 16],
}

extern "C" {
    /// `lib/xz/xz_dec_lzma2.c`. Decodes a raw LZMA2 stream from `b->in` to
    /// `b->out`; the one thing this file calls that it does not own.
    fn xz_dec_lzma2_run(s: *mut XzDecLzma2, b: *mut XzBuf) -> c_int;
}

// ---------------------------------------------------------------------------
// Unaligned helpers. include/linux/unaligned.h on the C side; here they are
// spelled out because a byte-wise definition is correct on every target and
// lowers to the wide load wherever one exists.
// ---------------------------------------------------------------------------

/// `get_unaligned_le32()`.
#[cfg(any(CONFIG_XZ_DEC_X86, CONFIG_XZ_DEC_ARM64, CONFIG_XZ_DEC_RISCV))]
#[inline]
fn get_le32(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

/// `put_unaligned_le32()`.
#[cfg(any(CONFIG_XZ_DEC_X86, CONFIG_XZ_DEC_ARM64, CONFIG_XZ_DEC_RISCV))]
#[inline]
fn put_le32(b: &mut [u8], i: usize, v: u32) {
    b[i..i + 4].copy_from_slice(&v.to_le_bytes());
}

/// `get_unaligned_be32()`.
#[cfg(any(CONFIG_XZ_DEC_POWERPC, CONFIG_XZ_DEC_SPARC, CONFIG_XZ_DEC_RISCV))]
#[inline]
fn get_be32(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

/// `put_unaligned_be32()`.
#[cfg(any(CONFIG_XZ_DEC_POWERPC, CONFIG_XZ_DEC_SPARC))]
#[inline]
fn put_be32(b: &mut [u8], i: usize, v: u32) {
    b[i..i + 4].copy_from_slice(&v.to_be_bytes());
}

// ---------------------------------------------------------------------------
// The filters. Each returns how many bytes at the start of `buf` it filtered;
// the rest are left for the next call, which is what `temp` in the wrapper
// exists to carry.
// ---------------------------------------------------------------------------

/// Test the most significant byte of a memory address in an x86 instruction.
#[cfg(CONFIG_XZ_DEC_X86)]
#[inline]
pub(crate) fn bcj_x86_test_msbyte(b: u8) -> bool {
    b == 0x00 || b == 0xFF
}

/// The x86 filter. The only one with state carried between calls.
#[cfg(CONFIG_XZ_DEC_X86)]
pub(crate) fn bcj_x86(pos: u32, prev_mask_state: &mut u32, buf: &mut [u8]) -> usize {
    const MASK_TO_ALLOWED_STATUS: [bool; 8] =
        [true, true, true, false, true, false, false, false];
    const MASK_TO_BIT_NUM: [u32; 8] = [0, 1, 2, 2, 3, 3, 3, 3];

    // The C's `size_t prev_pos = (size_t)-1`, and the wraparound that gives
    // `i - prev_pos == i + 1` on the first match is deliberate.
    let mut prev_pos: usize = usize::MAX;
    let mut prev_mask: u32 = *prev_mask_state;

    if buf.len() <= 4 {
        return 0;
    }

    let size = buf.len() - 4;
    let mut i: usize = 0;
    while i < size {
        if buf[i] & 0xFE != 0xE8 {
            i += 1;
            continue;
        }

        prev_pos = i.wrapping_sub(prev_pos);
        if prev_pos > 3 {
            prev_mask = 0;
        } else {
            // prev_pos is 1..=3 here, so the shift is 0..=2.
            debug_assert!(prev_pos >= 1);
            prev_mask = (prev_mask << (prev_pos - 1)) & 7;
            if prev_mask != 0 {
                let b = buf[i + 4 - MASK_TO_BIT_NUM[prev_mask as usize] as usize];
                if !MASK_TO_ALLOWED_STATUS[prev_mask as usize] || bcj_x86_test_msbyte(b) {
                    prev_pos = i;
                    prev_mask = (prev_mask << 1) | 1;
                    i += 1;
                    continue;
                }
            }
        }

        prev_pos = i;

        if bcj_x86_test_msbyte(buf[i + 4]) {
            let mut src = get_le32(buf, i + 1);
            let dest;
            loop {
                let d = src.wrapping_sub(pos.wrapping_add(i as u32).wrapping_add(5));
                if prev_mask == 0 {
                    dest = d;
                    break;
                }

                let j = MASK_TO_BIT_NUM[prev_mask as usize] * 8;
                let b = (d >> (24 - j)) as u8;
                if !bcj_x86_test_msbyte(b) {
                    dest = d;
                    break;
                }

                src = d ^ ((1u32 << (32 - j)) - 1);
            }

            let mut dest = dest & 0x01FF_FFFF;
            dest |= 0u32.wrapping_sub(dest & 0x0100_0000);
            put_le32(buf, i + 1, dest);
            i += 4;
        } else {
            prev_mask = (prev_mask << 1) | 1;
        }
        i += 1;
    }

    prev_pos = i.wrapping_sub(prev_pos);
    *prev_mask_state = if prev_pos > 3 {
        0
    } else {
        prev_mask << (prev_pos - 1)
    };
    i
}

/// The PowerPC filter: big-endian `bl` with `AA=0, LK=1`.
#[cfg(CONFIG_XZ_DEC_POWERPC)]
pub(crate) fn bcj_powerpc(pos: u32, buf: &mut [u8]) -> usize {
    let size = buf.len() & !3usize;

    let mut i = 0;
    while i < size {
        let mut instr = get_be32(buf, i);
        if instr & 0xFC00_0003 == 0x4800_0001 {
            instr &= 0x03FF_FFFC;
            instr = instr.wrapping_sub(pos.wrapping_add(i as u32));
            instr &= 0x03FF_FFFC;
            instr |= 0x4800_0001;
            put_be32(buf, i, instr);
        }
        i += 4;
    }

    i
}

/// The ARM filter: `BL` is `0xEB` in the top byte, little endian.
#[cfg(CONFIG_XZ_DEC_ARM)]
pub(crate) fn bcj_arm(pos: u32, buf: &mut [u8]) -> usize {
    let size = buf.len() & !3usize;

    let mut i = 0;
    while i < size {
        if buf[i + 3] == 0xEB {
            let mut addr =
                buf[i] as u32 | ((buf[i + 1] as u32) << 8) | ((buf[i + 2] as u32) << 16);
            addr <<= 2;
            addr = addr.wrapping_sub(pos.wrapping_add(i as u32).wrapping_add(8));
            addr >>= 2;
            buf[i] = addr as u8;
            buf[i + 1] = (addr >> 8) as u8;
            buf[i + 2] = (addr >> 16) as u8;
        }
        i += 4;
    }

    i
}

/// The ARM-Thumb filter: a `BL` pair, `F0..` followed by `F8..`.
#[cfg(CONFIG_XZ_DEC_ARMTHUMB)]
pub(crate) fn bcj_armthumb(pos: u32, buf: &mut [u8]) -> usize {
    if buf.len() < 4 {
        return 0;
    }

    let size = buf.len() - 4;
    let mut i = 0;
    while i <= size {
        if buf[i + 1] & 0xF8 == 0xF0 && buf[i + 3] & 0xF8 == 0xF8 {
            let mut addr = ((buf[i + 1] as u32 & 0x07) << 19)
                | ((buf[i] as u32) << 11)
                | ((buf[i + 3] as u32 & 0x07) << 8)
                | (buf[i + 2] as u32);
            addr <<= 1;
            addr = addr.wrapping_sub(pos.wrapping_add(i as u32).wrapping_add(4));
            addr >>= 1;
            buf[i + 1] = (0xF0 | ((addr >> 19) & 0x07)) as u8;
            buf[i] = (addr >> 11) as u8;
            buf[i + 3] = (0xF8 | ((addr >> 8) & 0x07)) as u8;
            buf[i + 2] = addr as u8;
            i += 2;
        }
        i += 2;
    }

    i
}

/// The SPARC filter: `CALL`, big endian.
#[cfg(CONFIG_XZ_DEC_SPARC)]
pub(crate) fn bcj_sparc(pos: u32, buf: &mut [u8]) -> usize {
    let size = buf.len() & !3usize;

    let mut i = 0;
    while i < size {
        let mut instr = get_be32(buf, i);
        if (instr >> 22) == 0x100 || (instr >> 22) == 0x1FF {
            instr <<= 2;
            instr = instr.wrapping_sub(pos.wrapping_add(i as u32));
            instr >>= 2;
            instr = 0x4000_0000u32.wrapping_sub(instr & 0x40_0000)
                | 0x4000_0000
                | (instr & 0x3F_FFFF);
            put_be32(buf, i, instr);
        }
        i += 4;
    }

    i
}

/// The ARM64 filter: `BL`, and `ADRP` within +/-512 MiB.
#[cfg(CONFIG_XZ_DEC_ARM64)]
pub(crate) fn bcj_arm64(pos: u32, buf: &mut [u8]) -> usize {
    let size = buf.len() & !3usize;

    let mut i = 0;
    while i < size {
        let mut instr = get_le32(buf, i);

        if (instr >> 26) == 0x25 {
            // BL instruction
            let addr = instr.wrapping_sub(pos.wrapping_add(i as u32) >> 2);
            instr = 0x9400_0000 | (addr & 0x03FF_FFFF);
            put_le32(buf, i, instr);
        } else if instr & 0x9F00_0000 == 0x9000_0000 {
            // ADRP instruction
            let mut addr = ((instr >> 29) & 3) | ((instr >> 3) & 0x1F_FFFC);

            // Only convert values in the range +/-512 MiB.
            if addr.wrapping_add(0x02_0000) & 0x1C_0000 != 0 {
                i += 4;
                continue;
            }

            addr = addr.wrapping_sub(pos.wrapping_add(i as u32) >> 12);

            instr &= 0x9000_001F;
            instr |= (addr & 3) << 29;
            instr |= (addr & 0x03_FFFC) << 3;
            instr |= 0u32.wrapping_sub(addr & 0x02_0000) & 0xE0_0000;

            put_le32(buf, i, instr);
        }
        i += 4;
    }

    i
}

/// The RISC-V filter: `JAL`, and the `AUIPC` + following-instruction pair.
#[cfg(CONFIG_XZ_DEC_RISCV)]
pub(crate) fn bcj_riscv(pos: u32, buf: &mut [u8]) -> usize {
    if buf.len() < 8 {
        return 0;
    }

    let size = buf.len() - 8;
    let mut i = 0;
    while i <= size {
        let mut instr = buf[i] as u32;

        if instr == 0xEF {
            // JAL
            let b1 = buf[i + 1] as u32;
            if b1 & 0x0D != 0 {
                i += 2;
                continue;
            }

            let b2 = buf[i + 2] as u32;
            let b3 = buf[i + 3] as u32;

            let mut addr = ((b1 & 0xF0) << 13) | (b2 << 9) | (b3 << 1);
            addr = addr.wrapping_sub(pos.wrapping_add(i as u32));

            buf[i + 1] = ((b1 & 0x0F) | ((addr >> 8) & 0xF0)) as u8;
            buf[i + 2] =
                (((addr >> 16) & 0x0F) | ((addr >> 7) & 0x10) | ((addr << 4) & 0xE0)) as u8;
            buf[i + 3] = (((addr >> 4) & 0x7F) | ((addr >> 13) & 0x80)) as u8;

            i += 4 - 2;
        } else if instr & 0x7F == 0x17 {
            // AUIPC
            let instr2;
            instr |= (buf[i + 1] as u32) << 8;
            instr |= (buf[i + 2] as u32) << 16;
            instr |= (buf[i + 3] as u32) << 24;

            if instr & 0xE80 != 0 {
                // AUIPC's rd doesn't equal x0 or x2.
                let old2 = get_le32(buf, i + 4);

                if ((instr << 8) ^ old2.wrapping_sub(3)) & 0xF_8003 != 0 {
                    i += 6 - 2;
                    i += 2;
                    continue;
                }

                let addr = (instr & 0xFFFF_F000).wrapping_add(old2 >> 20);

                instr2 = addr;
                instr = 0x17 | (2 << 7) | (old2 << 12);
            } else {
                // AUIPC's rd equals x0 or x2.
                let instr2_rs1 = instr >> 27;

                if (instr.wrapping_sub(0x3117) << 18) >= (instr2_rs1 & 0x1D) {
                    i += 4 - 2;
                    i += 2;
                    continue;
                }

                let mut addr = get_be32(buf, i + 4);
                addr = addr.wrapping_sub(pos.wrapping_add(i as u32));

                instr2 = (instr >> 12) | (addr << 20);

                instr = 0x17
                    | (instr2_rs1 << 7)
                    | (addr.wrapping_add(0x800) & 0xFFFF_F000);
            }

            put_le32(buf, i, instr);
            put_le32(buf, i + 4, instr2);

            i += 8 - 2;
        }
        i += 2;
    }

    i
}

// ---------------------------------------------------------------------------
// The wrapper: dispatch, the 16-byte straddle buffer, and the flush.
//
// Everything below reaches `struct xz_buf` through the raw pointer rather than
// holding a `&mut` across the call into LZMA2. The C hands the SAME pointer to
// `xz_dec_lzma2_run()` that it is itself writing through, and a long-lived
// `&mut` derived from it would be invalidated by that call.
// ---------------------------------------------------------------------------

/// Apply the selected BCJ filter to `buf[*off..]`, then advance `*off` and
/// `pos` by however much got filtered.
///
/// A `match` rather than a table of function pointers, for the same reason the
/// C uses a `switch`: the pre-boot decompressor must avoid pointers to static
/// data, at least on x86.
fn bcj_apply(kind: u32, pos: &mut u32, prev_mask: &mut u32, buf: &mut [u8], off: &mut usize) {
    // x86 is the only filter with state carried between calls, so `prev_mask`
    // is unused when CONFIG_XZ_DEC_X86 is off. At least one filter is always
    // enabled here: CONFIG_XZ_DEC_BCJ is `default n` and only ever arrives by
    // `select` from one of the seven (lib/xz/Kconfig:16-51), and the Makefile
    // builds this file only when it is set -- the same guarantee the C gets
    // from wrapping itself in `#ifdef XZ_DEC_BCJ`.
    let _ = &prev_mask;

    let at = *pos;
    let window = &mut buf[*off..];

    let filtered = match kind {
        #[cfg(CONFIG_XZ_DEC_X86)]
        BCJ_X86 => bcj_x86(at, prev_mask, window),
        #[cfg(CONFIG_XZ_DEC_POWERPC)]
        BCJ_POWERPC => bcj_powerpc(at, window),
        #[cfg(CONFIG_XZ_DEC_ARM)]
        BCJ_ARM => bcj_arm(at, window),
        #[cfg(CONFIG_XZ_DEC_ARMTHUMB)]
        BCJ_ARMTHUMB => bcj_armthumb(at, window),
        #[cfg(CONFIG_XZ_DEC_SPARC)]
        BCJ_SPARC => bcj_sparc(at, window),
        #[cfg(CONFIG_XZ_DEC_ARM64)]
        BCJ_ARM64 => bcj_arm64(at, window),
        #[cfg(CONFIG_XZ_DEC_RISCV)]
        BCJ_RISCV => bcj_riscv(at, window),
        // Never reached: xz_dec_bcj_reset() rejects every other ID.
        _ => 0,
    };

    *off += filtered;
    *pos = pos.wrapping_add(filtered as u32);
}

/// Flush pending filtered data from `temp` to the output buffer, then move the
/// remaining mixture of filtered and unfiltered data to the front of `temp`.
///
/// # Safety
///
/// `b` must point at a live `struct xz_buf` whose `out[out_pos..out_size]` is
/// writable and does not overlap `*s`.
unsafe fn bcj_flush(s: &mut XzDecBcj, b: *mut XzBuf) {
    // SAFETY: the caller guarantees `b` is live for the duration of the call.
    let (out, out_pos, out_size) = unsafe { ((*b).out, (*b).out_pos, (*b).out_size) };

    let copy_size = core::cmp::min(s.temp_filtered, out_size - out_pos);
    // SAFETY: `out[out_pos..out_size]` is writable and `copy_size` fits in it;
    // the source is `s.temp_buf`, which does not overlap it.
    unsafe { core::ptr::copy_nonoverlapping(s.temp_buf.as_ptr(), out.add(out_pos), copy_size) };
    // SAFETY: as above.
    unsafe { (*b).out_pos = out_pos + copy_size };

    s.temp_filtered -= copy_size;
    s.temp_size -= copy_size;
    s.temp_buf.copy_within(copy_size..copy_size + s.temp_size, 0);
}

/// Decode a raw BCJ + LZMA2 stream.
///
/// The BCJ filters process 1-16 bytes at a time; this hides that from the
/// caller by carrying the ragged tail in `temp` across calls. The result must
/// not depend on where the chunk boundaries fall, which is the axis
/// `port/test/xz/` varies.
///
/// # Safety
///
/// `s` must be a pointer returned by `xz_dec_bcj_create()` and reset by
/// `xz_dec_bcj_reset()`; `lzma2` and `b` must be live, `b`'s buffers must match
/// its `in_size`/`out_size`, and neither may overlap `*s`. This is the contract
/// `xz_dec_stream.c` already upholds.
#[no_mangle]
pub unsafe extern "C" fn xz_dec_bcj_run(
    s: *mut XzDecBcj,
    lzma2: *mut XzDecLzma2,
    b: *mut XzBuf,
) -> c_int {
    // SAFETY: the caller guarantees `s` is live and unaliased for the duration
    // of the call.
    let s = unsafe { &mut *s };

    // Flush pending already filtered data to the output buffer. Return
    // immediately if we couldn't flush everything, or if the next filter in
    // the chain had already returned XZ_STREAM_END.
    if s.temp_filtered > 0 {
        // SAFETY: `b` is live per the contract above.
        unsafe { bcj_flush(s, b) };
        if s.temp_filtered > 0 {
            return XZ_OK;
        }

        if s.ret == XZ_STREAM_END {
            return XZ_STREAM_END;
        }
    }

    // `out` and `out_size` are the caller's and LZMA2 does not touch them;
    // only `out_pos` moves, so that one is re-read after every call.
    // SAFETY: `b` is live per the contract above.
    let (out, out_size) = unsafe { ((*b).out, (*b).out_size) };
    // SAFETY: as above.
    let mut out_pos = unsafe { (*b).out_pos };

    // If we have more output space than what is currently pending in temp,
    // copy the unfiltered data from temp to the output buffer and try to fill
    // the output buffer by decoding more data from the next filter in the
    // chain. Apply the BCJ filter on the new data in the output buffer. If
    // everything cannot be filtered, copy it to temp and rewind the output
    // buffer position accordingly.
    //
    // This needs to be always run when temp_size == 0 to handle a special case
    // where the output buffer is full and the next filter has no more output
    // coming but hasn't returned XZ_STREAM_END yet.
    if s.temp_size < out_size - out_pos || s.temp_size == 0 {
        let mut out_start = out_pos;

        // SAFETY: the branch condition established there is at least
        // `temp_size` bytes of room left in the output buffer.
        unsafe {
            core::ptr::copy_nonoverlapping(s.temp_buf.as_ptr(), out.add(out_pos), s.temp_size);
        }
        out_pos += s.temp_size;
        // SAFETY: `b` is live.
        unsafe { (*b).out_pos = out_pos };

        // SAFETY: this is the C's own call into the next filter in the chain,
        // with the pointer it was given.
        s.ret = unsafe { xz_dec_lzma2_run(lzma2, b) };
        if s.ret != XZ_STREAM_END && (s.ret != XZ_OK || s.single_call) {
            return s.ret;
        }

        // SAFETY: `b` is live; LZMA2 has advanced `out_pos`.
        out_pos = unsafe { (*b).out_pos };
        // SAFETY: `out` covers `out_size >= out_pos` writable bytes, and it
        // does not overlap `*s`.
        let window = unsafe { core::slice::from_raw_parts_mut(out, out_pos) };
        bcj_apply(s.kind, &mut s.pos, &mut s.x86_prev_mask, window, &mut out_start);

        // As an exception, if the next filter returned XZ_STREAM_END, we can
        // do that too, since the last few bytes that remain unfiltered are
        // meant to remain unfiltered.
        if s.ret == XZ_STREAM_END {
            return XZ_STREAM_END;
        }

        s.temp_size = out_pos - out_start;
        out_pos -= s.temp_size;
        // SAFETY: `b` is live.
        unsafe { (*b).out_pos = out_pos };
        // SAFETY: `temp_size` is at most the 16-byte look-ahead the filters
        // leave behind, and those bytes are the tail of the output buffer.
        unsafe {
            core::ptr::copy_nonoverlapping(out.add(out_pos), s.temp_buf.as_mut_ptr(), s.temp_size);
        }

        // If there wasn't enough input to the next filter to fill the output
        // buffer with unfiltered data, there's no point to try decoding more
        // data to temp.
        if out_pos + s.temp_size < out_size {
            return XZ_OK;
        }
    }

    // We have unfiltered data in temp. If the output buffer isn't full yet,
    // try to fill the temp buffer by decoding more data from the next filter.
    // Apply the BCJ filter on temp. Then we hopefully can fill the actual
    // output buffer by copying filtered data from temp. A mix of filtered and
    // unfiltered data may be left in temp; it will be taken care of on the
    // next call to this function.
    if out_pos < out_size {
        // Make b->out{,_pos,_size} temporarily point to s->temp.
        s.out = out;
        s.out_pos = out_pos;
        s.out_size = out_size;
        // SAFETY: `b` is live, and `s.temp_buf` outlives the LZMA2 call below.
        unsafe {
            (*b).out = s.temp_buf.as_mut_ptr();
            (*b).out_pos = s.temp_size;
            (*b).out_size = s.temp_buf.len();
        }

        // SAFETY: as above; `b` now describes `s.temp_buf`.
        s.ret = unsafe { xz_dec_lzma2_run(lzma2, b) };

        // SAFETY: `b` is live.
        s.temp_size = unsafe { (*b).out_pos };
        // SAFETY: as above.
        unsafe {
            (*b).out = s.out;
            (*b).out_pos = s.out_pos;
            (*b).out_size = s.out_size;
        }

        if s.ret != XZ_OK && s.ret != XZ_STREAM_END {
            return s.ret;
        }

        let size = s.temp_size;
        let mut filtered = s.temp_filtered;
        bcj_apply(
            s.kind,
            &mut s.pos,
            &mut s.x86_prev_mask,
            &mut s.temp_buf[..size],
            &mut filtered,
        );
        s.temp_filtered = filtered;

        // If the next filter returned XZ_STREAM_END, we mark that everything
        // is filtered, since the last unfiltered bytes of the stream are meant
        // to be left as is.
        if s.ret == XZ_STREAM_END {
            s.temp_filtered = s.temp_size;
        }

        // SAFETY: `b` is live and describes the caller's buffer again.
        unsafe { bcj_flush(s, b) };
        if s.temp_filtered > 0 {
            return XZ_OK;
        }
    }

    s.ret
}

/// Decode the Filter ID of a BCJ filter and reset the decoder state.
///
/// This implementation doesn't support custom start offsets, so no decoding of
/// Filter Properties is needed. Returns `XZ_OK` if the given Filter ID is
/// supported, `XZ_OPTIONS_ERROR` otherwise.
///
/// # Safety
///
/// `s` must be a pointer returned by `xz_dec_bcj_create()`.
#[no_mangle]
pub unsafe extern "C" fn xz_dec_bcj_reset(s: *mut XzDecBcj, id: u8) -> c_int {
    match id as u32 {
        #[cfg(CONFIG_XZ_DEC_X86)]
        BCJ_X86 => {}
        #[cfg(CONFIG_XZ_DEC_POWERPC)]
        BCJ_POWERPC => {}
        #[cfg(CONFIG_XZ_DEC_ARM)]
        BCJ_ARM => {}
        #[cfg(CONFIG_XZ_DEC_ARMTHUMB)]
        BCJ_ARMTHUMB => {}
        #[cfg(CONFIG_XZ_DEC_SPARC)]
        BCJ_SPARC => {}
        #[cfg(CONFIG_XZ_DEC_ARM64)]
        BCJ_ARM64 => {}
        #[cfg(CONFIG_XZ_DEC_RISCV)]
        BCJ_RISCV => {}
        // Unsupported Filter ID.
        _ => return XZ_OPTIONS_ERROR,
    }

    // SAFETY: the caller guarantees `s` came from xz_dec_bcj_create().
    let s = unsafe { &mut *s };

    s.kind = id as u32;
    s.ret = XZ_OK;
    s.pos = 0;
    s.x86_prev_mask = 0;
    s.temp_filtered = 0;
    s.temp_size = 0;

    XZ_OK
}

// ---------------------------------------------------------------------------
// What xz_dec_bcj.c needs in order to allocate one of these. The layout is
// defined above and nowhere else, so the two cannot drift.
// ---------------------------------------------------------------------------

/// How many bytes `xz_dec_bcj_create()` must `kmalloc()`.
#[no_mangle]
pub extern "C" fn rust_xz_dec_bcj_size() -> usize {
    // kmalloc returns memory aligned to at least ARCH_KMALLOC_MINALIGN, which
    // is 8 on every architecture the kernel builds Rust for. Anything stricter
    // would need a different allocator, so refuse at compile time.
    const _: () = assert!(core::mem::align_of::<XzDecBcj>() <= 8);
    core::mem::size_of::<XzDecBcj>()
}

/// Initialise a freshly allocated decoder.
///
/// The C's `xz_dec_bcj_create()` sets only `single_call` and leaves the rest
/// for `xz_dec_bcj_reset()`; this writes every field, because reading
/// uninitialised memory is UB in Rust. See divergence 3 at the top of the file.
///
/// # Safety
///
/// `s` must point at `rust_xz_dec_bcj_size()` writable bytes aligned to at
/// least 8.
#[no_mangle]
pub unsafe extern "C" fn rust_xz_dec_bcj_init(s: *mut XzDecBcj, single_call: bool) {
    // SAFETY: the caller guarantees `s` covers a correctly aligned allocation
    // of `rust_xz_dec_bcj_size()` bytes.
    unsafe {
        s.write(XzDecBcj {
            kind: 0,
            ret: XZ_OK,
            single_call,
            pos: 0,
            x86_prev_mask: 0,
            out: core::ptr::null_mut(),
            out_pos: 0,
            out_size: 0,
            temp_filtered: 0,
            temp_size: 0,
            temp_buf: [0; 16],
        });
    }
}
