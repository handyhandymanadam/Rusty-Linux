// SPDX-License-Identifier: GPL-2.0+ OR BSD-3-Clause
// (dual BSD-3-Clause, as the file it is ported from)

//! huff0 Huffman decoder — the decode side of `lib/zstd`.
//!
//! Ported from `lib/zstd/decompress/huf_decompress.c` of 6.18.49,
//! `Copyright (c) Meta Platforms, Inc. and affiliates.`, dual
//! GPL-2.0+/BSD-3-Clause.
//!
//! # Shape: no entry thunks at all — the `lib/union_find` shape
//!
//! Measured with `nm` on the built objects. The file defines nine globals and
//! **not one of them is `EXPORT_SYMBOL`'d**, so none carries a MODVERSIONS CRC
//! and GOALS.md §2 criterion 4 does not reach any of them. Rust defines all
//! nine directly under their own names and
//! `lib/zstd/decompress/huf_decompress.c` leaves the Makefile entirely.
//!
//! | symbol | referenced by |
//! |---|---|
//! | `HUF_decompress1X1_DCtx_wksp` | `zstd_decompress_block.o` |
//! | `HUF_decompress1X_usingDTable` | `zstd_decompress_block.o` |
//! | `HUF_decompress4X_hufOnly_wksp` | `zstd_decompress_block.o` |
//! | `HUF_decompress4X_usingDTable` | `zstd_decompress_block.o` |
//! | `HUF_readDTableX2_wksp` | `zstd_decompress.o` |
//! | `HUF_readDTableX1_wksp` | nothing kernel-wide |
//! | `HUF_decompress1X2_DCtx_wksp` | nothing kernel-wide |
//! | `HUF_decompress1X_DCtx_wksp` | nothing kernel-wide |
//! | `HUF_selectDecoder` | nothing kernel-wide |
//!
//! Contrast `common/entropy_common.c`, which keeps three C thunks because
//! `zstd_common_module.c` exports its symbols. Nothing here needs one.
//!
//! The four dead-in-tree symbols are kept anyway: `huf.h` still declares them
//! and out-of-tree users may link them, and `nm` output stays identical.
//!
//! # `ZSTD_ENABLE_ASM_X86_64_BMI2` is a hard 0, so the asm loops are not here
//!
//! `common/portability_macros.h:97` is `#define ZSTD_ENABLE_ASM_X86_64_BMI2 0`
//! unconditionally in the kernel copy. Every
//! `#if ZSTD_ENABLE_ASM_X86_64_BMI2` block in `huf_decompress.c` is therefore
//! dead: the `HUF_decompress4X{1,2}_usingDTable_internal_fast_asm_loop`
//! declarations, both places `loopFn` is reassigned to them, and the
//! `HUF_flags_disableAsm` tests that guard those reassignments. **The C paths
//! are ported; the hand-written assembly decoder loops are not**, because they
//! are not compiled into this kernel at all.
//!
//! One consequence, recorded because it is a real deviation and not just dead
//! code: with the asm loops gone, `loopFn` has exactly **one** possible value
//! at both call sites, so the `HUF_DecompressFastLoopFn` function-pointer
//! parameter is dropped and
//! [`HUF_decompress4X1_usingDTable_internal_fast_c_loop`] /
//! [`HUF_decompress4X2_usingDTable_internal_fast_c_loop`] are called directly.
//! That is behaviour-identical, and it is also *forced*: a
//! `#[target_feature]` function cannot be coerced to a function pointer in
//! Rust, and in the C both the loop and its caller carry
//! `HUF_FAST_BMI2_ATTRS`, so a direct `#[inline(always)]` call is the only
//! arrangement that keeps the loop compiled with the caller's features.
//!
//! `HUF_flags_disableAsm` is consequently **not defined here**. Its only uses
//! were inside those dead `#if`s, and an unused `const` is a `dead_code`
//! warning, which `CONFIG_WERROR=y` turns into a build failure
//! (`logs/floor.md` RAISE 1).
//!
//! # `DYNAMIC_BMI2` is 1 here, and the axis is preserved
//!
//! `portability_macros.h:61-71` sets `DYNAMIC_BMI2` to 1 for GCC >= 11 on x86
//! when `__BMI2__` is unset — which is this build. So `HUF_NEED_BMI2_FUNCTION`
//! is 1, `HUF_FAST_BMI2_ATTRS` is `BMI2_TARGET_ATTRIBUTE`, and every `_bmi2`
//! body in this file is real, dispatched on at runtime.
//!
//! `compiler.h:97` defines `BMI2_TARGET_ATTRIBUTE` as
//! `TARGET_ATTRIBUTE("lzcnt,bmi,bmi2")` — **three** features — which in Rust is
//! `#[target_feature(enable = "lzcnt,bmi1,bmi2")]` (rustc spells GCC's `bmi`
//! as `bmi1`). Each `_body` is `#[inline(always)]` and each feature-carrying
//! wrapper is an `unsafe fn` carrying only that attribute.
//!
//! **`#[inline(always)]` on the bodies is load-bearing, not cosmetic.** Without
//! it rustc emits one shared feature-less copy and the `_bmi2` wrapper's body
//! silently compiles *without* bmi2 — identical results, so no differential can
//! see it, but `bzhi`/`shlx`/`shrx`/`lzcnt` never appear. Every function the C
//! marks `FORCE_INLINE_TEMPLATE` or `HINT_INLINE` therefore carries
//! `#[inline(always)]` here, and so do the small `static` helpers that the C
//! leaves to GCC's inliner.
//!
//! On non-x86 targets `DYNAMIC_BMI2` is 0: the `_bmi2` wrappers are not
//! compiled at all (`#[cfg]`, matching the C's `#if`), and the dispatchers take
//! the shape the C's `#else` arm takes. Per `logs/floor.md` RAISE 1 the gate is
//! on the items, not just their uses.
//!
//! # `HUF_readStats_wksp` is still a call into C, deliberately
//!
//! `HUF_readStats_wksp` is already ported — its body is
//! `rust_HUF_readStats_wksp` in `common/entropy_common_rs.rs` — but the kernel
//! reaches it through a C thunk in `common/entropy_common.c`, because the
//! symbol is `EXPORT_SYMBOL_GPL`'d (`zstd_common_module.c:23`) and under
//! `CONFIG_GENDWARFKSYMS` its MODVERSIONS CRC comes from the DWARF of the C
//! definition. This file calls the **C symbol** via `extern "C"`, so the
//! harness and the kernel agree.
//!
//! That is one internal FFI wall this port does not yet delete. A later change
//! could call `rust_HUF_readStats_wksp` directly and erase the crossing — the
//! thunk exists only to carry the exported symbol's DWARF, and nothing about
//! the *call site* has to go through it. It is left alone here so that the
//! differential harness links exactly what the kernel links.
//!
//! # `bitstream.h`/`mem.h`/`bits.h` are a VERBATIM COPY, not a re-translation
//!
//! `BIT_DStream_t`, `BIT_initDStream`, `BIT_reloadDStream(_internal)`,
//! `BIT_lookBits(Fast)`, `BIT_skipBits`, `BIT_readBits(Fast)`,
//! `BIT_getMiddleBits`, `MEM_readLE32`, `MEM_readLEST`, `MEM_write64`,
//! `ZSTD_highbit32` and `ZSTD_countTrailingZeros32` were transcribed from the
//! headers in `common/entropy_common_rs.rs`. **They are copied across from
//! that file character for character**, not re-translated. The two files are
//! separate crates, so a `static inline` in a C header — which has no linkable
//! symbol and cannot be called across the boundary — must be duplicated; the
//! only thing under our control is that the duplication be *identical*. A
//! second, subtly different transcription of the same header is exactly the
//! drift this project fears. If one copy is fixed, fix the other.
//!
//! Four members are new here because `huf_decompress.c` uses them and
//! `entropy_common.c` did not: [`BIT_reloadDStreamFast`] (`bitstream.h:385`),
//! [`BIT_endOfDStream`] (`bitstream.h:434`), [`MEM_readLE16`], [`MEM_read64`]
//! and [`MEM_write16`]. They are written in the same idiom.
//!
//! # Error codes are values, not a category
//!
//! `error_private.h:41` — `ERROR(name)` is `((size_t)-ZSTD_error_##name)`. A
//! differential harness comparing raw `usize` returns sees any confusion
//! between two error codes, and "also an error" is a failure. Every code is
//! reproduced by value.
//!
//! # Deliberate divergences, recorded so nobody fixes them back
//!
//! 1. **Buffer accesses are bounds-checked.** Every write to `dst`, read of
//!    `cSrc`, and index into a decode table goes through a helper that asserts
//!    first. The index arithmetic is transcribed one for one; only the check is
//!    added, and the invariant that makes each check redundant is written out
//!    in the corresponding `SAFETY` comment. The full list, with reachability,
//!    is in the report that accompanied this file.
//!
//! 2. **The workspaces are `#[repr(C)]` structs behind a `&mut`, exactly as the
//!    C casts them.** `huf_decompress.c:376` and `:1176` do
//!    `(HUF_ReadDTableX1_Workspace*)workSpace` after a `sizeof(*wksp) >
//!    wkspSize` check; so does this. That makes every access to them ordinary
//!    safe Rust indexing, which is bounds-checked for free. The 4-byte
//!    alignment the cast requires is a **precondition on the caller**, stated
//!    in each function's `# Safety` block, exactly as it is in the C.
//!
//! 3. **Every shift and sum whose operands the C does not bound uses
//!    `wrapping_*`.** These are C unsigned types; wraparound is *defined* in C
//!    and a plain `+`/`<<` under `CONFIG_RUST_OVERFLOW_CHECKS=y` (which is
//!    `default y`) would be a panic where the C keeps going. The ones that
//!    matter are called out at their sites.
//!
//! 4. **`BIT_DStream_t` gains a `src_size` field**, copied from
//!    `entropy_common_rs.rs` divergence 4, so [`BitDStream::read_st`] can check
//!    that the whole machine word it reads is inside the caller's buffer.
//!    [`HUF_initRemainingDStream`] builds a `BIT_DStream_t` *by hand* rather
//!    than through `BIT_initDStream` (`huf_decompress.c:278-299`), so it fills
//!    `src_size` by hand too — which is why
//!    [`HUF_DecompressFastArgs`] also gains a `src_end`.
//!
//! 5. **`loopFn` is gone.** See the asm section above.
//!
//! 6. **`HUF_selectDecoder`'s timing arithmetic uses `wrapping_*`.** The C
//!    computes `cSrcSize * 16 / dstSize` in `size_t` and
//!    `tableTime + decode256Time * D256` in `U32`; the second overflows for
//!    `dstSize` above roughly 4.74 GiB (dstSize >= 5,090,331,648; the "2 MB" this comment first claimed was wrong by ~2500x -- max decode256Time is 216 and D256 = dstSize>>8, so overflow needs D256 >= 19,884,108). The C's own `assert(dstSize <= 128*1024)` is
//!    compiled out (`DEBUGLEVEL` 0), and the function is a *heuristic* whose
//!    result is only ever used as a boolean, so an overflow there picks a
//!    different-but-valid decoder rather than being wrong. A plain `*` would
//!    panic. See uncertainty item 12.
//!
//! # What is NOT changed
//!
//! The decode loops are transcribed statement for statement, including the
//! things that look wrong and are not: the non-short-circuit `&` in
//! `(BIT_reloadDStream(p) == unfinished) & (p < pEnd-3)` (the reload is the
//! *left* operand and is called either way, so `&&` is the same program); the
//! `MEM_64bits()`/`MEM_32bits()`-keyed branches that are dead on 64-bit and
//! live on 32-bit, kept as `const` conditions so both arms type-check on every
//! target; the redundant `op1 > opStart2` corruption checks the C keeps because
//! "binary generated by gcc 7.2 & 7.3 with -mbmi2 runs faster when >=1 test is
//! present"; and the `#if defined(__clang__) && x86` variant ordering in
//! `HUF_decompress4X2_usingDTable_internal_body`, of which the **non-clang**
//! arm is taken (the kernel builds this with GCC; see uncertainty item 11).
//!
//! Replaces: lib/zstd/decompress/huf_decompress.c

// The C symbol names are the ABI and are reproduced verbatim; so are the
// header type names (`HUF_DEltX1`, `BIT_DStream_status`) that they appear in,
// so that a reader can grep the C and this file for the same string.
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

use core::ffi::{c_int, c_uint, c_void};

// ---------------------------------------------------------------------------
// include/linux/zstd_errors.h and lib/zstd/common/error_private.h
//
// Copied from common/entropy_common_rs.rs; see the module docs.
// ---------------------------------------------------------------------------

const ZSTD_error_GENERIC: usize = 1;
const ZSTD_error_corruption_detected: usize = 20;
const ZSTD_error_tableLog_tooLarge: usize = 44;
const ZSTD_error_dstSize_tooSmall: usize = 70;
const ZSTD_error_srcSize_wrong: usize = 72;
const ZSTD_error_maxCode: usize = 120;

/// `error_private.h:42` — `#define ZSTD_ERROR(name) ((size_t)-PREFIX(name))`.
#[inline(always)]
const fn ERROR(code: usize) -> usize {
    0usize.wrapping_sub(code)
}

/// `error_private.h:44` — `return (code > ERROR(maxCode));`
///
/// `huf_decompress.c:75` is `#define HUF_isError ERR_isError`, so every
/// `HUF_isError()` in the C reaches this.
#[inline(always)]
fn ERR_isError(code: usize) -> bool {
    code > ERROR(ZSTD_error_maxCode)
}

// ---------------------------------------------------------------------------
// lib/zstd/common/mem.h — unaligned access
//
// `MEM_read*`/`MEM_write*` are `get_unaligned`/`put_unaligned` in the kernel
// port, i.e. NATIVE endianness; only the `MEM_*LE*` family byteswaps. The
// kernel builds zstd for big-endian targets (s390, some powerpc/mips), so the
// distinction is load-bearing and `from_le`/`to_le` are used rather than being
// assumed away.
// ---------------------------------------------------------------------------

const SIZE_BYTES: usize = core::mem::size_of::<usize>();
const SIZE_BITS: u32 = (SIZE_BYTES * 8) as u32;

/// `mem.h:91` — `MEM_32bits()`.
const MEM_32BITS: bool = SIZE_BYTES == 4;
/// `mem.h:96` — `MEM_64bits()`.
const MEM_64BITS: bool = SIZE_BYTES == 8;
/// `mem.h:107` — `MEM_isLittleEndian()`, which is `#if defined(__LITTLE_ENDIAN)`.
const MEM_LITTLE_ENDIAN: bool = cfg!(target_endian = "little");

/// `mem.h:149` — `get_unaligned_le16()`.
///
/// # Safety
///
/// `p .. p + 2` must be readable.
#[inline(always)]
unsafe fn MEM_readLE16(p: *const u8) -> u16 {
    // SAFETY: class C (construction). The caller guarantees 2 readable bytes.
    // `read_unaligned` places no alignment requirement, which is what
    // `get_unaligned_le16()` provides; `from_le` is the byteswap on a
    // big-endian target and a no-op on a little-endian one.
    u16::from_le(unsafe { core::ptr::read_unaligned(p as *const u16) })
}

/// `mem.h:182` — `MEM_readLEST()`, which is `get_unaligned_le64()` on 64-bit
/// and `get_unaligned_le32()` on 32-bit.
///
/// # Safety
///
/// `p .. p + SIZE_BYTES` must be readable.
#[inline(always)]
unsafe fn MEM_readLEST(p: *const u8) -> usize {
    // SAFETY: class C (construction). As `MEM_readLE16`, at machine-word
    // width. The caller guarantees `SIZE_BYTES` readable bytes; nearly every
    // call site reaches this through `BitDStream::read_st`, which asserts it.
    usize::from_le(unsafe { core::ptr::read_unaligned(p as *const usize) })
}

/// `mem.h:122` — `get_unaligned()`, **native** endianness, not LE.
///
/// # Safety
///
/// `p .. p + 8` must be readable.
#[inline(always)]
unsafe fn MEM_read64(p: *const u8) -> u64 {
    // SAFETY: class C (construction). The caller guarantees 8 readable bytes.
    // No byteswap: `MEM_read64()` is `get_unaligned()`, not
    // `get_unaligned_le64()`. Its only call sites are the two fast decode
    // loops, which run on little-endian 64-bit only
    // (`HUF_DecompressFastArgs_init` returns 0 otherwise), so native and LE
    // coincide there — but the C is native and so is this.
    unsafe { core::ptr::read_unaligned(p as *const u64) }
}

/// `mem.h:132` — `put_unaligned()`, **native** endianness, not LE.
///
/// # Safety
///
/// `p .. p + 2` must be writable.
#[inline(always)]
unsafe fn MEM_write16(p: *mut u8, value: u16) {
    // SAFETY: class C (construction). The caller guarantees 2 writable bytes.
    unsafe { core::ptr::write_unaligned(p as *mut u16, value) }
}

/// `mem.h:142` — `put_unaligned()`, **native** endianness, not LE.
///
/// # Safety
///
/// `p .. p + 8` must be writable.
#[inline(always)]
unsafe fn MEM_write64(p: *mut u8, value: u64) {
    // SAFETY: class C (construction). The caller guarantees 8 writable bytes.
    unsafe { core::ptr::write_unaligned(p as *mut u64, value) }
}

// ---------------------------------------------------------------------------
// lib/zstd/common/bits.h
// ---------------------------------------------------------------------------

/// `bits.h:119` — `31 - ZSTD_countLeadingZeros32(val)`.
///
/// `assert(val != 0)` in the C, and `assert()` is compiled out
/// (`debug.h`, `DEBUGLEVEL` 0), so `val == 0` is UB there. Here it yields
/// `0xFFFFFFFF` — the answer `31 - lzcnt(0)` gives — rather than panicking.
///
/// Inside a `#[target_feature(enable = "lzcnt,...")]` caller this is `lzcnt`;
/// otherwise `bsr`.
#[inline(always)]
fn ZSTD_highbit32(val: u32) -> u32 {
    31u32.wrapping_sub(val.leading_zeros())
}

/// `bits.h:66` — `__builtin_ctzll(val)`.
///
/// `val == 0` is UB in the C; `trailing_zeros()` returns 64, which is what
/// `tzcnt` returns. Both call sites OR in a 1 bit before shifting left by at
/// most 8 ([`HUF_initFastDStream`] and the two `RELOAD_STREAM` macros), so the
/// argument is never zero.
#[inline(always)]
fn ZSTD_countTrailingZeros64(val: u64) -> u32 {
    val.trailing_zeros()
}

// ---------------------------------------------------------------------------
// lib/zstd/common/compiler.h
// ---------------------------------------------------------------------------

/// `compiler.h:271` — `ZSTD_maybeNullPtrAdd()`: `ptr + add` except that
/// `NULL + 0 == NULL`.
///
/// `wrapping_add` rather than `add`: the whole point of the helper is that
/// `ptr` may be null, and `add > 0` does not by itself prove the result is in
/// the same allocation on the paths where `dstSize` is caller-supplied.
#[inline(always)]
fn ZSTD_maybeNullPtrAdd(ptr: *mut u8, add: isize) -> *mut u8 {
    if add > 0 {
        ptr.wrapping_offset(add)
    } else {
        ptr
    }
}

// ---------------------------------------------------------------------------
// lib/zstd/common/bitstream.h
//
// Copied from common/entropy_common_rs.rs; see the module docs. The four
// additions for this file are marked.
// ---------------------------------------------------------------------------

/// `bitstream.h:92`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
enum BIT_DStream_status {
    unfinished = 0,
    endOfBuffer = 1,
    completed = 2,
    overflow = 3,
}

/// `bitstream.h:400-405` — the zero word `BIT_reloadDStream()` parks `ptr` on
/// once the stream has overflowed. Never dereferenced afterwards.
static BIT_ZERO_FILLED: usize = 0;

/// `bitstream.h:84`, plus `src_size` (divergence 4).
struct BitDStream {
    bitContainer: usize,
    bitsConsumed: u32,
    ptr: *const u8,
    start: *const u8,
    limitPtr: *const u8,
    /// Not in the C. The length of the buffer `start` points at, so
    /// [`BitDStream::read_st`] can check a whole-word read.
    src_size: usize,
}

impl BitDStream {
    /// `MEM_readLEST(bitD->ptr)`, bounds-checked.
    #[inline(always)]
    fn read_st(&self) -> usize {
        let off = (self.ptr as usize).wrapping_sub(self.start as usize);
        assert!(SIZE_BYTES <= self.src_size && off <= self.src_size - SIZE_BYTES);
        // SAFETY: class C (construction). `off + SIZE_BYTES <= src_size` was
        // just checked, and `start .. start + src_size` is the caller's
        // buffer, so the machine word is inside it. The C's own invariant is
        // that `ptr` starts at `start + srcSize - sizeof(bitContainer)` and
        // only ever decreases, never below `start` -- `bitstream.h:373` and
        // `:420-421` assert both halves. Divergence 4 is what lets that be
        // checked rather than assumed.
        unsafe { MEM_readLEST(self.ptr) }
    }
}

/// `bitstream.h:239` — `BIT_initDStream()`.
///
/// # Safety
///
/// `srcBuffer` must point at `srcSize` readable bytes.
#[inline(always)]
unsafe fn BIT_initDStream(bitD: &mut BitDStream, srcBuffer: *const u8, srcSize: usize) -> usize {
    if srcSize < 1 {
        // ZSTD_memset(bitD, 0, sizeof(*bitD))
        bitD.bitContainer = 0;
        bitD.bitsConsumed = 0;
        bitD.ptr = core::ptr::null();
        bitD.start = core::ptr::null();
        bitD.limitPtr = core::ptr::null();
        bitD.src_size = 0;
        return ERROR(ZSTD_error_srcSize_wrong);
    }

    bitD.start = srcBuffer;
    bitD.src_size = srcSize;
    bitD.limitPtr = bitD.start.wrapping_add(SIZE_BYTES);

    if srcSize >= SIZE_BYTES {
        // normal case
        bitD.ptr = srcBuffer.wrapping_add(srcSize - SIZE_BYTES);
        bitD.bitContainer = bitD.read_st();
        {
            // SAFETY: class C (construction). `srcSize >= 1`, so
            // `srcBuffer[srcSize - 1]` is the caller's last byte.
            let lastByte = unsafe { *srcBuffer.add(srcSize - 1) };
            // ensures bitsConsumed is always set
            bitD.bitsConsumed = if lastByte != 0 {
                8 - ZSTD_highbit32(lastByte as u32)
            } else {
                0
            };
            if lastByte == 0 {
                return ERROR(ZSTD_error_GENERIC); // endMark not present
            }
        }
    } else {
        bitD.ptr = bitD.start;
        // SAFETY: class C (construction). `srcSize >= 1`, so `start[0]` and
        // `start[srcSize - 1]` are inside the caller's buffer, and every
        // `case` below is guarded by `srcSize` being at least that large --
        // the C's fallthrough chain reads index `k - 1` in `case k`.
        unsafe {
            bitD.bitContainer = *bitD.start as usize;
            if srcSize >= 7 {
                bitD.bitContainer = bitD
                    .bitContainer
                    .wrapping_add((*srcBuffer.add(6) as usize).wrapping_shl(SIZE_BITS - 16));
            }
            if srcSize >= 6 {
                bitD.bitContainer = bitD
                    .bitContainer
                    .wrapping_add((*srcBuffer.add(5) as usize).wrapping_shl(SIZE_BITS - 24));
            }
            if srcSize >= 5 {
                bitD.bitContainer = bitD
                    .bitContainer
                    .wrapping_add((*srcBuffer.add(4) as usize).wrapping_shl(SIZE_BITS - 32));
            }
            if srcSize >= 4 {
                bitD.bitContainer = bitD
                    .bitContainer
                    .wrapping_add((*srcBuffer.add(3) as usize) << 24);
            }
            if srcSize >= 3 {
                bitD.bitContainer = bitD
                    .bitContainer
                    .wrapping_add((*srcBuffer.add(2) as usize) << 16);
            }
            if srcSize >= 2 {
                bitD.bitContainer = bitD
                    .bitContainer
                    .wrapping_add((*srcBuffer.add(1) as usize) << 8);
            }
            {
                let lastByte = *srcBuffer.add(srcSize - 1);
                bitD.bitsConsumed = if lastByte != 0 {
                    8 - ZSTD_highbit32(lastByte as u32)
                } else {
                    0
                };
                if lastByte == 0 {
                    // NOTE: a DIFFERENT error code from the branch above.
                    // `bitstream.h:279` says corruption_detected, `:251` says
                    // GENERIC, for the identical condition. Transcribed, not
                    // fixed.
                    return ERROR(ZSTD_error_corruption_detected);
                }
            }
        }
        bitD.bitsConsumed += ((SIZE_BYTES - srcSize) * 8) as u32;
    }

    srcSize
}

/// `bitstream.h:292` — `BIT_getMiddleBits()`.
#[inline(always)]
fn BIT_getMiddleBits(bitContainer: usize, start: u32, nbBits: u32) -> usize {
    let regMask: u32 = SIZE_BITS - 1;
    // The C has an `#if defined(__x86_64__)` arm using
    // `((U64)1 << nbBits) - 1` (so that x86 folds it to `bzhi`) and a
    // `BIT_mask[nbBits]` arm otherwise. For `nbBits < 32`, which
    // `assert(nbBits < BIT_MASK_SIZE)` and every call site guarantee, the two
    // are the same number, so one expression covers both.
    //
    // `wrapping_shl` rather than `<<`: `nbBits` is `HUF_DEltX1::nbBits` or
    // `HUF_DEltX2::nbBits`, which are `u8`s read out of a caller-supplied
    // decode table.
    (bitContainer.wrapping_shr(start & regMask))
        & (1u64.wrapping_shl(nbBits).wrapping_sub(1)) as usize
}

/// `bitstream.h:315` — `BIT_lookBits()`.
#[inline(always)]
fn BIT_lookBits(bitD: &BitDStream, nbBits: u32) -> usize {
    // if bitsConsumed + nbBits > SIZE_BITS the bitstream is likely corrupted
    // and the result is undefined -- the C says so and computes the start
    // offset in `U32`, where it wraps. `wrapping_sub` keeps that.
    BIT_getMiddleBits(
        bitD.bitContainer,
        SIZE_BITS.wrapping_sub(bitD.bitsConsumed).wrapping_sub(nbBits),
        nbBits,
    )
}

/// `bitstream.h:331` — `BIT_lookBitsFast()`, unsafe version; only works if
/// `nbBits >= 1`.
#[inline(always)]
fn BIT_lookBitsFast(bitD: &BitDStream, nbBits: u32) -> usize {
    let regMask: u32 = SIZE_BITS - 1;
    bitD.bitContainer
        .wrapping_shl(bitD.bitsConsumed & regMask)
        .wrapping_shr(((regMask + 1) - nbBits) & regMask)
}

/// `bitstream.h:338` — `BIT_skipBits()`.
#[inline(always)]
fn BIT_skipBits(bitD: &mut BitDStream, nbBits: u32) {
    bitD.bitsConsumed = bitD.bitsConsumed.wrapping_add(nbBits);
}

/// `bitstream.h:347` — `BIT_readBits()`.
/// `#[allow(dead_code)]` because `huf_decompress.c` uses only
/// `BIT_lookBitsFast()`. In the C this is a `static inline` in a header that
/// this translation unit does not call either, and GCC emits nothing for it;
/// keeping it here is what makes the bitstream block an identical copy of
/// `entropy_common_rs.rs`'s. It is also why no `bzhi` appears in this object:
/// [`BIT_getMiddleBits`], the only place the `(1 << nbBits) - 1` mask is
/// built, is reachable only from here.
#[inline(always)]
#[allow(dead_code)]
fn BIT_readBits(bitD: &mut BitDStream, nbBits: u32) -> usize {
    let value = BIT_lookBits(bitD, nbBits);
    BIT_skipBits(bitD, nbBits);
    value
}

/// `bitstream.h:356` — `BIT_readBitsFast()`; only works if `nbBits >= 1`.
/// `#[allow(dead_code)]`; see [`BIT_readBits`].
#[inline(always)]
#[allow(dead_code)]
fn BIT_readBitsFast(bitD: &mut BitDStream, nbBits: u32) -> usize {
    let value = BIT_lookBitsFast(bitD, nbBits);
    BIT_skipBits(bitD, nbBits);
    value
}

/// `bitstream.h:369` — `BIT_reloadDStream_internal()`.
#[inline(always)]
fn BIT_reloadDStream_internal(bitD: &mut BitDStream) -> BIT_DStream_status {
    // assert(bitsConsumed <= SIZE_BITS); assert(ptr >= start)
    bitD.ptr = bitD.ptr.wrapping_sub((bitD.bitsConsumed >> 3) as usize);
    bitD.bitsConsumed &= 7;
    bitD.bitContainer = bitD.read_st();
    BIT_DStream_status::unfinished
}

/// `bitstream.h:385` — `BIT_reloadDStreamFast()`. **Not in
/// `entropy_common_rs.rs`**; added here because the two 4-stream decode loops
/// use it.
#[inline(always)]
fn BIT_reloadDStreamFast(bitD: &mut BitDStream) -> BIT_DStream_status {
    if bitD.ptr < bitD.limitPtr {
        return BIT_DStream_status::overflow;
    }
    BIT_reloadDStream_internal(bitD)
}

/// `bitstream.h:397` — `BIT_reloadDStream()`.
#[inline(always)]
fn BIT_reloadDStream(bitD: &mut BitDStream) -> BIT_DStream_status {
    // note : once in overflow mode, a bitstream remains in this mode until
    // it's reset
    if bitD.bitsConsumed > SIZE_BITS {
        // aliasing is allowed for char
        bitD.ptr = &BIT_ZERO_FILLED as *const usize as *const u8;
        // overflow detected, erroneous scenario or end of stream: no update
        return BIT_DStream_status::overflow;
    }

    // assert(ptr >= start)

    if bitD.ptr >= bitD.limitPtr {
        return BIT_reloadDStream_internal(bitD);
    }
    if bitD.ptr == bitD.start {
        // reached end of bitStream => no update
        if bitD.bitsConsumed < SIZE_BITS {
            return BIT_DStream_status::endOfBuffer;
        }
        return BIT_DStream_status::completed;
    }
    // start < ptr < limitPtr => cautious update
    {
        let mut nbBytes: u32 = bitD.bitsConsumed >> 3;
        let mut result = BIT_DStream_status::unfinished;
        if bitD.ptr.wrapping_sub(nbBytes as usize) < bitD.start {
            // ptr > start
            nbBytes = (bitD.ptr as usize - bitD.start as usize) as u32;
            result = BIT_DStream_status::endOfBuffer;
        }
        bitD.ptr = bitD.ptr.wrapping_sub(nbBytes as usize);
        bitD.bitsConsumed -= nbBytes * 8;
        // reminder : srcSize > sizeof(bitContainer), otherwise ptr == start
        bitD.bitContainer = bitD.read_st();
        result
    }
}

/// `bitstream.h:434` — `BIT_endOfDStream()`. **Not in
/// `entropy_common_rs.rs`**; added here.
///
/// Returns `c_uint` rather than `bool` because the C's four call sites `&` the
/// four results together before testing, and that is transcribed.
#[inline(always)]
fn BIT_endOfDStream(DStream: &BitDStream) -> c_uint {
    ((DStream.ptr == DStream.start) && (DStream.bitsConsumed == SIZE_BITS)) as c_uint
}

// ---------------------------------------------------------------------------
// lib/zstd/common/fse.h and lib/zstd/common/huf.h constants
// ---------------------------------------------------------------------------

/// `fse.h:596`.
const FSE_MAX_SYMBOL_VALUE: c_uint = 255;

/// `fse.h:242`.
#[inline(always)]
const fn FSE_DTABLE_SIZE_U32(maxTableLog: c_uint) -> usize {
    1 + (1usize.wrapping_shl(maxTableLog))
}

/// `fse.h:268` — `sizeof(short) * (maxSymbolValue + 1) + (1ULL << maxTableLog) + 8`.
#[inline(always)]
const fn FSE_BUILD_DTABLE_WKSP_SIZE(maxTableLog: c_uint, maxSymbolValue: c_uint) -> u64 {
    2u64.wrapping_mul(maxSymbolValue.wrapping_add(1) as u64)
        .wrapping_add(1u64.wrapping_shl(maxTableLog))
        .wrapping_add(8)
}

/// `fse.h:269`.
#[inline(always)]
const fn FSE_BUILD_DTABLE_WKSP_SIZE_U32(maxTableLog: c_uint, maxSymbolValue: c_uint) -> usize {
    ((FSE_BUILD_DTABLE_WKSP_SIZE(maxTableLog, maxSymbolValue) + 3) / 4) as usize
}

/// `fse.h:273`.
#[inline(always)]
const fn FSE_DECOMPRESS_WKSP_SIZE_U32(maxTableLog: c_uint, maxSymbolValue: c_uint) -> usize {
    FSE_DTABLE_SIZE_U32(maxTableLog)
        + 1
        + FSE_BUILD_DTABLE_WKSP_SIZE_U32(maxTableLog, maxSymbolValue)
        + (FSE_MAX_SYMBOL_VALUE as usize + 1) / 2
        + 1
}

/// `huf.h:38`.
const HUF_TABLELOG_MAX: usize = 12;
/// `huf.h:40`.
const HUF_SYMBOLVALUE_MAX: usize = 255;
/// `huf.h:42`.
const HUF_TABLELOG_ABSOLUTEMAX: usize = 12;
/// `huf.h:86` — `HUF_flags_bmi2 = (1 << 0)`.
///
/// Gated on the same architectures as its only uses, because `logs/floor.md`
/// RAISE 1: an item defined ungated whose only use is gated becomes
/// `never used`, and `CONFIG_WERROR=y` makes that a build failure.
// DYNAMIC_BMI2 is x86 AND NOT compile-time BMI2. The `not(target_feature)`
// half was missing until 2026-09-04 and adversarial review caught it: with
// CONFIG_X86_NATIVE_CPU=y the kernel passes -march=native / -Ctarget-cpu=native
// (arch/x86/Makefile:169-171), which defines __BMI2__ and sets
// target_feature="bmi2" -- so the C's DYNAMIC_BMI2 goes 0 while this cfg stayed
// "1". That is not cosmetic: ZSTD_DCtx_get_bmi2() then returns 0 for every
// literals block, the C falls through to its always-try-_fast path, and this
// code returned _default instead. Observable in the return value on malformed
// input. See portability_macros.h:61-71.
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "bmi2")))]
const HUF_flags_bmi2: c_int = 1;
/// `huf.h:111` — `HUF_flags_disableFast = (1 << 5)`.
///
/// `HUF_flags_disableAsm` (`huf.h:105-106`) is deliberately NOT defined: its only
/// uses were inside `#if ZSTD_ENABLE_ASM_X86_64_BMI2` blocks, which are dead.
const HUF_flags_disableFast: c_int = 1 << 5;
/// `huf.h:182` — `FSE_DECOMPRESS_WKSP_SIZE_U32(6, HUF_TABLELOG_MAX - 1)`,
/// which works out to 219 words / 876 bytes.
const HUF_READ_STATS_WORKSPACE_SIZE_U32: usize =
    FSE_DECOMPRESS_WKSP_SIZE_U32(6, HUF_TABLELOG_MAX as c_uint - 1);
/// `huf.h:236` — `((2 << 10) + (1 << 9))`.
const HUF_DECOMPRESS_WORKSPACE_SIZE: usize = (2 << 10) + (1 << 9);

/// `huf_decompress.c:31`.
const HUF_DECODER_FAST_TABLELOG: u32 = 11;

/// `huf_decompress.c:37-41` — `HUF_DISABLE_FAST_DECODE` is never defined.
const HUF_ENABLE_FAST_DECODE: bool = true;

extern "C" {
    /// `lib/zstd/common/entropy_common.c:328` — the `EXPORT_SYMBOL_GPL`'d entry
    /// thunk whose body is `rust_HUF_readStats_wksp` in
    /// `common/entropy_common_rs.rs`. Called through the C symbol on purpose;
    /// see the module docs.
    fn HUF_readStats_wksp(
        huffWeight: *mut u8,
        hwSize: usize,
        rankStats: *mut u32,
        nbSymbolsPtr: *mut u32,
        tableLogPtr: *mut u32,
        src: *const c_void,
        srcSize: usize,
        workSpace: *mut c_void,
        wkspSize: usize,
        flags: c_int,
    ) -> usize;
}

// ---------------------------------------------------------------------------
// Bounds-checked primitives (divergence 1)
//
// The C does none of these checks. Each helper carries the invariant that
// makes the check redundant; the check exists so that a violated invariant is
// a loud panic rather than a silent out-of-bounds access.
// ---------------------------------------------------------------------------

/// `*p = b`, checked against the end of the output buffer.
///
/// # Safety
///
/// `p` and `oend` must be derived from the same output allocation.
#[inline(always)]
unsafe fn out_write1(p: *mut u8, oend: *const u8, b: u8) {
    assert!((p as *const u8) < oend);
    // SAFETY: class C (construction). `p < oend` was just checked and `oend`
    // is one past the caller's output buffer.
    unsafe { p.write(b) }
}

/// `MEM_write16(p, v)`, checked against the end of the output buffer.
///
/// # Safety
///
/// `p` and `oend` must be derived from the same output allocation.
#[inline(always)]
unsafe fn out_write2(p: *mut u8, oend: *const u8, v: u16) {
    // `p < oend` first, so that `oend - p` below is a real positive
    // difference and cannot be a wrapped huge value.
    assert!((p as *const u8) < oend && (oend as usize) - (p as usize) >= 2);
    // SAFETY: class C (construction). `p + 2 <= oend` was just checked.
    unsafe { MEM_write16(p, v) }
}

/// `MEM_read64(p)` / `MEM_readLEST(p)`, checked against both ends of the
/// input buffer.
///
/// # Safety
///
/// `p`, `ilow` and `iend` must be derived from the same input allocation.
#[inline(always)]
unsafe fn in_read64(p: *const u8, ilow: *const u8, iend: *const u8) -> u64 {
    // Expressed as offsets from `ilow`, like `BitDStream::read_st`, so that
    // a `p` below `ilow` or an `iend` less than 8 bytes above it fails the
    // check instead of wrapping past it.
    let off = (p as usize).wrapping_sub(ilow as usize);
    let len = (iend as usize).wrapping_sub(ilow as usize);
    assert!(len >= 8 && off <= len - 8);
    // SAFETY: class C (construction). `ilow <= p` and `p + 8 <= iend` were
    // just checked, and `ilow .. iend` is the caller's input buffer.
    unsafe { MEM_read64(p) }
}

// ---------------------------------------------------------------------------
// huf_decompress.c:133 — generic DTableDesc
// ---------------------------------------------------------------------------

/// `huf_decompress.c:138` — `{ BYTE maxTableLog; BYTE tableType; BYTE tableLog;
/// BYTE reserved; }`.
#[derive(Clone, Copy)]
struct DTableDesc {
    maxTableLog: u8,
    tableType: u8,
    tableLog: u8,
    reserved: u8,
}

// DEBUG_STATIC_ASSERT(sizeof(DTableDesc) == sizeof(HUF_DTable))
const _: () = assert!(core::mem::size_of::<DTableDesc>() == core::mem::size_of::<u32>());

/// `huf_decompress.c:140-144` — `ZSTD_memcpy(&dtd, table, sizeof(dtd))`.
///
/// The C copies the first four **bytes** of the table's first `U32`. That is
/// exactly `u32::to_ne_bytes()`, so this is byte-identical on both
/// endiannesses; a `from_le`/`to_le` here would be a bug.
///
/// # Safety
///
/// `table` must point at one readable, 4-byte-aligned `U32`.
#[inline(always)]
unsafe fn HUF_getDTableDesc(table: *const u32) -> DTableDesc {
    // SAFETY: class B (boundary). `HUF_DTable` is `U32` (`huf.h:65`), so the
    // caller's table is 4-byte aligned by construction and word 0 is its
    // header. The read is aligned, exactly as the C's `ZSTD_memcpy` from an
    // `HUF_DTable*`.
    let b = unsafe { core::ptr::read(table) }.to_ne_bytes();
    DTableDesc {
        maxTableLog: b[0],
        tableType: b[1],
        tableLog: b[2],
        reserved: b[3],
    }
}

/// `ZSTD_memcpy(DTable, &dtd, sizeof(dtd))` — the inverse of
/// [`HUF_getDTableDesc`], used at `huf_decompress.c:411` and `:1251`.
///
/// # Safety
///
/// `table` must point at one writable, 4-byte-aligned `U32`.
#[inline(always)]
unsafe fn HUF_setDTableDesc(table: *mut u32, dtd: DTableDesc) {
    // SAFETY: class B (boundary). As `HUF_getDTableDesc`.
    unsafe {
        core::ptr::write(
            table,
            u32::from_ne_bytes([dtd.maxTableLog, dtd.tableType, dtd.tableLog, dtd.reserved]),
        )
    }
}

/// `huf_decompress.c:147` — `HUF_initFastDStream()`.
///
/// `static` in the C, `#[inline(always)]` here so that the `lzcnt` inside
/// [`ZSTD_highbit32`] is selected by the feature set of whichever wrapper the
/// call ends up inside — which is what GCC does with a small `static` too.
///
/// # Safety
///
/// `ip .. ip + 8` must be readable.
#[inline(always)]
unsafe fn HUF_initFastDStream(ip: *const u8) -> usize {
    // SAFETY: class C (construction). The caller guarantees 8 readable bytes.
    // Every call site is `HUF_DecompressFastArgs_init`, which has just proved
    // `ilowest <= ip[i]` and `ip[i] + 8 <= ilowest + srcSize` for all four
    // streams -- see the SAFETY comment there.
    let lastByte = unsafe { *ip.add(7) };
    let bitsConsumed: usize = if lastByte != 0 {
        (8 - ZSTD_highbit32(lastByte as u32)) as usize
    } else {
        0
    };
    // SAFETY: class C (construction). As above.
    let value = unsafe { MEM_readLEST(ip) } | 1;
    // assert(bitsConsumed <= 8); assert(sizeof(size_t) == 8)
    // `wrapping_shl` for the same reason every other shift here is: the C's
    // `<<` is on a `size_t` and the count is derived from stream data.
    value.wrapping_shl(bitsConsumed as u32)
}

// ---------------------------------------------------------------------------
// huf_decompress.c:157-179 — the fast decoding loop's argument block
// ---------------------------------------------------------------------------

/// `huf_decompress.c:170-178` — `HUF_DecompressFastArgs`, plus `src_end`.
///
/// No `#[repr(C)]`: in the C this struct exists to be passed to the
/// hand-written assembly loops, which are compiled out here
/// (`ZSTD_ENABLE_ASM_X86_64_BMI2` is 0), so it never crosses a language
/// boundary and GOALS.md §5's layout rule does not reach it.
///
/// `src_end` is not in the C (divergence 4). The C reasons about the input's
/// upper bound implicitly; this field lets [`in_read64`] and
/// [`BitDStream::read_st`] check it.
struct HUF_DecompressFastArgs {
    ip: [*const u8; 4],
    op: [*mut u8; 4],
    bits: [u64; 4],
    dt: *const c_void,
    ilowest: *const u8,
    oend: *mut u8,
    iend: [*const u8; 4],
    /// Not in the C: `ilowest + srcSize`.
    src_end: *const u8,
}

/// `huf_decompress.c:188` — `HUF_DecompressFastArgs_init()`.
///
/// Returns 1 on success, 0 if the fallback implementation should be used, or
/// an error code on failure.
///
/// # Safety
///
/// `dst` must point at `dstSize` writable bytes, `src` at `srcSize` readable
/// bytes, and `DTable` at a readable 4-byte-aligned `HUF_DTable` array whose
/// header word is initialised.
#[inline(always)]
unsafe fn HUF_DecompressFastArgs_init(
    args: &mut HUF_DecompressFastArgs,
    dst: *mut c_void,
    dstSize: usize,
    src: *const c_void,
    srcSize: usize,
    DTable: *const u32,
) -> usize {
    // SAFETY: class C (construction). One word past the table header, which
    // the caller's `HUF_DTABLE_SIZE()` allocation covers. No dereference here.
    let dt = unsafe { DTable.add(1) } as *const c_void;
    // SAFETY: class B (boundary). Word 0 of the caller's table.
    let dtLog = unsafe { HUF_getDTableDesc(DTable) }.tableLog as u32;

    let istart = src as *const u8;

    let oend = ZSTD_maybeNullPtrAdd(dst as *mut u8, dstSize as isize);

    // The fast decoding loop assumes 64-bit little-endian.
    // This condition is false on x32.
    if !MEM_LITTLE_ENDIAN || MEM_32BITS {
        return 0;
    }

    // Avoid nullptr addition
    if dstSize == 0 {
        return 0;
    }
    // assert(dst != NULL)

    // strict minimum : jump table + 1 byte per stream
    if srcSize < 10 {
        return ERROR(ZSTD_error_corruption_detected);
    }

    // Must have at least 8 bytes per stream because we don't handle
    // initializing smaller bit containers. If table log is not correct at this
    // point, fallback to the old decoder. On small inputs we don't have enough
    // data to trigger the fast loop, so use the old decoder.
    if dtLog != HUF_DECODER_FAST_TABLELOG {
        return 0;
    }

    // Read the jump table.
    {
        // SAFETY: class C (construction). `srcSize >= 10` was just checked, so
        // bytes 0..6 of the caller's buffer are readable.
        let length1 = unsafe { MEM_readLE16(istart) } as usize;
        let length2 = unsafe { MEM_readLE16(istart.add(2)) } as usize;
        let length3 = unsafe { MEM_readLE16(istart.add(4)) } as usize;
        // `wrapping_sub`: the C computes this in `size_t` and relies on the
        // `length4 > srcSize` test below to catch the underflow.
        let length4 = srcSize.wrapping_sub(length1 + length2 + length3 + 6);
        args.iend[0] = istart.wrapping_add(6); // jumpTable
        args.iend[1] = args.iend[0].wrapping_add(length1);
        args.iend[2] = args.iend[1].wrapping_add(length2);
        args.iend[3] = args.iend[2].wrapping_add(length3);

        // HUF_initFastDStream() requires this, and this small of an input
        // won't benefit from the ASM loop anyways.
        if length1 < 8 || length2 < 8 || length3 < 8 || length4 < 8 {
            return 0;
        }
        if length4 > srcSize {
            return ERROR(ZSTD_error_corruption_detected); // overflow
        }
    }
    // ip[] contains the position that is currently loaded into bits[].
    args.ip[0] = args.iend[1].wrapping_sub(8);
    args.ip[1] = args.iend[2].wrapping_sub(8);
    args.ip[2] = args.iend[3].wrapping_sub(8);
    args.ip[3] = istart.wrapping_add(srcSize).wrapping_sub(8);

    // op[] contains the output pointers.
    args.op[0] = dst as *mut u8;
    args.op[1] = args.op[0].wrapping_add((dstSize + 3) / 4);
    args.op[2] = args.op[1].wrapping_add((dstSize + 3) / 4);
    args.op[3] = args.op[2].wrapping_add((dstSize + 3) / 4);

    // No point to call the ASM loop for tiny outputs.
    if (args.op[3] as *const u8) >= (oend as *const u8) {
        return 0;
    }

    args.src_end = istart.wrapping_add(srcSize);

    // bits[] is the bit container. It is read from the MSB down to the LSB.
    // It is shifted left as it is read, and zeros are shifted in. After the
    // lowest valid bit a 1 is set, so that CountTrailingZeros(bits[]) can be
    // used to count how many bits we've consumed.
    //
    // SAFETY: class C (construction). Each `ip[i] + 8` is inside the caller's
    // buffer. For i in 0..3, `ip[i] + 8 == iend[i + 1]` and
    // `iend[3] == istart + 6 + length1 + length2 + length3 <= istart + srcSize`
    // because `length4 <= srcSize` was just checked and
    // `6 + length1 + length2 + length3 + length4 == srcSize`; for i == 3,
    // `ip[3] + 8 == istart + srcSize` and `srcSize >= 10`. The lower bound is
    // `ip[i] >= iend[i] >= istart` because every `length` is at least 8.
    args.bits[0] = unsafe { HUF_initFastDStream(args.ip[0]) } as u64;
    args.bits[1] = unsafe { HUF_initFastDStream(args.ip[1]) } as u64;
    args.bits[2] = unsafe { HUF_initFastDStream(args.ip[2]) } as u64;
    args.bits[3] = unsafe { HUF_initFastDStream(args.ip[3]) } as u64;

    // The decoders must be sure to never read beyond ilowest. This is lower
    // than iend[0], but allowing decoders to read down to ilowest can allow an
    // extra iteration or two in the fast loop.
    args.ilowest = istart;

    args.oend = oend;
    args.dt = dt;

    1
}

/// `huf_decompress.c:278` — `HUF_initRemainingDStream()`.
///
/// Builds a `BIT_DStream_t` by hand rather than through
/// [`BIT_initDStream`], so `src_size` (divergence 4) is filled in by hand too:
/// `start` is `ilowest`, so the readable length is `src_end - ilowest`.
#[inline(always)]
fn HUF_initRemainingDStream(
    bit: &mut BitDStream,
    args: &HUF_DecompressFastArgs,
    stream: usize,
    segmentEnd: *mut u8,
) -> usize {
    // Validate that we haven't overwritten.
    if args.op[stream] > segmentEnd {
        return ERROR(ZSTD_error_corruption_detected);
    }
    // Validate that we haven't read beyond iend[]. Note that ip[] may be
    // < iend[] because the MSB is the next bit to read, and we may have
    // consumed 100% of the stream, so down to iend[i] - 8 is valid.
    if args.ip[stream] < args.iend[stream].wrapping_sub(8) {
        return ERROR(ZSTD_error_corruption_detected);
    }

    // Construct the BIT_DStream_t.
    // assert(sizeof(size_t) == 8)
    bit.start = args.ilowest;
    bit.src_size = (args.src_end as usize).wrapping_sub(args.ilowest as usize);
    bit.limitPtr = bit.start.wrapping_add(SIZE_BYTES);
    bit.ptr = args.ip[stream];
    // `read_st()` rather than a bare `MEM_readLEST()`: the C's own bound here
    // is `ip[stream] >= iend[stream] - 8`, which for stream 0 permits
    // `ip[0] == ilowest - 2` and would read two bytes in front of the buffer.
    // The fast loops guarantee `ip[i] >= ilowest` (the C asserts it at
    // `huf_decompress.c:857-862`), and `read_st()` is what turns that assert
    // into a real check. See the report's OOB list, item 3.
    bit.bitContainer = bit.read_st();
    bit.bitsConsumed = ZSTD_countTrailingZeros64(args.bits[stream]);

    0
}

// ===========================================================================
// huf_decompress.c:318-940 — single-symbol decoding (X1)
//
// The whole block is inside `#ifndef HUF_FORCE_DECOMPRESS_X2`, which is never
// defined in the kernel.
// ===========================================================================

/// `huf_decompress.c:326` — `{ BYTE nbBits; BYTE byte; }`.
#[repr(C)]
#[derive(Clone, Copy)]
struct HUF_DEltX1 {
    nbBits: u8,
    byte: u8,
}

const _: () = assert!(core::mem::size_of::<HUF_DEltX1>() == 2);
const _: () = assert!(core::mem::offset_of!(HUF_DEltX1, nbBits) == 0);
const _: () = assert!(core::mem::offset_of!(HUF_DEltX1, byte) == 1);

/// `dt[idx] = d`, bounds-checked (divergence 1).
///
/// # Safety
///
/// `dt` must point at `cap` writable `HUF_DEltX1`s.
#[inline(always)]
unsafe fn dtx1_set(dt: *mut HUF_DEltX1, cap: usize, idx: usize, d: HUF_DEltX1) {
    assert!(idx < cap);
    // SAFETY: class C (construction). `idx < cap` was just checked.
    unsafe { dt.add(idx).write(d) }
}

/// `MEM_write64(dt + idx, d4)` — lays down **four** `HUF_DEltX1`s at once,
/// bounds-checked (divergence 1).
///
/// # Safety
///
/// `dt` must point at `cap` writable `HUF_DEltX1`s.
#[inline(always)]
unsafe fn dtx1_set4(dt: *mut HUF_DEltX1, cap: usize, idx: usize, d4: u64) {
    assert!(cap >= 4 && idx <= cap - 4);
    // SAFETY: class C (construction). `idx + 4 <= cap` was just checked, and
    // four `HUF_DEltX1` are exactly the 8 bytes `MEM_write64` writes. The
    // table is `HUF_DTable`-aligned (4) and `HUF_DEltX1` has alignment 1, so
    // `write_unaligned` is what `put_unaligned` provides.
    unsafe { MEM_write64(dt.add(idx) as *mut u8, d4) }
}

/// `dt[idx]`, bounds-checked (divergence 1).
///
/// # Safety
///
/// `dt` must point at `cap` readable `HUF_DEltX1`s.
#[inline(always)]
unsafe fn dtx1_get(dt: *const HUF_DEltX1, cap: usize, idx: usize) -> HUF_DEltX1 {
    assert!(idx < cap);
    // SAFETY: class C (construction). `idx < cap` was just checked.
    unsafe { dt.add(idx).read() }
}

/// `huf_decompress.c:332` — `HUF_DEltX1_set4()`. Packs 4 `HUF_DEltX1` structs
/// into a `U64` so four entries can be laid down at a time.
#[inline(always)]
fn HUF_DEltX1_set4(symbol: u8, nbBits: u8) -> u64 {
    // This is a *layout* decision, not a byte-order conversion: on a
    // little-endian target `nbBits` is the low byte of the pair because it is
    // at offset 0 of the struct. Transcribed as written.
    let mut D4: u64 = if MEM_LITTLE_ENDIAN {
        ((symbol as u64) << 8) + nbBits as u64
    } else {
        symbol as u64 + ((nbBits as u64) << 8)
    };
    // assert(D4 < (1U << 16))
    // `wrapping_mul`: `0xFFFF * 0x0001000100010001 == u64::MAX` exactly, so a
    // plain `*` cannot overflow -- but the C's `*` on a `U64` is defined to
    // wrap and this keeps that true if the invariant above is ever broken.
    D4 = D4.wrapping_mul(0x0001_0001_0001_0001);
    D4
}

/// `huf_decompress.c:349` — `HUF_rescaleStats()`.
///
/// Increases the tableLog to `targetTableLog` and rescales the stats. If
/// `tableLog > targetTableLog` this is a no-op. Returns the new tableLog.
#[inline(always)]
fn HUF_rescaleStats(
    huffWeight: &mut [u8],
    rankVal: &mut [u32],
    nbSymbols: u32,
    tableLog: u32,
    targetTableLog: u32,
) -> u32 {
    if tableLog > targetTableLog {
        return tableLog;
    }
    if tableLog < targetTableLog {
        let scale: u32 = targetTableLog - tableLog;
        // Increase the weight for all non-zero probability symbols by scale.
        for s in 0..nbSymbols as usize {
            // `wrapping_add`: the C's `+=` on a `BYTE` wraps by definition
            // (divergence 3). It cannot actually wrap here -- every weight is
            // <= HUF_TABLELOG_MAX (12) and `scale` <= 11.
            huffWeight[s] = huffWeight[s].wrapping_add(if huffWeight[s] == 0 { 0 } else { scale as u8 });
        }
        // Update rankVal to reflect the new weights. All weights except 0 get
        // moved to weight + scale. Weights [1, scale] are empty.
        let mut s = targetTableLog;
        while s > scale {
            rankVal[s as usize] = rankVal[(s - scale) as usize];
            s -= 1;
        }
        let mut s = scale;
        while s > 0 {
            rankVal[s as usize] = 0;
            s -= 1;
        }
    }
    targetTableLog
}

/// `huf_decompress.c:374-380` — `HUF_ReadDTableX1_Workspace`.
///
/// `#[repr(C)]` and field-for-field identical to the C, because the C casts a
/// caller-supplied `void*` straight to it and this does the same.
#[repr(C)]
struct HUF_ReadDTableX1_Workspace {
    rankVal: [u32; HUF_TABLELOG_ABSOLUTEMAX + 1],
    rankStart: [u32; HUF_TABLELOG_ABSOLUTEMAX + 1],
    statsWksp: [u32; HUF_READ_STATS_WORKSPACE_SIZE_U32],
    symbols: [u8; HUF_SYMBOLVALUE_MAX + 1],
    huffWeight: [u8; HUF_SYMBOLVALUE_MAX + 1],
}

// DEBUG_STATIC_ASSERT(HUF_DECOMPRESS_WORKSPACE_SIZE >= sizeof(*wksp))
const _: () = assert!(
    HUF_DECOMPRESS_WORKSPACE_SIZE >= core::mem::size_of::<HUF_ReadDTableX1_Workspace>()
);
// Not in the C: the exact size and alignment GCC gives the C struct, measured
// on x86-64 and pinned here so that a field reorder or a changed constant is a
// compile error rather than a silent layout difference from the workspace the
// caller sized. (offsets 0/52/104/980/1236, no padding anywhere.)
const _: () = assert!(core::mem::size_of::<HUF_ReadDTableX1_Workspace>() == 1492);
const _: () = assert!(core::mem::align_of::<HUF_ReadDTableX1_Workspace>() == 4);

/// `huf_decompress.c:382` — `HUF_readDTableX1_wksp()`.
///
/// Dead in-tree (`nm` finds no reference outside this file), kept because
/// `huf.h:272` still declares it.
///
/// # Safety
///
/// `DTable` must point at `HUF_DTABLE_SIZE(dtd.maxTableLog)` writable,
/// 4-byte-aligned `U32`s whose header word is initialised; `src` at `srcSize`
/// readable bytes; `workSpace` at `wkspSize` writable bytes **aligned to 4**
/// (the C's cast to `HUF_ReadDTableX1_Workspace*` requires the same).
#[no_mangle]
pub unsafe extern "C" fn HUF_readDTableX1_wksp(
    DTable: *mut u32,
    src: *const c_void,
    srcSize: usize,
    workSpace: *mut c_void,
    wkspSize: usize,
    flags: c_int,
) -> usize {
    let mut tableLog: u32 = 0;
    let mut nbSymbols: u32 = 0;
    let iSize: usize;
    // SAFETY: class C (construction). One word past the table header, which
    // the caller's allocation covers. No dereference here.
    let dt = unsafe { DTable.add(1) } as *mut HUF_DEltX1;

    if core::mem::size_of::<HUF_ReadDTableX1_Workspace>() > wkspSize {
        return ERROR(ZSTD_error_tableLog_tooLarge);
    }
    // SAFETY: class B (boundary). The size check above is the C's own
    // `sizeof(*wksp) > wkspSize` test at `huf_decompress.c:390`; the 4-byte
    // alignment is this function's documented precondition, identical to the
    // one the C's cast imposes. Every in-tree caller routes the workspace
    // through `ZSTD_customMalloc`/`ZSTD_cwksp`, which are word-aligned.
    let wksp = unsafe { &mut *(workSpace as *mut HUF_ReadDTableX1_Workspace) };

    // ZSTD_memset(huffWeight, 0, sizeof(huffWeight)) is not necessary, even
    // though some analyzer complain ...

    {
        let hw = wksp.huffWeight.as_mut_ptr();
        let rv = wksp.rankVal.as_mut_ptr();
        let sw = wksp.statsWksp.as_mut_ptr();
        let swSize = core::mem::size_of_val(&wksp.statsWksp);
        // SAFETY: class B (boundary). Calls the C thunk in
        // `common/entropy_common.c`, whose body is `rust_HUF_readStats_wksp`.
        // Its contract (`huf.h:177-184`) is: `huffWeight` holds `hwSize`
        // bytes (256 here), `rankStats` holds `HUF_TABLELOG_MAX + 1` U32s (13;
        // `rankVal` is 13), `nbSymbolsPtr`/`tableLogPtr` are live U32s, `src`
        // holds `srcSize` bytes, and the workspace is `wkspSize` bytes aligned
        // to 4 (`statsWksp` is `[u32; 219]`). The four pointers name disjoint
        // fields of one `&mut`, so no aliasing rule is broken. Retires when
        // the call is re-pointed at the Rust body -- see the module docs.
        iSize = unsafe {
            HUF_readStats_wksp(
                hw,
                HUF_SYMBOLVALUE_MAX + 1,
                rv,
                &mut nbSymbols,
                &mut tableLog,
                src,
                srcSize,
                sw as *mut c_void,
                swSize,
                flags,
            )
        };
    }
    if ERR_isError(iSize) {
        return iSize;
    }

    // Table header
    {
        // SAFETY: class B (boundary). Word 0 of the caller's table.
        let mut dtd = unsafe { HUF_getDTableDesc(DTable) };
        let maxTableLog: u32 = dtd.maxTableLog as u32 + 1;
        let targetTableLog: u32 = core::cmp::min(maxTableLog, HUF_DECODER_FAST_TABLELOG);
        tableLog = HUF_rescaleStats(
            &mut wksp.huffWeight,
            &mut wksp.rankVal,
            nbSymbols,
            tableLog,
            targetTableLog,
        );
        if tableLog > dtd.maxTableLog as u32 + 1 {
            // DTable too small, Huffman tree cannot fit in
            return ERROR(ZSTD_error_tableLog_tooLarge);
        }
        dtd.tableType = 0;
        dtd.tableLog = tableLog as u8;
        // SAFETY: class B (boundary). Word 0 of the caller's table.
        unsafe { HUF_setDTableDesc(DTable, dtd) };
    }

    // `dt` holds `1 << tableLog` HUF_DEltX1. That is exactly the space behind
    // the header: `HUF_DTABLE_SIZE(dtd.maxTableLog)` is
    // `1 + (1 << maxTableLog)` U32s, `tableLog <= dtd.maxTableLog + 1` was
    // just checked, and `(1 << (maxTableLog + 1)) * sizeof(HUF_DEltX1)`
    // == `(1 << maxTableLog) * sizeof(U32)`.
    let dtCap: usize = 1usize.wrapping_shl(tableLog);

    // Compute symbols and rankStart given rankVal:
    //
    // rankVal already contains the number of values of each weight.
    //
    // symbols contains the symbols ordered by weight. First are the rankVal[0]
    // weight 0 symbols, followed by the rankVal[1] weight 1 symbols, and so on.
    // symbols[0] is filled (but unused) to avoid a branch.
    //
    // rankStart contains the offset where each rank belongs in the DTable.
    // rankStart[0] is not filled because there are no entries in the table for
    // weight 0.
    {
        let mut nextRankStart: u32 = 0;
        let unroll: usize = 4;
        // `nLimit` is `(int)nbSymbols - unroll + 1` in the C and is genuinely
        // negative for `nbSymbols < 4`, which is why it is signed here too.
        let nLimit: isize = nbSymbols as isize - unroll as isize + 1;
        for n in 0..(tableLog as usize + 1) {
            let curr = nextRankStart;
            nextRankStart += wksp.rankVal[n];
            wksp.rankStart[n] = curr;
        }
        let mut n: isize = 0;
        while n < nLimit {
            for u in 0..unroll {
                let idx = (n as usize) + u;
                let w = wksp.huffWeight[idx] as usize;
                wksp.symbols[wksp.rankStart[w] as usize] = idx as u8;
                wksp.rankStart[w] += 1;
            }
            n += unroll as isize;
        }
        while (n as usize) < nbSymbols as usize {
            let idx = n as usize;
            let w = wksp.huffWeight[idx] as usize;
            wksp.symbols[wksp.rankStart[w] as usize] = idx as u8;
            wksp.rankStart[w] += 1;
            n += 1;
        }
    }

    // fill DTable
    // We fill all entries of each weight in order. That way length is a
    // constant for each iteration of the outer loop. We can switch based on
    // the length to a different inner loop which is optimized for that
    // particular case.
    {
        let mut symbol: usize = wksp.rankVal[0] as usize;
        let mut rankStart: usize = 0;
        for w in 1..(tableLog + 1) {
            let symbolCount: usize = wksp.rankVal[w as usize] as usize;
            let length: usize = (1usize << w) >> 1;
            let mut uStart: usize = rankStart;
            let nbBits: u8 = (tableLog + 1 - w) as u8;
            match length {
                1 => {
                    for s in 0..symbolCount {
                        let D = HUF_DEltX1 {
                            nbBits,
                            byte: wksp.symbols[symbol + s],
                        };
                        // SAFETY: class C (construction). `uStart` walks the
                        // table in weight order and the weights sum to
                        // `1 << tableLog == dtCap` -- `HUF_readStats_wksp()`
                        // guarantees the weight total is exactly a power of
                        // two and `HUF_rescaleStats()` scaled it to
                        // `1 << tableLog`. `dtx1_set` asserts it.
                        unsafe { dtx1_set(dt, dtCap, uStart, D) };
                        uStart += 1;
                    }
                }
                2 => {
                    for s in 0..symbolCount {
                        let D = HUF_DEltX1 {
                            nbBits,
                            byte: wksp.symbols[symbol + s],
                        };
                        // SAFETY: class C (construction). As `case 1`.
                        unsafe {
                            dtx1_set(dt, dtCap, uStart, D);
                            dtx1_set(dt, dtCap, uStart + 1, D);
                        }
                        uStart += 2;
                    }
                }
                4 => {
                    for s in 0..symbolCount {
                        let D4 = HUF_DEltX1_set4(wksp.symbols[symbol + s], nbBits);
                        // SAFETY: class C (construction). As `case 1`; four
                        // entries at a time.
                        unsafe { dtx1_set4(dt, dtCap, uStart, D4) };
                        uStart += 4;
                    }
                }
                8 => {
                    for s in 0..symbolCount {
                        let D4 = HUF_DEltX1_set4(wksp.symbols[symbol + s], nbBits);
                        // SAFETY: class C (construction). As `case 1`.
                        unsafe {
                            dtx1_set4(dt, dtCap, uStart, D4);
                            dtx1_set4(dt, dtCap, uStart + 4, D4);
                        }
                        uStart += 8;
                    }
                }
                _ => {
                    for s in 0..symbolCount {
                        let D4 = HUF_DEltX1_set4(wksp.symbols[symbol + s], nbBits);
                        let mut u: usize = 0;
                        while u < length {
                            // SAFETY: class C (construction). As `case 1`.
                            // `length` is a power of two >= 16 in this arm, so
                            // the step of 16 divides it exactly -- which is the
                            // C's `assert(u == length)` after the loop.
                            unsafe {
                                dtx1_set4(dt, dtCap, uStart + u, D4);
                                dtx1_set4(dt, dtCap, uStart + u + 4, D4);
                                dtx1_set4(dt, dtCap, uStart + u + 8, D4);
                                dtx1_set4(dt, dtCap, uStart + u + 12, D4);
                            }
                            u += 16;
                        }
                        uStart += length;
                    }
                }
            }
            symbol += symbolCount;
            rankStart += symbolCount * length;
        }
    }
    iSize
}

/// `huf_decompress.c:518-525` — `HUF_decodeSymbolX1()`.
///
/// `FORCE_INLINE_TEMPLATE` in the C, `#[inline(always)]` here, for the same
/// reason: it is instantiated once per target-feature set.
///
/// # Safety
///
/// `dt` must point at `dtCap` readable `HUF_DEltX1`s.
#[inline(always)]
unsafe fn HUF_decodeSymbolX1(
    Dstream: &mut BitDStream,
    dt: *const HUF_DEltX1,
    dtCap: usize,
    dtLog: u32,
) -> u8 {
    // note : dtLog >= 1
    let val = BIT_lookBitsFast(Dstream, dtLog);
    // SAFETY: class C (construction). `BIT_lookBitsFast()` masks to `dtLog`
    // bits, so `val < (1 << dtLog) == dtCap` for every table this file built.
    // `dtx1_get` asserts it; see the report's OOB list, item 4, for the one
    // caller-supplied `dtLog` that could break it.
    let d = unsafe { dtx1_get(dt, dtCap, val) };
    let c = d.byte;
    BIT_skipBits(Dstream, d.nbBits as u32);
    c
}

/// `huf_decompress.c:542-543` — `HUF_decodeStreamX1()`. `HINT_INLINE` in the C,
/// which under GCC without `-Os` expands to `FORCE_INLINE_TEMPLATE`.
///
/// # Safety
///
/// `p` and `pEnd` must delimit a writable range of the output buffer, and `dt`
/// must point at `dtCap` readable `HUF_DEltX1`s.
#[inline(always)]
unsafe fn HUF_decodeStreamX1(
    p: *mut u8,
    bitDPtr: &mut BitDStream,
    pEnd: *mut u8,
    dt: *const HUF_DEltX1,
    dtCap: usize,
    dtLog: u32,
) -> usize {
    let pStart = p;
    let mut p = p;

    // `HUF_DECODE_SYMBOLX1_0` (`huf_decompress.c:527`).
    // SAFETY (all four uses): class C (construction). Every write is guarded
    // by the enclosing loop's `p < pEnd` (or `p < pEnd - 3`, which is
    // stronger); `out_write1` asserts `p < pEnd`.
    macro_rules! X1_0 {
        () => {{
            let c = unsafe { HUF_decodeSymbolX1(bitDPtr, dt, dtCap, dtLog) };
            unsafe { out_write1(p, pEnd, c) };
            p = p.wrapping_add(1);
        }};
    }
    // `HUF_DECODE_SYMBOLX1_1` (`huf_decompress.c:530`) -- the condition
    // `MEM_64bits() || (HUF_TABLELOG_MAX <= 12)` is a compile-time constant and
    // is true on every target, because HUF_TABLELOG_MAX is 12. Kept as written.
    macro_rules! X1_1 {
        () => {
            if MEM_64BITS || HUF_TABLELOG_MAX <= 12 {
                X1_0!();
            }
        };
    }
    // `HUF_DECODE_SYMBOLX1_2` (`huf_decompress.c:536`).
    macro_rules! X1_2 {
        () => {
            if MEM_64BITS {
                X1_0!();
            }
        };
    }

    // up to 4 symbols at a time
    if (pEnd as isize).wrapping_sub(p as isize) > 3 {
        // The C's `&` is not short-circuiting, but `BIT_reloadDStream()` is the
        // LEFT operand and so is evaluated either way; `&&` is the same program.
        while BIT_reloadDStream(bitDPtr) == BIT_DStream_status::unfinished
            && p < pEnd.wrapping_sub(3)
        {
            X1_2!();
            X1_1!();
            X1_2!();
            X1_0!();
        }
    } else {
        BIT_reloadDStream(bitDPtr);
    }

    // [0-3] symbols remaining
    if MEM_32BITS {
        while BIT_reloadDStream(bitDPtr) == BIT_DStream_status::unfinished && p < pEnd {
            X1_0!();
        }
    }

    // no more data to retrieve from bitstream, no need to reload
    while p < pEnd {
        X1_0!();
    }

    (pEnd as usize).wrapping_sub(pStart as usize)
}

/// `huf_decompress.c:571-572` — `HUF_decompress1X1_usingDTable_internal_body()`.
///
/// # Safety
///
/// `dst` must point at `dstSize` writable bytes, `cSrc` at `cSrcSize` readable
/// bytes, and `DTable` at a readable 4-byte-aligned table.
#[inline(always)]
unsafe fn HUF_decompress1X1_usingDTable_internal_body(
    dst: *mut c_void,
    dstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    DTable: *const u32,
) -> usize {
    let op = dst as *mut u8;
    let oend = ZSTD_maybeNullPtrAdd(op, dstSize as isize);
    // SAFETY: class C (construction). One word past the header. No dereference.
    let dt = unsafe { DTable.add(1) } as *const HUF_DEltX1;
    // SAFETY: class B (boundary). Word 0 of the caller's table.
    let dtd = unsafe { HUF_getDTableDesc(DTable) };
    let dtLog = dtd.tableLog as u32;
    let dtCap: usize = 1usize.wrapping_shl(dtLog);

    let mut bitD = BitDStream {
        bitContainer: 0,
        bitsConsumed: 0,
        ptr: core::ptr::null(),
        start: core::ptr::null(),
        limitPtr: core::ptr::null(),
        src_size: 0,
    };
    // CHECK_F(BIT_initDStream(&bitD, cSrc, cSrcSize))
    {
        // SAFETY: class C (construction). `cSrc`/`cSrcSize` are the caller's.
        let e = unsafe { BIT_initDStream(&mut bitD, cSrc as *const u8, cSrcSize) };
        if ERR_isError(e) {
            return e;
        }
    }

    // SAFETY: class C (construction). `op .. oend` is the caller's output
    // buffer and `dt`/`dtCap` name the table behind the header.
    unsafe { HUF_decodeStreamX1(op, &mut bitD, oend, dt, dtCap, dtLog) };

    if BIT_endOfDStream(&bitD) == 0 {
        return ERROR(ZSTD_error_corruption_detected);
    }

    dstSize
}

/// `huf_decompress.c:598-599` — `HUF_decompress4X1_usingDTable_internal_body()`.
///
/// Conditions: `dstSize >= 6`.
///
/// # Safety
///
/// As [`HUF_decompress1X1_usingDTable_internal_body`].
#[inline(always)]
unsafe fn HUF_decompress4X1_usingDTable_internal_body(
    dst: *mut c_void,
    dstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    DTable: *const u32,
) -> usize {
    // Check
    if cSrcSize < 10 {
        // strict minimum : jump table + 1 byte per stream
        return ERROR(ZSTD_error_corruption_detected);
    }
    if dstSize < 6 {
        // stream 4-split doesn't work
        return ERROR(ZSTD_error_corruption_detected);
    }

    {
        let istart = cSrc as *const u8;
        let ostart = dst as *mut u8;
        let oend = ostart.wrapping_add(dstSize);
        let olimit = oend.wrapping_sub(3);
        // SAFETY: class C (construction). One word past the header.
        let dt = unsafe { DTable.add(1) } as *const HUF_DEltX1;

        // Init
        // SAFETY: class C (construction). `cSrcSize >= 10` was checked, so
        // bytes 0..6 are readable.
        let length1 = unsafe { MEM_readLE16(istart) } as usize;
        let length2 = unsafe { MEM_readLE16(istart.add(2)) } as usize;
        let length3 = unsafe { MEM_readLE16(istart.add(4)) } as usize;
        // `wrapping_sub`: the C computes this in `size_t` and catches the
        // underflow with the `length4 > cSrcSize` test below.
        let length4 = cSrcSize.wrapping_sub(length1 + length2 + length3 + 6);
        let istart1 = istart.wrapping_add(6); // jumpTable
        let istart2 = istart1.wrapping_add(length1);
        let istart3 = istart2.wrapping_add(length2);
        let istart4 = istart3.wrapping_add(length3);
        let segmentSize = (dstSize + 3) / 4;
        let opStart2 = ostart.wrapping_add(segmentSize);
        let opStart3 = opStart2.wrapping_add(segmentSize);
        let opStart4 = opStart3.wrapping_add(segmentSize);
        let mut op1 = ostart;
        let mut op2 = opStart2;
        let mut op3 = opStart3;
        let mut op4 = opStart4;
        // SAFETY: class B (boundary). Word 0 of the caller's table.
        let dtd = unsafe { HUF_getDTableDesc(DTable) };
        let dtLog = dtd.tableLog as u32;
        let dtCap: usize = 1usize.wrapping_shl(dtLog);
        let mut endSignal: u32 = 1;

        if length4 > cSrcSize {
            return ERROR(ZSTD_error_corruption_detected); // overflow
        }
        if opStart4 > oend {
            return ERROR(ZSTD_error_corruption_detected); // overflow
        }
        // assert(dstSize >= 6) -- validated above

        let mk = || BitDStream {
            bitContainer: 0,
            bitsConsumed: 0,
            ptr: core::ptr::null(),
            start: core::ptr::null(),
            limitPtr: core::ptr::null(),
            src_size: 0,
        };
        let mut bitD1 = mk();
        let mut bitD2 = mk();
        let mut bitD3 = mk();
        let mut bitD4 = mk();

        // CHECK_F(BIT_initDStream(...)) x4
        // SAFETY: class C (construction). The four sub-buffers tile
        // `cSrc[6 .. cSrcSize]`: `6 + length1 + length2 + length3 + length4
        // == cSrcSize` and `length4 <= cSrcSize` was just checked, so each
        // `istartN .. istartN + lengthN` is inside the caller's buffer.
        for (bd, ist, len) in [
            (&mut bitD1, istart1, length1),
            (&mut bitD2, istart2, length2),
            (&mut bitD3, istart3, length3),
            (&mut bitD4, istart4, length4),
        ] {
            let e = unsafe { BIT_initDStream(bd, ist, len) };
            if ERR_isError(e) {
                return e;
            }
        }

        // `HUF_DECODE_SYMBOLX1_{0,1,2}`, one macro per output pointer because
        // Rust macros cannot take a place expression by reference.
        macro_rules! X1_0 {
            ($op:ident, $bd:ident) => {{
                // SAFETY: class C (construction). The loop guard is
                // `op4 < olimit == oend - 3`, and `op1 <= op2 <= op3 <= op4`
                // is maintained because all four advance by exactly one per
                // decode; `out_write1` asserts `< oend` regardless.
                let c = unsafe { HUF_decodeSymbolX1(&mut $bd, dt, dtCap, dtLog) };
                unsafe { out_write1($op, oend, c) };
                $op = $op.wrapping_add(1);
            }};
        }
        macro_rules! X1_1 {
            ($op:ident, $bd:ident) => {
                if MEM_64BITS || HUF_TABLELOG_MAX <= 12 {
                    X1_0!($op, $bd);
                }
            };
        }
        macro_rules! X1_2 {
            ($op:ident, $bd:ident) => {
                if MEM_64BITS {
                    X1_0!($op, $bd);
                }
            };
        }

        // up to 16 symbols per loop (4 symbols per stream) in 64-bit mode
        if (oend as usize).wrapping_sub(op4 as usize) >= SIZE_BYTES {
            while endSignal != 0 && op4 < olimit {
                X1_2!(op1, bitD1);
                X1_2!(op2, bitD2);
                X1_2!(op3, bitD3);
                X1_2!(op4, bitD4);
                X1_1!(op1, bitD1);
                X1_1!(op2, bitD2);
                X1_1!(op3, bitD3);
                X1_1!(op4, bitD4);
                X1_2!(op1, bitD1);
                X1_2!(op2, bitD2);
                X1_2!(op3, bitD3);
                X1_2!(op4, bitD4);
                X1_0!(op1, bitD1);
                X1_0!(op2, bitD2);
                X1_0!(op3, bitD3);
                X1_0!(op4, bitD4);
                endSignal &=
                    (BIT_reloadDStreamFast(&mut bitD1) == BIT_DStream_status::unfinished) as u32;
                endSignal &=
                    (BIT_reloadDStreamFast(&mut bitD2) == BIT_DStream_status::unfinished) as u32;
                endSignal &=
                    (BIT_reloadDStreamFast(&mut bitD3) == BIT_DStream_status::unfinished) as u32;
                endSignal &=
                    (BIT_reloadDStreamFast(&mut bitD4) == BIT_DStream_status::unfinished) as u32;
            }
        }

        // check corruption
        // note : should not be necessary : op# advance in lock step, and we
        //        control op4. but curiously, binary generated by gcc 7.2 & 7.3
        //        with -mbmi2 runs faster when >=1 test is present
        if op1 > opStart2 {
            return ERROR(ZSTD_error_corruption_detected);
        }
        if op2 > opStart3 {
            return ERROR(ZSTD_error_corruption_detected);
        }
        if op3 > opStart4 {
            return ERROR(ZSTD_error_corruption_detected);
        }
        // note : op4 supposed already verified within main loop

        // finish bitStreams one by one
        // SAFETY: class C (construction). Each `(op, segment end)` pair is
        // inside the caller's output buffer -- `opStart4 <= oend` was checked
        // and the three checks above give `opN <= opStartN+1`.
        unsafe {
            HUF_decodeStreamX1(op1, &mut bitD1, opStart2, dt, dtCap, dtLog);
            HUF_decodeStreamX1(op2, &mut bitD2, opStart3, dt, dtCap, dtLog);
            HUF_decodeStreamX1(op3, &mut bitD3, opStart4, dt, dtCap, dtLog);
            HUF_decodeStreamX1(op4, &mut bitD4, oend, dt, dtCap, dtLog);
        }

        // check
        {
            let endCheck = BIT_endOfDStream(&bitD1)
                & BIT_endOfDStream(&bitD2)
                & BIT_endOfDStream(&bitD3)
                & BIT_endOfDStream(&bitD4);
            if endCheck == 0 {
                return ERROR(ZSTD_error_corruption_detected);
            }
        }

        // decoded size
        dstSize
    }
}

/// `huf_decompress.c:717-718` — `HUF_decompress4X1_usingDTable_internal_fast_c_loop()`.
///
/// `HUF_FAST_BMI2_ATTRS` in the C, i.e. `BMI2_TARGET_ATTRIBUTE` under
/// `DYNAMIC_BMI2`. Here it is `#[inline(always)]` with no attribute of its own
/// and is called only from
/// [`HUF_decompress4X1_usingDTable_internal_fast_body`], which is inlined into
/// the feature-carrying wrapper — so it inherits exactly the feature set the C
/// gives it. See divergence 5 (`loopFn` is gone).
///
/// # Safety
///
/// `args` must have been filled in by a successful
/// [`HUF_DecompressFastArgs_init`].
#[inline(always)]
unsafe fn HUF_decompress4X1_usingDTable_internal_fast_c_loop(args: &mut HUF_DecompressFastArgs) {
    // Copy the arguments to local variables
    let mut bits: [u64; 4] = args.bits;
    let mut ip: [*const u8; 4] = args.ip;
    let mut op: [*mut u8; 4] = args.op;
    let dtable = args.dt as *const u16;
    let oend = args.oend;
    let ilowest = args.ilowest;
    let src_end = args.src_end;

    // `HUF_DecompressFastArgs_init()` returned 1, which it only does when
    // `dtLog == HUF_DECODER_FAST_TABLELOG`, so the table has exactly this many
    // entries and `bits >> 53` cannot index past it.
    const DTABLE_CAP: usize = 1usize << HUF_DECODER_FAST_TABLELOG;

    // assert(MEM_isLittleEndian()); assert(!MEM_32bits())

    loop {
        let olimit: *mut u8;

        // Compute olimit
        {
            // Each iteration produces 5 output symbols per stream.
            // `wrapping_sub` on the pointer difference: the C's `(size_t)(a - b)`
            // is a ptrdiff cast and `op[3] <= oend` is a loop invariant, not a
            // checked fact.
            let oiters: usize = (oend as usize).wrapping_sub(op[3] as usize) / 5;
            // Each iteration consumes up to 11 bits * 5 = 55 bits < 7 bytes per
            // stream.
            let iiters: usize = (ip[0] as usize).wrapping_sub(ilowest as usize) / 7;
            // We can safely run iters iterations before running bounds checks
            let iters: usize = core::cmp::min(oiters, iiters);
            let symbols: usize = iters * 5;

            // We can simply check that op[3] < olimit, instead of checking all
            // of our bounds, since we can't hit the other bounds until we've
            // run iters iterations, which only happens when op[3] == olimit.
            olimit = op[3].wrapping_add(symbols);

            // Exit fast decoding loop once we reach the end.
            if op[3] == olimit {
                break;
            }

            // Exit the decoding loop if any input pointer has crossed the
            // previous one. This indicates corruption, and a precondition to
            // our loop is that ip[i] >= ip[0]. (The C's `goto _out` and its
            // `break` both land on the same statement, so one `break` covers
            // both.)
            let mut crossed = false;
            for stream in 1..4 {
                if ip[stream] < ip[stream - 1] {
                    crossed = true;
                    break;
                }
            }
            if crossed {
                break;
            }
        }

        // `HUF_4X1_DECODE_SYMBOL` (`huf_decompress.c:784`).
        macro_rules! DECODE_SYMBOL {
            ($stream:expr, $symbol:expr) => {{
                let index: usize = (bits[$stream] >> 53) as usize;
                // SAFETY: class C (construction). `index < 2048 == DTABLE_CAP`
                // because `bits` is a `u64` shifted right by 53. The assert is
                // therefore redundant and free; it is here because
                // `DTABLE_CAP` is a constant that a future edit could get
                // wrong. The load is an aligned `U16` read exactly as the C's
                // `dtable[index]` is.
                assert!(index < DTABLE_CAP);
                let entry: u32 = unsafe { *dtable.add(index) } as u32;
                bits[$stream] = bits[$stream].wrapping_shl(entry & 0x3F);
                // SAFETY: class C (construction). `op[3] + 5 <= olimit <= oend`
                // by the `oiters` computation above, and
                // `op[0] <= op[1] <= op[2] <= op[3]` because all four advance
                // by exactly 5 per iteration and started ordered. `out_write1`
                // asserts `< oend` regardless.
                unsafe {
                    out_write1(op[$stream].wrapping_add($symbol), oend, ((entry >> 8) & 0xFF) as u8)
                };
            }};
        }

        // `HUF_4X1_RELOAD_STREAM` (`huf_decompress.c:792`).
        macro_rules! RELOAD_STREAM {
            ($stream:expr) => {{
                let ctz: u32 = ZSTD_countTrailingZeros64(bits[$stream]);
                let nbBits: u32 = ctz & 7;
                let nbBytes: usize = (ctz >> 3) as usize;
                op[$stream] = op[$stream].wrapping_add(5);
                ip[$stream] = ip[$stream].wrapping_sub(nbBytes);
                // SAFETY: class C (construction). `iiters` bounded the loop so
                // that `ip[i] >= ilowest` still holds after `iters`
                // iterations, and `ip[i]` only ever decreases from its initial
                // value of at most `src_end - 8`. `in_read64` asserts both
                // ends; see the report's OOB list, item 5.
                bits[$stream] = unsafe { in_read64(ip[$stream], ilowest, src_end) } | 1;
                bits[$stream] = bits[$stream].wrapping_shl(nbBits);
            }};
        }

        // The C manually unrolls this loop "because compilers don't
        // consistently unroll the inner loops, which destroys performance".
        // The Rust below is written with the same nesting -- symbol outer,
        // stream inner, matching `HUF_4X_FOR_EACH_STREAM_WITH_VAR` -- but with
        // the indices spelled out, so that the macro's `$stream`/`$symbol` are
        // literal constants and LLVM sees straight-line code, not a loop.
        loop {
            // Decode 5 symbols in each of the 4 streams
            DECODE_SYMBOL!(0, 0);
            DECODE_SYMBOL!(1, 0);
            DECODE_SYMBOL!(2, 0);
            DECODE_SYMBOL!(3, 0);
            DECODE_SYMBOL!(0, 1);
            DECODE_SYMBOL!(1, 1);
            DECODE_SYMBOL!(2, 1);
            DECODE_SYMBOL!(3, 1);
            DECODE_SYMBOL!(0, 2);
            DECODE_SYMBOL!(1, 2);
            DECODE_SYMBOL!(2, 2);
            DECODE_SYMBOL!(3, 2);
            DECODE_SYMBOL!(0, 3);
            DECODE_SYMBOL!(1, 3);
            DECODE_SYMBOL!(2, 3);
            DECODE_SYMBOL!(3, 3);
            DECODE_SYMBOL!(0, 4);
            DECODE_SYMBOL!(1, 4);
            DECODE_SYMBOL!(2, 4);
            DECODE_SYMBOL!(3, 4);

            // Reload each of the 4 the bitstreams
            RELOAD_STREAM!(0);
            RELOAD_STREAM!(1);
            RELOAD_STREAM!(2);
            RELOAD_STREAM!(3);

            if op[3] >= olimit {
                break;
            }
        }
    }

    // Save the final values of each of the state variables back to args.
    args.bits = bits;
    args.ip = ip;
    args.op = op;
}

/// `huf_decompress.c:835-837` — `HUF_decompress4X1_usingDTable_internal_fast()`.
///
/// Returns `dstSize` on success (>= 6), 0 if the fallback implementation
/// should be used, or an error code.
///
/// # Safety
///
/// As [`HUF_decompress1X1_usingDTable_internal_body`].
#[inline(always)]
unsafe fn HUF_decompress4X1_usingDTable_internal_fast_body(
    dst: *mut c_void,
    dstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    DTable: *const u32,
) -> usize {
    // SAFETY: class C (construction). One word past the header.
    let dt = unsafe { DTable.add(1) } as *const HUF_DEltX1;
    let oend = ZSTD_maybeNullPtrAdd(dst as *mut u8, dstSize as isize);

    let mut args = HUF_DecompressFastArgs {
        ip: [core::ptr::null(); 4],
        op: [core::ptr::null_mut(); 4],
        bits: [0; 4],
        dt: core::ptr::null(),
        ilowest: core::ptr::null(),
        oend: core::ptr::null_mut(),
        iend: [core::ptr::null(); 4],
        src_end: core::ptr::null(),
    };
    {
        // SAFETY: class C (construction). The caller's buffers, forwarded.
        let ret = unsafe {
            HUF_DecompressFastArgs_init(&mut args, dst, dstSize, cSrc, cSrcSize, DTable)
        };
        // FORWARD_IF_ERROR(ret, "Failed to init fast loop args")
        if ERR_isError(ret) {
            return ret;
        }
        if ret == 0 {
            return 0;
        }
    }

    // assert(args.ip[0] >= args.ilowest)
    // SAFETY: class C (construction). `args` was just filled in by a
    // successful `HUF_DecompressFastArgs_init()`, which is this function's
    // contract.
    unsafe { HUF_decompress4X1_usingDTable_internal_fast_c_loop(&mut args) };

    // Our loop guarantees that ip[] >= ilowest and that we haven't overwritten
    // any op[]. (The C's seven asserts here are compiled out at DEBUGLEVEL 0.)

    // finish bit streams one by one.
    {
        let segmentSize = (dstSize + 3) / 4;
        let mut segmentEnd = dst as *mut u8;
        for i in 0..4usize {
            let mut bit = BitDStream {
                bitContainer: 0,
                bitsConsumed: 0,
                ptr: core::ptr::null(),
                start: core::ptr::null(),
                limitPtr: core::ptr::null(),
                src_size: 0,
            };
            if segmentSize <= (oend as usize).wrapping_sub(segmentEnd as usize) {
                segmentEnd = segmentEnd.wrapping_add(segmentSize);
            } else {
                segmentEnd = oend;
            }
            // FORWARD_IF_ERROR(HUF_initRemainingDStream(...), "corruption")
            {
                let e = HUF_initRemainingDStream(&mut bit, &args, i, segmentEnd);
                if ERR_isError(e) {
                    return e;
                }
            }
            // Decompress and validate that we've produced exactly the expected
            // length.
            // SAFETY: class C (construction). `args.op[i] <= segmentEnd <= oend`
            // -- `HUF_initRemainingDStream()` just rejected the opposite -- and
            // `dt` has `1 << HUF_DECODER_FAST_TABLELOG` entries, which is what
            // `HUF_DecompressFastArgs_init()` checked before returning 1.
            let n = unsafe {
                HUF_decodeStreamX1(
                    args.op[i],
                    &mut bit,
                    segmentEnd,
                    dt,
                    1usize << HUF_DECODER_FAST_TABLELOG,
                    HUF_DECODER_FAST_TABLELOG,
                )
            };
            args.op[i] = args.op[i].wrapping_add(n);
            if args.op[i] != segmentEnd {
                return ERROR(ZSTD_error_corruption_detected);
            }
        }
    }

    // decoded size
    // assert(dstSize != 0)
    dstSize
}

// --- HUF_DGEN(HUF_decompress1X1_usingDTable_internal) and the 4X1 dispatch ---
//
// `huf_decompress.c:95-119` — the `HUF_DGEN` macro under `#if DYNAMIC_BMI2`.

/// `HUF_decompress1X1_usingDTable_internal_default()` — avoids the
/// `FORCE_INLINE` of the `_body()`.
///
/// # Safety
///
/// As [`HUF_decompress1X1_usingDTable_internal_body`].
unsafe fn HUF_decompress1X1_usingDTable_internal_default(
    dst: *mut c_void,
    dstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    DTable: *const u32,
) -> usize {
    // SAFETY: class C (construction). Preconditions forwarded unchanged.
    unsafe { HUF_decompress1X1_usingDTable_internal_body(dst, dstSize, cSrc, cSrcSize, DTable) }
}

/// `HUF_decompress1X1_usingDTable_internal_bmi2()`, under `#if DYNAMIC_BMI2`.
///
/// # Safety
///
/// As [`HUF_decompress1X1_usingDTable_internal_body`], **and** the CPU must
/// support LZCNT, BMI1 and BMI2.
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "bmi2")))]
#[target_feature(enable = "lzcnt,bmi1,bmi2")]
unsafe fn HUF_decompress1X1_usingDTable_internal_bmi2(
    dst: *mut c_void,
    dstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    DTable: *const u32,
) -> usize {
    // SAFETY: class C (construction). Preconditions forwarded unchanged. The
    // body is inlined here and so is compiled with this function's target
    // features -- that is the whole point of the wrapper.
    unsafe { HUF_decompress1X1_usingDTable_internal_body(dst, dstSize, cSrc, cSrcSize, DTable) }
}

/// `HUF_decompress1X1_usingDTable_internal()` — the `HUF_DGEN` dispatcher.
///
/// # Safety
///
/// As [`HUF_decompress1X1_usingDTable_internal_body`].
unsafe fn HUF_decompress1X1_usingDTable_internal(
    dst: *mut c_void,
    dstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    DTable: *const u32,
    flags: c_int,
) -> usize {
    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "bmi2")))]
    if (flags & HUF_flags_bmi2) != 0 {
        // SAFETY: class A (axiom). This is the ISA boundary. `HUF_flags_bmi2`
        // is zstd's own assertion, derived from `ZSTD_cpuid()`, that this CPU
        // has LZCNT/BMI1/BMI2 -- exactly the precondition
        // `#[target_feature(enable = ...)]` imposes. The C expresses the same
        // contract with `__attribute__((target(...)))` and a runtime branch.
        // Nothing in Rust can discharge it; it is a property of the silicon.
        return unsafe {
            HUF_decompress1X1_usingDTable_internal_bmi2(dst, dstSize, cSrc, cSrcSize, DTable)
        };
    }
    let _ = flags; // (void)flags
    // SAFETY: class C (construction). Preconditions forwarded unchanged.
    unsafe { HUF_decompress1X1_usingDTable_internal_default(dst, dstSize, cSrc, cSrcSize, DTable) }
}

/// `huf_decompress.c:705-706` —
/// `HUF_decompress4X1_usingDTable_internal_default()`.
///
/// # Safety
///
/// As [`HUF_decompress1X1_usingDTable_internal_body`].
unsafe fn HUF_decompress4X1_usingDTable_internal_default(
    dst: *mut c_void,
    dstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    DTable: *const u32,
) -> usize {
    // SAFETY: class C (construction). Preconditions forwarded unchanged.
    unsafe { HUF_decompress4X1_usingDTable_internal_body(dst, dstSize, cSrc, cSrcSize, DTable) }
}

/// `huf_decompress.c:698-699` —
/// `HUF_decompress4X1_usingDTable_internal_bmi2()`, under
/// `#if HUF_NEED_BMI2_FUNCTION`.
///
/// # Safety
///
/// As [`HUF_decompress1X1_usingDTable_internal_body`], **and** the CPU must
/// support LZCNT, BMI1 and BMI2.
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "bmi2")))]
#[target_feature(enable = "lzcnt,bmi1,bmi2")]
unsafe fn HUF_decompress4X1_usingDTable_internal_bmi2(
    dst: *mut c_void,
    dstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    DTable: *const u32,
) -> usize {
    // SAFETY: class C (construction). Preconditions forwarded unchanged; the
    // body is inlined here with this function's target features.
    unsafe { HUF_decompress4X1_usingDTable_internal_body(dst, dstSize, cSrc, cSrcSize, DTable) }
}

/// `huf_decompress.c:835-837` — the `HUF_FAST_BMI2_ATTRS` wrapper over
/// [`HUF_decompress4X1_usingDTable_internal_fast_body`].
///
/// # Safety
///
/// As [`HUF_decompress1X1_usingDTable_internal_body`], **and** the CPU must
/// support LZCNT, BMI1 and BMI2.
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "bmi2")))]
#[target_feature(enable = "lzcnt,bmi1,bmi2")]
unsafe fn HUF_decompress4X1_usingDTable_internal_fast(
    dst: *mut c_void,
    dstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    DTable: *const u32,
) -> usize {
    // SAFETY: class C (construction). Preconditions forwarded unchanged; the
    // body and the decode loop it calls are inlined here with this function's
    // target features.
    unsafe { HUF_decompress4X1_usingDTable_internal_fast_body(dst, dstSize, cSrc, cSrcSize, DTable) }
}

/// `huf_decompress.c:835` — `HUF_FAST_BMI2_ATTRS` is empty when
/// `DYNAMIC_BMI2` is 0, i.e. on every non-x86 target.
///
/// # Safety
///
/// As [`HUF_decompress1X1_usingDTable_internal_body`].
#[cfg(not(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "bmi2"))))]
unsafe fn HUF_decompress4X1_usingDTable_internal_fast(
    dst: *mut c_void,
    dstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    DTable: *const u32,
) -> usize {
    // SAFETY: class C (construction). Preconditions forwarded unchanged.
    unsafe { HUF_decompress4X1_usingDTable_internal_fast_body(dst, dstSize, cSrc, cSrcSize, DTable) }
}

/// `huf_decompress.c:894` — `HUF_decompress4X1_usingDTable_internal()`,
/// `#if DYNAMIC_BMI2` arm.
///
/// The `#if ZSTD_ENABLE_ASM_X86_64_BMI2` blocks that would reassign `loopFn`
/// to the assembly loop are compiled out (the macro is a hard 0), so `loopFn`
/// is dropped entirely; see divergence 5.
///
/// # Safety
///
/// As [`HUF_decompress1X1_usingDTable_internal_body`].
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "bmi2")))]
unsafe fn HUF_decompress4X1_usingDTable_internal(
    dst: *mut c_void,
    dstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    DTable: *const u32,
    flags: c_int,
) -> usize {
    if (flags & HUF_flags_bmi2) == 0 {
        // The C's `else { return fallbackFn(...); }` -- with DYNAMIC_BMI2 on,
        // a non-bmi2 CPU never reaches the fast loop at all.
        // SAFETY: class C (construction). Preconditions forwarded unchanged.
        return unsafe {
            HUF_decompress4X1_usingDTable_internal_default(dst, dstSize, cSrc, cSrcSize, DTable)
        };
    }
    if HUF_ENABLE_FAST_DECODE && (flags & HUF_flags_disableFast) == 0 {
        // SAFETY: class A (axiom). The ISA boundary, as in
        // `HUF_decompress1X1_usingDTable_internal`: `HUF_flags_bmi2` was just
        // tested and is zstd's assertion that this CPU has LZCNT/BMI1/BMI2.
        let ret = unsafe {
            HUF_decompress4X1_usingDTable_internal_fast(dst, dstSize, cSrc, cSrcSize, DTable)
        };
        // The C tests `ret != 0`, which is true for an error code as well as
        // for a success; an error is forwarded, not retried on the fallback.
        if ret != 0 {
            return ret;
        }
    }
    // SAFETY: class A (axiom). As above.
    unsafe { HUF_decompress4X1_usingDTable_internal_bmi2(dst, dstSize, cSrc, cSrcSize, DTable) }
}

/// `huf_decompress.c:894` — `HUF_decompress4X1_usingDTable_internal()` with
/// `DYNAMIC_BMI2 == 0`, i.e. on every non-x86 target. The whole
/// `#if DYNAMIC_BMI2` block disappears and the fast loop runs unconditionally.
///
/// # Safety
///
/// As [`HUF_decompress1X1_usingDTable_internal_body`].
#[cfg(not(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "bmi2"))))]
unsafe fn HUF_decompress4X1_usingDTable_internal(
    dst: *mut c_void,
    dstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    DTable: *const u32,
    flags: c_int,
) -> usize {
    if HUF_ENABLE_FAST_DECODE && (flags & HUF_flags_disableFast) == 0 {
        // SAFETY: class C (construction). Preconditions forwarded unchanged.
        let ret = unsafe {
            HUF_decompress4X1_usingDTable_internal_fast(dst, dstSize, cSrc, cSrcSize, DTable)
        };
        if ret != 0 {
            return ret;
        }
    }
    // SAFETY: class C (construction). Preconditions forwarded unchanged.
    unsafe { HUF_decompress4X1_usingDTable_internal_default(dst, dstSize, cSrc, cSrcSize, DTable) }
}

/// `huf_decompress.c:927` — `HUF_decompress4X1_DCtx_wksp()`.
///
/// # Safety
///
/// As [`HUF_readDTableX1_wksp`], plus `dst` pointing at `dstSize` writable
/// bytes.
unsafe fn HUF_decompress4X1_DCtx_wksp(
    dctx: *mut u32,
    dst: *mut c_void,
    dstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    workSpace: *mut c_void,
    wkspSize: usize,
    flags: c_int,
) -> usize {
    let ip = cSrc as *const u8;

    // SAFETY: class C (construction). The caller's buffers, forwarded.
    let hSize =
        unsafe { HUF_readDTableX1_wksp(dctx, cSrc, cSrcSize, workSpace, wkspSize, flags) };
    if ERR_isError(hSize) {
        return hSize;
    }
    if hSize >= cSrcSize {
        return ERROR(ZSTD_error_srcSize_wrong);
    }
    // SAFETY: class C (construction). `hSize < cSrcSize` was just checked, so
    // `ip + hSize` is inside the caller's input buffer.
    let ip = unsafe { ip.add(hSize) };
    let cSrcSize = cSrcSize - hSize;

    // SAFETY: class C (construction). `dctx` now holds a table this file just
    // built; `ip`/`cSrcSize` name the tail of the caller's input.
    unsafe {
        HUF_decompress4X1_usingDTable_internal(
            dst,
            dstSize,
            ip as *const c_void,
            cSrcSize,
            dctx,
            flags,
        )
    }
}

// ===========================================================================
// huf_decompress.c:943-1772 — double-symbol decoding (X2)
//
// The whole block is inside `#ifndef HUF_FORCE_DECOMPRESS_X1`, which is never
// defined in the kernel.
// ===========================================================================

/// `huf_decompress.c:950` — `{ U16 sequence; BYTE nbBits; BYTE length; }`.
#[repr(C)]
#[derive(Clone, Copy)]
struct HUF_DEltX2 {
    sequence: u16,
    nbBits: u8,
    length: u8,
}

// The four DEBUG_STATIC_ASSERTs at `huf_decompress.c:960-963`.
const _: () = assert!(core::mem::offset_of!(HUF_DEltX2, sequence) == 0);
const _: () = assert!(core::mem::offset_of!(HUF_DEltX2, nbBits) == 2);
const _: () = assert!(core::mem::offset_of!(HUF_DEltX2, length) == 3);
const _: () = assert!(core::mem::size_of::<HUF_DEltX2>() == core::mem::size_of::<u32>());

/// `huf_decompress.c:952` — `typedef U32 rankValCol_t[HUF_TABLELOG_MAX + 1]`.
type rankValCol_t = [u32; HUF_TABLELOG_MAX + 1];

// `huf_decompress.c:951` — `typedef struct { BYTE symbol; } sortedSymbol_t;`
// is a one-byte struct, so `sortedSymbol_t[N]` and `[u8; N]` have identical
// layout. The plain `[u8; N]` is used here and the `.symbol` field accesses
// disappear; nothing else about the type is observable.

/// `dt[idx] = d`, bounds-checked (divergence 1).
///
/// # Safety
///
/// `dt` must point at `cap` writable `HUF_DEltX2`s.
#[inline(always)]
unsafe fn dtx2_set(dt: *mut HUF_DEltX2, cap: usize, idx: usize, d: HUF_DEltX2) {
    assert!(idx < cap);
    // SAFETY: class C (construction). `idx < cap` was just checked.
    unsafe { dt.add(idx).write(d) }
}

/// `ZSTD_memcpy(dt + idx, &DEltX2, sizeof(U64))` — lays down **two**
/// `HUF_DEltX2`s at once, bounds-checked (divergence 1).
///
/// # Safety
///
/// `dt` must point at `cap` writable `HUF_DEltX2`s.
#[inline(always)]
unsafe fn dtx2_set2(dt: *mut HUF_DEltX2, cap: usize, idx: usize, v: u64) {
    assert!(cap >= 2 && idx <= cap - 2);
    // SAFETY: class C (construction). `idx + 2 <= cap` was just checked, and
    // two `HUF_DEltX2` are exactly the 8 bytes the C's `ZSTD_memcpy` writes.
    // `HUF_DEltX2` has alignment 2, so `write_unaligned` is required.
    unsafe { MEM_write64(dt.add(idx) as *mut u8, v) }
}

/// `dt[idx]`, bounds-checked (divergence 1).
///
/// # Safety
///
/// `dt` must point at `cap` readable `HUF_DEltX2`s.
#[inline(always)]
unsafe fn dtx2_get(dt: *const HUF_DEltX2, cap: usize, idx: usize) -> HUF_DEltX2 {
    assert!(idx < cap);
    // SAFETY: class C (construction). `idx < cap` was just checked.
    unsafe { dt.add(idx).read() }
}

/// `huf_decompress.c:955-958` — `HUF_buildDEltX2U32()`.
///
/// As with [`HUF_DEltX1_set4`], the little/big-endian split is a *layout*
/// choice — it builds the same struct either way — not a byte-order
/// conversion. Transcribed as written.
#[inline(always)]
fn HUF_buildDEltX2U32(symbol: u32, nbBits: u32, baseSeq: u32, level: c_int) -> u32 {
    // Every operator here is C `U32` arithmetic, which is defined to wrap.
    if MEM_LITTLE_ENDIAN {
        let seq = if level == 1 {
            symbol
        } else {
            baseSeq.wrapping_add(symbol.wrapping_shl(8))
        };
        seq.wrapping_add(nbBits.wrapping_shl(16))
            .wrapping_add((level as u32).wrapping_shl(24))
    } else {
        let seq = if level == 1 {
            symbol.wrapping_shl(8)
        } else {
            baseSeq.wrapping_shl(8).wrapping_add(symbol)
        };
        seq.wrapping_shl(16)
            .wrapping_add(nbBits.wrapping_shl(8))
            .wrapping_add(level as u32)
    }
}

/// `huf_decompress.c:976-979` — `HUF_buildDEltX2()`.
#[inline(always)]
fn HUF_buildDEltX2(symbol: u32, nbBits: u32, baseSeq: u32, level: c_int) -> HUF_DEltX2 {
    let val = HUF_buildDEltX2U32(symbol, nbBits, baseSeq, level);
    // `ZSTD_memcpy(&DElt, &val, sizeof(val))` -- a byte copy of the U32 into
    // the struct, so `to_ne_bytes` and the field offsets asserted above make
    // this exact on both endiannesses.
    let b = val.to_ne_bytes();
    HUF_DEltX2 {
        sequence: u16::from_ne_bytes([b[0], b[1]]),
        nbBits: b[2],
        length: b[3],
    }
}

/// `huf_decompress.c:986-989` — `HUF_buildDEltX2U64()`. Two `HUF_DEltX2`s packed
/// into a `U64`.
#[inline(always)]
fn HUF_buildDEltX2U64(symbol: u32, nbBits: u32, baseSeq: u16, level: c_int) -> u64 {
    let DElt = HUF_buildDEltX2U32(symbol, nbBits, baseSeq as u32, level);
    (DElt as u64).wrapping_add((DElt as u64) << 32)
}

/// `huf_decompress.c:1007` — `HUF_fillDTableX2ForWeight()`.
///
/// Fills the DTable rank with all the symbols from `[begin, end)` that are each
/// `nbBits` long. `rank` is the C's `DTableRank`, expressed as an index into
/// `dt` rather than as a pointer so it can be bounds-checked.
///
/// # Safety
///
/// `dt` must point at `cap` writable `HUF_DEltX2`s.
#[inline(always)]
unsafe fn HUF_fillDTableX2ForWeight(
    dt: *mut HUF_DEltX2,
    cap: usize,
    mut rank: usize,
    sorted: &[u8],
    begin: usize,
    end: usize,
    nbBits: u32,
    tableLog: u32,
    baseSeq: u16,
    level: c_int,
) {
    // `& 0x1F` is the C's own "quiet static-analyzer" mask; `wrapping_shl`
    // makes the shift total for the same reason.
    let length: usize = 1usize.wrapping_shl(tableLog.wrapping_sub(nbBits) & 0x1F);
    // assert(level >= 1 && level <= 2)
    match length {
        1 => {
            for p in begin..end {
                let DElt = HUF_buildDEltX2(sorted[p] as u32, nbBits, baseSeq as u32, level);
                // SAFETY: class C (construction). `rank` walks the rank the
                // caller reserved; the reservation is `rankVal[w]` plus the
                // running `length`, and the ranks tile `1 << targetLog`
                // entries exactly. `dtx2_set` asserts it.
                unsafe { dtx2_set(dt, cap, rank, DElt) };
                rank += 1;
            }
        }
        2 => {
            for p in begin..end {
                let DElt = HUF_buildDEltX2(sorted[p] as u32, nbBits, baseSeq as u32, level);
                // SAFETY: class C (construction). As `case 1`.
                unsafe {
                    dtx2_set(dt, cap, rank, DElt);
                    dtx2_set(dt, cap, rank + 1, DElt);
                }
                rank += 2;
            }
        }
        4 => {
            for p in begin..end {
                let DEltX2 = HUF_buildDEltX2U64(sorted[p] as u32, nbBits, baseSeq, level);
                // SAFETY: class C (construction). As `case 1`; two entries at
                // a time.
                unsafe {
                    dtx2_set2(dt, cap, rank, DEltX2);
                    dtx2_set2(dt, cap, rank + 2, DEltX2);
                }
                rank += 4;
            }
        }
        8 => {
            for p in begin..end {
                let DEltX2 = HUF_buildDEltX2U64(sorted[p] as u32, nbBits, baseSeq, level);
                // SAFETY: class C (construction). As `case 1`.
                unsafe {
                    dtx2_set2(dt, cap, rank, DEltX2);
                    dtx2_set2(dt, cap, rank + 2, DEltX2);
                    dtx2_set2(dt, cap, rank + 4, DEltX2);
                    dtx2_set2(dt, cap, rank + 6, DEltX2);
                }
                rank += 8;
            }
        }
        _ => {
            for p in begin..end {
                let DEltX2 = HUF_buildDEltX2U64(sorted[p] as u32, nbBits, baseSeq, level);
                let rankEnd = rank + length;
                while rank != rankEnd {
                    // SAFETY: class C (construction). As `case 1`. `length` is
                    // a power of two >= 16 in this arm, so the step of 8
                    // divides it exactly and `rank` lands on `rankEnd`.
                    unsafe {
                        dtx2_set2(dt, cap, rank, DEltX2);
                        dtx2_set2(dt, cap, rank + 2, DEltX2);
                        dtx2_set2(dt, cap, rank + 4, DEltX2);
                        dtx2_set2(dt, cap, rank + 6, DEltX2);
                    }
                    rank += 8;
                }
            }
        }
    }
}

/// `huf_decompress.c:1064-1066` — `HUF_fillDTableX2Level2()`.
///
/// `rankVal` is the C's `rankValOrigin[nbBits]` row; `rankStart` is
/// `wksp->rankStart0`, indexed exactly as the C indexes it.
///
/// # Safety
///
/// `dt` must point at `cap` writable `HUF_DEltX2`s.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
unsafe fn HUF_fillDTableX2Level2(
    dt: *mut HUF_DEltX2,
    cap: usize,
    base: usize,
    targetLog: u32,
    consumedBits: u32,
    rankVal: &[u32],
    minWeight: i32,
    maxWeight1: i32,
    sortedSymbols: &[u8],
    rankStart: &[u32],
    nbBitsBaseline: u32,
    baseSeq: u16,
) {
    // Fill skipped values (all positions up to rankVal[minWeight]). These
    // positions only get a single symbol because the combined weight is too
    // large.
    if minWeight > 1 {
        let length: usize = 1usize.wrapping_shl(targetLog.wrapping_sub(consumedBits) & 0x1F);
        let DEltX2 = HUF_buildDEltX2U64(baseSeq as u32, consumedBits, /* baseSeq */ 0, /* level */ 1);
        let skipSize: usize = rankVal[minWeight as usize] as usize;
        // assert(length > 1); assert((U32)skipSize < length)
        match length {
            2 => {
                // assert(skipSize == 1)
                // SAFETY: class C (construction). `base .. base + length` is
                // the region the caller reserved for this second-level table.
                unsafe { dtx2_set2(dt, cap, base, DEltX2) };
            }
            4 => {
                // assert(skipSize <= 4)
                // SAFETY: class C (construction). As above.
                unsafe {
                    dtx2_set2(dt, cap, base, DEltX2);
                    dtx2_set2(dt, cap, base + 2, DEltX2);
                }
            }
            _ => {
                let mut i: usize = 0;
                while i < skipSize {
                    // SAFETY: class C (construction). As above. `skipSize <
                    // length` and `length` is a multiple of 8 in this arm, so
                    // the round-up to `i + 8` stays inside the reservation --
                    // that over-write of up to 7 entries past `skipSize` is
                    // deliberate in the C and is kept.
                    unsafe {
                        dtx2_set2(dt, cap, base + i, DEltX2);
                        dtx2_set2(dt, cap, base + i + 2, DEltX2);
                        dtx2_set2(dt, cap, base + i + 4, DEltX2);
                        dtx2_set2(dt, cap, base + i + 6, DEltX2);
                    }
                    i += 8;
                }
            }
        }
    }

    // Fill each of the second level symbols by weight.
    {
        let mut w = minWeight;
        while w < maxWeight1 {
            let begin = rankStart[w as usize] as usize;
            let end = rankStart[(w + 1) as usize] as usize;
            let nbBits = nbBitsBaseline.wrapping_sub(w as u32);
            let totalBits = nbBits.wrapping_add(consumedBits);
            // SAFETY: class C (construction). Preconditions forwarded; the
            // rank base is inside the caller's reservation.
            unsafe {
                HUF_fillDTableX2ForWeight(
                    dt,
                    cap,
                    base + rankVal[w as usize] as usize,
                    sortedSymbols,
                    begin,
                    end,
                    totalBits,
                    targetLog,
                    baseSeq,
                    /* level */ 2,
                )
            };
            w += 1;
        }
    }
}

/// `huf_decompress.c:1121` — `HUF_fillDTableX2()`.
///
/// # Safety
///
/// `dt` must point at `cap` writable `HUF_DEltX2`s.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
unsafe fn HUF_fillDTableX2(
    dt: *mut HUF_DEltX2,
    cap: usize,
    targetLog: u32,
    sortedList: &[u8],
    rankStart: &[u32],
    rankValOrigin: &[rankValCol_t; HUF_TABLELOG_MAX],
    maxWeight: u32,
    nbBitsBaseline: u32,
) {
    let rankVal = &rankValOrigin[0];
    // note : targetLog >= srcLog, hence scaleLog <= 1
    let scaleLog: i32 = nbBitsBaseline as i32 - targetLog as i32;
    let minBits: u32 = nbBitsBaseline.wrapping_sub(maxWeight);
    let wEnd: i32 = maxWeight as i32 + 1;

    // Fill DTable in order of weight.
    let mut w: i32 = 1;
    while w < wEnd {
        // The C passes `wksp->rankStart0` here, NOT the `+ 1` view used while
        // sorting, so `rankStart[w]` is the *begin* of rank w -- the sort loop
        // left `rankStart0[w + 1]` holding the end of rank w. Indexed exactly
        // as the C does.
        let begin = rankStart[w as usize] as usize;
        let end = rankStart[(w + 1) as usize] as usize;
        let nbBits: u32 = nbBitsBaseline.wrapping_sub(w as u32);

        if targetLog.wrapping_sub(nbBits) >= minBits {
            // Enough room for a second symbol.
            let mut start: usize = rankVal[w as usize] as usize;
            let length: usize = 1usize.wrapping_shl(targetLog.wrapping_sub(nbBits) & 0x1F);
            let mut minWeight: i32 = nbBits as i32 + scaleLog;
            if minWeight < 1 {
                minWeight = 1;
            }
            // Fill the DTable for every symbol of weight w. These symbols get
            // at least 1 second symbol.
            //
            // `rankValOrigin[nbBits]` is in range because this branch requires
            // `nbBits <= targetLog - minBits <= HUF_TABLELOG_MAX - 1 == 11`,
            // and `rankValOrigin` has HUF_TABLELOG_MAX (12) rows. The slice
            // index checks it.
            for s in begin..end {
                // SAFETY: class C (construction). Preconditions forwarded.
                unsafe {
                    HUF_fillDTableX2Level2(
                        dt,
                        cap,
                        start,
                        targetLog,
                        nbBits,
                        &rankValOrigin[nbBits as usize],
                        minWeight,
                        wEnd,
                        sortedList,
                        rankStart,
                        nbBitsBaseline,
                        sortedList[s] as u16,
                    )
                };
                start += length;
            }
        } else {
            // Only a single symbol.
            // SAFETY: class C (construction). Preconditions forwarded.
            unsafe {
                HUF_fillDTableX2ForWeight(
                    dt,
                    cap,
                    rankVal[w as usize] as usize,
                    sortedList,
                    begin,
                    end,
                    nbBits,
                    targetLog,
                    /* baseSeq */ 0,
                    /* level */ 1,
                )
            };
        }
        w += 1;
    }
}

/// `huf_decompress.c:1167-1174` — `HUF_ReadDTableX2_Workspace`.
#[repr(C)]
struct HUF_ReadDTableX2_Workspace {
    rankVal: [rankValCol_t; HUF_TABLELOG_MAX],
    rankStats: [u32; HUF_TABLELOG_MAX + 1],
    rankStart0: [u32; HUF_TABLELOG_MAX + 3],
    sortedSymbol: [u8; HUF_SYMBOLVALUE_MAX + 1],
    weightList: [u8; HUF_SYMBOLVALUE_MAX + 1],
    calleeWksp: [u32; HUF_READ_STATS_WORKSPACE_SIZE_U32],
}

const _: () = assert!(
    HUF_DECOMPRESS_WORKSPACE_SIZE >= core::mem::size_of::<HUF_ReadDTableX2_Workspace>()
);
// As above: offsets 0/624/676/736/992/1248, no padding anywhere.
const _: () = assert!(core::mem::size_of::<HUF_ReadDTableX2_Workspace>() == 2124);
const _: () = assert!(core::mem::align_of::<HUF_ReadDTableX2_Workspace>() == 4);

/// `huf_decompress.c:1176` — `HUF_readDTableX2_wksp()`.
///
/// # Safety
///
/// As [`HUF_readDTableX1_wksp`], with `HUF_ReadDTableX2_Workspace` in place of
/// `HUF_ReadDTableX1_Workspace`.
#[no_mangle]
pub unsafe extern "C" fn HUF_readDTableX2_wksp(
    DTable: *mut u32,
    src: *const c_void,
    srcSize: usize,
    workSpace: *mut c_void,
    wkspSize: usize,
    flags: c_int,
) -> usize {
    let mut tableLog: u32 = 0;
    let mut nbSymbols: u32 = 0;
    let iSize: usize;
    // SAFETY: class B (boundary). Word 0 of the caller's table.
    let mut dtd = unsafe { HUF_getDTableDesc(DTable) };
    let mut maxTableLog: u32 = dtd.maxTableLog as u32;
    // SAFETY: class C (construction). One word past the header.
    let dt = unsafe { DTable.add(1) } as *mut HUF_DEltX2;
    // The table region behind the header is `HUF_DTABLE_SIZE(dtd.maxTableLog)`
    // minus the header word, i.e. `1 << dtd.maxTableLog` U32s, and
    // `sizeof(HUF_DEltX2) == sizeof(HUF_DTable)`. `dtd.maxTableLog` rather
    // than the possibly-reduced `maxTableLog` below, because this is the
    // *allocation* bound, which is what a memory-safety check wants.
    let dtCap: usize = 1usize.wrapping_shl(dtd.maxTableLog as u32);

    // NOTE: a DIFFERENT error code from HUF_readDTableX1_wksp, which returns
    // tableLog_tooLarge for the same condition (`huf_decompress.c:1186` vs
    // `:390`). Transcribed, not fixed.
    if core::mem::size_of::<HUF_ReadDTableX2_Workspace>() > wkspSize {
        return ERROR(ZSTD_error_GENERIC);
    }
    // SAFETY: class B (boundary). As in `HUF_readDTableX1_wksp`: the size
    // check above is the C's own, and the 4-byte alignment is this function's
    // documented precondition.
    let wksp = unsafe { &mut *(workSpace as *mut HUF_ReadDTableX2_Workspace) };

    // `rankStart = wksp->rankStart0 + 1`. Kept as an explicit `+ 1` on every
    // index rather than a sub-slice, so that the places where the C passes the
    // UNSHIFTED `rankStart0` to HUF_fillDTableX2 stay visibly different.
    wksp.rankStats = [0; HUF_TABLELOG_MAX + 1];
    wksp.rankStart0 = [0; HUF_TABLELOG_MAX + 3];

    if maxTableLog > HUF_TABLELOG_MAX as u32 {
        return ERROR(ZSTD_error_tableLog_tooLarge);
    }
    // ZSTD_memset(weightList, 0, sizeof(weightList)) is not necessary, even
    // though some analyzer complain ...

    {
        let wl = wksp.weightList.as_mut_ptr();
        let rs = wksp.rankStats.as_mut_ptr();
        let cw = wksp.calleeWksp.as_mut_ptr();
        let cwSize = core::mem::size_of_val(&wksp.calleeWksp);
        // SAFETY: class B (boundary). As in `HUF_readDTableX1_wksp`;
        // `rankStats` is the 13-U32 array `huf.h:178` requires and
        // `calleeWksp` is `[u32; 219]`, 4-byte aligned.
        iSize = unsafe {
            HUF_readStats_wksp(
                wl,
                HUF_SYMBOLVALUE_MAX + 1,
                rs,
                &mut nbSymbols,
                &mut tableLog,
                src,
                srcSize,
                cw as *mut c_void,
                cwSize,
                flags,
            )
        };
    }
    if ERR_isError(iSize) {
        return iSize;
    }

    // check result
    if tableLog > maxTableLog {
        return ERROR(ZSTD_error_tableLog_tooLarge); // DTable can't fit code depth
    }
    if tableLog <= HUF_DECODER_FAST_TABLELOG && maxTableLog > HUF_DECODER_FAST_TABLELOG {
        maxTableLog = HUF_DECODER_FAST_TABLELOG;
    }

    // find maxWeight
    // The C is `for (maxW = tableLog; wksp->rankStats[maxW]==0; maxW--) {}`
    // with the comment "necessarily finds a solution before 0" -- which holds
    // because `HUF_readStats()` guarantees `rankStats[1] >= 2`. The `maxW > 0`
    // guard added here cannot change the result; it exists so that a broken
    // guarantee is a wrong answer rather than a `maxW` of `u32::MAX` and a
    // panicking index. See the report's OOB list, item 6.
    let mut maxW: u32 = tableLog;
    while maxW > 0 && wksp.rankStats[maxW as usize] == 0 {
        maxW -= 1;
    }

    // Get start index of each weight
    {
        let mut nextRankStart: u32 = 0;
        for w in 1..(maxW + 1) {
            let curr = nextRankStart;
            nextRankStart += wksp.rankStats[w as usize];
            wksp.rankStart0[w as usize + 1] = curr;
        }
        // put all 0w symbols at the end of sorted list
        wksp.rankStart0[1] = nextRankStart;
        wksp.rankStart0[maxW as usize + 2] = nextRankStart;
    }

    // sort symbols by weight
    {
        for s in 0..nbSymbols as usize {
            let w = wksp.weightList[s] as usize;
            let r = wksp.rankStart0[w + 1] as usize;
            wksp.rankStart0[w + 1] += 1;
            wksp.sortedSymbol[r] = s as u8;
        }
        // forget 0w symbols; this is beginning of weight(1)
        wksp.rankStart0[1] = 0;
    }

    // Build rankVal
    {
        {
            // tableLog <= maxTableLog, so `rescale` is >= -1
            let rescale: i32 = (maxTableLog as i32 - tableLog as i32) - 1;
            let mut nextRankVal: u32 = 0;
            for w in 1..(maxW + 1) {
                let curr = nextRankVal;
                nextRankVal = nextRankVal.wrapping_add(
                    wksp.rankStats[w as usize].wrapping_shl((w as i32 + rescale) as u32),
                );
                wksp.rankVal[0][w as usize] = curr;
            }
        }
        {
            let minBits: u32 = tableLog + 1 - maxW;
            let mut consumed: u32 = minBits;
            while consumed < maxTableLog - minBits + 1 {
                let rankVal0 = wksp.rankVal[0];
                let rankValPtr = &mut wksp.rankVal[consumed as usize];
                for w in 1..(maxW + 1) {
                    rankValPtr[w as usize] = rankVal0[w as usize] >> consumed;
                }
                consumed += 1;
            }
        }
    }

    // SAFETY: class C (construction). `dt` names the `dtCap` `HUF_DEltX2`s
    // behind the table header; `sortedSymbol`, `rankStart0` and `rankVal` are
    // this function's own workspace, filled in above.
    unsafe {
        HUF_fillDTableX2(
            dt,
            dtCap,
            maxTableLog,
            &wksp.sortedSymbol,
            &wksp.rankStart0,
            &wksp.rankVal,
            maxW,
            tableLog + 1,
        )
    };

    dtd.tableLog = maxTableLog as u8;
    dtd.tableType = 1;
    // SAFETY: class B (boundary). Word 0 of the caller's table.
    unsafe { HUF_setDTableDesc(DTable, dtd) };
    iSize
}

/// `huf_decompress.c:1262-1263` — `HUF_decodeSymbolX2()`.
///
/// `FORCE_INLINE_TEMPLATE` in the C.
///
/// # Safety
///
/// `op .. oend` must be a writable range of the output buffer and `dt` must
/// point at `dtCap` readable `HUF_DEltX2`s.
#[inline(always)]
unsafe fn HUF_decodeSymbolX2(
    op: *mut u8,
    oend: *const u8,
    DStream: &mut BitDStream,
    dt: *const HUF_DEltX2,
    dtCap: usize,
    dtLog: u32,
) -> u32 {
    // note : dtLog >= 1
    let val = BIT_lookBitsFast(DStream, dtLog);
    // SAFETY: class C (construction). `BIT_lookBitsFast()` masks to `dtLog`
    // bits, so `val < (1 << dtLog) == dtCap` for every table this file built.
    let d = unsafe { dtx2_get(dt, dtCap, val) };
    // `ZSTD_memcpy(op, &dt[val].sequence, 2)` is a byte copy of the `U16`'s
    // representation, i.e. `put_unaligned()` at native endianness -- NOT
    // `put_unaligned_le16()`.
    // SAFETY: class C (construction). Every call site guards `op + 2 <= oend`
    // (the `p < pEnd - 3`, `p < pEnd - 9`, `p <= pEnd - 2` and `op4 < olimit`
    // conditions); `out_write2` asserts it.
    unsafe { out_write2(op, oend, d.sequence) };
    BIT_skipBits(DStream, d.nbBits as u32);
    d.length as u32
}

/// `huf_decompress.c:1271-1272` — `HUF_decodeLastSymbolX2()`.
///
/// # Safety
///
/// As [`HUF_decodeSymbolX2`], except that only **one** byte is written.
#[inline(always)]
unsafe fn HUF_decodeLastSymbolX2(
    op: *mut u8,
    oend: *const u8,
    DStream: &mut BitDStream,
    dt: *const HUF_DEltX2,
    dtCap: usize,
    dtLog: u32,
) -> u32 {
    // note : dtLog >= 1
    let val = BIT_lookBitsFast(DStream, dtLog);
    // SAFETY: class C (construction). As `HUF_decodeSymbolX2`.
    let d = unsafe { dtx2_get(dt, dtCap, val) };
    // `ZSTD_memcpy(op, &dt[val].sequence, 1)` copies the FIRST BYTE of the
    // `U16`'s representation -- the low byte on a little-endian target, the
    // high byte on a big-endian one. `to_ne_bytes()[0]` is exactly that.
    // SAFETY: class C (construction). The single call site guards `p < pEnd`.
    unsafe { out_write1(op, oend, d.sequence.to_ne_bytes()[0]) };
    if d.length == 1 {
        BIT_skipBits(DStream, d.nbBits as u32);
    } else if DStream.bitsConsumed < SIZE_BITS {
        BIT_skipBits(DStream, d.nbBits as u32);
        if DStream.bitsConsumed > SIZE_BITS {
            // ugly hack; works only because it's the last symbol. Note : can't
            // easily extract nbBits from just this symbol
            DStream.bitsConsumed = SIZE_BITS;
        }
    }
    1
}

/// `huf_decompress.c:1304-1305` — `HUF_decodeStreamX2()`. `HINT_INLINE` in the C.
///
/// # Safety
///
/// As [`HUF_decodeStreamX1`], with `HUF_DEltX2`.
#[inline(always)]
unsafe fn HUF_decodeStreamX2(
    p: *mut u8,
    bitDPtr: &mut BitDStream,
    pEnd: *mut u8,
    dt: *const HUF_DEltX2,
    dtCap: usize,
    dtLog: u32,
) -> usize {
    let pStart = p;
    let mut p = p;

    // `HUF_DECODE_SYMBOLX2_0` (`huf_decompress.c:1289`).
    macro_rules! X2_0 {
        () => {{
            // SAFETY: class C (construction). See `HUF_decodeSymbolX2`; the
            // enclosing loop guards `p + 2 <= pEnd`.
            let n = unsafe { HUF_decodeSymbolX2(p, pEnd, bitDPtr, dt, dtCap, dtLog) };
            p = p.wrapping_add(n as usize);
        }};
    }
    // `HUF_DECODE_SYMBOLX2_1` -- constant-true, HUF_TABLELOG_MAX is 12.
    macro_rules! X2_1 {
        () => {
            if MEM_64BITS || HUF_TABLELOG_MAX <= 12 {
                X2_0!();
            }
        };
    }
    // `HUF_DECODE_SYMBOLX2_2`.
    macro_rules! X2_2 {
        () => {
            if MEM_64BITS {
                X2_0!();
            }
        };
    }

    // up to 8 symbols at a time
    if (pEnd as usize).wrapping_sub(p as usize) >= SIZE_BYTES {
        if dtLog <= 11 && MEM_64BITS {
            // up to 10 symbols at a time
            while BIT_reloadDStream(bitDPtr) == BIT_DStream_status::unfinished
                && p < pEnd.wrapping_sub(9)
            {
                X2_0!();
                X2_0!();
                X2_0!();
                X2_0!();
                X2_0!();
            }
        } else {
            // up to 8 symbols at a time
            while BIT_reloadDStream(bitDPtr) == BIT_DStream_status::unfinished
                && p < pEnd.wrapping_sub(SIZE_BYTES - 1)
            {
                X2_2!();
                X2_1!();
                X2_2!();
                X2_0!();
            }
        }
    } else {
        BIT_reloadDStream(bitDPtr);
    }

    // closer to end : up to 2 symbols at a time
    if (pEnd as usize).wrapping_sub(p as usize) >= 2 {
        while BIT_reloadDStream(bitDPtr) == BIT_DStream_status::unfinished
            && p <= pEnd.wrapping_sub(2)
        {
            X2_0!();
        }

        // no need to reload : reached the end of DStream
        while p <= pEnd.wrapping_sub(2) {
            X2_0!();
        }
    }

    if p < pEnd {
        // SAFETY: class C (construction). `p < pEnd` was just checked and
        // `HUF_decodeLastSymbolX2` writes exactly one byte.
        let n = unsafe { HUF_decodeLastSymbolX2(p, pEnd, bitDPtr, dt, dtCap, dtLog) };
        p = p.wrapping_add(n as usize);
    }

    (p as usize).wrapping_sub(pStart as usize)
}

/// `huf_decompress.c:1349-1350` — `HUF_decompress1X2_usingDTable_internal_body()`.
///
/// # Safety
///
/// As [`HUF_decompress1X1_usingDTable_internal_body`].
#[inline(always)]
unsafe fn HUF_decompress1X2_usingDTable_internal_body(
    dst: *mut c_void,
    dstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    DTable: *const u32,
) -> usize {
    let mut bitD = BitDStream {
        bitContainer: 0,
        bitsConsumed: 0,
        ptr: core::ptr::null(),
        start: core::ptr::null(),
        limitPtr: core::ptr::null(),
        src_size: 0,
    };

    // Init
    // CHECK_F(BIT_initDStream(&bitD, cSrc, cSrcSize))
    {
        // SAFETY: class C (construction). `cSrc`/`cSrcSize` are the caller's.
        let e = unsafe { BIT_initDStream(&mut bitD, cSrc as *const u8, cSrcSize) };
        if ERR_isError(e) {
            return e;
        }
    }

    // decode
    {
        let ostart = dst as *mut u8;
        let oend = ZSTD_maybeNullPtrAdd(ostart, dstSize as isize);
        // SAFETY: class C (construction). One word past the header.
        let dt = unsafe { DTable.add(1) } as *const HUF_DEltX2;
        // SAFETY: class B (boundary). Word 0 of the caller's table.
        let dtd = unsafe { HUF_getDTableDesc(DTable) };
        let dtCap: usize = 1usize.wrapping_shl(dtd.tableLog as u32);
        // SAFETY: class C (construction). `ostart .. oend` is the caller's
        // output buffer.
        unsafe {
            HUF_decodeStreamX2(ostart, &mut bitD, oend, dt, dtCap, dtd.tableLog as u32)
        };
    }

    // check
    if BIT_endOfDStream(&bitD) == 0 {
        return ERROR(ZSTD_error_corruption_detected);
    }

    // decoded size
    dstSize
}

/// `huf_decompress.c:1380-1381` — `HUF_decompress4X2_usingDTable_internal_body()`.
///
/// Conditions: `dstSize >= 6`.
///
/// # Safety
///
/// As [`HUF_decompress1X1_usingDTable_internal_body`].
#[inline(always)]
unsafe fn HUF_decompress4X2_usingDTable_internal_body(
    dst: *mut c_void,
    dstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    DTable: *const u32,
) -> usize {
    if cSrcSize < 10 {
        // strict minimum : jump table + 1 byte per stream
        return ERROR(ZSTD_error_corruption_detected);
    }
    if dstSize < 6 {
        // stream 4-split doesn't work
        return ERROR(ZSTD_error_corruption_detected);
    }

    {
        let istart = cSrc as *const u8;
        let ostart = dst as *mut u8;
        let oend = ostart.wrapping_add(dstSize);
        let olimit = oend.wrapping_sub(SIZE_BYTES - 1);
        // SAFETY: class C (construction). One word past the header.
        let dt = unsafe { DTable.add(1) } as *const HUF_DEltX2;

        // Init
        // SAFETY: class C (construction). `cSrcSize >= 10` was checked.
        let length1 = unsafe { MEM_readLE16(istart) } as usize;
        let length2 = unsafe { MEM_readLE16(istart.add(2)) } as usize;
        let length3 = unsafe { MEM_readLE16(istart.add(4)) } as usize;
        let length4 = cSrcSize.wrapping_sub(length1 + length2 + length3 + 6);
        let istart1 = istart.wrapping_add(6); // jumpTable
        let istart2 = istart1.wrapping_add(length1);
        let istart3 = istart2.wrapping_add(length2);
        let istart4 = istart3.wrapping_add(length3);
        let segmentSize = (dstSize + 3) / 4;
        let opStart2 = ostart.wrapping_add(segmentSize);
        let opStart3 = opStart2.wrapping_add(segmentSize);
        let opStart4 = opStart3.wrapping_add(segmentSize);
        let mut op1 = ostart;
        let mut op2 = opStart2;
        let mut op3 = opStart3;
        let mut op4 = opStart4;
        let mut endSignal: u32 = 1;
        // SAFETY: class B (boundary). Word 0 of the caller's table.
        let dtd = unsafe { HUF_getDTableDesc(DTable) };
        let dtLog = dtd.tableLog as u32;
        let dtCap: usize = 1usize.wrapping_shl(dtLog);

        if length4 > cSrcSize {
            return ERROR(ZSTD_error_corruption_detected); // overflow
        }
        if opStart4 > oend {
            return ERROR(ZSTD_error_corruption_detected); // overflow
        }
        // assert(dstSize >= 6) -- validated above

        let mk = || BitDStream {
            bitContainer: 0,
            bitsConsumed: 0,
            ptr: core::ptr::null(),
            start: core::ptr::null(),
            limitPtr: core::ptr::null(),
            src_size: 0,
        };
        let mut bitD1 = mk();
        let mut bitD2 = mk();
        let mut bitD3 = mk();
        let mut bitD4 = mk();

        // SAFETY: class C (construction). As in the X1 body: the four
        // sub-buffers tile `cSrc[6 .. cSrcSize]`.
        for (bd, ist, len) in [
            (&mut bitD1, istart1, length1),
            (&mut bitD2, istart2, length2),
            (&mut bitD3, istart3, length3),
            (&mut bitD4, istart4, length4),
        ] {
            let e = unsafe { BIT_initDStream(bd, ist, len) };
            if ERR_isError(e) {
                return e;
            }
        }

        macro_rules! X2_0 {
            ($op:ident, $bd:ident) => {{
                // SAFETY: class C (construction). The loop guard is
                // `op4 < olimit == oend - 7` and each of the four decodes
                // advances an `op` by at most 2, so every write of 2 bytes
                // starts at or before `oend - 2`; `out_write2` asserts it.
                let n = unsafe { HUF_decodeSymbolX2($op, oend, &mut $bd, dt, dtCap, dtLog) };
                $op = $op.wrapping_add(n as usize);
            }};
        }
        macro_rules! X2_1 {
            ($op:ident, $bd:ident) => {
                if MEM_64BITS || HUF_TABLELOG_MAX <= 12 {
                    X2_0!($op, $bd);
                }
            };
        }
        macro_rules! X2_2 {
            ($op:ident, $bd:ident) => {
                if MEM_64BITS {
                    X2_0!($op, $bd);
                }
            };
        }

        // 16-32 symbols per loop (4-8 symbols per stream)
        //
        // The C has a `#if defined(__clang__) && (x86_64 || i386)` variant that
        // interleaves the reloads differently. The kernel builds this with GCC,
        // so the `#else` arm is the one compiled and the one transcribed. The
        // two arms decode the same symbols in the same order; they differ only
        // in when `endSignal` is folded, which changes nothing observable.
        if (oend as usize).wrapping_sub(op4 as usize) >= SIZE_BYTES {
            while endSignal != 0 && op4 < olimit {
                X2_2!(op1, bitD1);
                X2_2!(op2, bitD2);
                X2_2!(op3, bitD3);
                X2_2!(op4, bitD4);
                X2_1!(op1, bitD1);
                X2_1!(op2, bitD2);
                X2_1!(op3, bitD3);
                X2_1!(op4, bitD4);
                X2_2!(op1, bitD1);
                X2_2!(op2, bitD2);
                X2_2!(op3, bitD3);
                X2_2!(op4, bitD4);
                X2_0!(op1, bitD1);
                X2_0!(op2, bitD2);
                X2_0!(op3, bitD3);
                X2_0!(op4, bitD4);
                // `LIKELY()` is a `__builtin_expect` hint with no semantics.
                endSignal = ((BIT_reloadDStreamFast(&mut bitD1)
                    == BIT_DStream_status::unfinished) as u32)
                    & ((BIT_reloadDStreamFast(&mut bitD2) == BIT_DStream_status::unfinished)
                        as u32)
                    & ((BIT_reloadDStreamFast(&mut bitD3) == BIT_DStream_status::unfinished)
                        as u32)
                    & ((BIT_reloadDStreamFast(&mut bitD4) == BIT_DStream_status::unfinished)
                        as u32);
            }
        }

        // check corruption
        if op1 > opStart2 {
            return ERROR(ZSTD_error_corruption_detected);
        }
        if op2 > opStart3 {
            return ERROR(ZSTD_error_corruption_detected);
        }
        if op3 > opStart4 {
            return ERROR(ZSTD_error_corruption_detected);
        }
        // note : op4 already verified within main loop

        // finish bitStreams one by one
        // SAFETY: class C (construction). Each `(op, segment end)` pair is
        // inside the caller's output buffer.
        unsafe {
            HUF_decodeStreamX2(op1, &mut bitD1, opStart2, dt, dtCap, dtLog);
            HUF_decodeStreamX2(op2, &mut bitD2, opStart3, dt, dtCap, dtLog);
            HUF_decodeStreamX2(op3, &mut bitD3, opStart4, dt, dtCap, dtLog);
            HUF_decodeStreamX2(op4, &mut bitD4, oend, dt, dtCap, dtLog);
        }

        // check
        {
            let endCheck = BIT_endOfDStream(&bitD1)
                & BIT_endOfDStream(&bitD2)
                & BIT_endOfDStream(&bitD3)
                & BIT_endOfDStream(&bitD4);
            if endCheck == 0 {
                return ERROR(ZSTD_error_corruption_detected);
            }
        }

        // decoded size
        dstSize
    }
}

/// `huf_decompress.c:1520-1521` — `HUF_decompress4X2_usingDTable_internal_fast_c_loop()`.
///
/// As with the X1 loop, `HUF_FAST_BMI2_ATTRS` is carried by the wrapper this
/// is inlined into rather than by this function.
///
/// # Safety
///
/// `args` must have been filled in by a successful
/// [`HUF_DecompressFastArgs_init`].
#[inline(always)]
unsafe fn HUF_decompress4X2_usingDTable_internal_fast_c_loop(args: &mut HUF_DecompressFastArgs) {
    // Copy the arguments to local registers.
    let mut bits: [u64; 4] = args.bits;
    let mut ip: [*const u8; 4] = args.ip;
    let mut op: [*mut u8; 4] = args.op;
    let dtable = args.dt as *const HUF_DEltX2;
    let ilowest = args.ilowest;
    let src_end = args.src_end;

    let oendv: [*mut u8; 4] = [op[1], op[2], op[3], args.oend];

    // As in the X1 loop: `dtLog == HUF_DECODER_FAST_TABLELOG` is what
    // `HUF_DecompressFastArgs_init()` checked before returning 1.
    const DTABLE_CAP: usize = 1usize << HUF_DECODER_FAST_TABLELOG;

    // assert(MEM_isLittleEndian()); assert(!MEM_32bits())

    loop {
        let olimit: *mut u8;

        // Compute olimit
        {
            // Each loop does 5 table lookups for each of the 4 streams. Each
            // table lookup consumes up to 11 bits of input, and produces up to
            // 2 bytes of output.
            //
            // We can consume up to 7 bytes of input per iteration per stream.
            // We also know that each input pointer is >= ip[0]. So we can run
            // iters loops before running out of input.
            let mut iters: usize = (ip[0] as usize).wrapping_sub(ilowest as usize) / 7;
            // Each iteration can produce up to 10 bytes of output per stream.
            // Each output stream may advance at different rates. So take the
            // minimum number of safe iterations among all the output streams.
            for stream in 0..4 {
                let oiters: usize =
                    (oendv[stream] as usize).wrapping_sub(op[stream] as usize) / 10;
                iters = core::cmp::min(iters, oiters);
            }

            // Each iteration produces at least 5 output symbols. So until
            // op[3] crosses olimit, we know we haven't executed iters
            // iterations yet.
            olimit = op[3].wrapping_add(iters * 5);

            // Exit the fast decoding loop once we reach the end.
            if op[3] == olimit {
                break;
            }

            // Exit the decoding loop if any input pointer has crossed the
            // previous one. This indicates corruption, and a precondition to
            // our loop is that ip[i] >= ip[0].
            let mut crossed = false;
            for stream in 1..4 {
                if ip[stream] < ip[stream - 1] {
                    crossed = true;
                    break;
                }
            }
            if crossed {
                break;
            }
        }

        // `HUF_4X2_DECODE_SYMBOL` (`huf_decompress.c:1602`).
        macro_rules! DECODE_SYMBOL {
            ($stream:expr, $decode3:expr) => {{
                if $decode3 || $stream != 3 {
                    let index: usize = (bits[$stream] >> 53) as usize;
                    // SAFETY: class C (construction). `index < 2048` because
                    // `bits` is a `u64` shifted right by 53; `dtx2_get`
                    // asserts it against the table's real entry count.
                    let entry = unsafe { dtx2_get(dtable, DTABLE_CAP, index) };
                    // SAFETY: class C (construction). The `oiters` computation
                    // above guarantees `op[s] + 10 <= oend[s]` for the whole
                    // iteration, and this is at most the fifth 2-byte write of
                    // that iteration; `out_write2` asserts it.
                    unsafe { out_write2(op[$stream], oendv[$stream], entry.sequence) };
                    bits[$stream] = bits[$stream].wrapping_shl((entry.nbBits as u32) & 0x3F);
                    op[$stream] = op[$stream].wrapping_add(entry.length as usize);
                }
            }};
        }

        // `HUF_4X2_RELOAD_STREAM` (`huf_decompress.c:1613`). Note that it
        // begins by decoding one more symbol from stream 3 -- that is how
        // stream 3 gets its five symbols per iteration.
        macro_rules! RELOAD_STREAM {
            ($stream:expr) => {{
                DECODE_SYMBOL!(3, true);
                {
                    let ctz: u32 = ZSTD_countTrailingZeros64(bits[$stream]);
                    let nbBits: u32 = ctz & 7;
                    let nbBytes: usize = (ctz >> 3) as usize;
                    ip[$stream] = ip[$stream].wrapping_sub(nbBytes);
                    // SAFETY: class C (construction). `iters` bounded the loop
                    // so that `ip[i] >= ilowest` still holds, and `ip[i]` only
                    // decreases from its initial value of at most
                    // `src_end - 8`. `in_read64` asserts both ends.
                    bits[$stream] = unsafe { in_read64(ip[$stream], ilowest, src_end) } | 1;
                    bits[$stream] = bits[$stream].wrapping_shl(nbBits);
                }
            }};
        }

        // The C manually unrolls this loop; so does the Rust, for the same
        // reason and in the same order.
        loop {
            // Decode 5 symbols from each of the first 3 streams. The final
            // stream will be decoded during the reload phase to reduce
            // register pressure.
            DECODE_SYMBOL!(0, false);
            DECODE_SYMBOL!(1, false);
            DECODE_SYMBOL!(2, false);
            DECODE_SYMBOL!(3, false);
            DECODE_SYMBOL!(0, false);
            DECODE_SYMBOL!(1, false);
            DECODE_SYMBOL!(2, false);
            DECODE_SYMBOL!(3, false);
            DECODE_SYMBOL!(0, false);
            DECODE_SYMBOL!(1, false);
            DECODE_SYMBOL!(2, false);
            DECODE_SYMBOL!(3, false);
            DECODE_SYMBOL!(0, false);
            DECODE_SYMBOL!(1, false);
            DECODE_SYMBOL!(2, false);
            DECODE_SYMBOL!(3, false);
            DECODE_SYMBOL!(0, false);
            DECODE_SYMBOL!(1, false);
            DECODE_SYMBOL!(2, false);
            DECODE_SYMBOL!(3, false);

            // Decode one symbol from the final stream
            DECODE_SYMBOL!(3, true);

            // Decode 4 symbols from the final stream & reload bitstreams. The
            // final stream is reloaded last, meaning that all 5 symbols are
            // decoded from the final stream before it is reloaded.
            RELOAD_STREAM!(0);
            RELOAD_STREAM!(1);
            RELOAD_STREAM!(2);
            RELOAD_STREAM!(3);

            if op[3] >= olimit {
                break;
            }
        }
    }

    // Save the final values of each of the state variables back to args.
    args.bits = bits;
    args.ip = ip;
    args.op = op;
}

/// `huf_decompress.c:1662-1664` — `HUF_decompress4X2_usingDTable_internal_fast()`.
///
/// # Safety
///
/// As [`HUF_decompress1X1_usingDTable_internal_body`].
#[inline(always)]
unsafe fn HUF_decompress4X2_usingDTable_internal_fast_body(
    dst: *mut c_void,
    dstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    DTable: *const u32,
) -> usize {
    // SAFETY: class C (construction). One word past the header.
    let dt = unsafe { DTable.add(1) } as *const HUF_DEltX2;
    let oend = ZSTD_maybeNullPtrAdd(dst as *mut u8, dstSize as isize);

    let mut args = HUF_DecompressFastArgs {
        ip: [core::ptr::null(); 4],
        op: [core::ptr::null_mut(); 4],
        bits: [0; 4],
        dt: core::ptr::null(),
        ilowest: core::ptr::null(),
        oend: core::ptr::null_mut(),
        iend: [core::ptr::null(); 4],
        src_end: core::ptr::null(),
    };
    {
        // SAFETY: class C (construction). The caller's buffers, forwarded.
        let ret = unsafe {
            HUF_DecompressFastArgs_init(&mut args, dst, dstSize, cSrc, cSrcSize, DTable)
        };
        // FORWARD_IF_ERROR(ret, "Failed to init asm args")
        if ERR_isError(ret) {
            return ret;
        }
        if ret == 0 {
            return 0;
        }
    }

    // SAFETY: class C (construction). `args` was just filled in by a
    // successful `HUF_DecompressFastArgs_init()`.
    unsafe { HUF_decompress4X2_usingDTable_internal_fast_c_loop(&mut args) };

    // note : op4 already verified within main loop. (The C's asserts here are
    // compiled out at DEBUGLEVEL 0.)

    // finish bitStreams one by one
    {
        let segmentSize = (dstSize + 3) / 4;
        let mut segmentEnd = dst as *mut u8;
        for i in 0..4usize {
            let mut bit = BitDStream {
                bitContainer: 0,
                bitsConsumed: 0,
                ptr: core::ptr::null(),
                start: core::ptr::null(),
                limitPtr: core::ptr::null(),
                src_size: 0,
            };
            if segmentSize <= (oend as usize).wrapping_sub(segmentEnd as usize) {
                segmentEnd = segmentEnd.wrapping_add(segmentSize);
            } else {
                segmentEnd = oend;
            }
            {
                let e = HUF_initRemainingDStream(&mut bit, &args, i, segmentEnd);
                if ERR_isError(e) {
                    return e;
                }
            }
            // SAFETY: class C (construction). `args.op[i] <= segmentEnd <= oend`
            // and `dt` has `1 << HUF_DECODER_FAST_TABLELOG` entries.
            let n = unsafe {
                HUF_decodeStreamX2(
                    args.op[i],
                    &mut bit,
                    segmentEnd,
                    dt,
                    1usize << HUF_DECODER_FAST_TABLELOG,
                    HUF_DECODER_FAST_TABLELOG,
                )
            };
            args.op[i] = args.op[i].wrapping_add(n);
            if args.op[i] != segmentEnd {
                return ERROR(ZSTD_error_corruption_detected);
            }
        }
    }

    // decoded size
    dstSize
}

// --- HUF_DGEN(HUF_decompress1X2_usingDTable_internal) and the 4X2 dispatch ---

/// `HUF_decompress1X2_usingDTable_internal_default()`.
///
/// # Safety
///
/// As [`HUF_decompress1X1_usingDTable_internal_body`].
unsafe fn HUF_decompress1X2_usingDTable_internal_default(
    dst: *mut c_void,
    dstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    DTable: *const u32,
) -> usize {
    // SAFETY: class C (construction). Preconditions forwarded unchanged.
    unsafe { HUF_decompress1X2_usingDTable_internal_body(dst, dstSize, cSrc, cSrcSize, DTable) }
}

/// `HUF_decompress1X2_usingDTable_internal_bmi2()`, under `#if DYNAMIC_BMI2`.
///
/// # Safety
///
/// As [`HUF_decompress1X1_usingDTable_internal_body`], **and** the CPU must
/// support LZCNT, BMI1 and BMI2.
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "bmi2")))]
#[target_feature(enable = "lzcnt,bmi1,bmi2")]
unsafe fn HUF_decompress1X2_usingDTable_internal_bmi2(
    dst: *mut c_void,
    dstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    DTable: *const u32,
) -> usize {
    // SAFETY: class C (construction). Preconditions forwarded unchanged; the
    // body is inlined here with this function's target features.
    unsafe { HUF_decompress1X2_usingDTable_internal_body(dst, dstSize, cSrc, cSrcSize, DTable) }
}

/// `HUF_decompress1X2_usingDTable_internal()` — the `HUF_DGEN` dispatcher.
///
/// # Safety
///
/// As [`HUF_decompress1X1_usingDTable_internal_body`].
unsafe fn HUF_decompress1X2_usingDTable_internal(
    dst: *mut c_void,
    dstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    DTable: *const u32,
    flags: c_int,
) -> usize {
    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "bmi2")))]
    if (flags & HUF_flags_bmi2) != 0 {
        // SAFETY: class A (axiom). The ISA boundary; see
        // `HUF_decompress1X1_usingDTable_internal`.
        return unsafe {
            HUF_decompress1X2_usingDTable_internal_bmi2(dst, dstSize, cSrc, cSrcSize, DTable)
        };
    }
    let _ = flags; // (void)flags
    // SAFETY: class C (construction). Preconditions forwarded unchanged.
    unsafe { HUF_decompress1X2_usingDTable_internal_default(dst, dstSize, cSrc, cSrcSize, DTable) }
}

/// `huf_decompress.c:1508-1509` —
/// `HUF_decompress4X2_usingDTable_internal_default()`.
///
/// # Safety
///
/// As [`HUF_decompress1X1_usingDTable_internal_body`].
unsafe fn HUF_decompress4X2_usingDTable_internal_default(
    dst: *mut c_void,
    dstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    DTable: *const u32,
) -> usize {
    // SAFETY: class C (construction). Preconditions forwarded unchanged.
    unsafe { HUF_decompress4X2_usingDTable_internal_body(dst, dstSize, cSrc, cSrcSize, DTable) }
}

/// `huf_decompress.c:1501-1502` —
/// `HUF_decompress4X2_usingDTable_internal_bmi2()`, under
/// `#if HUF_NEED_BMI2_FUNCTION`.
///
/// # Safety
///
/// As [`HUF_decompress1X1_usingDTable_internal_body`], **and** the CPU must
/// support LZCNT, BMI1 and BMI2.
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "bmi2")))]
#[target_feature(enable = "lzcnt,bmi1,bmi2")]
unsafe fn HUF_decompress4X2_usingDTable_internal_bmi2(
    dst: *mut c_void,
    dstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    DTable: *const u32,
) -> usize {
    // SAFETY: class C (construction). Preconditions forwarded unchanged; the
    // body is inlined here with this function's target features.
    unsafe { HUF_decompress4X2_usingDTable_internal_body(dst, dstSize, cSrc, cSrcSize, DTable) }
}

/// `huf_decompress.c:1662-1664` — the `HUF_FAST_BMI2_ATTRS` wrapper over
/// [`HUF_decompress4X2_usingDTable_internal_fast_body`].
///
/// # Safety
///
/// As [`HUF_decompress1X1_usingDTable_internal_body`], **and** the CPU must
/// support LZCNT, BMI1 and BMI2.
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "bmi2")))]
#[target_feature(enable = "lzcnt,bmi1,bmi2")]
unsafe fn HUF_decompress4X2_usingDTable_internal_fast(
    dst: *mut c_void,
    dstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    DTable: *const u32,
) -> usize {
    // SAFETY: class C (construction). Preconditions forwarded unchanged; the
    // body and the decode loop it calls are inlined here with this function's
    // target features.
    unsafe { HUF_decompress4X2_usingDTable_internal_fast_body(dst, dstSize, cSrc, cSrcSize, DTable) }
}

/// `huf_decompress.c:1662` — `HUF_FAST_BMI2_ATTRS` is empty when
/// `DYNAMIC_BMI2` is 0.
///
/// # Safety
///
/// As [`HUF_decompress1X1_usingDTable_internal_body`].
#[cfg(not(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "bmi2"))))]
unsafe fn HUF_decompress4X2_usingDTable_internal_fast(
    dst: *mut c_void,
    dstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    DTable: *const u32,
) -> usize {
    // SAFETY: class C (construction). Preconditions forwarded unchanged.
    unsafe { HUF_decompress4X2_usingDTable_internal_fast_body(dst, dstSize, cSrc, cSrcSize, DTable) }
}

/// `huf_decompress.c:1716` — `HUF_decompress4X2_usingDTable_internal()`,
/// `#if DYNAMIC_BMI2` arm.
///
/// # Safety
///
/// As [`HUF_decompress1X1_usingDTable_internal_body`].
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "bmi2")))]
unsafe fn HUF_decompress4X2_usingDTable_internal(
    dst: *mut c_void,
    dstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    DTable: *const u32,
    flags: c_int,
) -> usize {
    if (flags & HUF_flags_bmi2) == 0 {
        // SAFETY: class C (construction). Preconditions forwarded unchanged.
        return unsafe {
            HUF_decompress4X2_usingDTable_internal_default(dst, dstSize, cSrc, cSrcSize, DTable)
        };
    }
    if HUF_ENABLE_FAST_DECODE && (flags & HUF_flags_disableFast) == 0 {
        // SAFETY: class A (axiom). The ISA boundary; `HUF_flags_bmi2` was just
        // tested.
        let ret = unsafe {
            HUF_decompress4X2_usingDTable_internal_fast(dst, dstSize, cSrc, cSrcSize, DTable)
        };
        if ret != 0 {
            return ret;
        }
    }
    // SAFETY: class A (axiom). As above.
    unsafe { HUF_decompress4X2_usingDTable_internal_bmi2(dst, dstSize, cSrc, cSrcSize, DTable) }
}

/// `huf_decompress.c:1716` — `HUF_decompress4X2_usingDTable_internal()` with
/// `DYNAMIC_BMI2 == 0`.
///
/// # Safety
///
/// As [`HUF_decompress1X1_usingDTable_internal_body`].
#[cfg(not(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "bmi2"))))]
unsafe fn HUF_decompress4X2_usingDTable_internal(
    dst: *mut c_void,
    dstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    DTable: *const u32,
    flags: c_int,
) -> usize {
    if HUF_ENABLE_FAST_DECODE && (flags & HUF_flags_disableFast) == 0 {
        // SAFETY: class C (construction). Preconditions forwarded unchanged.
        let ret = unsafe {
            HUF_decompress4X2_usingDTable_internal_fast(dst, dstSize, cSrc, cSrcSize, DTable)
        };
        if ret != 0 {
            return ret;
        }
    }
    // SAFETY: class C (construction). Preconditions forwarded unchanged.
    unsafe { HUF_decompress4X2_usingDTable_internal_default(dst, dstSize, cSrc, cSrcSize, DTable) }
}

/// `huf_decompress.c:1751` — `HUF_decompress1X2_DCtx_wksp()`.
///
/// Dead in-tree, kept because `huf.h:259` still declares it.
///
/// # Safety
///
/// As [`HUF_readDTableX2_wksp`], plus `dst` pointing at `dstSize` writable
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn HUF_decompress1X2_DCtx_wksp(
    DCtx: *mut u32,
    dst: *mut c_void,
    dstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    workSpace: *mut c_void,
    wkspSize: usize,
    flags: c_int,
) -> usize {
    let ip = cSrc as *const u8;

    // SAFETY: class B (boundary). The C caller's buffers, forwarded unchanged.
    let hSize =
        unsafe { HUF_readDTableX2_wksp(DCtx, cSrc, cSrcSize, workSpace, wkspSize, flags) };
    if ERR_isError(hSize) {
        return hSize;
    }
    if hSize >= cSrcSize {
        return ERROR(ZSTD_error_srcSize_wrong);
    }
    // SAFETY: class C (construction). `hSize < cSrcSize` was just checked.
    let ip = unsafe { ip.add(hSize) };
    let cSrcSize = cSrcSize - hSize;

    // SAFETY: class C (construction). `DCtx` now holds a table this file just
    // built; `ip`/`cSrcSize` name the tail of the caller's input.
    unsafe {
        HUF_decompress1X2_usingDTable_internal(
            dst,
            dstSize,
            ip as *const c_void,
            cSrcSize,
            DCtx,
            flags,
        )
    }
}

/// `huf_decompress.c:1766` — `HUF_decompress4X2_DCtx_wksp()`.
///
/// # Safety
///
/// As [`HUF_decompress1X2_DCtx_wksp`].
unsafe fn HUF_decompress4X2_DCtx_wksp(
    dctx: *mut u32,
    dst: *mut c_void,
    dstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    workSpace: *mut c_void,
    wkspSize: usize,
    flags: c_int,
) -> usize {
    let ip = cSrc as *const u8;

    // SAFETY: class C (construction). The caller's buffers, forwarded.
    let hSize =
        unsafe { HUF_readDTableX2_wksp(dctx, cSrc, cSrcSize, workSpace, wkspSize, flags) };
    if ERR_isError(hSize) {
        return hSize;
    }
    if hSize >= cSrcSize {
        return ERROR(ZSTD_error_srcSize_wrong);
    }
    // SAFETY: class C (construction). `hSize < cSrcSize` was just checked.
    let ip = unsafe { ip.add(hSize) };
    let cSrcSize = cSrcSize - hSize;

    // SAFETY: class C (construction). As `HUF_decompress1X2_DCtx_wksp`.
    unsafe {
        HUF_decompress4X2_usingDTable_internal(
            dst,
            dstSize,
            ip as *const c_void,
            cSrcSize,
            dctx,
            flags,
        )
    }
}

// ===========================================================================
// huf_decompress.c:1776-1941 — universal decompression selectors
// ===========================================================================

/// `huf_decompress.c:1790` — `{ U32 tableTime; U32 decode256Time; }`.
#[derive(Clone, Copy)]
struct algo_time_t {
    tableTime: u32,
    decode256Time: u32,
}

/// `huf_decompress.c:1791` — `algoTime[16][2]`, `/* single, double */`.
static algoTime: [[algo_time_t; 2]; 16] = {
    const fn t(tableTime: u32, decode256Time: u32) -> algo_time_t {
        algo_time_t {
            tableTime,
            decode256Time,
        }
    }
    [
        [t(0, 0), t(1, 1)],       // Q==0 : impossible
        [t(0, 0), t(1, 1)],       // Q==1 : impossible
        [t(150, 216), t(381, 119)], // Q == 2 : 12-18%
        [t(170, 205), t(514, 112)], // Q == 3 : 18-25%
        [t(177, 199), t(539, 110)], // Q == 4 : 25-32%
        [t(197, 194), t(644, 107)], // Q == 5 : 32-38%
        [t(221, 192), t(735, 107)], // Q == 6 : 38-44%
        [t(256, 189), t(881, 106)], // Q == 7 : 44-50%
        [t(359, 188), t(1167, 109)], // Q == 8 : 50-56%
        [t(582, 187), t(1570, 114)], // Q == 9 : 56-62%
        [t(688, 187), t(1712, 122)], // Q ==10 : 62-69%
        [t(825, 186), t(1965, 136)], // Q ==11 : 69-75%
        [t(976, 185), t(2131, 150)], // Q ==12 : 75-81%
        [t(1180, 186), t(2070, 175)], // Q ==13 : 81-87%
        [t(1377, 185), t(1731, 202)], // Q ==14 : 87-93%
        [t(1412, 185), t(1695, 202)], // Q ==15 : 93-99%
    ]
};

/// `huf_decompress.c:1818` — `HUF_selectDecoder()`.
///
/// Tells which decoder is likely to decode faster, based on a set of
/// pre-computed metrics. Returns 0 for `HUF_decompress4X1`, 1 for
/// `HUF_decompress4X2`. Assumption: `0 < dstSize <= 128 KB`.
///
/// Dead in-tree (`nm` finds no reference outside this file), kept because
/// `huf.h` declares it and it is not `static` in the C.
#[no_mangle]
pub extern "C" fn HUF_selectDecoder(dstSize: usize, cSrcSize: usize) -> c_uint {
    // assert(dstSize > 0); assert(dstSize <= 128*1024) -- both compiled out at
    // DEBUGLEVEL 0.

    // decoder timing evaluation
    // `wrapping_mul`: the C computes `cSrcSize * 16` in `size_t`, which wraps
    // for `cSrcSize > 2^60`. Divergence 6. The division cannot be by zero:
    // `dstSize == 0` implies `cSrcSize >= dstSize` and takes the other arm.
    let Q: u32 = if cSrcSize >= dstSize {
        15
    } else {
        (cSrcSize.wrapping_mul(16) / dstSize) as u32
    };
    // Q < 16 whenever `cSrcSize * 16` did not wrap. The index below is
    // bounds-checked; see the report's OOB list, item 7 -- the C indexes
    // `algoTime[Q][...]` with no check at all.
    let D256: u32 = (dstSize >> 8) as u32;
    let a0 = algoTime[Q as usize][0];
    let a1 = algoTime[Q as usize][1];
    // `wrapping_*`: all four operands are C `U32`s. `decode256Time * D256`
    // overflows for `dstSize` above roughly 4.74 GiB (dstSize >= 5,090,331,648; the "2 MB" this comment first claimed was wrong by ~2500x -- max decode256Time is 216 and D256 = dstSize>>8, so overflow needs D256 >= 19,884,108), which the function's stated
    // assumption forbids. Divergence 6.
    let DTime0: u32 = a0.tableTime.wrapping_add(a0.decode256Time.wrapping_mul(D256));
    let mut DTime1: u32 = a1.tableTime.wrapping_add(a1.decode256Time.wrapping_mul(D256));
    // small advantage to algorithm using less memory, to reduce cache eviction
    DTime1 = DTime1.wrapping_add(DTime1 >> 5);
    (DTime1 < DTime0) as c_uint
}

/// `huf_decompress.c:1842` — `HUF_decompress1X_DCtx_wksp()`.
///
/// Dead in-tree, kept because `huf.h:257` still declares it.
///
/// # Safety
///
/// `dctx` must point at a writable, 4-byte-aligned `HUF_DTable` array whose
/// header word is initialised; `dst` at `dstSize` writable bytes; `cSrc` at
/// `cSrcSize` readable bytes; `workSpace` at `wkspSize` writable bytes aligned
/// to 4.
#[no_mangle]
pub unsafe extern "C" fn HUF_decompress1X_DCtx_wksp(
    dctx: *mut u32,
    dst: *mut c_void,
    dstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    workSpace: *mut c_void,
    wkspSize: usize,
    flags: c_int,
) -> usize {
    // validation checks
    if dstSize == 0 {
        return ERROR(ZSTD_error_dstSize_tooSmall);
    }
    if cSrcSize > dstSize {
        return ERROR(ZSTD_error_corruption_detected); // invalid
    }
    if cSrcSize == dstSize {
        // not compressed
        // SAFETY: class B (boundary). `dstSize == cSrcSize` and both are
        // `> 0`, so neither pointer is the null-with-zero-length case that
        // `copy_nonoverlapping` forbids, and the caller guarantees `dstSize`
        // writable bytes and `cSrcSize` readable ones. The C's
        // `ZSTD_memcpy` requires non-overlap for the same reason `memcpy`
        // does.
        unsafe { core::ptr::copy_nonoverlapping(cSrc as *const u8, dst as *mut u8, dstSize) };
        return dstSize;
    }
    if cSrcSize == 1 {
        // RLE
        // SAFETY: class B (boundary). `cSrcSize == 1` so `cSrc[0]` is
        // readable, and `dstSize > 0` writable bytes were promised.
        unsafe {
            let b = *(cSrc as *const u8);
            core::ptr::write_bytes(dst as *mut u8, b, dstSize);
        }
        return dstSize;
    }

    {
        let algoNb = HUF_selectDecoder(dstSize, cSrcSize);
        // SAFETY: class B (boundary). The C caller's buffers, forwarded
        // unchanged to whichever decoder the heuristic picked.
        if algoNb != 0 {
            unsafe {
                HUF_decompress1X2_DCtx_wksp(
                    dctx, dst, dstSize, cSrc, cSrcSize, workSpace, wkspSize, flags,
                )
            }
        } else {
            unsafe {
                HUF_decompress1X1_DCtx_wksp(
                    dctx, dst, dstSize, cSrc, cSrcSize, workSpace, wkspSize, flags,
                )
            }
        }
    }
}

/// `huf_decompress.c:1873` — `HUF_decompress1X_usingDTable()`.
///
/// # Safety
///
/// `dst` must point at `maxDstSize` writable bytes, `cSrc` at `cSrcSize`
/// readable bytes, and `DTable` at a readable, 4-byte-aligned table built by
/// [`HUF_readDTableX1_wksp`] or [`HUF_readDTableX2_wksp`].
#[no_mangle]
pub unsafe extern "C" fn HUF_decompress1X_usingDTable(
    dst: *mut c_void,
    maxDstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    DTable: *const u32,
    flags: c_int,
) -> usize {
    // SAFETY: class B (boundary). Word 0 of the caller's table.
    let dtd = unsafe { HUF_getDTableDesc(DTable) };
    // SAFETY: class B (boundary). The C caller's buffers, forwarded unchanged.
    if dtd.tableType != 0 {
        unsafe {
            HUF_decompress1X2_usingDTable_internal(dst, maxDstSize, cSrc, cSrcSize, DTable, flags)
        }
    } else {
        unsafe {
            HUF_decompress1X1_usingDTable_internal(dst, maxDstSize, cSrc, cSrcSize, DTable, flags)
        }
    }
}

/// `huf_decompress.c:1891` — `HUF_decompress1X1_DCtx_wksp()`, inside
/// `#ifndef HUF_FORCE_DECOMPRESS_X2`.
///
/// # Safety
///
/// As [`HUF_decompress1X_DCtx_wksp`].
#[no_mangle]
pub unsafe extern "C" fn HUF_decompress1X1_DCtx_wksp(
    dctx: *mut u32,
    dst: *mut c_void,
    dstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    workSpace: *mut c_void,
    wkspSize: usize,
    flags: c_int,
) -> usize {
    let ip = cSrc as *const u8;

    // SAFETY: class B (boundary). The C caller's buffers, forwarded unchanged.
    let hSize =
        unsafe { HUF_readDTableX1_wksp(dctx, cSrc, cSrcSize, workSpace, wkspSize, flags) };
    if ERR_isError(hSize) {
        return hSize;
    }
    if hSize >= cSrcSize {
        return ERROR(ZSTD_error_srcSize_wrong);
    }
    // SAFETY: class C (construction). `hSize < cSrcSize` was just checked.
    let ip = unsafe { ip.add(hSize) };
    let cSrcSize = cSrcSize - hSize;

    // SAFETY: class C (construction). `dctx` now holds a table this file just
    // built; `ip`/`cSrcSize` name the tail of the caller's input.
    unsafe {
        HUF_decompress1X1_usingDTable_internal(
            dst,
            dstSize,
            ip as *const c_void,
            cSrcSize,
            dctx,
            flags,
        )
    }
}

/// `huf_decompress.c:1904` — `HUF_decompress4X_usingDTable()`.
///
/// # Safety
///
/// As [`HUF_decompress1X_usingDTable`].
#[no_mangle]
pub unsafe extern "C" fn HUF_decompress4X_usingDTable(
    dst: *mut c_void,
    maxDstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    DTable: *const u32,
    flags: c_int,
) -> usize {
    // SAFETY: class B (boundary). Word 0 of the caller's table.
    let dtd = unsafe { HUF_getDTableDesc(DTable) };
    // SAFETY: class B (boundary). The C caller's buffers, forwarded unchanged.
    if dtd.tableType != 0 {
        unsafe {
            HUF_decompress4X2_usingDTable_internal(dst, maxDstSize, cSrc, cSrcSize, DTable, flags)
        }
    } else {
        unsafe {
            HUF_decompress4X1_usingDTable_internal(dst, maxDstSize, cSrc, cSrcSize, DTable, flags)
        }
    }
}

/// `huf_decompress.c:1921` — `HUF_decompress4X_hufOnly_wksp()`.
///
/// # Safety
///
/// As [`HUF_decompress1X_DCtx_wksp`].
#[no_mangle]
pub unsafe extern "C" fn HUF_decompress4X_hufOnly_wksp(
    dctx: *mut u32,
    dst: *mut c_void,
    dstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    workSpace: *mut c_void,
    wkspSize: usize,
    flags: c_int,
) -> usize {
    // validation checks
    if dstSize == 0 {
        return ERROR(ZSTD_error_dstSize_tooSmall);
    }
    if cSrcSize == 0 {
        return ERROR(ZSTD_error_corruption_detected);
    }

    {
        let algoNb = HUF_selectDecoder(dstSize, cSrcSize);
        // SAFETY: class B (boundary). The C caller's buffers, forwarded
        // unchanged to whichever decoder the heuristic picked.
        if algoNb != 0 {
            unsafe {
                HUF_decompress4X2_DCtx_wksp(
                    dctx, dst, dstSize, cSrc, cSrcSize, workSpace, wkspSize, flags,
                )
            }
        } else {
            unsafe {
                HUF_decompress4X1_DCtx_wksp(
                    dctx, dst, dstSize, cSrc, cSrcSize, workSpace, wkspSize, flags,
                )
            }
        }
    }
}
