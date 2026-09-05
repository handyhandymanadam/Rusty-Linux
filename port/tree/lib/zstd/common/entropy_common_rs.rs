// SPDX-License-Identifier: GPL-2.0+ OR BSD-3-Clause
// (dual BSD-3-Clause, as the two files it is ported from)

//! FSE/Huffman entropy-header parsing and FSE decompression.
//!
//! Ported from **two** files of 6.18.49, both `Copyright (c) Meta Platforms,
//! Inc. and affiliates.`, both dual GPL-2.0+/BSD-3-Clause:
//!
//! - `lib/zstd/common/entropy_common.c` — `FSE_readNCount*`, `HUF_readStats*`,
//!   and the five dead version/error accessors.
//! - `lib/zstd/common/fse_decompress.c` — `FSE_buildDTable_*`,
//!   `FSE_decompress_wksp_*`.
//!
//! # Why one file
//!
//! **The two C translation units are mutually recursive.** `entropy_common.o`
//! calls `FSE_decompress_wksp_bmi2` (`entropy_common.c:273`);
//! `fse_decompress.o` calls `FSE_readNCount_bmi2`
//! (`fse_decompress.c:266`). `nm` says nothing else in the built kernel
//! references either symbol. Porting them into one crate therefore erases
//! **two** internal FFI walls at once, which is exactly the progress
//! GOALS.md §1 measures — "a subsystem is done when its internal FFI walls
//! are gone".
//!
//! The static-inline machinery both files depend on comes along for the ride,
//! because a `static inline` in a header has no linkable symbol and cannot be
//! called from Rust at all: `bitstream.h`'s `BIT_DStream_t` reader,
//! `fse.h`'s `FSE_DState_t` decoder, `mem.h`'s unaligned accessors and
//! `bits.h`'s `ZSTD_highbit32`/`ZSTD_countTrailingZeros32`.
//!
//! # Shape: three C entry thunks, everything else defined here
//!
//! Measured with `nm` on the built objects, then cross-checked against
//! `grep` over `lib/zstd/`:
//!
//! | symbol | referenced by | shape |
//! |---|---|---|
//! | `FSE_readNCount` | **`EXPORT_SYMBOL_GPL`** (`zstd_common_module.c:21`), `zstd_decompress.o`, `zstd_decompress_block.o` | **C thunk** |
//! | `HUF_readStats` | **`EXPORT_SYMBOL_GPL`** (`:22`) | **C thunk** |
//! | `HUF_readStats_wksp` | **`EXPORT_SYMBOL_GPL`** (`:23`), `huf_decompress.o` | **C thunk** |
//! | `FSE_readNCount_bmi2` | `fse_decompress.o` only | defined here; the call is now internal |
//! | `FSE_decompress_wksp_bmi2` | `entropy_common.o` only | defined here; the call is now internal |
//! | `FSE_buildDTable_wksp` | nothing, kernel-wide | defined here |
//! | `FSE_versionNumber`, `FSE_isError`, `FSE_getErrorName`, `HUF_isError`, `HUF_getErrorName` | nothing, kernel-wide | defined here |
//!
//! The three exported ones keep C definitions — `entropy_common.c` is reduced
//! to exactly those three thunks (the `lib/bcd` shape). Under
//! `CONFIG_GENDWARFKSYMS` the MODVERSIONS CRC is computed from the DWARF of
//! the **definition**, so a Rust definition changes the CRC and breaks module
//! loading; GOALS.md §2 criterion 4. That is GOALS.md §1's first exception,
//! forced rather than chosen. Everything else takes the `lib/union_find`
//! shape and is defined here under its own name, so
//! `lib/zstd/common/fse_decompress.c` has **no code left at all** and is
//! dropped from the Makefile.
//!
//! The five dead accessors (`FSE_versionNumber` and friends) are kept because
//! `fse.h`/`huf.h` still declare them and out-of-tree users may link them.
//! They are dead in-tree for a specific reason worth recording: every
//! in-tree caller of `FSE_isError`/`HUF_isError` gets the **macro**
//! (`zstd_internal.h:39-40`, `huf_compress.c:38`, `huf_decompress.c:75`,
//! `fse_compress.c:36`), which expands to `ERR_isError` and never reaches the
//! out-of-line definition.
//!
//! `FSE_readNCount_bmi2` and `FSE_decompress_wksp_bmi2` also keep their
//! `#[no_mangle]` symbols even though nothing outside this crate calls them
//! any more: `nm` output stays identical, out-of-tree users keep working, and
//! the *call sites* are still direct internal Rust calls, which is the thing
//! the milestone is about.
//!
//! # `DYNAMIC_BMI2` is 1 here, and the axis is preserved
//!
//! `portability_macros.h:60-70` sets `DYNAMIC_BMI2` to 1 for GCC >= 11 on
//! x86 when `__BMI2__` is unset — which is this build (x86-64, GCC 16, the
//! kernel never passes `-mbmi2`). So both `_body_default` and `_body_bmi2`
//! really are compiled, and `bmi2` really is dispatched on at runtime.
//!
//! That is reproduced, not collapsed. `compiler.h:97` defines
//! `BMI2_TARGET_ATTRIBUTE` as `__attribute__((__target__("lzcnt,bmi,bmi2")))`
//! — **three** features, not two — which in Rust is
//! `#[target_feature(enable = "lzcnt,bmi1,bmi2")]` (rustc spells GCC's `bmi`
//! as `bmi1`). Each `_body` is `#[inline(always)]` and each `_bmi2` wrapper is
//! an `unsafe fn` carrying only that attribute, so the two wrappers differ in
//! exactly what the C's two wrappers differ in: instruction selection for
//! [`ZSTD_highbit32`] (`bsr` vs `lzcnt`) and
//! [`ZSTD_countTrailingZeros32`] (`bsf` vs `tzcnt`). **Both paths compute the
//! same values**; a differential run must see zero difference between
//! `bmi2 = 0` and `bmi2 = 1` on every input.
//!
//! **The one thing this rests on that the C does not** is that LLVM honours
//! `#[inline(always)]` when inlining a feature-less callee into a
//! feature-carrying caller. It is allowed to (the callee's feature set is a
//! subset of the caller's, which is the same rule GCC applies to
//! `always_inline` + `target`), and it is the same arrangement `core::arch`
//! uses throughout — but it is a codegen property, not a language guarantee.
//! **If it ever stops holding, the bmi2 arm silently degrades to the default
//! arm's instruction selection and nothing observable changes.** The
//! guaranteed-but-ugly alternative is a `macro_rules!` body textually
//! expanded into both wrappers; it was not taken because it would make the
//! file unreadable against the C.
//!
//! **It does hold, checked rather than assumed** — but on **N = 1**, and not
//! on the pinned toolchain. Compiling this file standalone with
//! `rustc 1.100.0-nightly -Copt-level=2 -Ccodegen-units=1 --emit=asm` on
//! `x86_64-unknown-linux-gnu`, `FSE_readNCount_body_bmi2` contains `lzcntl`,
//! `tzcntl`, `shlxl` and `shrxl` while `FSE_readNCount_dispatch` (which
//! swallowed `_body_default`) contains `bsrl` and `rep bsfl`;
//! `HUF_readStats_body_bmi2` and `FSE_decompress_wksp_body_bmi2` likewise
//! carry `lzcntl`/`shlx`. **That is one observation on one rustc at one
//! optimisation level, not a property of the arrangement**, and the pinned
//! 1.98 with the kernel's own flags has not been checked. Re-check it if the
//! toolchain moves.
//!
//! One consequence of the axis being real is worth stating: `bsr` leaves its
//! destination **undefined** for a zero operand where `lzcnt` returns 32, so
//! `ZSTD_highbit32(0)` — UB in the C, `0xFFFFFFFF` here (divergence 1) — is
//! the one input on which the two arms could disagree, in the C as well as
//! here. Every call site is proved non-zero; see uncertainty item 9.
//!
//! On non-x86 targets `DYNAMIC_BMI2` is 0, the `_bmi2` wrappers are not
//! compiled at all (`#[cfg]`, matching the C's `#if`), and the `bmi2`
//! parameter is consumed by a `let _ =` exactly where the C writes
//! `(void)bmi2;`. Per `logs/floor.md` RAISE 1 the gate is on the items, not
//! just their uses, so `CONFIG_WERROR=y` cannot trip over a dead definition.
//!
//! # Error codes are values, not a category
//!
//! `error_private.h:41` — `ERROR(name)` is `((size_t)-ZSTD_error_##name)` and
//! `ERR_isError(code)` is `code > ERROR(maxCode)`, i.e. `code` is an error iff
//! it is one of the 119 values `0usize - 1 ..= 0usize - 119`. Every one of
//! them is reproduced by value ([`ERROR`], [`ERR_isError`]). A differential
//! harness comparing raw `usize` returns will see any confusion between two
//! error codes, and "also an error" is a failure — which is why, for one
//! example, [`BIT_initDStream`] returns `GENERIC` on a zero end-mark in the
//! long-input branch and `corruption_detected` in the short-input branch
//! (`bitstream.h:251` vs `:279`). That asymmetry looks like a C typo. It is
//! transcribed, not fixed.
//!
//! # Deliberate divergences, recorded so nobody fixes them back
//!
//! 1. **`ZSTD_highbit32` uses `wrapping_sub`, and every shift whose count the
//!    C does not bound uses `wrapping_shl`/`wrapping_shr`.** `bits.h`'s
//!    `ZSTD_highbit32(0)` is `31 - __builtin_clz(0)`, which is UB; a C shift
//!    by >= the width is UB. Both are reachable only through the public
//!    [`FSE_buildDTable_wksp`], which nothing in the kernel calls, and only
//!    with a `normalizedCounter`/`tableLog` that `FSE_readNCount` would have
//!    rejected. A plain `-` or `<<` would panic there, turning C's
//!    garbage-in-garbage-out into a kernel panic — a denial of service this
//!    port would have *introduced*. `wrapping_*` instead reproduces what the C
//!    actually compiles to on x86-64 (`shl` masks its count; `lzcnt` returns
//!    32). See uncertainty items 8 and 9.
//!
//! 2. **Buffer accesses are bounds-checked.** Every read of `headerBuffer`,
//!    write to `normalizedCounter`, write to `dst`, and access to the
//!    workspace goes through a helper that asserts first. The index
//!    arithmetic is transcribed one for one; only the check is added, and the
//!    invariant that makes each check redundant is written out in the
//!    corresponding `SAFETY` comment. **None of them fires on any input the
//!    in-tree callers can produce, including corrupt compressed data, which
//!    is this file's whole job.** The two that are genuinely load-bearing are
//!    `store_symbol` (the `dst` walk in
//!    [`FSE_decompress_usingDTable_generic`]) and `spread_write64` (see
//!    divergence 3).
//!
//! 3. **`FSE_buildDTable_internal`'s 8-byte-at-a-time spread write is kept,
//!    over-write and all.** `fse_decompress.c:96-114` lays symbols down with
//!    `MEM_write64()` even when a symbol's count is 0 or not a multiple of 8,
//!    and says so: *"We ensure we have 8 bytes at the end of our buffer to
//!    handle the over-write."* That slack is real and it is exactly 8 bytes —
//!    `fse.h:268` sizes the workspace as
//!    `sizeof(short) * (maxSymbolValue + 1) + (1ULL << maxTableLog) + 8`, and
//!    `spread` starts at `2 * maxSV1`, so `spread` has at least
//!    `tableSize + 8` bytes behind it. The highest write is at `pos == tableSize`
//!    (the last iteration with `n == 0`), covering `tableSize .. tableSize + 8`.
//!    [`spread_write64`] asserts `pos + 8 <= spread_capacity` rather than
//!    `pos + 8 <= tableSize`, which is what makes the deliberate over-write
//!    legal rather than merely tolerated. **Do not "fix" this to a
//!    byte loop; it is the reason the function is fast.**
//!
//! 4. **`BIT_DStream_t` gains a `src_size` field.** The C's struct carries
//!    `ptr`, `start` and `limitPtr` and reasons about the upper bound
//!    implicitly ("reminder : srcSize > sizeof(bitContainer)", `bitstream.h:426`).
//!    [`BitDStream`] keeps `src_size` so [`BitDStream::read_st`] can check that
//!    the whole machine word it is about to read is inside the caller's
//!    buffer. The struct is a local in [`FSE_decompress_usingDTable_generic`]
//!    and is never seen by C, so GOALS.md §5's layout rule does not reach it.
//!
//! 5. **`bitD->ptr = &zeroFilled` is transcribed literally** (`bitstream.h:400-405`),
//!    including the fact that it points outside the caller's buffer. It is
//!    never dereferenced afterwards: `bitsConsumed` only ever grows, so once
//!    it exceeds `SIZE_BITS` every later [`BIT_reloadDStream`] takes the same
//!    early return, and the tail loop in
//!    [`FSE_decompress_usingDTable_generic`] breaks on the first
//!    `BIT_DStream_overflow`. [`BitDStream::read_st`]'s assert would fire if
//!    that reasoning were ever wrong, which is the point of divergence 4.
//!
//! 6. **`charnum`, `weightTotal` and the `bitContainer` accumulation use
//!    `wrapping_add`.** All three are C unsigned types, so wraparound is
//!    *defined* in C and a plain `+` under `CONFIG_RUST_OVERFLOW_CHECKS=y`
//!    (which is `default y`) would be a panic where the C keeps going.
//!    `charnum` is the one that can actually reach it: the repeat loop at
//!    `entropy_common.c:90-101` adds 36 per iteration with no bound check, so
//!    a `headerBuffer` of a few hundred megabytes of `0xFF` wraps a `u32`.
//!    See uncertainty item 4.
//!
//! 7. **The recursive `FSE_readNCount()` call at `entropy_common.c:62` calls
//!    the internal dispatcher, not back out through the C thunk.** The C's
//!    `FSE_readNCount(a,b,c,d,e)` is *defined* as
//!    `FSE_readNCount_bmi2(a,b,c,d,e,0)` (`:220-225`), so
//!    [`FSE_readNCount_dispatch`]`(.., 0)` is the identical program with one
//!    fewer call. It matters for a second reason: routing it through an
//!    `#[inline(always)]` cycle would be an inlining loop. The recursion is
//!    only one level deep in any case — the inner call always has
//!    `hbSize == 8`.
//!
//! 8. **`HUF_readStats`' workspace is a Rust stack array.** `entropy_common.c:239`
//!    declares `U32 wksp[HUF_READ_STATS_WORKSPACE_SIZE_U32]`; here it is
//!    `[u32; HUF_READ_STATS_WORKSPACE_SIZE_U32]` (219 words, 876 bytes), same
//!    size, same 4-byte alignment, same stack frame cost. No allocator is
//!    involved on either side.
//!
//! # What is NOT changed
//!
//! The two decode loops are transcribed statement for statement, including
//! the things that look wrong and are not: `entropy_common.c:111-115`'s
//! "break and return an error at the end, because returning out of a loop
//! makes it harder for the compiler to optimize"; the non-short-circuit `&`
//! at `fse_decompress.c:199` (`BIT_reloadDStream()` is the *left* operand and
//! is called either way, so `&&` is the same program); and the two
//! `sizeof(bitContainer)`-keyed `if`s at `:202` and `:207` that are dead on
//! 64-bit and live on 32-bit, kept as `const` conditions so both arms are
//! type-checked on every target.
//!
//! Replaces: lib/zstd/common/entropy_common.c lib/zstd/common/fse_decompress.c

// The C symbol names are the ABI and are reproduced verbatim; so are the
// header type names (`FSE_decode_t`, `BIT_DStream_status`) that they appear
// in, so that a reader can grep the C and this file for the same string.
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

use core::ffi::{c_char, c_int, c_uint, c_void};

// ---------------------------------------------------------------------------
// include/linux/zstd_errors.h and lib/zstd/common/error_private.h
// ---------------------------------------------------------------------------

const ZSTD_error_GENERIC: usize = 1;
const ZSTD_error_corruption_detected: usize = 20;
const ZSTD_error_tableLog_tooLarge: usize = 44;
const ZSTD_error_maxSymbolValue_tooLarge: usize = 46;
const ZSTD_error_maxSymbolValue_tooSmall: usize = 48;
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
/// Returns `bool` where the C returns `unsigned`; every in-tree use is a
/// condition. [`FSE_isError`] and [`HUF_isError`] convert back to `unsigned`
/// for their C signatures.
#[inline(always)]
fn ERR_isError(code: usize) -> bool {
    code > ERROR(ZSTD_error_maxCode)
}

/// `error_private.h:46`.
#[inline(always)]
fn ERR_getErrorCode(code: usize) -> c_int {
    if !ERR_isError(code) {
        return 0;
    }
    // `(ERR_enum)(0-code)`: size_t negation, then a narrowing conversion to
    // the enum's underlying `int`. `as` truncates, which is what C does.
    0usize.wrapping_sub(code) as c_int
}

extern "C" {
    /// `lib/zstd/common/error_private.c:16`. A real out-of-line symbol, so it
    /// can be called from here; `ERR_getErrorName()` itself is a
    /// `static __attribute__((unused))` in the header and has none.
    fn ERR_getErrorString(code: c_int) -> *const c_char;
}

/// `error_private.h:63`.
#[inline(always)]
fn ERR_getErrorName(code: usize) -> *const c_char {
    // SAFETY: class B (boundary). `ERR_getErrorString()` is a pure lookup
    // over a table of string literals in `lib/zstd/common/error_private.c`;
    // it reads no memory we own, takes no pointer, and returns a pointer to a
    // `.rodata` literal with static lifetime. It is total: its `switch` has a
    // `default` returning "Unspecified error code". Retires when
    // `error_private.c` is ported.
    unsafe { ERR_getErrorString(ERR_getErrorCode(code)) }
}

// ---------------------------------------------------------------------------
// lib/zstd/common/fse.h and lib/zstd/common/huf.h constants
// ---------------------------------------------------------------------------

/// `fse.h:47` — `0 * 100 * 100 + 9 * 100 + 0`.
const FSE_VERSION_NUMBER: c_uint = 900;

/// `fse.h:596`.
const FSE_MAX_SYMBOL_VALUE: c_uint = 255;
/// `fse.h:613` — `FSE_MAX_MEMORY_USAGE - 2`, and `FSE_MAX_MEMORY_USAGE` is 14.
const FSE_MAX_TABLELOG: c_uint = 12;
/// `fse.h:617`.
const FSE_MIN_TABLELOG: i32 = 5;
/// `fse.h:619`.
const FSE_TABLELOG_ABSOLUTE_MAX: i32 = 15;

/// `fse.h:624`.
#[inline(always)]
const fn FSE_TABLESTEP(tableSize: usize) -> usize {
    (tableSize >> 1) + (tableSize >> 3) + 3
}

/// `fse.h:242`.
#[inline(always)]
const fn FSE_DTABLE_SIZE_U32(maxTableLog: c_uint) -> usize {
    1 + (1usize.wrapping_shl(maxTableLog))
}

/// `fse.h:246`.
#[inline(always)]
const fn FSE_DTABLE_SIZE(maxTableLog: c_uint) -> usize {
    FSE_DTABLE_SIZE_U32(maxTableLog) * core::mem::size_of::<u32>()
}

/// `fse.h:268` — `sizeof(short) * (maxSymbolValue + 1) + (1ULL << maxTableLog) + 8`.
///
/// Computed in `u64` because the C's `1ULL` promotes the whole expression,
/// and `wrapping_*` because both operands are unbounded on the public
/// [`FSE_buildDTable_wksp`] path (divergence 1).
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

/// `fse.h:274`.
#[inline(always)]
const fn FSE_DECOMPRESS_WKSP_SIZE(maxTableLog: c_uint, maxSymbolValue: c_uint) -> usize {
    FSE_DECOMPRESS_WKSP_SIZE_U32(maxTableLog, maxSymbolValue) * core::mem::size_of::<u32>()
}

/// `huf.h:38`.
const HUF_TABLELOG_MAX: u32 = 12;
/// `huf.h:86` — `HUF_flags_bmi2 = (1 << 0)`.
///
/// Gated on the same architectures as its only use, because
/// `logs/floor.md` RAISE 1: an item defined ungated whose only use is gated
/// becomes `never used`, and `CONFIG_WERROR=y` makes that a build failure.
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
/// `huf.h:182` — `FSE_DECOMPRESS_WKSP_SIZE_U32(6, HUF_TABLELOG_MAX - 1)`, which
/// works out to 219 words / 876 bytes.
const HUF_READ_STATS_WORKSPACE_SIZE_U32: usize =
    FSE_DECOMPRESS_WKSP_SIZE_U32(6, HUF_TABLELOG_MAX - 1);

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

/// `mem.h:164` — `get_unaligned_le32()`.
///
/// # Safety
///
/// `p .. p + 4` must be readable.
#[inline(always)]
unsafe fn MEM_readLE32(p: *const u8) -> u32 {
    // SAFETY: class C (construction). The caller guarantees 4 readable bytes.
    // `read_unaligned` places no alignment requirement, which is what
    // `get_unaligned_le32()` provides; `from_le` is the byteswap on a
    // big-endian target and a no-op on a little-endian one.
    u32::from_le(unsafe { core::ptr::read_unaligned(p as *const u32) })
}

/// `mem.h:182` — `MEM_readLEST()`, which is `get_unaligned_le64()` on 64-bit
/// and `get_unaligned_le32()` on 32-bit.
///
/// # Safety
///
/// `p .. p + SIZE_BYTES` must be readable.
#[inline(always)]
unsafe fn MEM_readLEST(p: *const u8) -> usize {
    // SAFETY: class C (construction). As `MEM_readLE32`, at machine-word
    // width. The caller guarantees `SIZE_BYTES` readable bytes; every call
    // site reaches this through `BitDStream::read_st`, which asserts it.
    usize::from_le(unsafe { core::ptr::read_unaligned(p as *const usize) })
}

/// `mem.h:139` — `put_unaligned()`, **native** endianness, not LE.
///
/// # Safety
///
/// `p .. p + 8` must be writable.
#[inline(always)]
unsafe fn MEM_write64(p: *mut u8, value: u64) {
    // SAFETY: class C (construction). The caller guarantees 8 writable bytes.
    // No byteswap: `MEM_write64()` is `put_unaligned()`, not
    // `put_unaligned_le64()`. It happens not to matter at the one call site
    // (every byte of `sv` is equal), but the C is native and so is this.
    unsafe { core::ptr::write_unaligned(p as *mut u64, value) }
}

// ---------------------------------------------------------------------------
// lib/zstd/common/bits.h
// ---------------------------------------------------------------------------

/// `bits.h:56` + `bits.h:117` — `31 - __builtin_clz(val)`.
///
/// `assert(val != 0)` in the C, and `assert()` is compiled out
/// (`debug.h:71`, `DEBUGLEVEL` 0), so `val == 0` is UB there. Here it yields
/// `0xFFFFFFFF` — the answer `31 - lzcnt(0)` gives — rather than panicking.
/// Divergence 1.
///
/// Inside a `#[target_feature(enable = "lzcnt,...")]` caller this is `lzcnt`;
/// otherwise `bsr`. That difference is the entire content of the `bmi2` axis
/// for this function.
#[inline(always)]
fn ZSTD_highbit32(val: u32) -> u32 {
    31u32.wrapping_sub(val.leading_zeros())
}

/// `bits.h:29` — `__builtin_ctz(val)`.
///
/// `val == 0` is UB in the C; `trailing_zeros()` returns 32, which is what
/// `tzcnt` returns. The single call site ORs in `0x80000000` first
/// (`entropy_common.c:89`, *"Avoid UB by setting the high bit to 1"*), so it
/// is unreachable either way.
#[inline(always)]
fn ZSTD_countTrailingZeros32(val: u32) -> u32 {
    val.trailing_zeros()
}

// ===========================================================================
// PART 1 — lib/zstd/common/entropy_common.c
// ===========================================================================

/// `entropy_common.c:28`.
#[no_mangle]
pub extern "C" fn FSE_versionNumber() -> c_uint {
    FSE_VERSION_NUMBER
}

/// `entropy_common.c:32`. Dead in-tree — every caller gets the
/// `#define FSE_isError ERR_isError` macro instead.
#[no_mangle]
pub extern "C" fn FSE_isError(code: usize) -> c_uint {
    ERR_isError(code) as c_uint
}

/// `entropy_common.c:33`. Dead in-tree.
#[no_mangle]
pub extern "C" fn FSE_getErrorName(code: usize) -> *const c_char {
    ERR_getErrorName(code)
}

/// `entropy_common.c:35`. Dead in-tree.
#[no_mangle]
pub extern "C" fn HUF_isError(code: usize) -> c_uint {
    ERR_isError(code) as c_uint
}

/// `entropy_common.c:36`. Dead in-tree.
#[no_mangle]
pub extern "C" fn HUF_getErrorName(code: usize) -> *const c_char {
    ERR_getErrorName(code)
}

// --- FSE NCount decoding ---------------------------------------------------

/// `normalizedCounter[i] = v`, bounds-checked against `maxSV1`.
///
/// # Safety
///
/// `p` must point at `maxSV1` writable `i16`s.
#[inline(always)]
unsafe fn ncount_store(p: *mut i16, maxSV1: c_uint, i: c_uint, v: i16) {
    assert!(i < maxSV1);
    // SAFETY: class C (construction). The C's contract for
    // `FSE_readNCount()` is that `normalizedCounter` holds `*maxSVPtr + 1`
    // shorts; `entropy_common.c:71` memsets exactly that many. `i` is
    // `charnum`, and every path to a store has just passed either
    // `charnum >= maxSV1 -> break` (`:115`, `:168`) or is the first iteration
    // with `charnum == 0`. The assert is divergence 2.
    unsafe { p.add(i as usize).write(v) }
}

/// `MEM_readLE32(istart + off)`, bounds-checked against `hbSize`.
///
/// # Safety
///
/// `istart` must point at `hbSize` readable bytes.
#[inline(always)]
unsafe fn header_read_le32(istart: *const u8, hbSize: isize, off: isize) -> u32 {
    assert!(off >= 0 && off + 4 <= hbSize);
    // SAFETY: class C (construction). `ip` is held as a signed byte offset
    // from `istart` exactly as the C holds it as a pointer. The C's invariant
    // is `istart <= ip <= iend - 4`, established by the three `ip` updates:
    // `ip = iend - 4` clamps directly; `ip += bitCount >> 3` is guarded by
    // `ip <= iend - 7 || ip + (bitCount >> 3) <= iend - 4`, and in the first
    // arm `bitCount >> 3 <= 3` (`entropy_common.c:122`) so `ip + 3 <= iend - 4`;
    // `ip += 3` inside the repeat loop is guarded by `ip <= iend - 7`. The
    // assert is divergence 2.
    unsafe { MEM_readLE32(istart.offset(off)) }
}

/// `entropy_common.c:42-188` — `FSE_readNCount_body()`.
///
/// `FORCE_INLINE_TEMPLATE` in the C, `#[inline(always)]` here, for the same
/// reason: it is instantiated twice, once per target-feature set.
///
/// # Safety
///
/// `normalizedCounter` must point at `*maxSVPtr + 1` writable `i16`s,
/// `maxSVPtr` and `tableLogPtr` at writable `unsigned`s, and `headerBuffer`
/// at `hbSize` readable bytes.
#[inline(always)]
unsafe fn FSE_readNCount_body(
    normalizedCounter: *mut i16,
    maxSVPtr: *mut c_uint,
    tableLogPtr: *mut c_uint,
    headerBuffer: *const c_void,
    hbSize: usize,
) -> usize {
    let istart = headerBuffer as *const u8;
    // `iend`/`ip` are byte offsets from `istart` rather than pointers, so the
    // C's `iend - 7 - ip` stays a plain signed subtraction. `isize` because
    // that expression is genuinely negative in the clamped state.
    let iend: isize = hbSize as isize;
    let mut ip: isize = 0;

    let mut nbBits: i32;
    let mut remaining: i32;
    let mut threshold: i32;
    let mut bitStream: u32;
    let mut bitCount: i32;
    let mut charnum: c_uint = 0;
    // SAFETY: class B (boundary). The caller guarantees `maxSVPtr` points at
    // a live, initialised `unsigned`. `wrapping_add` because `*maxSVPtr + 1`
    // is C unsigned arithmetic (divergence 6); the in-tree callers pass 255.
    let maxSV1: c_uint = unsafe { *maxSVPtr }.wrapping_add(1);
    let mut previous0 = false;

    if hbSize < 8 {
        // This function only works when hbSize >= 8
        let mut buffer = [0u8; 8];
        // The `hbSize != 0` guard is not in the C, and it changes nothing
        // observable: a zero-length copy copies nothing either way. It is here
        // because `copy_nonoverlapping` requires a NON-NULL source even for a
        // count of zero, so `FSE_readNCount(_, _, _, NULL, 0)` -- which the C
        // handles benignly and which `ZSTD_memcpy(dst, NULL, 0)` makes
        // formally UB in C too -- would be Rust UB and can trip the
        // debug-assertion the harness builds with. No in-tree caller passes
        // NULL; the symbol is EXPORT_SYMBOL_GPL'd, so an out-of-tree one
        // could. Raised by adversarial review, 2026-09-04.
        if hbSize != 0 {
            // SAFETY: class C (construction). `hbSize < 8` here, so the copy
            // fits the 8-byte stack buffer; the caller guarantees `hbSize`
            // readable bytes at `headerBuffer`, and the two cannot overlap
            // because `buffer` is a fresh local.
            unsafe {
                core::ptr::copy_nonoverlapping(istart, buffer.as_mut_ptr(), hbSize)
            };
        }
        {
            // The C calls the public `FSE_readNCount()`, which is defined as
            // this dispatcher with `bmi2 = 0`. Divergence 7.
            // SAFETY: class C (construction). `buffer` is 8 live readable
            // bytes and the other three pointers are the caller's, forwarded
            // unchanged.
            let countSize = unsafe {
                FSE_readNCount_dispatch(
                    normalizedCounter,
                    maxSVPtr,
                    tableLogPtr,
                    buffer.as_ptr() as *const c_void,
                    core::mem::size_of_val(&buffer),
                    0,
                )
            };
            if ERR_isError(countSize) {
                return countSize;
            }
            if countSize > hbSize {
                return ERROR(ZSTD_error_corruption_detected);
            }
            return countSize;
        }
    }
    // assert(hbSize >= 8)

    // init
    // SAFETY: class B (boundary). `entropy_common.c:71` memsets
    // `(*maxSVPtr + 1) * sizeof(short)` bytes; the caller's contract is that
    // `normalizedCounter` is at least that large. `write_bytes` with a count
    // of `maxSV1` `i16`s is exactly that many bytes.
    unsafe { core::ptr::write_bytes(normalizedCounter, 0, maxSV1 as usize) };
    // SAFETY: class C (construction). `ip == 0` and `hbSize >= 8`, so the
    // 4-byte read is inside the caller's buffer; `header_read_le32` asserts it.
    bitStream = unsafe { header_read_le32(istart, iend, ip) };
    nbBits = ((bitStream & 0xF) as i32) + FSE_MIN_TABLELOG; // extract tableLog
    if nbBits > FSE_TABLELOG_ABSOLUTE_MAX {
        return ERROR(ZSTD_error_tableLog_tooLarge);
    }
    bitStream >>= 4;
    bitCount = 4;
    // SAFETY: class B (boundary). Caller-owned out-parameter.
    unsafe { *tableLogPtr = nbBits as c_uint };
    remaining = (1i32 << nbBits) + 1;
    threshold = 1i32 << nbBits;
    nbBits += 1;

    loop {
        if previous0 {
            // Count the number of repeats. Each time the 2-bit repeat code is
            // 0b11 there is another repeat. Avoid UB by setting the high bit
            // to 1.
            let mut repeats: i32 =
                (ZSTD_countTrailingZeros32(!bitStream | 0x8000_0000) >> 1) as i32;
            while repeats >= 12 {
                charnum = charnum.wrapping_add(3 * 12);
                if ip <= iend - 7 {
                    ip += 3;
                } else {
                    bitCount -= 8isize.wrapping_mul(iend - 7 - ip) as i32;
                    bitCount &= 31;
                    ip = iend - 4;
                }
                // SAFETY: class C (construction). See `header_read_le32`; both
                // arms above leave `ip <= iend - 4`.
                bitStream = unsafe { header_read_le32(istart, iend, ip) }
                    .wrapping_shr(bitCount as u32);
                repeats = (ZSTD_countTrailingZeros32(!bitStream | 0x8000_0000) >> 1) as i32;
            }
            charnum = charnum.wrapping_add(3u32.wrapping_mul(repeats as u32));
            bitStream >>= 2 * repeats as u32;
            bitCount += 2 * repeats;

            // Add the final repeat which isn't 0b11.
            // assert((bitStream & 3) < 3)
            charnum = charnum.wrapping_add(bitStream & 3);
            bitCount += 2;

            // This is an error, but break and return an error at the end,
            // because returning out of a loop makes it harder for the
            // compiler to optimize.
            if charnum >= maxSV1 {
                break;
            }

            // We don't need to set the normalized count to 0 because we
            // already memset the whole buffer to 0.

            if ip <= iend - 7 || ip + (bitCount >> 3) as isize <= iend - 4 {
                // assert((bitCount >> 3) <= 3) -- for the first condition to work
                ip += (bitCount >> 3) as isize;
                bitCount &= 7;
            } else {
                bitCount -= 8isize.wrapping_mul(iend - 4 - ip) as i32;
                bitCount &= 31;
                ip = iend - 4;
            }
            // SAFETY: class C (construction). As above.
            bitStream =
                unsafe { header_read_le32(istart, iend, ip) }.wrapping_shr(bitCount as u32);
        }
        {
            let max: i32 = (2 * threshold - 1) - remaining;
            let mut count: i32;

            if (bitStream & (threshold as u32).wrapping_sub(1)) < max as u32 {
                count = (bitStream & (threshold as u32).wrapping_sub(1)) as i32;
                bitCount += nbBits - 1;
            } else {
                count = (bitStream & (2 * threshold - 1) as u32) as i32;
                if count >= threshold {
                    count -= max;
                }
                bitCount += nbBits;
            }

            count -= 1; // extra accuracy
            // When it matters (small blocks), this is a predictable branch,
            // because we don't use -1.
            if count >= 0 {
                remaining -= count;
            } else {
                // assert(count == -1)
                remaining += count;
            }
            // SAFETY: class B (boundary). `charnum < maxSV1` here -- see
            // `ncount_store`, which asserts it. `count as i16` is the C's
            // `(short)count` narrowing conversion.
            unsafe { ncount_store(normalizedCounter, maxSV1, charnum, count as i16) };
            charnum = charnum.wrapping_add(1);
            previous0 = count == 0;

            // assert(threshold > 1)
            if remaining < threshold {
                // This branch can be folded into the threshold update
                // condition because we know that threshold > 1.
                if remaining <= 1 {
                    break;
                }
                nbBits = ZSTD_highbit32(remaining as u32) as i32 + 1;
                threshold = 1i32 << (nbBits - 1);
            }
            if charnum >= maxSV1 {
                break;
            }

            if ip <= iend - 7 || ip + (bitCount >> 3) as isize <= iend - 4 {
                ip += (bitCount >> 3) as isize;
                bitCount &= 7;
            } else {
                bitCount -= 8isize.wrapping_mul(iend - 4 - ip) as i32;
                bitCount &= 31;
                ip = iend - 4;
            }
            // SAFETY: class C (construction). As above.
            bitStream =
                unsafe { header_read_le32(istart, iend, ip) }.wrapping_shr(bitCount as u32);
        }
    }
    if remaining != 1 {
        return ERROR(ZSTD_error_corruption_detected);
    }
    // Only possible when there are too many zeros.
    if charnum > maxSV1 {
        return ERROR(ZSTD_error_maxSymbolValue_tooSmall);
    }
    if bitCount > 32 {
        return ERROR(ZSTD_error_corruption_detected);
    }
    // SAFETY: class B (boundary). Caller-owned out-parameter. `charnum >= 1`
    // because the first pass through the loop always takes the `else` block
    // (`previous0` starts false) and that block increments it.
    unsafe { *maxSVPtr = charnum - 1 };

    ip += ((bitCount + 7) >> 3) as isize;
    ip as usize // return ip - istart
}

/// `entropy_common.c:191` — avoids the `FORCE_INLINE` of the `_body()`
/// function.
///
/// # Safety
///
/// As [`FSE_readNCount_body`].
unsafe fn FSE_readNCount_body_default(
    normalizedCounter: *mut i16,
    maxSVPtr: *mut c_uint,
    tableLogPtr: *mut c_uint,
    headerBuffer: *const c_void,
    hbSize: usize,
) -> usize {
    // SAFETY: class C (construction). Preconditions forwarded unchanged from
    // this function's own contract.
    unsafe { FSE_readNCount_body(normalizedCounter, maxSVPtr, tableLogPtr, headerBuffer, hbSize) }
}

/// `entropy_common.c:199` — `BMI2_TARGET_ATTRIBUTE static ..._body_bmi2()`,
/// under `#if DYNAMIC_BMI2`.
///
/// # Safety
///
/// As [`FSE_readNCount_body`], **and** the CPU must support LZCNT, BMI1 and
/// BMI2. The caller establishes that by passing `bmi2 != 0`, which zstd's
/// callers derive from `ZSTD_cpuid()`.
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "bmi2")))]
#[target_feature(enable = "lzcnt,bmi1,bmi2")]
unsafe fn FSE_readNCount_body_bmi2(
    normalizedCounter: *mut i16,
    maxSVPtr: *mut c_uint,
    tableLogPtr: *mut c_uint,
    headerBuffer: *const c_void,
    hbSize: usize,
) -> usize {
    // SAFETY: class C (construction). Preconditions forwarded unchanged. The
    // body is inlined here and so is compiled with this function's target
    // features -- that is the whole point of the wrapper.
    unsafe { FSE_readNCount_body(normalizedCounter, maxSVPtr, tableLogPtr, headerBuffer, hbSize) }
}

/// `entropy_common.c:207` — `FSE_readNCount_bmi2()`, as an ordinary Rust
/// function so that in-crate callers reach it without going through the FFI
/// symbol. [`FSE_readNCount_bmi2`] is the `#[no_mangle]` wrapper.
///
/// # Safety
///
/// As [`FSE_readNCount_body`].
unsafe fn FSE_readNCount_dispatch(
    normalizedCounter: *mut i16,
    maxSVPtr: *mut c_uint,
    tableLogPtr: *mut c_uint,
    headerBuffer: *const c_void,
    hbSize: usize,
    bmi2: c_int,
) -> usize {
    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "bmi2")))]
    if bmi2 != 0 {
        // SAFETY: class A (axiom). This is the ISA boundary. `bmi2 != 0` is
        // zstd's own assertion that `ZSTD_cpuid()` found LZCNT/BMI1/BMI2 on
        // this CPU, which is exactly the precondition
        // `#[target_feature(enable = ...)]` imposes; the C expresses the same
        // contract with `__attribute__((target(...)))` and a runtime branch.
        // Nothing in Rust can discharge it -- it is a property of the silicon.
        // The pointer preconditions are forwarded unchanged.
        return unsafe {
            FSE_readNCount_body_bmi2(
                normalizedCounter,
                maxSVPtr,
                tableLogPtr,
                headerBuffer,
                hbSize,
            )
        };
    }
    let _ = bmi2; // (void)bmi2
    // SAFETY: class C (construction). Preconditions forwarded unchanged.
    unsafe {
        FSE_readNCount_body_default(normalizedCounter, maxSVPtr, tableLogPtr, headerBuffer, hbSize)
    }
}

/// `entropy_common.c:207` — the C symbol. Not `EXPORT_SYMBOL`'d and, since
/// `fse_decompress.c` is now Rust, called by nothing outside this crate; the
/// symbol is kept so `nm` output and out-of-tree links are unchanged.
///
/// # Safety
///
/// As [`FSE_readNCount_body`].
#[no_mangle]
pub unsafe extern "C" fn FSE_readNCount_bmi2(
    normalizedCounter: *mut i16,
    maxSVPtr: *mut c_uint,
    tableLogPtr: *mut c_uint,
    headerBuffer: *const c_void,
    hbSize: usize,
    bmi2: c_int,
) -> usize {
    // SAFETY: class B (boundary). The C caller guarantees the four pointers
    // are live, unaliased and correctly sized for the duration of the call.
    unsafe {
        FSE_readNCount_dispatch(
            normalizedCounter,
            maxSVPtr,
            tableLogPtr,
            headerBuffer,
            hbSize,
            bmi2,
        )
    }
}

/// `entropy_common.c:220` — the body of the `FSE_readNCount()` entry thunk in
/// `entropy_common.c`. **`FSE_readNCount` itself stays C**: it is
/// `EXPORT_SYMBOL_GPL`'d (`zstd_common_module.c:21`) and a Rust definition
/// would change its MODVERSIONS CRC.
///
/// # Safety
///
/// As [`FSE_readNCount_body`].
#[no_mangle]
pub unsafe extern "C" fn FSE_readNCount(
    normalizedCounter: *mut i16,
    maxSVPtr: *mut c_uint,
    tableLogPtr: *mut c_uint,
    headerBuffer: *const c_void,
    hbSize: usize,
) -> usize {
    // SAFETY: class B (boundary). As `FSE_readNCount_bmi2`.
    unsafe {
        FSE_readNCount_dispatch(
            normalizedCounter,
            maxSVPtr,
            tableLogPtr,
            headerBuffer,
            hbSize,
            /* bmi2 */ 0,
        )
    }
}

// --- HUF_readStats ---------------------------------------------------------

/// `entropy_common.c:243-307` — `HUF_readStats_body()`.
///
/// # Safety
///
/// `huffWeight` must point at `hwSize` writable bytes, `rankStats` at
/// `HUF_TABLELOG_MAX + 1` writable `U32`s, `nbSymbolsPtr` and `tableLogPtr` at
/// writable `U32`s, `src` at `srcSize` readable bytes, and `workSpace` at
/// `wkspSize` writable bytes aligned to 4 (`huf.h:178`).
#[inline(always)]
unsafe fn HUF_readStats_body(
    huffWeight: *mut u8,
    hwSize: usize,
    rankStats: *mut u32,
    nbSymbolsPtr: *mut u32,
    tableLogPtr: *mut u32,
    src: *const c_void,
    srcSize: usize,
    workSpace: *mut c_void,
    wkspSize: usize,
    bmi2: c_int,
) -> usize {
    let mut weightTotal: u32;
    let ip = src as *const u8;
    let mut iSize: usize;
    let oSize: usize;

    if srcSize == 0 {
        return ERROR(ZSTD_error_srcSize_wrong);
    }
    // SAFETY: class B (boundary). `srcSize >= 1` was just established, so
    // `src[0]` is inside the caller's buffer.
    iSize = unsafe { *ip } as usize;
    // ZSTD_memset(huffWeight, 0, hwSize) is not necessary, even though some
    // analyzer complain ...

    if iSize >= 128 {
        // special header
        oSize = iSize - 127;
        iSize = (oSize + 1) / 2;
        if iSize + 1 > srcSize {
            return ERROR(ZSTD_error_srcSize_wrong);
        }
        if oSize >= hwSize {
            return ERROR(ZSTD_error_corruption_detected);
        }
        // SAFETY: class C (construction). `iSize + 1 <= srcSize` and
        // `srcSize >= 1` were both established, so `src + 1` is inside the
        // caller's buffer (or one past its end when `srcSize == 1`, which
        // `ptr::add` permits and which the loop below never dereferences,
        // because `iSize + 1 <= 1` forces `oSize == 0`).
        let ip = unsafe { ip.add(1) };
        {
            let mut n: usize = 0;
            while n < oSize {
                // SAFETY: class C (construction). Read side: `n < oSize` so
                // `n / 2 <= (oSize - 1) / 2 = iSize - 1`, and `iSize + 1 <= srcSize`
                // was checked, so `ip[n / 2]` is `src[1 + n / 2]` with
                // `1 + n / 2 <= iSize <= srcSize - 1`. Write side: the loop
                // steps by 2 and writes `n` and `n + 1`, so the highest index
                // touched is `oSize` when `oSize` is odd, and
                // `oSize < hwSize` was checked. Both bounds are asserted.
                unsafe {
                    assert!(1 + n / 2 < srcSize);
                    assert!(n + 1 < hwSize);
                    let b = *ip.add(n / 2);
                    huffWeight.add(n).write(b >> 4);
                    huffWeight.add(n + 1).write(b & 15);
                }
                n += 2;
            }
        }
    } else {
        // header compressed with FSE (normal case)
        if iSize + 1 > srcSize {
            return ERROR(ZSTD_error_srcSize_wrong);
        }
        // max (hwSize-1) values decoded, as last one is implied.
        // The C calls the public `FSE_decompress_wksp_bmi2()`, which lives in
        // the other translation unit; here it is a direct in-crate call, and
        // that is one of the two FFI walls this file exists to delete.
        // `hwSize - 1` is `wrapping_sub` because the C computes it in
        // `size_t` and would underflow just as loudly for `hwSize == 0`.
        // SAFETY: class C (construction). `iSize + 1 <= srcSize` was just
        // checked, so `src[1 .. 1 + iSize]` is inside the caller's buffer;
        // `huffWeight` and `workSpace` are forwarded with the caller's own
        // sizes.
        oSize = unsafe {
            FSE_decompress_wksp_dispatch(
                huffWeight as *mut c_void,
                hwSize.wrapping_sub(1),
                ip.add(1) as *const c_void,
                iSize,
                6,
                workSpace,
                wkspSize,
                bmi2,
            )
        };
        if ERR_isError(oSize) {
            return oSize;
        }
    }

    // collect weight stats
    // SAFETY: class B (boundary). `huf.h:178` requires `rankStats` to hold at
    // least `HUF_TABLELOG_MAX + 1` U32s; this writes exactly that many bytes.
    unsafe { core::ptr::write_bytes(rankStats, 0, HUF_TABLELOG_MAX as usize + 1) };
    weightTotal = 0;
    {
        let mut n: usize = 0;
        while n < oSize {
            // SAFETY: class C (construction). `oSize < hwSize` in the special
            // branch (checked) and `oSize <= hwSize - 1` in the FSE branch
            // (that is the capacity handed to the decompressor), so
            // `n < oSize` is inside `huffWeight`. `rankStats` is indexed only
            // after the `> HUF_TABLELOG_MAX` rejection below, so the index is
            // at most 12.
            let w = unsafe {
                assert!(n < hwSize);
                *huffWeight.add(n)
            };
            if w as u32 > HUF_TABLELOG_MAX {
                return ERROR(ZSTD_error_corruption_detected);
            }
            // SAFETY: class C (construction). `w <= HUF_TABLELOG_MAX` was just
            // established, so the index is within the 13 U32s.
            unsafe {
                let p = rankStats.add(w as usize);
                p.write(p.read().wrapping_add(1));
            }
            weightTotal = weightTotal.wrapping_add((1u32 << w) >> 1);
            n += 1;
        }
    }
    if weightTotal == 0 {
        return ERROR(ZSTD_error_corruption_detected);
    }

    // get last non-null symbol weight (implied, total must be 2^n)
    {
        let tableLog: u32 = ZSTD_highbit32(weightTotal) + 1;
        if tableLog > HUF_TABLELOG_MAX {
            return ERROR(ZSTD_error_corruption_detected);
        }
        // SAFETY: class B (boundary). Caller-owned out-parameter.
        unsafe { *tableLogPtr = tableLog };
        // determine last weight
        {
            let total: u32 = 1u32 << tableLog;
            let rest: u32 = total - weightTotal;
            let verif: u32 = 1u32 << ZSTD_highbit32(rest);
            let lastWeight: u32 = ZSTD_highbit32(rest) + 1;
            if verif != rest {
                // last value must be a clean power of 2
                return ERROR(ZSTD_error_corruption_detected);
            }
            // SAFETY: class C (construction). `oSize < hwSize` (see above), so
            // `huffWeight[oSize]` is the last slot the caller provided --
            // which is exactly what "as last one is implied" reserves.
            // `lastWeight <= tableLog <= HUF_TABLELOG_MAX` because
            // `rest < total == 1 << tableLog`, so `rankStats[lastWeight]` is
            // in range. Both asserted.
            unsafe {
                assert!(oSize < hwSize);
                huffWeight.add(oSize).write(lastWeight as u8);
                assert!(lastWeight <= HUF_TABLELOG_MAX);
                let p = rankStats.add(lastWeight as usize);
                p.write(p.read().wrapping_add(1));
            }
        }
    }

    // check tree construction validity
    // SAFETY: class B (boundary). Index 1 of the 13 U32s the caller provided.
    let rank1 = unsafe { *rankStats.add(1) };
    if rank1 < 2 || (rank1 & 1) != 0 {
        // by construction : at least 2 elts of rank 1, must be even
        return ERROR(ZSTD_error_corruption_detected);
    }

    // results
    // SAFETY: class B (boundary). Caller-owned out-parameter.
    unsafe { *nbSymbolsPtr = (oSize + 1) as u32 };
    iSize + 1
}

/// `entropy_common.c:310` — avoids the `FORCE_INLINE` of the `_body()`.
///
/// # Safety
///
/// As [`HUF_readStats_body`].
unsafe fn HUF_readStats_body_default(
    huffWeight: *mut u8,
    hwSize: usize,
    rankStats: *mut u32,
    nbSymbolsPtr: *mut u32,
    tableLogPtr: *mut u32,
    src: *const c_void,
    srcSize: usize,
    workSpace: *mut c_void,
    wkspSize: usize,
) -> usize {
    // SAFETY: class C (construction). Preconditions forwarded unchanged.
    unsafe {
        HUF_readStats_body(
            huffWeight,
            hwSize,
            rankStats,
            nbSymbolsPtr,
            tableLogPtr,
            src,
            srcSize,
            workSpace,
            wkspSize,
            0,
        )
    }
}

/// `entropy_common.c:319` — under `#if DYNAMIC_BMI2`.
///
/// Note that the C passes `bmi2 = 1` **into the body** here, not just into
/// the target attribute: the body forwards it to `FSE_decompress_wksp_bmi2()`,
/// so the nested decompression is dispatched on it too.
///
/// # Safety
///
/// As [`HUF_readStats_body`], **and** the CPU must support LZCNT, BMI1, BMI2.
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "bmi2")))]
#[target_feature(enable = "lzcnt,bmi1,bmi2")]
unsafe fn HUF_readStats_body_bmi2(
    huffWeight: *mut u8,
    hwSize: usize,
    rankStats: *mut u32,
    nbSymbolsPtr: *mut u32,
    tableLogPtr: *mut u32,
    src: *const c_void,
    srcSize: usize,
    workSpace: *mut c_void,
    wkspSize: usize,
) -> usize {
    // SAFETY: class C (construction). Preconditions forwarded unchanged.
    unsafe {
        HUF_readStats_body(
            huffWeight,
            hwSize,
            rankStats,
            nbSymbolsPtr,
            tableLogPtr,
            src,
            srcSize,
            workSpace,
            wkspSize,
            1,
        )
    }
}

/// `entropy_common.c:328` — the body of the `HUF_readStats_wksp()` entry
/// thunk. **`HUF_readStats_wksp` itself stays C**
/// (`EXPORT_SYMBOL_GPL`, `zstd_common_module.c:23`).
///
/// # Safety
///
/// As [`HUF_readStats_body`].
#[no_mangle]
pub unsafe extern "C" fn HUF_readStats_wksp(
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
) -> usize {
    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "bmi2")))]
    if (flags & HUF_flags_bmi2) != 0 {
        // SAFETY: class A (axiom). The ISA boundary, as in
        // `FSE_readNCount_dispatch`: `HUF_flags_bmi2` is the caller's
        // assertion, derived from `ZSTD_cpuid()`, that this CPU has
        // LZCNT/BMI1/BMI2. The pointer preconditions come from the C caller.
        return unsafe {
            HUF_readStats_body_bmi2(
                huffWeight,
                hwSize,
                rankStats,
                nbSymbolsPtr,
                tableLogPtr,
                src,
                srcSize,
                workSpace,
                wkspSize,
            )
        };
    }
    let _ = flags; // (void)flags
    // SAFETY: class B (boundary). The C caller guarantees every pointer is
    // live, unaliased and correctly sized for the duration of the call.
    unsafe {
        HUF_readStats_body_default(
            huffWeight,
            hwSize,
            rankStats,
            nbSymbolsPtr,
            tableLogPtr,
            src,
            srcSize,
            workSpace,
            wkspSize,
        )
    }
}

/// `entropy_common.c:235` — the body of the `HUF_readStats()` entry thunk.
/// **`HUF_readStats` itself stays C** (`EXPORT_SYMBOL_GPL`,
/// `zstd_common_module.c:22`).
///
/// The C's `U32 wksp[HUF_READ_STATS_WORKSPACE_SIZE_U32]` becomes a Rust stack
/// array of the same 219 words; `[u32; N]` is 4-byte aligned, which is what
/// `huf.h:178` requires of the workspace. Divergence 8.
///
/// # Safety
///
/// As [`HUF_readStats_body`], minus the workspace arguments.
#[no_mangle]
pub unsafe extern "C" fn rust_HUF_readStats(
    huffWeight: *mut u8,
    hwSize: usize,
    rankStats: *mut u32,
    nbSymbolsPtr: *mut u32,
    tableLogPtr: *mut u32,
    src: *const c_void,
    srcSize: usize,
) -> usize {
    let mut wksp = [0u32; HUF_READ_STATS_WORKSPACE_SIZE_U32];
    // SAFETY: class B (boundary). The C caller guarantees the five pointers;
    // `wksp` is a live local of exactly `HUF_READ_STATS_WORKSPACE_SIZE` bytes,
    // 4-byte aligned, and cannot alias any of them.
    unsafe {
        HUF_readStats_wksp(
            huffWeight,
            hwSize,
            rankStats,
            nbSymbolsPtr,
            tableLogPtr,
            src,
            srcSize,
            wksp.as_mut_ptr() as *mut c_void,
            core::mem::size_of_val(&wksp),
            /* flags */ 0,
        )
    }
}

// ===========================================================================
// PART 2 — lib/zstd/common/fse_decompress.c
//
// plus the `static inline` machinery it uses from bitstream.h and fse.h,
// which has no linkable symbol and therefore has to come with it.
// ===========================================================================

/// `fse.h:506` — `sizeof == sizeof(FSE_DTable) == 4`.
#[repr(C)]
#[derive(Clone, Copy)]
struct FSE_DTableHeader {
    tableLog: u16,
    fastMode: u16,
}

/// `fse.h:511` — `FSE_decode_t`, `size == U32`. `#[repr(C)]` because
/// `FSE_buildDTable_wksp()` is a public symbol and a C caller may inspect the
/// table it fills in.
#[repr(C)]
#[derive(Clone, Copy)]
struct FSE_decode_t {
    newState: u16,
    symbol: u8,
    nbBits: u8,
}

// --- bitstream.h -----------------------------------------------------------

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
/// once the stream has overflowed. Never dereferenced afterwards; see
/// divergence 5.
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
                bitD.bitContainer = bitD.bitContainer.wrapping_add(
                    (*srcBuffer.add(6) as usize).wrapping_shl(SIZE_BITS - 16),
                );
            }
            if srcSize >= 6 {
                bitD.bitContainer = bitD.bitContainer.wrapping_add(
                    (*srcBuffer.add(5) as usize).wrapping_shl(SIZE_BITS - 24),
                );
            }
            if srcSize >= 5 {
                bitD.bitContainer = bitD.bitContainer.wrapping_add(
                    (*srcBuffer.add(4) as usize).wrapping_shl(SIZE_BITS - 32),
                );
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
                    // fixed. See the module docs and uncertainty item 6.
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
    // `wrapping_shl` rather than `<<`: `nbBits` is `FSE_decode_t::nbBits`,
    // which is a `u8` and is only bounded by `tableLog` on a table this file
    // built. Divergence 1.
    (bitContainer.wrapping_shr(start & regMask)) & (1u64.wrapping_shl(nbBits).wrapping_sub(1)) as usize
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
#[inline(always)]
fn BIT_readBits(bitD: &mut BitDStream, nbBits: u32) -> usize {
    let value = BIT_lookBits(bitD, nbBits);
    BIT_skipBits(bitD, nbBits);
    value
}

/// `bitstream.h:356` — `BIT_readBitsFast()`; only works if `nbBits >= 1`.
#[inline(always)]
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

// --- fse.h decoding state --------------------------------------------------

/// `fse.h:352` — `FSE_DState_t`. The C's `const void* table` becomes a real
/// slice, which is what makes `FSE_decodeSymbol`'s index check free.
struct FSE_DState_t<'a> {
    state: usize,
    table: &'a [FSE_decode_t],
}

/// `fse.h:518` — `FSE_initDState()`.
#[inline(always)]
fn FSE_initDState<'a>(
    bitD: &mut BitDStream,
    tableLog: u32,
    table: &'a [FSE_decode_t],
) -> FSE_DState_t<'a> {
    let state = BIT_readBits(bitD, tableLog);
    BIT_reloadDStream(bitD);
    FSE_DState_t { state, table }
}

/// `fse.h:541` — `FSE_decodeSymbol()`.
#[inline(always)]
fn FSE_decodeSymbol(DStatePtr: &mut FSE_DState_t<'_>, bitD: &mut BitDStream) -> u8 {
    // Bounds-checked by the slice index. It cannot fire on a table this file
    // built: the initial state is `BIT_readBits(tableLog)`, masked to
    // `tableLog` bits and so `< tableSize`, and `FSE_buildDTable_internal()`
    // gives every entry `newState + (1 << nbBits) <= tableSize`.
    let DInfo = DStatePtr.table[DStatePtr.state];
    let nbBits = DInfo.nbBits as u32;
    let symbol = DInfo.symbol;
    let lowBits = BIT_readBits(bitD, nbBits);

    DStatePtr.state = DInfo.newState as usize + lowBits;
    symbol
}

/// `fse.h:554` — `FSE_decodeSymbolFast()`; unsafe, only works if no symbol has
/// a probability > 50%.
#[inline(always)]
fn FSE_decodeSymbolFast(DStatePtr: &mut FSE_DState_t<'_>, bitD: &mut BitDStream) -> u8 {
    let DInfo = DStatePtr.table[DStatePtr.state];
    let nbBits = DInfo.nbBits as u32;
    let symbol = DInfo.symbol;
    let lowBits = BIT_readBitsFast(bitD, nbBits);

    DStatePtr.state = DInfo.newState as usize + lowBits;
    symbol
}

// --- FSE_buildDTable -------------------------------------------------------

/// `MEM_write64(spread + pos, sv)`, bounds-checked against the workspace's
/// real capacity rather than against `tableSize`.
///
/// This is the deliberate 8-byte over-write of `fse_decompress.c:96-114`;
/// see divergence 3.
///
/// # Safety
///
/// `spread` must point at `spread_capacity` writable bytes.
#[inline(always)]
unsafe fn spread_write64(spread: *mut u8, spread_capacity: usize, pos: usize, sv: u64) {
    assert!(pos + 8 <= spread_capacity);
    // SAFETY: class C (construction). THIS WRITE IS DELIBERATELY PAST THE END
    // OF THE USED PART OF `spread`, and the C says so: "We use a uint64_t to
    // lay down 8 bytes at a time... We ensure we have 8 bytes at the end of
    // our buffer to handle the over-write." The slack is exactly the `+ 8` in
    // `fse.h:268`'s FSE_BUILD_DTABLE_WKSP_SIZE, and `spread` begins at
    // `2 * maxSV1` bytes into the workspace, so `spread_capacity >= tableSize + 8`
    // whenever the size check at `fse_decompress.c:71` passed. The highest
    // `pos` reached is `tableSize` (the final iteration, whose `n` may be 0
    // and which still writes), covering `tableSize .. tableSize + 8`.
    // Checking against `spread_capacity` rather than `tableSize` is what makes
    // the over-write legal rather than merely tolerated.
    unsafe { MEM_write64(spread.add(pos), sv) }
}

/// `fse_decompress.c:59-160` — `FSE_buildDTable_internal()`.
///
/// # Safety
///
/// `dt` must point at `FSE_DTABLE_SIZE(tableLog)` writable bytes aligned to 4,
/// `normalizedCounter` at `maxSymbolValue + 1` readable `short`s, and
/// `workSpace` at `wkspSize` writable bytes aligned to 2.
/// `FORCE_INLINE_TEMPLATE` in the C for the same reason -- see
/// [`FSE_decompress_usingDTable_generic`].
#[inline(always)]
unsafe fn FSE_buildDTable_internal(
    dt: *mut u32,
    normalizedCounter: *const i16,
    maxSymbolValue: c_uint,
    tableLog: c_uint,
    workSpace: *mut c_void,
    wkspSize: usize,
) -> usize {
    // `void* const tdPtr = dt+1;` -- because *dt is unsigned, 32-bits aligned
    // on 32-bits.
    // SAFETY: class C (construction). One element past `dt`, which the
    // caller's `FSE_DTABLE_SIZE(tableLog)` allocation covers
    // (`1 + (1 << tableLog)` words). No dereference here.
    let tableDecode = unsafe { dt.add(1) } as *mut FSE_decode_t;
    let symbolNext = workSpace as *mut u16;
    // SAFETY: class C (construction). `2 * maxSV1` bytes into the workspace;
    // the size check below rejects a workspace too small for that plus
    // `tableSize + 8`. No dereference here.
    let spread = unsafe { (symbolNext as *mut u8).add(2 * (maxSymbolValue as usize + 1)) };

    let maxSV1: u32 = maxSymbolValue.wrapping_add(1);
    // `wrapping_shl`: `tableLog` is unchecked until three lines down, and the
    // C's `1 << tableLog` is UB for `tableLog >= 32`. Divergence 1.
    let tableSize: u32 = 1u32.wrapping_shl(tableLog);
    let mut highThreshold: u32 = tableSize.wrapping_sub(1);

    // Sanity Checks
    if FSE_BUILD_DTABLE_WKSP_SIZE(tableLog, maxSymbolValue) > wkspSize as u64 {
        return ERROR(ZSTD_error_maxSymbolValue_tooLarge);
    }
    if maxSymbolValue > FSE_MAX_SYMBOL_VALUE {
        return ERROR(ZSTD_error_maxSymbolValue_tooLarge);
    }
    if tableLog > FSE_MAX_TABLELOG {
        return ERROR(ZSTD_error_tableLog_tooLarge);
    }

    // Everything below is now bounded: tableLog <= 12, maxSymbolValue <= 255,
    // and the workspace holds at least 2 * maxSV1 + tableSize + 8 bytes.
    let table_size = tableSize as usize;
    let spread_capacity = wkspSize - 2 * (maxSymbolValue as usize + 1);

    // Init, lay down lowprob symbols
    {
        let mut DTableH = FSE_DTableHeader {
            tableLog: tableLog as u16,
            fastMode: 1,
        };
        {
            // `(S16)(1 << (tableLog - 1))`. `wrapping_shl` because tableLog
            // may be 0 on the public path, where `tableLog - 1` is a huge
            // unsigned. Divergence 1.
            let largeLimit: i16 = 1u32.wrapping_shl(tableLog.wrapping_sub(1)) as i16;
            for s in 0..maxSV1 {
                // SAFETY: class B (boundary). `s < maxSV1 == maxSymbolValue + 1`,
                // which is the length the caller promised for
                // `normalizedCounter`.
                let nc = unsafe { *normalizedCounter.add(s as usize) };
                if nc == -1 {
                    // SAFETY: class C (construction). `highThreshold` starts at
                    // `tableSize - 1` and decrements once per `-1` count.
                    // `FSE_readNCount()` guarantees the counts' magnitudes sum
                    // to `tableSize`, so it cannot pass 0 and wrap; the assert
                    // holds the public `FSE_buildDTable_wksp()` path to the
                    // same rule instead of letting it write out of bounds.
                    unsafe {
                        assert!((highThreshold as usize) < table_size);
                        (*tableDecode.add(highThreshold as usize)).symbol = s as u8;
                    }
                    highThreshold = highThreshold.wrapping_sub(1);
                    // SAFETY: class C (construction). `s < maxSV1` and
                    // `symbolNext` has `maxSV1` u16 slots (the size check
                    // above reserves `2 * maxSV1` bytes for them).
                    unsafe { symbolNext.add(s as usize).write(1) };
                } else {
                    if nc >= largeLimit {
                        DTableH.fastMode = 0;
                    }
                    // SAFETY: class C (construction). As above.
                    unsafe { symbolNext.add(s as usize).write(nc as u16) };
                }
            }
        }
        // ZSTD_memcpy(dt, &DTableH, sizeof(DTableH))
        // SAFETY: class C (construction). `dt` is 4-byte aligned and
        // `FSE_DTABLE_SIZE(tableLog)` is at least `1 + tableSize` words, so
        // word 0 is inside it. `FSE_DTableHeader` is `#[repr(C)]` with two
        // `u16`s, matching `fse.h:506` byte for byte.
        unsafe { (dt as *mut FSE_DTableHeader).write(DTableH) };
    }

    // Spread symbols
    if highThreshold == tableSize - 1 {
        let tableMask: usize = table_size - 1;
        let step: usize = FSE_TABLESTEP(table_size);
        // First lay down the symbols in order. We use a uint64_t to lay down
        // 8 bytes at a time. This reduces branch misses since small blocks
        // generally have small table logs, so nearly all symbols have counts
        // <= 8. We ensure we have 8 bytes at the end of our buffer to handle
        // the over-write.
        {
            const ADD: u64 = 0x0101_0101_0101_0101;
            let mut pos: usize = 0;
            let mut sv: u64 = 0;
            for s in 0..maxSV1 {
                // SAFETY: class B (boundary). `s < maxSV1`, the caller's
                // length for `normalizedCounter`.
                let n: i32 = unsafe { *normalizedCounter.add(s as usize) } as i32;
                // SAFETY: class C (construction). See `spread_write64` -- the
                // deliberate over-write, divergence 3.
                unsafe { spread_write64(spread, spread_capacity, pos, sv) };
                let mut i: i32 = 8;
                while i < n {
                    // SAFETY: class C (construction). `i < n` and
                    // `pos + n <= tableSize`, so `pos + i < tableSize` and the
                    // 8 bytes land inside `tableSize + 8`.
                    unsafe { spread_write64(spread, spread_capacity, pos + i as usize, sv) };
                    i += 8;
                }
                pos += n as usize;
                sv = sv.wrapping_add(ADD);
            }
        }
        // Now we spread those positions across the table. The benefit of
        // doing it in two stages is that we avoid the variable size inner
        // loop, which caused lots of branch misses. Now we can run through
        // all the positions without any branch misses. We unroll the loop
        // twice, since that is what empirically worked best.
        {
            let mut position: usize = 0;
            const UNROLL: usize = 2;
            // assert(tableSize % unroll == 0) -- FSE_MIN_TABLELOG is 5
            let mut s: usize = 0;
            while s < table_size {
                for u in 0..UNROLL {
                    let uPosition = (position + (u * step)) & tableMask;
                    // SAFETY: class C (construction). `uPosition <= tableMask`
                    // by the mask, so it indexes `tableDecode`'s `tableSize`
                    // entries. `spread[s + u]` is inside the `tableSize` bytes
                    // the previous block filled whenever `tableSize` is even,
                    // which the C asserts on the grounds that
                    // `FSE_MIN_TABLELOG is 5`. The check here is against
                    // `spread_capacity` rather than `table_size` on purpose:
                    // `tableLog == 0` is reachable through the public
                    // `FSE_buildDTable_wksp()`, where the C reads one byte of
                    // the workspace's 8-byte slack, and reproducing that is
                    // better than turning it into a panic. Nothing in the
                    // kernel reaches it: `FSE_readNCount()` yields
                    // `tableLog >= FSE_MIN_TABLELOG`.
                    unsafe {
                        assert!(s + u < spread_capacity);
                        (*tableDecode.add(uPosition)).symbol = *spread.add(s + u);
                    }
                }
                position = (position + (UNROLL * step)) & tableMask;
                s += UNROLL;
            }
            // assert(position == 0)
        }
    } else {
        let tableMask: u32 = tableSize - 1;
        let step: u32 = FSE_TABLESTEP(table_size) as u32;
        let mut position: u32 = 0;
        for s in 0..maxSV1 {
            // SAFETY: class B (boundary). `s < maxSV1`.
            let nc = unsafe { *normalizedCounter.add(s as usize) };
            let mut i: i32 = 0;
            while i < nc as i32 {
                // SAFETY: class C (construction). `position <= tableMask`, so
                // it indexes `tableDecode`'s `tableSize` entries.
                unsafe {
                    assert!((position as usize) < table_size);
                    (*tableDecode.add(position as usize)).symbol = s as u8;
                }
                position = (position + step) & tableMask;
                while position > highThreshold {
                    // lowprob area
                    position = (position + step) & tableMask;
                }
                i += 1;
            }
        }
        if position != 0 {
            // position must reach all cells once, otherwise normalizedCounter
            // is incorrect
            return ERROR(ZSTD_error_GENERIC);
        }
    }

    // Build Decoding table
    {
        for u in 0..table_size {
            // SAFETY: class C (construction). `u < tableSize`, so it indexes
            // `tableDecode`. `symbol` indexes `symbolNext`, whose length is
            // `maxSV1`: in the spread branch every byte of `spread[0..tableSize]`
            // came from a `sv` built for some `s < maxSV1`, and in the other
            // branch every write was `s as u8` with `s < maxSV1`. The assert
            // holds the public `FSE_buildDTable_wksp()` path to that too --
            // it is the one place a `normalizedCounter` whose magnitudes do
            // not sum to `tableSize` would leave stale workspace bytes in
            // `spread` and read `symbolNext` out of bounds.
            unsafe {
                let symbol = (*tableDecode.add(u)).symbol;
                assert!((symbol as u32) < maxSV1);
                let p = symbolNext.add(symbol as usize);
                let nextState: u32 = p.read() as u32;
                p.write(nextState.wrapping_add(1) as u16);
                // `wrapping_sub`/`wrapping_shl`: on the validated path
                // `nextState` is never 0 and `nbBits <= tableLog`, but on the
                // public path both are unconstrained and the C is UB there.
                // Divergence 1.
                let nbBits = tableLog.wrapping_sub(ZSTD_highbit32(nextState)) as u8;
                (*tableDecode.add(u)).nbBits = nbBits;
                (*tableDecode.add(u)).newState =
                    (nextState.wrapping_shl(nbBits as u32)).wrapping_sub(tableSize) as u16;
            }
        }
    }

    0
}

/// `fse_decompress.c:162` — `FSE_buildDTable_wksp()`.
///
/// Referenced by nothing in the built kernel; the symbol is kept because
/// `fse.h:270` still declares it.
///
/// # Safety
///
/// As [`FSE_buildDTable_internal`].
#[no_mangle]
pub unsafe extern "C" fn FSE_buildDTable_wksp(
    dt: *mut u32,
    normalizedCounter: *const i16,
    maxSymbolValue: c_uint,
    tableLog: c_uint,
    workSpace: *mut c_void,
    wkspSize: usize,
) -> usize {
    // SAFETY: class B (boundary). The C caller guarantees the three pointers
    // are live, unaliased and correctly sized for the duration of the call.
    unsafe {
        FSE_buildDTable_internal(
            dt,
            normalizedCounter,
            maxSymbolValue,
            tableLog,
            workSpace,
            wkspSize,
        )
    }
}

// --- Decompression (byte symbols) ------------------------------------------

/// `*op = b`, bounds-checked against `maxDstSize`.
///
/// # Safety
///
/// `dst` must point at `maxDstSize` writable bytes.
#[inline(always)]
unsafe fn store_symbol(dst: *mut u8, maxDstSize: usize, op: usize, b: u8) {
    assert!(op < maxDstSize);
    // SAFETY: class C (construction). The C walks `op` from `ostart` and
    // guards every write: the 4-at-a-time loop runs only while
    // `op < omax - 3` (so `op + 4 <= maxDstSize`) and the tail loop returns
    // `dstSize_tooSmall` unless `op <= omax - 2`. `wrapping_add` rather than
    // `add` so the offset computation stays defined for a null `dst` with
    // `maxDstSize == 0`, where the assert fires before any dereference and
    // the C would have returned `dstSize_tooSmall` on the same input.
    unsafe { dst.wrapping_add(op).write(b) }
}

/// `fse_decompress.c:174-237` — `FSE_decompress_usingDTable_generic()`.
///
/// The C's `const unsigned fast` parameter, always a literal 0 or 1 into a
/// `FORCE_INLINE_TEMPLATE`, is a `const FAST: bool` generic here: same two
/// specialisations, same folded branches.
///
/// # Safety
///
/// `dst` must point at `maxDstSize` writable bytes, `cSrc` at `cSrcSize`
/// readable bytes, and `dt` at a table this file built.
/// `FORCE_INLINE_TEMPLATE` in the C, and the attribute is load-bearing rather
/// than decorative. The C textually inlines this into
/// `FSE_decompress_wksp_body_bmi2`, so the whole decode loop is compiled under
/// `BMI2_TARGET_ATTRIBUTE`. Without `#[inline(always)]` rustc emits ONE shared
/// copy with no target features and both dispatch arms call it -- adversarial
/// review measured exactly that on the built object: the C's bmi2 body carried
/// `lzcnt`/`shlx`/`shrx`/`bzhi` while this ran `bsr` and plain shifts on both
/// paths. Behaviourally identical, which is why the differential could not see
/// it; a performance regression on the bmi2 path all the same.
#[inline(always)]
unsafe fn FSE_decompress_usingDTable_generic<const FAST: bool>(
    dst: *mut c_void,
    maxDstSize: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    dt: *const u32,
) -> usize {
    let ostart = dst as *mut u8;
    // `op`, `omax` and `olimit` are byte offsets from `ostart`. The C forms
    // `omax - 3` and `omax - 2` as pointers, which underflow below `ostart`
    // for tiny `maxDstSize`; the comparisons are rewritten as the equivalent
    // additions on the left, which is the same predicate over the integers
    // and has no underflow to reproduce.
    let mut op: usize = 0;
    let omax: usize = maxDstSize;

    // Init
    let mut bitD = BitDStream {
        bitContainer: 0,
        bitsConsumed: 0,
        ptr: core::ptr::null(),
        start: core::ptr::null(),
        limitPtr: core::ptr::null(),
        src_size: 0,
    };
    // CHECK_F(BIT_initDStream(&bitD, cSrc, cSrcSize))
    // SAFETY: class C (construction). The caller guarantees `cSrcSize`
    // readable bytes at `cSrc`.
    {
        let e = unsafe { BIT_initDStream(&mut bitD, cSrc as *const u8, cSrcSize) };
        if ERR_isError(e) {
            return e;
        }
    }

    // SAFETY: class C (construction). `dt` is 4-byte aligned and points at a
    // table `FSE_buildDTable_internal()` filled in, so word 0 is its
    // `FSE_DTableHeader` and words `1 ..= tableSize` are its `FSE_decode_t`s.
    let (table, tableLog) = unsafe {
        let hdr = (dt as *const FSE_DTableHeader).read();
        assert!(hdr.tableLog as u32 <= FSE_MAX_TABLELOG);
        let table_size = 1usize << hdr.tableLog;
        (
            core::slice::from_raw_parts(dt.add(1) as *const FSE_decode_t, table_size),
            hdr.tableLog as u32,
        )
    };

    let mut state1 = FSE_initDState(&mut bitD, tableLog, table);
    let mut state2 = FSE_initDState(&mut bitD, tableLog, table);

    // RETURN_ERROR_IF(BIT_reloadDStream(&bitD) == BIT_DStream_overflow,
    //                 corruption_detected, "")
    if BIT_reloadDStream(&mut bitD) == BIT_DStream_status::overflow {
        return ERROR(ZSTD_error_corruption_detected);
    }

    // #define FSE_GETSYMBOL(statePtr) fast ? FSE_decodeSymbolFast(...)
    //                                      : FSE_decodeSymbol(...)
    #[inline(always)]
    fn get_symbol<const FAST: bool>(
        statePtr: &mut FSE_DState_t<'_>,
        bitD: &mut BitDStream,
    ) -> u8 {
        if FAST {
            FSE_decodeSymbolFast(statePtr, bitD)
        } else {
            FSE_decodeSymbol(statePtr, bitD)
        }
    }

    // These two tests must be static. `sizeof(bitD.bitContainer) * 8` is
    // `SIZE_BITS`; on 64-bit both are false and the reloads vanish, on 32-bit
    // only the second is true.
    const RELOAD_2: bool = FSE_MAX_TABLELOG * 2 + 7 > SIZE_BITS;
    const RELOAD_4: bool = FSE_MAX_TABLELOG * 4 + 7 > SIZE_BITS;

    // 4 symbols per loop.
    //
    // The C's loop condition uses `&` rather than `&&`. It makes no
    // difference: `BIT_reloadDStream()` is the left operand and is evaluated
    // either way, and `op < olimit` has no side effects.
    loop {
        if !(BIT_reloadDStream(&mut bitD) == BIT_DStream_status::unfinished && op + 3 < omax) {
            break;
        }
        // SAFETY: class C (construction). `op + 3 < omax` was just checked, so
        // all four writes are inside `dst`; `store_symbol` asserts each.
        unsafe { store_symbol(ostart, omax, op, get_symbol::<FAST>(&mut state1, &mut bitD)) };

        if RELOAD_2 {
            BIT_reloadDStream(&mut bitD);
        }

        // SAFETY: class C (construction). As above.
        unsafe { store_symbol(ostart, omax, op + 1, get_symbol::<FAST>(&mut state2, &mut bitD)) };

        if RELOAD_4 {
            if BIT_reloadDStream(&mut bitD) > BIT_DStream_status::unfinished {
                op += 2;
                break;
            }
        }

        // SAFETY: class C (construction). As above.
        unsafe { store_symbol(ostart, omax, op + 2, get_symbol::<FAST>(&mut state1, &mut bitD)) };

        if RELOAD_2 {
            BIT_reloadDStream(&mut bitD);
        }

        // SAFETY: class C (construction). As above.
        unsafe { store_symbol(ostart, omax, op + 3, get_symbol::<FAST>(&mut state2, &mut bitD)) };

        op += 4;
    }

    // tail
    // note : BIT_reloadDStream(&bitD) >= FSE_DStream_partiallyFilled;
    // Ends at exactly BIT_DStream_completed
    loop {
        if op + 2 > omax {
            return ERROR(ZSTD_error_dstSize_tooSmall);
        }
        // SAFETY: class C (construction). `op + 2 <= omax` was just checked,
        // so `op < omax`.
        unsafe { store_symbol(ostart, omax, op, get_symbol::<FAST>(&mut state1, &mut bitD)) };
        op += 1;
        if BIT_reloadDStream(&mut bitD) == BIT_DStream_status::overflow {
            // SAFETY: class C (construction). `op` was `<= omax - 2` before
            // the increment, so it is `<= omax - 1` now.
            unsafe { store_symbol(ostart, omax, op, get_symbol::<FAST>(&mut state2, &mut bitD)) };
            op += 1;
            break;
        }

        if op + 2 > omax {
            return ERROR(ZSTD_error_dstSize_tooSmall);
        }
        // SAFETY: class C (construction). As above.
        unsafe { store_symbol(ostart, omax, op, get_symbol::<FAST>(&mut state2, &mut bitD)) };
        op += 1;
        if BIT_reloadDStream(&mut bitD) == BIT_DStream_status::overflow {
            // SAFETY: class C (construction). As above.
            unsafe { store_symbol(ostart, omax, op, get_symbol::<FAST>(&mut state1, &mut bitD)) };
            op += 1;
            break;
        }
    }

    // assert(op >= ostart)
    op
}

/// `fse_decompress.c:239` — `FSE_DecompressWksp`. `short ncount[256]`, so 512
/// bytes, and `512 % sizeof(FSE_DTable) == 0` is what makes `dtablePos`
/// exact.
const FSE_DECOMPRESS_WKSP_NCOUNT: usize = FSE_MAX_SYMBOL_VALUE as usize + 1;
const SIZEOF_FSE_DECOMPRESS_WKSP: usize = FSE_DECOMPRESS_WKSP_NCOUNT * 2;

// `FSE_STATIC_ASSERT((FSE_MAX_SYMBOL_VALUE + 1) % 2 == 0)` and
// `FSE_STATIC_ASSERT(sizeof(FSE_DecompressWksp) % sizeof(FSE_DTable) == 0)`,
// as compile-time checks rather than the C's `sizeof(char[c ? 1 : -1])`.
const _: () = assert!(FSE_DECOMPRESS_WKSP_NCOUNT % 2 == 0);
const _: () = assert!(SIZEOF_FSE_DECOMPRESS_WKSP % core::mem::size_of::<u32>() == 0);

/// `fse_decompress.c:244-290` — `FSE_decompress_wksp_body()`.
///
/// # Safety
///
/// `dst` must point at `dstCapacity` writable bytes, `cSrc` at `cSrcSize`
/// readable bytes, and `workSpace` at `wkspSize` writable bytes aligned to 4.
#[inline(always)]
unsafe fn FSE_decompress_wksp_body(
    dst: *mut c_void,
    dstCapacity: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    maxLog: c_uint,
    workSpace: *mut c_void,
    wkspSize: usize,
    bmi2: c_int,
) -> usize {
    let istart = cSrc as *const u8;
    let mut ip = istart;
    let mut cSrcSize = cSrcSize;
    let mut wkspSize = wkspSize;
    let mut workSpace = workSpace;
    let mut tableLog: c_uint = 0;
    let mut maxSymbolValue: c_uint = FSE_MAX_SYMBOL_VALUE;
    let ncount = workSpace as *mut i16;
    // `sizeof(FSE_DecompressWksp) / sizeof(FSE_DTable)` == 512 / 4 == 128.
    let dtablePos: usize = SIZEOF_FSE_DECOMPRESS_WKSP / core::mem::size_of::<u32>();

    if wkspSize < SIZEOF_FSE_DECOMPRESS_WKSP {
        return ERROR(ZSTD_error_GENERIC);
    }

    // correct offset to dtable depends on this property (the two
    // FSE_STATIC_ASSERTs are the `const _: ()` items above)
    // SAFETY: class C (construction). `wkspSize >= 512` was just checked, so
    // `(FSE_DTable*)workSpace + 128` is one past the `ncount` region and
    // still inside the caller's workspace. No dereference here.
    let dtable = unsafe { (workSpace as *mut u32).add(dtablePos) };

    // normal FSE decoding mode
    {
        // The C calls the public `FSE_readNCount_bmi2()`, which lives in the
        // other translation unit; here it is a direct in-crate call, and that
        // is the second of the two FFI walls this file exists to delete.
        // SAFETY: class C (construction). `ncount` is the first 512 bytes of
        // the workspace, i.e. 256 `i16`s, which is `maxSymbolValue + 1` for
        // `maxSymbolValue == FSE_MAX_SYMBOL_VALUE`. `maxSymbolValue` and
        // `tableLog` are live locals. `istart` is the caller's buffer.
        let NCountLength = unsafe {
            FSE_readNCount_dispatch(
                ncount,
                &mut maxSymbolValue,
                &mut tableLog,
                istart as *const c_void,
                cSrcSize,
                bmi2,
            )
        };
        if ERR_isError(NCountLength) {
            return NCountLength;
        }
        if tableLog > maxLog {
            return ERROR(ZSTD_error_tableLog_tooLarge);
        }
        // assert(NCountLength <= cSrcSize)
        // SAFETY: class C (construction). `FSE_readNCount()` returns at most
        // `hbSize`, which is `cSrcSize` here, so `ip` stays inside the
        // caller's buffer.
        ip = unsafe { ip.add(NCountLength) };
        cSrcSize -= NCountLength;
    }

    if FSE_DECOMPRESS_WKSP_SIZE(tableLog, maxSymbolValue) > wkspSize {
        return ERROR(ZSTD_error_tableLog_tooLarge);
    }
    // assert(sizeof(*wksp) + FSE_DTABLE_SIZE(tableLog) <= wkspSize)
    // SAFETY: class C (construction). The check above gives
    // `wkspSize >= FSE_DECOMPRESS_WKSP_SIZE(...)`, whose expansion contains
    // `FSE_DTABLE_SIZE(tableLog) + 4 + BUILD_DTABLE_WKSP + 512 + 4`, so the
    // advance is strictly inside the workspace and the subtraction below
    // cannot underflow.
    workSpace = unsafe {
        (workSpace as *mut u8).add(SIZEOF_FSE_DECOMPRESS_WKSP + FSE_DTABLE_SIZE(tableLog))
    } as *mut c_void;
    wkspSize -= SIZEOF_FSE_DECOMPRESS_WKSP + FSE_DTABLE_SIZE(tableLog);

    // CHECK_F(FSE_buildDTable_internal(...))
    // SAFETY: class C (construction). `dtable` has `FSE_DTABLE_SIZE(tableLog)`
    // bytes reserved for it (the same check), `ncount` has the 256 shorts
    // `FSE_readNCount()` just filled, and `workSpace`/`wkspSize` now name the
    // tail of the caller's workspace.
    {
        let e = unsafe {
            FSE_buildDTable_internal(
                dtable,
                ncount,
                maxSymbolValue,
                tableLog,
                workSpace,
                wkspSize,
            )
        };
        if ERR_isError(e) {
            return e;
        }
    }

    {
        // SAFETY: class C (construction). Word 0 of the table
        // `FSE_buildDTable_internal()` just wrote.
        let fastMode = unsafe { (dtable as *const FSE_DTableHeader).read().fastMode };

        // select fast mode (static)
        // SAFETY: class C (construction). `dst`/`dstCapacity` and
        // `ip`/`cSrcSize` are the caller's buffers, narrowed by
        // `NCountLength`; `dtable` is the table just built.
        if fastMode != 0 {
            return unsafe {
                FSE_decompress_usingDTable_generic::<true>(
                    dst,
                    dstCapacity,
                    ip as *const c_void,
                    cSrcSize,
                    dtable,
                )
            };
        }
        // SAFETY: class C (construction). As the `fastMode` arm above; the
        // only difference is the `FAST` const parameter, which selects
        // `FSE_decodeSymbol()` over `FSE_decodeSymbolFast()`.
        unsafe {
            FSE_decompress_usingDTable_generic::<false>(
                dst,
                dstCapacity,
                ip as *const c_void,
                cSrcSize,
                dtable,
            )
        }
    }
}

/// `fse_decompress.c:293` — avoids the `FORCE_INLINE` of the `_body()`.
///
/// # Safety
///
/// As [`FSE_decompress_wksp_body`].
unsafe fn FSE_decompress_wksp_body_default(
    dst: *mut c_void,
    dstCapacity: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    maxLog: c_uint,
    workSpace: *mut c_void,
    wkspSize: usize,
) -> usize {
    // SAFETY: class C (construction). Preconditions forwarded unchanged.
    unsafe {
        FSE_decompress_wksp_body(
            dst,
            dstCapacity,
            cSrc,
            cSrcSize,
            maxLog,
            workSpace,
            wkspSize,
            0,
        )
    }
}

/// `fse_decompress.c:299` — under `#if DYNAMIC_BMI2`.
///
/// As with `HUF_readStats_body_bmi2()`, the C passes `bmi2 = 1` into the body
/// as well as onto the attribute, so the nested `FSE_readNCount_bmi2()` is
/// dispatched on it too.
///
/// # Safety
///
/// As [`FSE_decompress_wksp_body`], **and** the CPU must support LZCNT, BMI1
/// and BMI2.
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "bmi2")))]
#[target_feature(enable = "lzcnt,bmi1,bmi2")]
unsafe fn FSE_decompress_wksp_body_bmi2(
    dst: *mut c_void,
    dstCapacity: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    maxLog: c_uint,
    workSpace: *mut c_void,
    wkspSize: usize,
) -> usize {
    // SAFETY: class C (construction). Preconditions forwarded unchanged.
    unsafe {
        FSE_decompress_wksp_body(
            dst,
            dstCapacity,
            cSrc,
            cSrcSize,
            maxLog,
            workSpace,
            wkspSize,
            1,
        )
    }
}

/// `fse_decompress.c:305` — `FSE_decompress_wksp_bmi2()`, as an ordinary Rust
/// function so `HUF_readStats_body()` reaches it without going through the
/// FFI symbol. [`FSE_decompress_wksp_bmi2`] is the `#[no_mangle]` wrapper.
///
/// # Safety
///
/// As [`FSE_decompress_wksp_body`].
unsafe fn FSE_decompress_wksp_dispatch(
    dst: *mut c_void,
    dstCapacity: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    maxLog: c_uint,
    workSpace: *mut c_void,
    wkspSize: usize,
    bmi2: c_int,
) -> usize {
    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "bmi2")))]
    if bmi2 != 0 {
        // SAFETY: class A (axiom). The ISA boundary, as in
        // `FSE_readNCount_dispatch`. `bmi2 != 0` is the caller's assertion,
        // ultimately from `ZSTD_cpuid()`, that this CPU has LZCNT/BMI1/BMI2.
        return unsafe {
            FSE_decompress_wksp_body_bmi2(
                dst,
                dstCapacity,
                cSrc,
                cSrcSize,
                maxLog,
                workSpace,
                wkspSize,
            )
        };
    }
    let _ = bmi2; // (void)bmi2
    // SAFETY: class C (construction). Preconditions forwarded unchanged.
    unsafe {
        FSE_decompress_wksp_body_default(
            dst,
            dstCapacity,
            cSrc,
            cSrcSize,
            maxLog,
            workSpace,
            wkspSize,
        )
    }
}

/// `fse_decompress.c:305` — the C symbol. Not `EXPORT_SYMBOL`'d and, since
/// `entropy_common.c` is now Rust, called by nothing outside this crate; the
/// symbol is kept so `nm` output and out-of-tree links are unchanged.
///
/// # Safety
///
/// As [`FSE_decompress_wksp_body`].
#[no_mangle]
pub unsafe extern "C" fn FSE_decompress_wksp_bmi2(
    dst: *mut c_void,
    dstCapacity: usize,
    cSrc: *const c_void,
    cSrcSize: usize,
    maxLog: c_uint,
    workSpace: *mut c_void,
    wkspSize: usize,
    bmi2: c_int,
) -> usize {
    // SAFETY: class B (boundary). The C caller guarantees the three pointers
    // are live, unaliased and correctly sized for the duration of the call.
    unsafe {
        FSE_decompress_wksp_dispatch(
            dst,
            dstCapacity,
            cSrc,
            cSrcSize,
            maxLog,
            workSpace,
            wkspSize,
            bmi2,
        )
    }
}
