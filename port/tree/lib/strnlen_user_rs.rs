// SPDX-License-Identifier: GPL-2.0

//! `do_strnlen_user()` -- the word-at-a-time NUL scan behind `lib/strnlen_user.c`.
//!
//! Replaces: `do_strnlen_user()` (`static __always_inline` in the C, so no
//! symbol of its own -- this file's `strnlen_user_body()` gives it one, the
//! same shape as `sha1_blocks_dispatch()`/`blake2s_compress_dispatch()`, see
//! `logs/c-entry-rule.md`'s SIMD-dispatch section).
//!
//! `strnlen_user()` itself -- the `EXPORT_SYMBOL` -- STAYS IN C
//! (`lib/strnlen_user.c`). It is not a pass-through: it dispatches between
//! `can_do_masked_user_access()`'s masked path (dead on this build --
//! `CONFIG_X86_MASKED_USER_ACCESS` is unset in both configs, so this arm
//! never runs, but the C keeps the branch as written, faithfully) and the
//! ordinary `user_read_access_begin()`/`user_access_end()` bracket, and that
//! bracket is the STAC/CLAC toggle. Per `logs/c-entry-rule.md`, "A C ENTRY
//! FUNCTION THAT DOES WORK IS NOT OPTIONAL" -- moving it would either lose
//! the bracket or force this file to reach for `stac()`/`clac()` directly,
//! which Rust has no stable way to emit. No kabi pin is needed: the export
//! never leaves C.
//!
//! # Why the raw access itself is a retained C call, not inline asm
//!
//! `unsafe_get_user()` expands (`CONFIG_CC_HAS_ASM_GOTO_OUTPUT`, the case on
//! this toolchain) to `asm_goto_output()` emitting a hand-built exception
//! table entry (`_ASM_EXTABLE_UA(1b, %l2)`) that redirects a page fault to a
//! local `goto` label in the SAME function. Rust has no stable equivalent to
//! `asm_goto_output` or to planting that table entry itself. `rust_strnlen_uaccess_get_long()`
//! (`lib/strnlen_user.c`) reproduces the read + fault recovery as an
//! out-of-line call returning a success flag instead -- called once per word,
//! matching the original's per-word `unsafe_get_user()` call exactly.
//!
//! **This is a real, measured divergence, not a free substitution**: an
//! out-of-line call replaces inlined asm on every word. It is NOT a STAC/CLAC
//! divergence -- that toggle stays bracketing the whole call, in the retained
//! C, at its original granularity. See `logs/porting-hazards.md`, "raw
//! uaccess", for the measurement and the reasoning for choosing this over
//! toggling per word.
//!
//! # The SWAR helpers, reproduced from `arch/x86/include/asm/word-at-a-time.h`
//!
//! Confirmed by reading that header directly (not the generic
//! `include/asm-generic/word-at-a-time.h`, which has different constants):
//! on `CONFIG_64BIT`, `has_zero()` is `((a - ONE_BITS) & !a) & HIGH_BITS`,
//! `prep_zero_mask()` and `create_zero_mask()` are both the identity, and
//! `find_zero()` is `bits.trailing_zeros() >> 3` (`__ffs` =
//! count-trailing-zeros, matching `u64::trailing_zeros`), called directly
//! on `has_zero()`'s own result -- `do_strnlen_user()` never calls
//! `zero_bytemask()` at all; that helper only exists for
//! `do_strncpy_from_user()`'s destination-masking (see
//! `strncpy_from_user_rs.rs`), and does not belong in this file's
//! translation. `load_unaligned_zeropad()` -- the header's other
//! inline-asm exception-table user -- is not reached: neither
//! `strnlen_user.c` nor `strncpy_from_user.c` calls it (confirmed by grep).
//! `aligned_byte_mask(n)` is `include/linux/wordpart.h`'s little-endian arm,
//! `(1 << 8*n) - 1` (this project is little-endian only).

use core::ffi::{c_long, c_ulong};

const ONE_BITS: u64 = (!0u64 / 0xff) * 0x01;
const HIGH_BITS: u64 = (!0u64 / 0xff) * 0x80;

extern "C" {
    /// Reads one `unsigned long` from `ptr` (user memory, already inside the
    /// caller's `user_read_access_begin()`/`user_access_end()` bracket) and
    /// reports whether it faulted. See `lib/strnlen_user.c`.
    fn rust_strnlen_uaccess_get_long(ptr: *const c_ulong, val: *mut c_ulong) -> bool;
}

#[inline]
fn has_zero(a: u64) -> Option<u64> {
    let mask = a.wrapping_sub(ONE_BITS) & !a & HIGH_BITS;
    if mask != 0 {
        Some(mask)
    } else {
        None
    }
}

#[inline]
fn find_zero(mask: u64) -> u64 {
    (mask.trailing_zeros() as u64) >> 3
}

#[inline]
fn aligned_byte_mask(n: u64) -> u64 {
    // `n & 7` is a no-op on every real call site (`align` is already masked
    // to [0,7] at its one definition below) but makes the bound provable to
    // the compiler at this function's own boundary, not just after inlining
    // -- adversarially found 2026-09-06: without it, this shift-then-
    // subtract compiles to a checked subtraction under
    // CONFIG_RUST_OVERFLOW_CHECKS=y, which is ON by default whenever
    // CONFIG_RUST=y (lib/Kconfig.debug) and IS SET in both of this
    // project's configs -- confirmed against the actual .cmd file, not
    // assumed; this is live today, not a hypothetical future config. A
    // panic here fires from inside the retained C caller's
    // user_read_access_begin()/
    // user_access_end() bracket -- SMAP stays disabled at panic time, worse
    // than anything the C this replaces could do. Same fix shape as
    // usercopy_rs.rs's aligned_byte_mask (logs/build-limits.md).
    let n = n & 7;
    (1u64 << (8 * n)) - 1
}

/// The portable body of `do_strnlen_user()`. Called from the retained C
/// `strnlen_user()` (`lib/strnlen_user.c`), already inside its
/// `user_read_access_begin()`/`user_access_end()` bracket, exactly where the
/// C called `do_strnlen_user()` itself. Return-value contract matches the C
/// precisely: 0 on a fault, `count+1` if the string is at least `count`
/// bytes with no NUL found, else the string length including the NUL.
///
/// # Safety
///
/// `src` must be a user-space pointer such that reading up to `max` bytes
/// starting from `src` rounded down to word alignment (i.e. `[src - align,
/// src - align + max + align)`) is within the range already validated by the
/// caller's `user_read_access_begin()`/`masked_user_access_begin()` call --
/// matching exactly what the C's own `do_strnlen_user()` assumes of its
/// caller.
#[no_mangle]
pub unsafe extern "C" fn strnlen_user_body(
    src: *const u8,
    count: c_ulong,
    max: c_ulong,
) -> c_long {
    let align = (core::mem::size_of::<c_ulong>() as u64 - 1) & (src as u64);
    let mut src = src.wrapping_sub(align as usize);
    // Faithful to the C's own unsigned-wraparound semantics, and removes
    // the checked-arithmetic panic path this loop otherwise compiles to
    // under CONFIG_RUST_OVERFLOW_CHECKS=y -- see `aligned_byte_mask`'s doc.
    // `max`/`res`/`count` never realistically approach these bounds; the
    // point is matching what the C can do (silently wrap), never panic.
    let mut max = max.wrapping_add(align);
    let mut res: u64 = 0;

    let mut c: u64 = 0;
    if !unsafe { rust_strnlen_uaccess_get_long(src as *const c_ulong, &mut c as *mut u64 as *mut c_ulong) } {
        return 0;
    }
    c |= aligned_byte_mask(align);

    loop {
        if let Some(bits) = has_zero(c) {
            return res
                .wrapping_add(find_zero(bits))
                .wrapping_add(1)
                .wrapping_sub(align) as c_long;
        }
        res = res.wrapping_add(core::mem::size_of::<c_ulong>() as u64);
        if max <= core::mem::size_of::<c_ulong>() as u64 {
            break;
        }
        max = max.wrapping_sub(core::mem::size_of::<c_ulong>() as u64);
        src = src.wrapping_add(core::mem::size_of::<c_ulong>());
        if !unsafe { rust_strnlen_uaccess_get_long(src as *const c_ulong, &mut c as *mut u64 as *mut c_ulong) } {
            return 0;
        }
    }
    res = res.wrapping_sub(align);

    if res >= count {
        return count.wrapping_add(1) as c_long;
    }
    0
}
