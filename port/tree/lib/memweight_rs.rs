// SPDX-License-Identifier: GPL-2.0

//! `memweight()` -- count the set bits in a memory area.
//!
//! Ported from `lib/memweight.c` (6.18.49).
//!
//! # The three phases, and why they survive the port
//!
//! The C counts byte at a time up to the first `long` boundary, then calls
//! `bitmap_weight()` over the aligned middle, then goes byte at a time again
//! for the tail. Its own comment explains the third phase: a partial `long`
//! has to be counted bytewise **on big-endian systems**, where
//! `bitmap_weight()` would otherwise read bit positions the area does not
//! contain.
//!
//! This keeps the same three phases -- `align_to::<usize>()` is what splits
//! them off -- and counts the middle as whole `usize` words with
//! `count_ones()` rather than through `bitmap_weight()`. The endianness
//! caveat does not arise here for either phase: the *number* of set bits in a
//! word does not depend on byte order, and the tail never enters a word at
//! all.
//!
//! # A word at a time, and the measurement that forced it
//!
//! **The first version of this file counted every byte's `count_ones()` and
//! summed them**, with a comment claiming that since `u8::count_ones()`
//! compiles to `popcnt` on x86-64, the aligned middle gave nothing up. That
//! comment was wrong, and the GOALS.md §4 rig measured how wrong: **3.26x
//! slower than the C**. A popcount per *byte* is eight times the popcounts of
//! a popcount per *word*, and on a 4 KiB area that is 4,096 of them against
//! the C's 512. The instruction being a single `popcnt` says nothing about
//! how many times it is issued.
//!
//! It is recorded here rather than quietly fixed because the wrong version
//! read as obviously correct, and the next person reasoning about generated
//! code from the instruction alone will make the same mistake.
//!
//! # The GOALS.md §5 questions
//!
//! 1. **Observable?** No. Same count, for every input, on any endianness.
//!    There are no writes at all.
//! 2. **Layout or interface?** No. Same symbol, same signature, same CRC.
//! 3. **Forces a change elsewhere?** No.
//!
//! The `BUG_ON` for absurdly large areas stays in `lib/memweight.c`: it is
//! observable behaviour, and `BUG_ON` plants a bug-table entry naming its own
//! file and line.
//!
//! Replaces: lib/memweight.c

/// Body of `memweight()`.
///
/// # Safety
/// `ptr` must be readable for `bytes` bytes. Same contract as the C.
///
/// See `include/linux/string.h` for the C declaration.
#[no_mangle]
pub unsafe extern "C" fn rust_memweight(ptr: *const core::ffi::c_void, bytes: usize) -> usize {
    if bytes == 0 {
        return 0;
    }

    // SAFETY: the caller guarantees `bytes` readable bytes at `ptr`. The
    // slice is read-only and does not outlive this call.
    let area = unsafe { core::slice::from_raw_parts(ptr as *const u8, bytes) };

    // SAFETY: `usize` has no padding and no invalid bit patterns, so a run of
    // initialised bytes is a valid `usize`. `align_to` only reinterprets the
    // aligned middle and never reads outside `area`.
    let (head, words, tail) = unsafe { area.align_to::<usize>() };

    fn bytewise(s: &[u8]) -> usize {
        s.iter().map(|b| b.count_ones() as usize).sum()
    }

    bytewise(head)
        + words.iter().map(|w| w.count_ones() as usize).sum::<usize>()
        + bytewise(tail)
}
