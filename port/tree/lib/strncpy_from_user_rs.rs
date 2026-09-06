// SPDX-License-Identifier: GPL-2.0

//! `do_strncpy_from_user()` -- the word-at-a-time copy behind
//! `lib/strncpy_from_user.c`. Same shape and same reasoning as
//! `lib/strnlen_user_rs.rs`; see that file's module doc for the full account
//! of why the raw access is a retained C call (`rust_strncpy_uaccess_get_long`/
//! `rust_strncpy_uaccess_get_byte`, `lib/strncpy_from_user.c`) rather than inline
//! asm, and why `strncpy_from_user()` itself -- the `EXPORT_SYMBOL` -- stays
//! in C.
//!
//! # The one shape difference from `strnlen_user`: two loops, one shared exit
//!
//! `do_strncpy_from_user()` has a word-at-a-time fast loop AND a
//! byte-at-a-time fallback loop, and the C reaches the fallback three ways:
//! `IS_UNALIGNED(src, dst)` up front (compile-time `0` on this build --
//! `CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS=y` -- so dead, kept faithfully
//! rather than pruned), falling out of the word loop when `max` drops below
//! one word, and a `goto byte_at_a_time` when `unsafe_get_user()` faults
//! mid-word -- **at the SAME `res`, not reset to 0**, so the byte loop
//! resumes exactly where the faulting word read would have started. The
//! Rust reproduces this by falling out of the word loop (`break`) into the
//! byte loop on a `rust_strncpy_uaccess_get_long()` failure, without having advanced
//! `res`/`max` for that word -- matching the C's control flow exactly.
//!
//! `IS_UNALIGNED` also governs whether `dst`'s word writes are word-aligned;
//! since it is dead here, `write_unaligned` is used regardless (the C's
//! plain pointer store is unaligned-safe on x86-64 either way, so this
//! matches without needing to special-case it).

use core::ffi::{c_long, c_ulong};

const ONE_BITS: u64 = (!0u64 / 0xff) * 0x01;
const HIGH_BITS: u64 = (!0u64 / 0xff) * 0x80;
const EFAULT: c_long = 14;

extern "C" {
    fn rust_strncpy_uaccess_get_long(ptr: *const c_ulong, val: *mut c_ulong) -> bool;
    fn rust_strncpy_uaccess_get_byte(ptr: *const u8, val: *mut u8) -> bool;
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
fn zero_bytemask(bits: u64) -> u64 {
    let bits = bits.wrapping_sub(1) & !bits;
    bits >> 7
}

#[inline]
fn find_zero(mask: u64) -> u64 {
    (mask.trailing_zeros() as u64) >> 3
}

/// The portable body of `do_strncpy_from_user()`. Called from the retained
/// C `strncpy_from_user()` (`lib/strncpy_from_user.c`), already inside its
/// `user_read_access_begin()`/`user_access_end()` bracket, exactly where the
/// C called `do_strncpy_from_user()` itself. Return-value contract matches
/// the C precisely: string length (excluding NUL) on success, `count` if
/// truncated at the caller's limit, `-EFAULT` on a fault with insufficient
/// data copied.
///
/// # Safety
///
/// `src` must be a user-space pointer valid for `max` bytes under the
/// caller's already-established `user_read_access_begin()`/
/// `masked_user_access_begin()` bracket; `dst` must be a valid, writable
/// kernel buffer of at least `max` bytes -- matching exactly what the C's
/// own `do_strncpy_from_user()` assumes of its caller.
#[no_mangle]
pub unsafe extern "C" fn strncpy_from_user_body(
    dst: *mut u8,
    src: *const u8,
    count: c_ulong,
    max: c_ulong,
) -> c_long {
    let word_size = core::mem::size_of::<c_ulong>() as u64;
    let mut max = max;
    let mut res: u64 = 0;

    // IS_UNALIGNED is compile-time 0 on this build; the C's initial
    // `goto byte_at_a_time` never fires, so we go straight to the word loop.
    while max >= word_size {
        let mut c: u64 = 0;
        if !unsafe {
            rust_strncpy_uaccess_get_long(
                src.wrapping_add(res as usize) as *const c_ulong,
                &mut c as *mut u64 as *mut c_ulong,
            )
        } {
            break; // byte_at_a_time, same res -- matches the C's goto exactly
        }

        if let Some(bits) = has_zero(c) {
            let mask = zero_bytemask(bits);
            unsafe {
                core::ptr::write_unaligned(dst.wrapping_add(res as usize) as *mut u64, c & mask)
            };
            return res.wrapping_add(find_zero(bits)) as c_long;
        }

        unsafe { core::ptr::write_unaligned(dst.wrapping_add(res as usize) as *mut u64, c) };

        // Faithful to the C's own unsigned-wraparound semantics, and
        // removes the checked-arithmetic panic path this loop otherwise
        // compiles to under CONFIG_RUST_OVERFLOW_CHECKS=y -- adversarially
        // found 2026-09-06, same class as strnlen_user_rs.rs's
        // aligned_byte_mask (see that file, and logs/build-limits.md): a
        // panic here fires from inside the retained C caller's
        // user_read_access_begin()/user_access_end() bracket, leaving SMAP
        // disabled at panic time. `res`/`max` never realistically approach
        // these bounds; the point is matching what the C can do (silently
        // wrap), never panic.
        res = res.wrapping_add(word_size);
        max = max.wrapping_sub(word_size);
    }

    // byte_at_a_time:
    while max != 0 {
        let mut c: u8 = 0;
        if !unsafe { rust_strncpy_uaccess_get_byte(src.wrapping_add(res as usize), &mut c) } {
            return -EFAULT;
        }
        unsafe { *dst.wrapping_add(res as usize) = c };
        if c == 0 {
            return res as c_long;
        }
        res = res.wrapping_add(1);
        max = max.wrapping_sub(1);
    }

    if res >= count {
        return res as c_long;
    }
    -EFAULT
}
