// SPDX-License-Identifier: GPL-2.0

//! `check_zeroed_user()`'s word-at-a-time zero-scan, from `lib/usercopy.c`.
//!
//! Replaces: the body of `check_zeroed_user()` from just after
//! `user_read_access_begin()` succeeds to just before
//! `user_read_access_end()`. `check_zeroed_user()` itself -- the
//! `EXPORT_SYMBOL` -- STAYS IN C (`lib/usercopy.c`). It is not a
//! pass-through: it computes the word alignment and adjusts `from`/`size`
//! BEFORE calling `user_read_access_begin()` (the STAC/CLAC toggle), since
//! that call needs the already-aligned-down range, not the caller's
//! original one. Per `logs/c-entry-rule.md`, "A C ENTRY FUNCTION THAT DOES
//! WORK IS NOT OPTIONAL" -- moving it would either lose the bracket or force
//! this file to reach for `stac()`/`clac()` directly, which Rust has no
//! stable way to emit. No kabi pin is needed: the export never leaves C.
//!
//! # Why the raw access itself is a retained C call, not inline asm
//!
//! Same reasoning as `lib/strnlen_user.c`/`lib/strncpy_from_user.c` (see
//! `logs/porting-hazards.md`, "raw uaccess", and `strnlen_user_rs.rs`'s own
//! module doc): `unsafe_get_user()` expands to `asm_goto_output()` planting a
//! hand-built exception-table entry, which Rust has no stable equivalent
//! for. `rust_checkzeroeduser_uaccess_get_long()` (`lib/usercopy.c`)
//! reproduces the read + fault recovery as an out-of-line call, called once
//! per word -- matching the original's per-word `unsafe_get_user()` call
//! exactly, and keeping the STAC/CLAC bracket at its ORIGINAL granularity
//! (once per `check_zeroed_user()` call, not once per word). Given its own
//! name, not shared with `strnlen_user.c`'s or `strncpy_from_user.c`'s own
//! retained helpers: giving two of these the SAME name was a real
//! duplicate-symbol link error caught during that port.
//!
//! `aligned_byte_mask(n)` is `include/linux/wordpart.h`'s little-endian arm,
//! `(1 << 8*n) - 1` (this project is little-endian only) -- reproduced here
//! rather than called, same as `strnlen_user_rs.rs`'s own copy.

use core::ffi::{c_int, c_ulong};

extern "C" {
    /// Reads one `unsigned long` from `ptr` (user memory, already inside the
    /// caller's `user_read_access_begin()`/`user_access_end()` bracket) and
    /// reports whether it faulted. See `lib/usercopy.c`.
    fn rust_checkzeroeduser_uaccess_get_long(ptr: *const c_ulong, val: *mut c_ulong) -> bool;
}

/// `n` is always in `0..=7` at both call sites below (an alignment offset
/// or a `size < sizeof(unsigned long)` remainder), matching the C macro's
/// only defined domain -- but the compiler can't see that across the FFI
/// boundary, so `8 * n` and the shift both compile to real panic branches
/// under `-C overflow-checks=on` (`panic_const_mul_overflow`,
/// `panic_const_shl_overflow` -- confirmed via `nm -u` on the built
/// object). That panic would fire from inside `check_zeroed_user_body()`,
/// i.e. between `user_read_access_begin()` and `user_read_access_end()`
/// with EFLAGS.AC (SMAP) still set -- found by review (adversary,
/// 2026-09-06), who reached it by literally mutating a comparison
/// operator one character (`size < wordsize` -> `size <= wordsize`) in a
/// differential harness and getting SIGABRT instead of a reported
/// mismatch. `& 7` makes the domain restriction the compiler can already
/// prove, matching the C macro's behavior on x86 (a shift count taken mod
/// 64) instead of leaving it as an unreachable-in-practice but
/// compiled-in panic. Confirmed by re-running `nm -u` after this fix:
/// only `rust_checkzeroeduser_uaccess_get_long` remains undefined.
#[inline]
fn aligned_byte_mask(n: u64) -> u64 {
    let n = n & 7;
    (1u64 << (8 * n)) - 1
}

/// The portable body of `check_zeroed_user()`, from just after
/// `user_read_access_begin()` succeeds to just before
/// `user_read_access_end()`. Called from the retained C `check_zeroed_user()`
/// (`lib/usercopy.c`) with `from`/`size` already adjusted for word alignment
/// and `align` carrying that adjustment's amount, exactly the state the C's
/// own body had at the same point.
///
/// Return-value contract matches the C precisely: negative (the C's
/// `err_fault` path returned via `-EFAULT`; the retained C caller maps any
/// negative return the same way) on a fault, `1` if every byte in range was
/// zero, `0` otherwise.
///
/// # Safety
///
/// `from` must be a user-space pointer such that reading `size` bytes
/// starting at `from` is within the range already validated by the caller's
/// `user_read_access_begin()` call -- matching exactly what the C's own
/// `check_zeroed_user()` body assumes at this point.
#[no_mangle]
pub unsafe extern "C" fn check_zeroed_user_body(
    from: *const u8,
    size: c_ulong,
    align: c_ulong,
) -> c_int {
    let wordsize = core::mem::size_of::<c_ulong>() as c_ulong;
    let mut from = from;
    let mut size = size;
    let mut val: c_ulong = 0;

    if !unsafe { rust_checkzeroeduser_uaccess_get_long(from as *const c_ulong, &mut val) } {
        return -1;
    }
    if align != 0 {
        val &= !aligned_byte_mask(align);
    }

    loop {
        if size > wordsize {
            if val != 0 {
                return 0;
            }
            from = from.wrapping_add(wordsize as usize);
            size -= wordsize;
            if !unsafe { rust_checkzeroeduser_uaccess_get_long(from as *const c_ulong, &mut val) }
            {
                return -1;
            }
        } else {
            break;
        }
    }

    if size < wordsize {
        val &= aligned_byte_mask(size);
    }

    (val == 0) as c_int
}
