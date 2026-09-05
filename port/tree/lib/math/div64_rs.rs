// SPDX-License-Identifier: GPL-2.0

//! 64-bit division helpers -- the Rust body behind `lib/math/div64.c`.
//!
//! Ported from `lib/math/div64.c` (6.18.49) and the `__iter_div_u64_rem()`
//! it inlines from `include/vdso/math64.h`.
//!
//! **On x86-64 this file is the whole of `div64.o`.** Every other function
//! in `lib/math/div64.c` is inside `#ifndef div_s64_rem` and friends, and
//! `arch/x86/include/asm/div64.h` defines all of them, so they are never
//! compiled here. Confirmed by reading `nm vmlinux`, not by reading the
//! `#ifdef`s.
//!
//! Replaces: lib/math/div64.c

/// Body of `iter_div_u64_rem()`.
///
/// Iterative div/mod for when the dividend is not expected to be much bigger
/// than the divisor.
///
/// **The loop is not an accident and is not replaced by `/` and `%`.** The C
/// carries an empty `asm("" : "+rm"(dividend))` inside it for the express
/// purpose of stopping the compiler turning it into a division; the callers
/// -- timekeeping, mostly -- want repeated subtraction. `black_box` is the
/// stable Rust spelling of that barrier. Using division here would give the
/// same answers and quietly discard the reason the function exists.
///
/// # Safety
/// `remainder` must be valid, non-null and writable. Same contract as the C.
///
/// See `include/linux/math64.h` for the C declaration.
#[no_mangle]
pub unsafe extern "C" fn rust_iter_div_u64_rem(
    dividend: u64,
    divisor: u32,
    remainder: *mut u64,
) -> u32 {
    let mut dividend = dividend;
    let divisor = divisor as u64;
    let mut ret: u32 = 0;

    while dividend >= divisor {
        dividend = core::hint::black_box(dividend);
        dividend -= divisor;
        ret += 1;
    }

    // SAFETY: the caller guarantees `remainder` is valid and writable.
    unsafe {
        *remainder = dividend;
    }

    ret
}
