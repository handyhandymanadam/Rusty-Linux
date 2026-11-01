// SPDX-License-Identifier: GPL-2.0

//! `num_digits()` -- the Rust behind `arch/x86/lib/misc.c`.
//!
//! Ported from `arch/x86/lib/misc.c` (6.18.49), which no longer exists in the
//! CONFIG_RUST build: this file is the whole of it. The function is not
//! `EXPORT_SYMBOL`ed (its only callers are in `arch/x86/kernel/smpboot.c`,
//! which prints the `#N` CPU-bringup banner), so there is no MODVERSIONS CRC
//! and no C entry thunk to keep (`logs/c-entry-rule.md`).
//!
//! # Same arithmetic as the C, including the edge nobody calls
//!
//! The C counts the decimal digits of `val` plus one for a sign. For
//! `val == INT_MIN`, `val = -val` is signed overflow, which the kernel builds
//! with `-fno-strict-overflow` (`-fwrapv`), so it wraps and stays `INT_MIN`;
//! the loop then does not run and the answer is 2. `wrapping_neg()` is the
//! same wrap, and the Rust is checked against the C over all 2^32 inputs
//! (`port/test/misc/run.sh`). `m` is a `long long` in the C; `i64` here.
//!
//! Replaces: arch/x86/lib/misc.c

use core::ffi::c_int;

/// Count the digits of `val` including a possible sign.
///
/// See `arch/x86/include/asm/misc.h` for the C declaration this must keep
/// matching: `int num_digits(int val)`.
#[no_mangle]
pub extern "C" fn num_digits(val: c_int) -> c_int {
    let mut m: i64 = 10;
    let mut d: c_int = 1;
    let mut val = val;

    if val < 0 {
        d += 1;
        val = val.wrapping_neg();
    }

    while (val as i64) >= m {
        m *= 10;
        d += 1;
    }
    d
}
