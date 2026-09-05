// SPDX-License-Identifier: GPL-2.0-only

//! Count-leading/trailing-zeros builtins -- the Rust bodies behind
//! `lib/clz_ctz.c`.
//!
//! Ported from `lib/clz_ctz.c` (6.18.49), Copyright (C) 2013 Chanho Min.
//!
//! Nothing calls these directly. They exist because GCC and Clang emit calls
//! to them for `__builtin_ctz` and friends on code paths where the inline
//! form is not used, which is why the C says they "can't be removed despite
//! appearing unreferenced in kernel source".
//!
//! # A divergence at zero, which the C leaves undefined
//!
//! `__ctzsi2(0)` and `__ctzdi2(0)` are `__ffs(0)` and `__ffs64(0)` in the C.
//! `__ffs` is documented as undefined for zero, and on x86 it compiles to
//! `bsf`, which leaves its destination unchanged — so the C returns whatever
//! happened to be in that register. Rust's `trailing_zeros()` returns the
//! width, 32 or 64.
//!
//! The three GOALS.md §5 questions:
//!
//! 1. **Observable?** Only on an input for which the C has no defined
//!    answer. Every input the C defines gives the same result here.
//! 2. **Layout or interface?** No.
//! 3. **Forces a change elsewhere?** No.
//!
//! So the Rust is defined where the C was not, which is the direction worth
//! diverging in. It is recorded because a reader comparing the two will
//! otherwise see a difference and think one of them is wrong.
//!
//! The `__clz` pair needs no such note: `32 - fls(x)` and
//! `64 - fls64(x)` are exactly `leading_zeros()`, including at zero, because
//! `fls(0)` is defined to be 0.
//!
//! Replaces: lib/clz_ctz.c

use core::ffi::c_int;

/// Body of `__ctzsi2()`: count trailing zeros of a 32-bit value.
#[no_mangle]
pub extern "C" fn rust_ctzsi2(val: c_int) -> c_int {
    (val as u32).trailing_zeros() as c_int
}

/// Body of `__clzsi2()`: count leading zeros of a 32-bit value.
#[no_mangle]
pub extern "C" fn rust_clzsi2(val: c_int) -> c_int {
    (val as u32).leading_zeros() as c_int
}

/// Body of `__clzdi2()`: count leading zeros of a 64-bit value.
#[no_mangle]
pub extern "C" fn rust_clzdi2(val: u64) -> c_int {
    val.leading_zeros() as c_int
}

/// Body of `__ctzdi2()`: count trailing zeros of a 64-bit value.
#[no_mangle]
pub extern "C" fn rust_ctzdi2(val: u64) -> c_int {
    val.trailing_zeros() as c_int
}
