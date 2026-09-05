// SPDX-License-Identifier: GPL-2.0-only

//! Lowest common multiple -- the Rust bodies behind `lib/math/lcm.c`.
//!
//! Ported from `lib/math/lcm.c` (6.18.49).
//!
//! These call back out to the C `gcd()`, which is a C↔Rust crossing in the
//! wrong direction. It is deliberate and temporary: `gcd()` is the function
//! that reads the `efficient_ffs_key` jump label, so it has to be the C one.
//! When the whole of `lib/math` is Rust that dispatch is the only C left in
//! it, and this crossing is what it costs until then (SCOPE.md §1).
//!
//! Replaces: lib/math/lcm.c

extern "C" {
    /// `lib/math/gcd.c`. Consults the `efficient_ffs_key` jump label, then
    /// calls one of the two Rust bodies in `lib/math/gcd_rs.rs`.
    fn gcd(a: usize, b: usize) -> usize;
}

kernel::kabi_export! {
    lcm,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter base_type unsigned long byte_size(8) encoding(7) a , formal_parameter base_type unsigned long byte_size(8) encoding(7) b ) -> base_type unsigned long byte_size(8) encoding(7)",
}

/// Body of `lcm()`. Zero if either argument is zero.
///
/// See `include/linux/lcm.h` for the C declaration.
#[no_mangle]
pub extern "C" fn lcm(a: usize, b: usize) -> usize {
    if a != 0 && b != 0 {
        // SAFETY: gcd() is a pure function over two integers with no
        // preconditions -- it returns a | b when either is zero -- and it
        // touches no memory. Both arguments are non-zero here, so the
        // division below cannot divide by zero either.
        (a / unsafe { gcd(a, b) }).wrapping_mul(b)
    } else {
        0
    }
}

kernel::kabi_export! {
    lcm_not_zero,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter base_type unsigned long byte_size(8) encoding(7) a , formal_parameter base_type unsigned long byte_size(8) encoding(7) b ) -> base_type unsigned long byte_size(8) encoding(7)",
}

/// Body of `lcm_not_zero()`: like [`lcm`], but falls back to whichever
/// argument is non-zero rather than returning zero.
///
/// See `include/linux/lcm.h` for the C declaration.
#[no_mangle]
pub extern "C" fn lcm_not_zero(a: usize, b: usize) -> usize {
    let l = lcm(a, b);

    if l != 0 {
        return l;
    }
    if b != 0 { b } else { a }
}
