// SPDX-License-Identifier: GPL-2.0

//! Integer square root.
//!
//! Ported from `lib/math/int_sqrt.c` (6.18.49). The shift-and-subtract
//! algorithm attributed to Guy L. Steele, unchanged.
//!
//! `int_sqrt64()` is not here: on 64-bit it is a `static inline` in
//! `include/linux/math.h` that just calls `int_sqrt()`, and only 32-bit
//! builds compile the out-of-line version. This tree is x86-64.
//!
//! Replaces: lib/math/int_sqrt.c

kernel::kabi_export! {
    int_sqrt,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter base_type unsigned long byte_size(8) encoding(7) x ) -> base_type unsigned long byte_size(8) encoding(7)",
}

/// Computes `floor(sqrt(x))`.
///
/// See `include/linux/math.h` for the C declaration this matches.
#[no_mangle]
pub extern "C" fn int_sqrt(x: usize) -> usize {
    let mut x = x;

    if x <= 1 {
        return x;
    }

    // The C is `1UL << (__fls(x) & ~1UL)`: the highest set bit, rounded down
    // to an even position. `leading_zeros` gives the same index without a
    // kernel helper -- x > 1 here, so it is never called on zero.
    let fls = (usize::BITS - 1 - x.leading_zeros()) as usize;
    let mut m: usize = 1 << (fls & !1);
    let mut y: usize = 0;

    while m != 0 {
        let b = y.wrapping_add(m);
        y >>= 1;

        if x >= b {
            x = x.wrapping_sub(b);
            y = y.wrapping_add(m);
        }
        m >>= 2;
    }

    y
}
