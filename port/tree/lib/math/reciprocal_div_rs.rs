// SPDX-License-Identifier: GPL-2.0

//! Reciprocal division constants -- the Rust body behind
//! `lib/math/reciprocal_div.c`'s two exported entry symbols.
//!
//! Ported from `lib/math/reciprocal_div.c` (6.18.49). The algorithm is the
//! one described in `include/linux/reciprocal_div.h`, unchanged.
//!
//! Both returned structs are **caller-owned layout** in the GOALS.md §5
//! sense: callers embed them, `reciprocal_divide()` reads their fields, and
//! they cross the FFI boundary by value. So both are `#[repr(C)]` with the
//! field order and widths of the C declarations in
//! `include/linux/reciprocal_div.h`, and that is not ours to tidy.
//!
//! Replaces: lib/math/reciprocal_div.c

/// Mirrors `struct reciprocal_value` in `include/linux/reciprocal_div.h`.
#[repr(C)]
pub struct ReciprocalValue {
    /// The magic multiplier.
    pub m: u32,
    /// First shift.
    pub sh1: u8,
    /// Second shift.
    pub sh2: u8,
}

/// Mirrors `struct reciprocal_value_adv` in `include/linux/reciprocal_div.h`.
#[repr(C)]
pub struct ReciprocalValueAdv {
    /// The magic multiplier.
    pub m: u32,
    /// Post-shift.
    pub sh: u8,
    /// `ceil(log2(d))`.
    pub exp: u8,
    /// Whether `m` did not fit in 32 bits.
    pub is_wide_m: bool,
}

/// The kernel's `fls()`: one plus the index of the highest set bit, or 0.
#[inline]
fn fls(x: u32) -> u32 {
    u32::BITS - x.leading_zeros()
}

/// Body of `reciprocal_value()`.
///
/// See `include/linux/reciprocal_div.h` for the C declaration.
#[no_mangle]
pub extern "C" fn rust_reciprocal_value(d: u32) -> ReciprocalValue {
    let l = fls(d.wrapping_sub(1));

    // The C is `m = (1ULL << 32) * ((1ULL << l) - d); do_div(m, d); ++m;`
    // `l` is at most 32 here, so `1ULL << l` is computed in 64 bits.
    let m: u64 = ((1u64 << 32).wrapping_mul((1u64 << l).wrapping_sub(d as u64))) / d as u64;
    let m = m.wrapping_add(1);

    ReciprocalValue {
        m: m as u32,
        // min(l, 1) and max(l - 1, 0) on a SIGNED int in the C. `l` is
        // non-negative there too, so the max() is just a saturating
        // subtraction -- but it is written out rather than assumed.
        sh1: core::cmp::min(l, 1) as u8,
        sh2: l.saturating_sub(1) as u8,
    }
}

/// Body of `reciprocal_value_adv()`.
///
/// The `l == 32` case is rejected by the C wrapper's `WARN()` before this is
/// reached; see `lib/math/reciprocal_div.c`.
///
/// See `include/linux/reciprocal_div.h` for the C declaration.
#[no_mangle]
pub extern "C" fn rust_reciprocal_value_adv(d: u32, prec: u8) -> ReciprocalValueAdv {
    // ceil(log2(d))
    let l = fls(d.wrapping_sub(1));
    let mut post_shift = l;

    // NOTE, from the C: mlow/mhigh overflow u64 when l == 32, which the C
    // wrapper WARNs about and does not prevent. So `32 + l` reaches 64 and
    // `32 + l - prec` can go negative, and BOTH are shift amounts.
    //
    // In C those are undefined behaviour; on x86-64 they compile to `shl`,
    // which masks the count to 6 bits, and that masked result is what every
    // caller has been getting. `wrapping_shl` masks identically, so the Rust
    // reproduces the shipped behaviour rather than panicking on a path the C
    // merely complains about. A plain `<<` here would be a kernel BUG() on
    // any divisor above 2^31.
    let mut mlow: u64 = 1u64.wrapping_shl(32 + l) / d as u64;
    let mut mhigh: u64 = 1u64
        .wrapping_shl(32 + l)
        .wrapping_add(1u64.wrapping_shl((32 + l).wrapping_sub(prec as u32)))
        / d as u64;

    while post_shift > 0 {
        let lo = mlow >> 1;
        let hi = mhigh >> 1;

        if lo >= hi {
            break;
        }
        mlow = lo;
        mhigh = hi;
        post_shift -= 1;
    }

    ReciprocalValueAdv {
        m: mhigh as u32,
        sh: post_shift as u8,
        exp: l as u8,
        is_wide_m: mhigh > u32::MAX as u64,
    }
}
