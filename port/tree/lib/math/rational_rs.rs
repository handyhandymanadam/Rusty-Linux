// SPDX-License-Identifier: GPL-2.0

//! Best rational approximation -- the Rust body behind
//! `lib/math/rational.c`'s exported entry symbol.
//!
//! Ported from `lib/math/rational.c` (6.18.49), which is
//! Copyright (C) 2009 emlix GmbH, Oskar Schirmer and
//! Copyright (C) 2019 Trent Piepho. The continued-fraction algorithm is
//! unchanged.
//!
//! # Every multiplication here wraps, on purpose
//!
//! The C computes `a * n1`, `t * n1`, `2u * t`, `d0 * dp` and `d1 * d` on
//! `unsigned long` and lets them wrap. With `max_numerator` or
//! `max_denominator` near `ULONG_MAX` several of them genuinely do —
//! `t` can reach `ULONG_MAX - d0`, and `2 * t` then overflows.
//!
//! The kernel builds Rust with overflow checks on, so a plain `*` there
//! would not be a subtly different answer, it would be a **kernel panic on
//! an input the C handles**. `wrapping_*` reproduces what callers have
//! always got. This is the same judgement made in `int_pow_rs.rs` and
//! `reciprocal_div_rs.rs`, and it is the one place where being faithful to
//! the C means writing something that looks careless.
//!
//! Replaces: lib/math/rational.c

// The MODULE_*() metadata of the C file this replaced. It is real output
// for a built-in object: kbuild extracts .modinfo into the installed
// modules.builtin.modinfo. See kernel::kabi_modinfo.
kernel::kabi_modinfo! {
    "rational",
    file = "lib/math/rational",
    description = "Rational fraction support library",
    license = "GPL v2",
}

kernel::kabi_export! {
    rational_best_approximation,
    license = "",
    namespace = "",
    contract = "subprogram ( formal_parameter base_type unsigned long byte_size(8) encoding(7) given_numerator , formal_parameter base_type unsigned long byte_size(8) encoding(7) given_denominator , formal_parameter base_type unsigned long byte_size(8) encoding(7) max_numerator , formal_parameter base_type unsigned long byte_size(8) encoding(7) max_denominator , formal_parameter pointer_type { base_type unsigned long byte_size(8) encoding(7) } best_numerator , formal_parameter pointer_type { base_type unsigned long byte_size(8) encoding(7) } best_denominator ) -> base_type void",
}

/// Body of `rational_best_approximation()`.
///
/// Writes the best numerator and denominator through the two out-pointers.
///
/// # Safety
/// `best_numerator` and `best_denominator` must be valid, non-null, writable
/// and non-overlapping. That is the same contract the C had.
///
/// See `include/linux/rational.h` for the C declaration.
#[no_mangle]
pub unsafe extern "C" fn rational_best_approximation(
    given_numerator: usize,
    given_denominator: usize,
    max_numerator: usize,
    max_denominator: usize,
    best_numerator: *mut usize,
    best_denominator: *mut usize,
) {
    // n/d is the starting rational, decreased each iteration by the
    // Euclidean algorithm. dp is d from the prior iteration. n2/d2, n1/d1
    // and n0/d0 are the current, previous and two-prior convergents. `a` is
    // the current term of the continued fraction.
    let mut n = given_numerator;
    let mut d = given_denominator;
    let (mut n0, mut d0) = (0usize, 1usize);
    let (mut n1, mut d1) = (1usize, 0usize);

    while d != 0 {
        let dp = d;
        let a = n / d;

        d = n % d;
        n = dp;

        let n2 = n0.wrapping_add(a.wrapping_mul(n1));
        let d2 = d0.wrapping_add(a.wrapping_mul(d1));

        // If the current convergent exceeds the maxes, take either the
        // previous convergent or the largest semi-convergent, whose final
        // term is `t`.
        if n2 > max_numerator || d2 > max_denominator {
            let mut t = usize::MAX;

            if d1 != 0 {
                t = (max_denominator - d0) / d1;
            }
            if n1 != 0 {
                t = core::cmp::min(t, (max_numerator - n0) / n1);
            }

            // Is the semi-convergent closer than the previous convergent?
            // When d1 is zero there is no previous convergent -- this is the
            // first iteration -- so always take the semi-convergent.
            if d1 == 0
                || 2usize.wrapping_mul(t) > a
                || (2usize.wrapping_mul(t) == a && d0.wrapping_mul(dp) > d1.wrapping_mul(d))
            {
                n1 = n0.wrapping_add(t.wrapping_mul(n1));
                d1 = d0.wrapping_add(t.wrapping_mul(d1));
            }
            break;
        }

        n0 = n1;
        n1 = n2;
        d0 = d1;
        d1 = d2;
    }

    // SAFETY: the caller guarantees both pointers are valid, writable and
    // distinct. Nothing else in this function touches memory.
    unsafe {
        *best_numerator = n1;
        *best_denominator = d1;
    }
}
