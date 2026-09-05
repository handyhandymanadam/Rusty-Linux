// SPDX-License-Identifier: GPL-2.0-only

//! Greatest common divisor -- the Rust bodies behind `lib/math/gcd.c`.
//!
//! Ported from `lib/math/gcd.c` (6.18.49). Both algorithms are the binary
//! GCD (often attributed to Stein, but as Knuth noted, it appears in a
//! first-century Chinese text), in the two forms the C carries: one that
//! uses a find-first-set instruction and one that normalises by shifting in
//! a loop.
//!
//! **The choice between them stays in C.** It is a jump label
//! (`static_branch_likely(&efficient_ffs_key)`), which is patched into the
//! instruction stream at boot and is not something a Rust body can consult.
//! `lib/math/gcd.c` reads the key and calls one of these two.
//!
//! Only riscv ever clears that key, so on this tree [`rust_binary_gcd`] is
//! what runs -- but [`rust_gcd_even_odd`] is ported all the same, because
//! leaving half a module in C to save ten minutes is how a subsystem never
//! finishes (GOALS.md §1).
//!
//! Both are entered only with `a` and `b` both non-zero; `gcd()` handles the
//! zero cases before dispatching, exactly as the C did.
//!
//! Replaces: lib/math/gcd.c

/// Binary GCD using find-first-set. `a` and `b` must both be non-zero.
///
/// See `include/linux/gcd.h` for the C declaration.
#[no_mangle]
pub extern "C" fn rust_binary_gcd(a: usize, b: usize) -> usize {
    let mut a = a;
    let mut b = b;
    let r = a | b;

    b >>= b.trailing_zeros();
    if b == 1 {
        return r & r.wrapping_neg();
    }

    loop {
        a >>= a.trailing_zeros();
        if a == 1 {
            return r & r.wrapping_neg();
        }
        if a == b {
            return a << r.trailing_zeros();
        }

        if a < b {
            core::mem::swap(&mut a, &mut b);
        }
        a -= b;
    }
}

/// Binary GCD normalising by loop rather than by find-first-set.
///
/// `a` and `b` must both be non-zero. Used where the CPU has no efficient
/// ffs; on that hardware the C benchmarks this one faster.
///
/// See `include/linux/gcd.h` for the C declaration.
#[no_mangle]
pub extern "C" fn rust_gcd_even_odd(a: usize, b: usize) -> usize {
    let mut a = a;
    let mut b = b;

    // Isolate the lowest set bit of a | b.
    let r0 = a | b;
    let r = r0 & r0.wrapping_neg();

    while b & r == 0 {
        b >>= 1;
    }
    if b == r {
        return r;
    }

    loop {
        while a & r == 0 {
            a >>= 1;
        }
        if a == r {
            return r;
        }
        if a == b {
            return a;
        }

        if a < b {
            core::mem::swap(&mut a, &mut b);
        }
        a -= b;
        a >>= 1;
        if a & r != 0 {
            a += b;
        }
        a >>= 1;
    }
}
