// SPDX-License-Identifier: GPL-2.0-or-later

//! MPI division helpers -- the Rust behind `lib/crypto/mpi/mpih-div.c`.
//!
//! Ported from `lib/crypto/mpi/mpih-div.c` (6.18.49). Knuth's Algorithm D,
//! by way of GNU MP's `mpn` division core.
//!
//! Replaces: lib/crypto/mpi/mpih-div.c
//!
//! # No exported symbols here
//!
//! None of `mpihelp_mod_1`/`mpihelp_divrem`/`mpihelp_divmod_1` is
//! `EXPORT_SYMBOL`, but all three are real (non-`static`) symbols other
//! still-C files in `lib/crypto/mpi/` call directly -- same class as
//! `mpiutil.c`'s non-exported functions.
//!
//! # The pre-inverted-divisor path is dead code on this architecture, and
//! # it is not reproduced
//!
//! `mpih-div.c` guards its fast path with
//! `UDIV_TIME > (2 * UMUL_TIME + 6) && (UDIV_TIME - (2*UMUL_TIME+6)) *
//! dividend_size > UDIV_TIME`. `mpih-div.c` itself defines `UMUL_TIME` and
//! `UDIV_TIME` to `1` if nothing has already defined them
//! (`#ifndef UMUL_TIME` / `#define UMUL_TIME 1`), and `lib/crypto/mpi/
//! longlong.h` has no `__x86_64__`/`__amd64__` section at all (checked: zero
//! matches) -- so on this architecture neither macro is ever redefined and
//! the guard is `1 > 8`, a compile-time-constant false. GCC/clang eliminate
//! the branch entirely; `objdump` on the currently-compiled `mpih-div.o`
//! shows nothing resembling the extra inversion arithmetic. Only the `else`
//! arm of each function is ported.
//!
//! # `count_leading_zeros` is `u64::leading_zeros`
//!
//! `include/linux/count_zeros.h`: `count_leading_zeros(x) = BITS_PER_LONG -
//! fls64(x)`, and `fls64(0) == 0` -- so `count_leading_zeros(0) ==
//! BITS_PER_LONG`. `u64::leading_zeros()` has the identical contract
//! (`0u64.leading_zeros() == 64`), so it is used directly rather than
//! reproducing `fls64`'s bit-scan by hand.
//!
//! # `umul_ppmm` is a widened `u128` multiply; `udiv_qrnnd` is NOT a
//! # widened `u128` divide -- measured, not assumed
//!
//! The first draft of this file used `u128` for both, on the reasoning
//! that Rust's built-in 128-bit type makes both a one-line widening
//! operation instead of `longlong.h`'s 32-bit half-limb schoolbook
//! algorithm (needed there only because C has no 128-bit type to fall back
//! on). That is true for the multiply: `((u as u128) * (v as u128))`
//! lowers to a single native widening multiply, no runtime call, verified
//! by linking cleanly. **It is not true for the divide.** `u128` division
//! for a general divisor has no single x86-64 instruction, and rustc lowers
//! it to a call to `__udivti3`/`__umodti3` -- symbols `rust/compiler_
//! builtins.rs` does not provide, and the first attempt at this file failed
//! `vmlinux` link with exactly those two undefined. x86-64 does have a
//! native 128-by-64-bit divide instruction (the one `udiv_qrnnd`'s
//! precondition -- quotient fits in one limb -- exists to make usable),
//! but nothing here asks the compiler to recognise that special case, and
//! generating raw `asm!` for it is more axiom-class `unsafe` than
//! reproducing the C's own portable algorithm. So `udiv_qrnnd` below IS the
//! half-limb algorithm, `longlong.h`'s `__udiv_qrnnd_c` transliterated
//! (32-bit halves of a 64-bit limb, two ordinary `u64` divisions rather
//! than one `u128` one -- `u64` division has no such linking problem).
//! `count_leading_zeros` uses `u64::leading_zeros` regardless, since that
//! has no such caveat.
//!
//! # `1 / dsize` (divide by zero) becomes a panic, not the C's UB
//!
//! `mpihelp_divrem`'s `dsize == 0` arm is the C's own words: "existing
//! clients ... have been modified not to call it with dsize == 0, so this
//! should not happen." `1 / 0` in C is undefined behaviour (a SIGFPE on
//! x86); every caller in this project already avoids it, so this never
//! executes either version. A Rust integer division by zero panics
//! unconditionally, which is what happens here instead of the SIGFPE --
//! recorded because a future reader diffing against the C would otherwise
//! wonder where the exact expression went.

use core::ffi::{c_int, c_ulong};

/// `BITS_PER_MPI_LIMB` on this architecture (`mpi_limb_t` is `unsigned
/// long`, 64 bits on x86-64).
const BITS_PER_MPI_LIMB: u32 = 64;

unsafe extern "C" {
    fn mpihelp_add_n(res_ptr: *mut c_ulong, s1_ptr: *const c_ulong, s2_ptr: *const c_ulong, size: c_int) -> c_ulong;
    fn mpihelp_sub_n(res_ptr: *mut c_ulong, s1_ptr: *const c_ulong, s2_ptr: *const c_ulong, size: c_int) -> c_ulong;
    fn mpihelp_cmp(op1_ptr: *const c_ulong, op2_ptr: *const c_ulong, size: c_int) -> c_int;
    fn mpihelp_submul_1(res_ptr: *mut c_ulong, s1_ptr: *const c_ulong, s1_size: c_int, s2_limb: c_ulong) -> c_ulong;
}

/// `count_leading_zeros()` (`include/linux/count_zeros.h`). See the module
/// doc comment.
#[inline(always)]
fn count_leading_zeros(x: c_ulong) -> u32 {
    x.leading_zeros()
}

/// `umul_ppmm(w1, w0, u, v)`: full 128-bit product, returned as (high, low).
/// See the module doc comment for why this is a `u128` multiply rather than
/// the half-limb schoolbook algorithm the C macro expands to.
#[inline(always)]
fn umul_ppmm(u: c_ulong, v: c_ulong) -> (c_ulong, c_ulong) {
    let p = (u as u128) * (v as u128);
    ((p >> 64) as c_ulong, p as c_ulong)
}

/// `udiv_qrnnd(q, r, n1, n0, d)`: divide the 128-bit numerator `(n1:n0)` by
/// `d`, returning `(quotient, remainder)`. `longlong.h`'s `__udiv_qrnnd_c`,
/// transliterated -- see the module doc comment for why this is not a
/// `u128` divide.
///
/// # Precondition (not memory safety, but still on the caller)
/// `d` must be normalized (its top bit set, so `d`'s high 32 bits alone are
/// already nonzero) and `n1 < d`, so the quotient fits in one limb -- the
/// same precondition the C macro documents. Every call site in this file
/// establishes this before calling.
#[inline(always)]
fn udiv_qrnnd(n1: c_ulong, n0: c_ulong, d: c_ulong) -> (c_ulong, c_ulong) {
    const HALF_BITS: u32 = BITS_PER_MPI_LIMB / 2;
    const B: u64 = 1u64 << HALF_BITS;
    let lowpart = |t: u64| t & (B - 1);
    let highpart = |t: u64| t >> HALF_BITS;

    let d1 = highpart(d);
    let d0 = lowpart(d);

    let mut r1 = n1 % d1;
    let mut q1 = n1 / d1;
    let mut m = q1.wrapping_mul(d0);
    r1 = r1.wrapping_mul(B) | highpart(n0);
    if r1 < m {
        q1 = q1.wrapping_sub(1);
        r1 = r1.wrapping_add(d);
        if r1 >= d && r1 < m {
            q1 = q1.wrapping_sub(1);
            r1 = r1.wrapping_add(d);
        }
    }
    r1 = r1.wrapping_sub(m);

    let mut r0 = r1 % d1;
    let mut q0 = r1 / d1;
    m = q0.wrapping_mul(d0);
    r0 = r0.wrapping_mul(B) | lowpart(n0);
    if r0 < m {
        q0 = q0.wrapping_sub(1);
        r0 = r0.wrapping_add(d);
        if r0 >= d && r0 < m {
            q0 = q0.wrapping_sub(1);
            r0 = r0.wrapping_add(d);
        }
    }
    r0 = r0.wrapping_sub(m);

    (q1.wrapping_mul(B) | q0, r0)
}

/// `add_ssaaaa(sh, sl, ah, al, bh, bl)`: `(sh, sl) = (ah, al) + (bh, bl)`,
/// a double-limb add.
#[inline(always)]
fn add_ssaaaa(ah: c_ulong, al: c_ulong, bh: c_ulong, bl: c_ulong) -> (c_ulong, c_ulong) {
    let (sl, c) = al.overflowing_add(bl);
    let sh = ah.wrapping_add(bh).wrapping_add(c as c_ulong);
    (sh, sl)
}

/// `sub_ddmmss(sh, sl, ah, al, bh, bl)`: `(sh, sl) = (ah, al) - (bh, bl)`,
/// a double-limb subtract.
#[inline(always)]
fn sub_ddmmss(ah: c_ulong, al: c_ulong, bh: c_ulong, bl: c_ulong) -> (c_ulong, c_ulong) {
    let (sl, b) = al.overflowing_sub(bl);
    let sh = ah.wrapping_sub(bh).wrapping_sub(b as c_ulong);
    (sh, sl)
}

/// `mpihelp_mod_1()`: remainder of `(dividend_ptr, dividend_size)` divided
/// by `divisor_limb`.
///
/// # Safety
/// `dividend_ptr` must be readable for `dividend_size` limbs.
#[no_mangle]
pub unsafe extern "C" fn mpihelp_mod_1(
    dividend_ptr: *const c_ulong,
    dividend_size: c_int,
    mut divisor_limb: c_ulong,
) -> c_ulong {
    if dividend_size == 0 {
        return 0;
    }

    let normalization_steps = count_leading_zeros(divisor_limb);
    if normalization_steps != 0 {
        divisor_limb <<= normalization_steps;

        // SAFETY: `dividend_size >= 1` (checked above), so index
        // `dividend_size - 1` is in bounds.
        let mut n1 = unsafe { *dividend_ptr.add((dividend_size - 1) as usize) };
        let mut r = n1 >> (BITS_PER_MPI_LIMB - normalization_steps);

        let mut i = dividend_size - 2;
        while i >= 0 {
            // SAFETY: `i` in `0..dividend_size - 1` here.
            let n0 = unsafe { *dividend_ptr.add(i as usize) };
            let (_q, rr) = udiv_qrnnd(
                r,
                (n1 << normalization_steps) | (n0 >> (BITS_PER_MPI_LIMB - normalization_steps)),
                divisor_limb,
            );
            r = rr;
            n1 = n0;
            i -= 1;
        }
        let (_q, rr) = udiv_qrnnd(r, n1 << normalization_steps, divisor_limb);
        r = rr;
        return r >> normalization_steps;
    }

    // No normalization needed: divisor_limb is already normalized.
    let mut i = dividend_size - 1;
    // SAFETY: `i` in bounds (`dividend_size >= 1`).
    let mut r = unsafe { *dividend_ptr.add(i as usize) };
    if r >= divisor_limb {
        r = 0;
    } else {
        i -= 1;
    }
    while i >= 0 {
        // SAFETY: `i` in `0..dividend_size` here.
        let n0 = unsafe { *dividend_ptr.add(i as usize) };
        let (_q, rr) = udiv_qrnnd(r, n0, divisor_limb);
        r = rr;
        i -= 1;
    }
    r
}

/// `mpihelp_divmod_1()`: like [`mpihelp_mod_1`], but also writes the
/// quotient's `dividend_size` limbs at `quot_ptr`.
///
/// # Safety
/// `dividend_ptr` readable and `quot_ptr` writable for `dividend_size`
/// limbs; they may point at the same buffer.
#[no_mangle]
pub unsafe extern "C" fn mpihelp_divmod_1(
    quot_ptr: *mut c_ulong,
    dividend_ptr: *const c_ulong,
    dividend_size: c_int,
    mut divisor_limb: c_ulong,
) -> c_ulong {
    if dividend_size == 0 {
        return 0;
    }

    let normalization_steps = count_leading_zeros(divisor_limb);
    if normalization_steps != 0 {
        divisor_limb <<= normalization_steps;

        // SAFETY: `dividend_size >= 1`.
        let mut n1 = unsafe { *dividend_ptr.add((dividend_size - 1) as usize) };
        let mut r = n1 >> (BITS_PER_MPI_LIMB - normalization_steps);

        let mut i = dividend_size - 2;
        while i >= 0 {
            // SAFETY: `i` in `0..dividend_size - 1`.
            let n0 = unsafe { *dividend_ptr.add(i as usize) };
            let (q, rr) = udiv_qrnnd(
                r,
                (n1 << normalization_steps) | (n0 >> (BITS_PER_MPI_LIMB - normalization_steps)),
                divisor_limb,
            );
            // SAFETY: `quot_ptr` writable for `dividend_size` limbs;
            // `i + 1` is in `1..dividend_size` here.
            unsafe { *quot_ptr.add((i + 1) as usize) = q };
            r = rr;
            n1 = n0;
            i -= 1;
        }
        let (q, rr) = udiv_qrnnd(r, n1 << normalization_steps, divisor_limb);
        // SAFETY: `quot_ptr` writable for `dividend_size` limbs.
        unsafe { *quot_ptr = q };
        r = rr;
        return r >> normalization_steps;
    }

    let mut i = dividend_size - 1;
    // SAFETY: `i` in bounds.
    let mut r = unsafe { *dividend_ptr.add(i as usize) };
    if r >= divisor_limb {
        r = 0;
    } else {
        // SAFETY: `quot_ptr` writable for `dividend_size` limbs.
        unsafe { *quot_ptr.add(i as usize) = 0 };
        i -= 1;
    }
    while i >= 0 {
        // SAFETY: `i` in `0..dividend_size`.
        let n0 = unsafe { *dividend_ptr.add(i as usize) };
        let (q, rr) = udiv_qrnnd(r, n0, divisor_limb);
        unsafe { *quot_ptr.add(i as usize) = q };
        r = rr;
        i -= 1;
    }
    r
}

/// `mpihelp_divrem()`: divide `(np, nsize)` by `(dp, dsize)`, writing
/// `nsize - dsize (+ qextra_limbs)` quotient limbs at `qp` and leaving the
/// `dsize`-limb remainder in `np`. Returns the quotient's own most
/// significant limb, always 0 or 1.
///
/// # Safety
/// Preconditions, from the C's own comment: `nsize >= dsize`; the most
/// significant bit of `dp[dsize - 1]` must be set; `qp` must either not
/// overlap `np`/`dp` at all, or satisfy `qp + dsize >= np`. `qp` writable
/// for `nsize - dsize + qextra_limbs` limbs, `np` valid (readable and
/// writable) for `nsize` limbs, `dp` readable for `dsize` limbs.
#[no_mangle]
pub unsafe extern "C" fn mpihelp_divrem(
    qp: *mut c_ulong,
    qextra_limbs: c_int,
    np: *mut c_ulong,
    nsize: c_int,
    dp: *const c_ulong,
    dsize: c_int,
) -> c_ulong {
    let mut most_significant_q_limb: c_ulong = 0;

    match dsize {
        0 => {
            // "Should not happen" per the C's own comment -- see the
            // module doc comment for why a panic is the faithful
            // reproduction of its `1 / dsize`.
            panic!("mpihelp_divrem: dsize == 0");
        }

        1 => {
            // SAFETY: `dp` readable for 1 limb (`dsize == 1`).
            let d = unsafe { *dp };
            // SAFETY: `nsize >= dsize == 1`, so index `nsize - 1` is valid.
            let mut n1 = unsafe { *np.add((nsize - 1) as usize) };

            if n1 >= d {
                n1 -= d;
                most_significant_q_limb = 1;
            }

            // SAFETY: `qp` writable for `nsize - 1 + qextra_limbs` limbs
            // starting here (caller contract).
            let qp_shifted = unsafe { qp.add(qextra_limbs as usize) };
            let mut i = nsize - 2;
            while i >= 0 {
                // SAFETY: `i` in `0..nsize - 1`.
                let n0 = unsafe { *np.add(i as usize) };
                let (q, r) = udiv_qrnnd(n1, n0, d);
                unsafe { *qp_shifted.add(i as usize) = q };
                n1 = r;
                i -= 1;
            }
            let mut i = qextra_limbs - 1;
            while i >= 0 {
                let (q, r) = udiv_qrnnd(n1, 0, d);
                // SAFETY: `qp` writable for `qextra_limbs` limbs here.
                unsafe { *qp.add(i as usize) = q };
                n1 = r;
                i -= 1;
            }
            // SAFETY: `np` writable for at least 1 limb.
            unsafe { *np = n1 };
        }

        2 => {
            // SAFETY: `nsize >= dsize == 2`, so this stays within `np`'s
            // `nsize` limbs.
            let mut np = unsafe { np.add((nsize - 2) as usize) };
            // SAFETY: `dp` readable for 2 limbs.
            let (d1, d0) = unsafe { (*dp.add(1), *dp) };
            // SAFETY: `np` (after the offset above) readable for 2 limbs.
            let (mut n1, mut n0) = unsafe { (*np.add(1), *np) };

            if n1 >= d1 && (n1 > d1 || n0 >= d0) {
                let (sh, sl) = sub_ddmmss(n1, n0, d1, d0);
                n1 = sh;
                n0 = sl;
                most_significant_q_limb = 1;
            }

            let mut i = qextra_limbs + nsize - 2 - 1;
            'outer: while i >= 0 {
                let q;
                let mut r;
                let n2;

                if i >= qextra_limbs {
                    // SAFETY: within `np`'s original `nsize`-limb range;
                    // the C's own precondition 2 (`qp` clear of `np`, or
                    // `qp + dsize >= np`) is what makes this safe against
                    // the writes below.
                    np = unsafe { np.sub(1) };
                } else {
                    // SAFETY: `np[0]` is writable (part of the `nsize`-limb
                    // buffer, or the caller-guaranteed overlap allows it).
                    unsafe { *np = 0 };
                }

                if n1 == d1 {
                    let qq = !0 as c_ulong;
                    let (rr, carry) = n0.overflowing_add(d1);
                    if carry {
                        // "Carry in the addition": q is exactly right,
                        // shortcut the rest of this iteration.
                        // SAFETY: `np` valid.
                        let np0 = unsafe { *np };
                        let (sh, sl) = add_ssaaaa(rr.wrapping_sub(d0), np0, 0, d0);
                        n1 = sh;
                        n0 = sl;
                        // SAFETY: `qp` writable at index `i`.
                        unsafe { *qp.add(i as usize) = qq };
                        i -= 1;
                        continue 'outer;
                    }
                    n1 = d0.wrapping_sub((d0 != 0) as c_ulong);
                    n0 = d0.wrapping_neg();
                    r = rr;
                    q = qq;
                } else {
                    let (qq, rr) = udiv_qrnnd(n1, n0, d1);
                    let (nh, nl) = umul_ppmm(d0, qq);
                    n1 = nh;
                    n0 = nl;
                    q = qq;
                    r = rr;
                }

                // SAFETY: `np` valid.
                n2 = unsafe { *np };
                let mut q = q;
                loop {
                    if !(n1 > r || (n1 == r && n0 > n2)) {
                        break;
                    }
                    q -= 1;
                    let (sh, sl) = sub_ddmmss(n1, n0, 0, d0);
                    n1 = sh;
                    n0 = sl;
                    let (rr, carry) = r.overflowing_add(d1);
                    r = rr;
                    if carry {
                        break;
                    }
                }

                // SAFETY: `qp` writable at index `i`.
                unsafe { *qp.add(i as usize) = q };
                let (sh, sl) = sub_ddmmss(r, n2, n1, n0);
                n1 = sh;
                n0 = sl;

                i -= 1;
            }
            // SAFETY: `np` valid for 2 limbs.
            unsafe {
                *np.add(1) = n1;
                *np = n0;
            }
        }

        _ => {
            // SAFETY: `nsize >= dsize`, so this stays within `np`'s range.
            let mut np = unsafe { np.add((nsize - dsize) as usize) };
            // SAFETY: `dp` readable for `dsize` limbs.
            let dx = unsafe { *dp.add((dsize - 1) as usize) };
            let d1 = unsafe { *dp.add((dsize - 2) as usize) };
            // SAFETY: `np` (after the offset) readable for `dsize` limbs.
            let mut n0 = unsafe { *np.add((dsize - 1) as usize) };

            if n0 >= dx {
                // SAFETY: `np`, `dp` each readable for `dsize - 1` limbs.
                if n0 > dx || unsafe { mpihelp_cmp(np, dp, dsize - 1) } >= 0 {
                    // SAFETY: `np`, `dp` each valid for `dsize` limbs.
                    unsafe { mpihelp_sub_n(np, np, dp, dsize) };
                    n0 = unsafe { *np.add((dsize - 1) as usize) };
                    most_significant_q_limb = 1;
                }
            }

            let mut i = qextra_limbs + nsize - dsize - 1;
            while i >= 0 {
                let q;
                let n2;

                if i >= qextra_limbs {
                    np = unsafe { np.sub(1) };
                    // SAFETY: `np[dsize]` is the limb this decrement just
                    // uncovered -- within the caller's `nsize`-limb range
                    // by the same reasoning as case 2 above.
                    n2 = unsafe { *np.add(dsize as usize) };
                } else {
                    // SAFETY: `np` readable for `dsize` limbs here.
                    n2 = unsafe { *np.add((dsize - 1) as usize) };
                    // MPN_COPY_DECR(np + 1, np, dsize - 1): shift the
                    // buffer up by one limb, highest index first -- safe
                    // for this direction of overlap.
                    let mut j = dsize - 2;
                    while j >= 0 {
                        // SAFETY: both indices in `0..dsize` here.
                        unsafe { *np.add((j + 1) as usize) = *np.add(j as usize) };
                        j -= 1;
                    }
                    // SAFETY: `np[0]` writable.
                    unsafe { *np = 0 };
                }

                if n0 == dx {
                    q = !0 as c_ulong;
                } else {
                    // SAFETY: `np` readable for `dsize` limbs.
                    let np_dsize_1 = unsafe { *np.add((dsize - 1) as usize) };
                    let (qq, r0) = udiv_qrnnd(n0, np_dsize_1, dx);
                    let (nh, nl) = umul_ppmm(d1, qq);
                    let mut n1 = nh;
                    let mut n0_inner = nl;
                    let mut r = r0;
                    let mut qq = qq;

                    // SAFETY: `np` readable for `dsize` limbs (`dsize >= 3`
                    // here, so index `dsize - 2` is valid).
                    let np_dsize_2 = unsafe { *np.add((dsize - 2) as usize) };
                    loop {
                        if !(n1 > r || (n1 == r && n0_inner > np_dsize_2)) {
                            break;
                        }
                        qq -= 1;
                        let (rr, carry) = r.overflowing_add(dx);
                        r = rr;
                        if carry {
                            break;
                        }
                        n1 = n1.wrapping_sub((n0_inner < d1) as c_ulong);
                        n0_inner = n0_inner.wrapping_sub(d1);
                    }
                    q = qq;
                }

                // SAFETY: `np` valid for `dsize` limbs, `dp` readable for
                // `dsize` limbs.
                let cy_limb = unsafe { mpihelp_submul_1(np, dp, dsize, q) };

                let mut q = q;
                if n2 != cy_limb {
                    // SAFETY: as above.
                    unsafe { mpihelp_add_n(np, np, dp, dsize) };
                    q -= 1;
                }

                // SAFETY: `qp` writable at index `i`.
                unsafe { *qp.add(i as usize) = q };
                // SAFETY: `np` readable for `dsize` limbs.
                n0 = unsafe { *np.add((dsize - 1) as usize) };

                i -= 1;
            }
        }
    }

    most_significant_q_limb
}
