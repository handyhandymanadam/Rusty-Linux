// SPDX-License-Identifier: GPL-2.0-or-later

//! MPI division -- the Rust behind `lib/crypto/mpi/mpi-div.c`.
//!
//! Ported from `lib/crypto/mpi/mpi-div.c` (6.18.49).
//!
//! Replaces: lib/crypto/mpi/mpi-div.c
//!
//! # No exported symbols here
//!
//! None of `mpi_fdiv_r`/`mpi_tdiv_r`/`mpi_tdiv_qr` is `EXPORT_SYMBOL`, but
//! all three are real (non-`static`) symbols other callers reach directly:
//! `mpi-mul.c` (still C) calls `mpi_tdiv_r`, and `mpi_mod_rs.rs` (also
//! ported, in the same pass as this file) calls `mpi_fdiv_r`.
//!
//! # `marker[5]` becomes a fixed-size array plus an index, and `goto
//! # out_free_marker` becomes a labeled `loop { ...; break; }`
//!
//! `mpi_tdiv_qr()`'s C body allocates zero to two scratch limb buffers
//! along different paths and frees whichever ones it allocated, in
//! reverse order, from a single cleanup point every path (success or
//! allocation failure) reaches via `goto`. Rust has no `goto`; a
//! single-iteration loop whose body ends in `break` on every path, with the
//! `marker`-cleanup loop placed unconditionally after it, is the standard
//! translation of exactly this idiom and is what is used here. The `[5]`
//! sizing is carried over unchanged even though at most two markers are
//! ever populated in practice (one from the "qp aliases np" copy, one,
//! mutually exclusive with the first only in the sense that it comes from
//! the other branch, from normalization or from the "dp aliases rp/qp"
//! copy) -- matching the C's own declared bound rather than tightening it.

use core::ffi::{c_int, c_uint, c_ulong};

/// `ENOMEM` (`include/uapi/asm-generic/errno-base.h`).
const ENOMEM: c_int = 12;

/// Mirrors `struct gcry_mpi` (`include/linux/mpi.h`). Named distinctly per
/// file -- see `mpi_add_rs.rs`'s module doc comment for why.
#[repr(C)]
pub struct MpiDivGcryMpi {
    /// Allocated array size, in limbs.
    pub alloced: c_int,
    /// Number of valid limbs.
    pub nlimbs: c_int,
    /// The real number of valid bits (info only).
    pub nbits: c_int,
    /// Nonzero if this value is negative.
    pub sign: c_int,
    /// Flag bits; not read by the functions in this file.
    pub flags: u32,
    /// The limb array itself.
    pub d: *mut c_ulong,
}

unsafe extern "C" {
    fn mpi_resize(a: *mut MpiDivGcryMpi, nlimbs: c_uint) -> c_int;
    fn mpi_copy(a: *const MpiDivGcryMpi) -> *mut MpiDivGcryMpi;
    fn mpi_free(a: *mut MpiDivGcryMpi);
    fn mpi_alloc_limb_space(nlimbs: c_uint) -> *mut c_ulong;
    fn mpi_free_limb_space(a: *mut c_ulong);
    fn mpi_add(w: *mut MpiDivGcryMpi, u: *mut MpiDivGcryMpi, v: *mut MpiDivGcryMpi) -> c_int;
    fn mpihelp_divmod_1(quot_ptr: *mut c_ulong, dividend_ptr: *const c_ulong, dividend_size: c_int, divisor_limb: c_ulong) -> c_ulong;
    fn mpihelp_mod_1(dividend_ptr: *const c_ulong, dividend_size: c_int, divisor_limb: c_ulong) -> c_ulong;
    fn mpihelp_divrem(qp: *mut c_ulong, qextra_limbs: c_int, np: *mut c_ulong, nsize: c_int, dp: *const c_ulong, dsize: c_int) -> c_ulong;
    fn mpihelp_lshift(wp: *mut c_ulong, up: *const c_ulong, usize_: c_int, cnt: c_uint) -> c_ulong;
    fn mpihelp_rshift(wp: *mut c_ulong, up: *const c_ulong, usize_: c_int, cnt: c_uint) -> c_ulong;
}

/// `count_leading_zeros()` (`include/linux/count_zeros.h`). Same as
/// `mpih_div_rs.rs`'s copy: `u64::leading_zeros()` matches its contract
/// exactly, `count_leading_zeros(0) == BITS_PER_LONG` included.
#[inline(always)]
fn count_leading_zeros(x: c_ulong) -> u32 {
    x.leading_zeros()
}

/// `MPN_NORMALIZE(d, n)`: shrink `n` while the top limb is zero.
///
/// # Safety
/// `d` must be readable for `n` limbs.
unsafe fn mpn_normalize(d: *const c_ulong, mut n: c_int) -> c_int {
    while n > 0 {
        // SAFETY: `n > 0`, so index `n - 1` is in bounds.
        if unsafe { *d.add((n - 1) as usize) } != 0 {
            break;
        }
        n -= 1;
    }
    n
}

kernel::kabi_rule!("type_string", "t#MPI",
    "typedef_type MPI { pointer_type { s#gcry_mpi } }");
kernel::kabi_rule!("type_string", "s#gcry_mpi",
    "structure_type gcry_mpi { member base_type int byte_size(4) encoding(5) alloced data_member_location(0) , member base_type int byte_size(4) encoding(5) nlimbs data_member_location(4) , member base_type int byte_size(4) encoding(5) nbits data_member_location(8) , member base_type int byte_size(4) encoding(5) sign data_member_location(12) , member base_type unsigned int byte_size(4) encoding(7) flags data_member_location(16) , member pointer_type { t#mpi_limb_t } d data_member_location(24) } byte_size(32)");
kernel::kabi_rule!("type_string", "t#mpi_limb_t",
    "typedef_type mpi_limb_t { base_type unsigned long byte_size(8) encoding(7) }");

/// `mpi_fdiv_r()` -- floor-divide (Euclidean-toward-negative-infinity):
/// `rem = dividend - divisor * floor(dividend / divisor)`, i.e. `rem`'s
/// sign matches `divisor`'s. Not exported, but a real symbol.
///
/// # Safety
/// `rem`, `dividend`, `divisor` must be valid, initialized
/// `MpiDivGcryMpi`s. `rem` may alias `divisor`.
#[no_mangle]
pub unsafe extern "C" fn mpi_fdiv_r(
    rem: *mut MpiDivGcryMpi,
    dividend: *mut MpiDivGcryMpi,
    divisor: *mut MpiDivGcryMpi,
) -> c_int {
    // SAFETY: caller guarantees `divisor` valid.
    let divisor_sign = unsafe { (*divisor).sign };
    let mut temp_divisor: *mut MpiDivGcryMpi = core::ptr::null_mut();
    let mut divisor = divisor;

    // We need the original value of the divisor after the remainder has
    // been preliminarily calculated. Copy it to temporary space if it's
    // the same variable as `rem`.
    if rem == divisor {
        // SAFETY: `divisor` valid.
        temp_divisor = unsafe { mpi_copy(divisor) };
        if temp_divisor.is_null() {
            return -ENOMEM;
        }
        divisor = temp_divisor;
    }

    // SAFETY: `rem`, `dividend` are the caller's; `divisor` is either the
    // caller's or the fresh copy above.
    let mut err = unsafe { mpi_tdiv_r(rem, dividend, divisor) };
    if err == 0 {
        // SAFETY: `dividend` valid.
        let dividend_sign = unsafe { (*dividend).sign };
        // SAFETY: `rem` valid (written by `mpi_tdiv_r` above).
        let rem_nlimbs = unsafe { (*rem).nlimbs };
        if (((divisor_sign != 0) as c_int) ^ ((dividend_sign != 0) as c_int)) != 0
            && rem_nlimbs != 0
        {
            // SAFETY: `rem` and `divisor` valid.
            err = unsafe { mpi_add(rem, rem, divisor) };
        }
    }

    // SAFETY: `temp_divisor` is either null (no-op, `mpi_free` checks) or
    // was allocated by `mpi_copy` above and not freed since.
    unsafe { mpi_free(temp_divisor) };

    err
}

/// `mpi_tdiv_r()` -- truncating division's remainder: `mpi_tdiv_qr()` with
/// no quotient wanted. Not exported, but a real symbol.
///
/// # Safety
/// `rem`, `num`, `den` must be valid, initialized `MpiDivGcryMpi`s.
#[no_mangle]
pub unsafe extern "C" fn mpi_tdiv_r(
    rem: *mut MpiDivGcryMpi,
    num: *mut MpiDivGcryMpi,
    den: *mut MpiDivGcryMpi,
) -> c_int {
    // SAFETY: caller guarantees `rem`, `num`, `den` valid; `quot` is null,
    // which `mpi_tdiv_qr` treats as "no quotient wanted".
    unsafe { mpi_tdiv_qr(core::ptr::null_mut(), rem, num, den) }
}

/// `mpi_tdiv_qr()` -- truncating division: `quot = trunc(num / den)`,
/// `rem = num - den * quot`, so `rem`'s sign matches `num`'s (when
/// nonzero). `quot` may be null ("no quotient wanted", as `mpi_tdiv_r()`
/// uses it). Not exported, but a real symbol.
///
/// # Safety
/// `rem`, `num`, `den` must be valid, initialized `MpiDivGcryMpi`s; `quot`
/// must be null or a valid, initialized `MpiDivGcryMpi`. See the C's own
/// comment on aliasing: `den == quot`, `den == rem`, and `num == quot` are
/// all permitted (handled by the temporary-copy logic below); `quot` and
/// `rem` themselves may need to be distinct from each other for the
/// aliasing checks below to make sense, matching the C's own assumption.
#[no_mangle]
pub unsafe extern "C" fn mpi_tdiv_qr(
    quot: *mut MpiDivGcryMpi,
    rem: *mut MpiDivGcryMpi,
    num: *mut MpiDivGcryMpi,
    den: *mut MpiDivGcryMpi,
) -> c_int {
    // SAFETY: caller guarantees `num`, `den` valid.
    let nsize = unsafe { (*num).nlimbs };
    let dsize = unsafe { (*den).nlimbs };
    let sign_remainder = unsafe { (*num).sign };
    let sign_quotient = unsafe { (*num).sign ^ (*den).sign };

    // Ensure space is enough for quotient and remainder. We need space
    // for an extra limb in the remainder, because it's up-shifted
    // (normalized) below.
    let mut rsize = nsize + 1;
    // SAFETY: `rem` valid.
    let err = unsafe { mpi_resize(rem, rsize as c_uint) };
    if err != 0 {
        return err;
    }

    let mut qsize = rsize - dsize; // qsize cannot be bigger than this.
    if qsize <= 0 {
        if num != rem {
            // SAFETY: `rem`, `num` valid, distinct.
            unsafe {
                (*rem).nlimbs = (*num).nlimbs;
                (*rem).sign = (*num).sign;
                // `copy_nonoverlapping` requires non-null, aligned
                // pointers even at count 0 -- `num->d` can be null when
                // `nsize == 0` (an MPI with no limbs), so skip the call
                // entirely rather than pass it a null src/dst.
                if nsize != 0 {
                    core::ptr::copy_nonoverlapping((*num).d, (*rem).d, nsize as usize);
                }
            }
        }
        if !quot.is_null() {
            // This needs to follow the assignment to rem, in case the
            // numerator and quotient are the same.
            unsafe {
                (*quot).nlimbs = 0;
                (*quot).sign = 0;
            }
        }
        return 0;
    }

    if !quot.is_null() {
        // SAFETY: `quot` valid.
        let err = unsafe { mpi_resize(quot, qsize as c_uint) };
        if err != 0 {
            return err;
        }
    }

    // Read pointers here, when reallocation is finished.
    // SAFETY: `num`, `den`, `rem` valid.
    let mut np = unsafe { (*num).d } as *const c_ulong;
    let mut dp = unsafe { (*den).d } as *const c_ulong;
    let rp = unsafe { (*rem).d };

    // Optimize division by a single-limb divisor.
    if dsize == 1 {
        let rlimb;
        // SAFETY: `dp` readable for 1 limb.
        let d0 = unsafe { *dp };
        if !quot.is_null() {
            // SAFETY: `quot` valid.
            let qp = unsafe { (*quot).d };
            // SAFETY: `np` readable for `nsize` limbs, `qp` writable for
            // `qsize` (== `nsize`, since `dsize == 1`) limbs.
            rlimb = unsafe { mpihelp_divmod_1(qp, np, nsize, d0) };
            // SAFETY: `qsize >= 1` here (checked above), so index
            // `qsize - 1` is in bounds.
            qsize -= (unsafe { *qp.add((qsize - 1) as usize) } == 0) as c_int;
            unsafe {
                (*quot).nlimbs = qsize;
                (*quot).sign = sign_quotient;
            }
        } else {
            // SAFETY: `np` readable for `nsize` limbs.
            rlimb = unsafe { mpihelp_mod_1(np, nsize, d0) };
        }
        // SAFETY: `rp` writable for at least 1 limb (`rsize == nsize + 1
        // >= 2` was established above, but the C only ever needs 1 here).
        unsafe { *rp = rlimb };
        rsize = (rlimb != 0) as c_int;
        unsafe {
            (*rem).nlimbs = rsize;
            (*rem).sign = sign_remainder;
        }
        return 0;
    }

    let mut marker: [*mut c_ulong; 5] = [core::ptr::null_mut(); 5];
    let mut markidx: usize = 0;
    let qp: *mut c_ulong;
    let err: c_int;

    // See the module doc comment: this loop runs exactly once and every
    // path ends in `break`, standing in for the C's `goto
    // out_free_marker`.
    loop {
        if !quot.is_null() {
            // SAFETY: `quot` valid.
            qp = unsafe { (*quot).d };
            // Make sure qp and np point to different objects. Otherwise
            // the numerator would be gradually overwritten by the
            // quotient limbs.
            if qp as *const c_ulong == np {
                // SAFETY: allocating fresh scratch space.
                let p = unsafe { mpi_alloc_limb_space(nsize as c_uint) };
                marker[markidx] = p;
                markidx += 1;
                if p.is_null() {
                    err = -ENOMEM;
                    break;
                }
                // SAFETY: `p` freshly allocated for `nsize` limbs; the old
                // `np` (== `qp`) readable for `nsize` limbs.
                unsafe { core::ptr::copy_nonoverlapping(np, p, nsize as usize) };
                np = p;
            }
        } else {
            // Put quotient at top of remainder.
            // SAFETY: `rp` has room for at least `dsize + (nsize - dsize)
            // = nsize` limbs beyond `dsize`, within the `rsize == nsize +
            // 1`-limb buffer `rem` was resized to above.
            qp = unsafe { rp.add(dsize as usize) };
        }

        // SAFETY: `dp` readable for `dsize` limbs.
        let normalization_steps = count_leading_zeros(unsafe { *dp.add((dsize - 1) as usize) });

        // Normalize the denominator, i.e. make its most significant bit
        // set by shifting it `normalization_steps` bits to the left. Also
        // shift the numerator the same number of steps (to keep the
        // quotient the same!).
        if normalization_steps != 0 {
            // SAFETY: allocating fresh scratch space.
            let tp = unsafe { mpi_alloc_limb_space(dsize as c_uint) };
            marker[markidx] = tp;
            markidx += 1;
            if tp.is_null() {
                err = -ENOMEM;
                break;
            }
            // SAFETY: `tp` valid for `dsize` limbs, `dp` readable for
            // `dsize` limbs.
            unsafe { mpihelp_lshift(tp, dp, dsize, normalization_steps) };
            dp = tp;

            // Shift up the numerator, possibly introducing a new most
            // significant word. Move the shifted numerator into the
            // remainder meanwhile.
            // SAFETY: `rp` valid for `nsize + 1` limbs, `np` readable for
            // `nsize` limbs.
            let nlimb = unsafe { mpihelp_lshift(rp, np, nsize, normalization_steps) };
            if nlimb != 0 {
                // SAFETY: `rp` has room for `nsize + 1` limbs.
                unsafe { *rp.add(nsize as usize) = nlimb };
                rsize = nsize + 1;
            } else {
                rsize = nsize;
            }
        } else {
            // The denominator is already normalized, as required. Copy it
            // to temporary space if it overlaps with the quotient or
            // remainder.
            if dp == rp as *const c_ulong
                || (!quot.is_null() && dp == qp as *const c_ulong)
            {
                // SAFETY: allocating fresh scratch space.
                let tp = unsafe { mpi_alloc_limb_space(dsize as c_uint) };
                marker[markidx] = tp;
                markidx += 1;
                if tp.is_null() {
                    err = -ENOMEM;
                    break;
                }
                // SAFETY: `tp` valid, `dp` readable, both `dsize` limbs.
                unsafe { core::ptr::copy_nonoverlapping(dp, tp, dsize as usize) };
                dp = tp;
            }

            // Move the numerator to the remainder.
            if rp as *const c_ulong != np {
                // SAFETY: `rp` valid, `np` readable, both `nsize` limbs.
                unsafe { core::ptr::copy_nonoverlapping(np, rp, nsize as usize) };
            }
            rsize = nsize;
        }

        // SAFETY: `qp` valid for `rsize - dsize` limbs, `rp` valid for
        // `rsize` limbs, `dp` readable for `dsize` limbs.
        let q_limb = unsafe { mpihelp_divrem(qp, 0, rp, rsize, dp, dsize) };

        if !quot.is_null() {
            let mut qsize2 = rsize - dsize;
            if q_limb != 0 {
                // SAFETY: `qp` has room for one more limb here (the
                // C's own comment: "the most significant limb of the
                // quotient, this is always 0 or 1").
                unsafe { *qp.add(qsize2 as usize) = q_limb };
                qsize2 += 1;
            }
            // SAFETY: `quot` valid.
            unsafe {
                (*quot).nlimbs = qsize2;
                (*quot).sign = sign_quotient;
            }
        }

        // SAFETY: `rp` valid for `dsize` limbs (the low `dsize` limbs of
        // the `rsize`-limb buffer `mpihelp_divrem` left the remainder in).
        let mut rsize2 = unsafe { mpn_normalize(rp, dsize) };

        if normalization_steps != 0 && rsize2 != 0 {
            // SAFETY: `rp` valid for `rsize2` limbs.
            unsafe { mpihelp_rshift(rp, rp, rsize2, normalization_steps) };
            let last = unsafe { *rp.add((rsize2 - 1) as usize) };
            rsize2 -= (last == 0) as c_int;
        }

        // SAFETY: `rem` valid.
        unsafe {
            (*rem).nlimbs = rsize2;
            (*rem).sign = sign_remainder;
        }

        err = 0;
        break;
    }

    while markidx > 0 {
        markidx -= 1;
        // SAFETY: every populated `marker` slot was allocated by
        // `mpi_alloc_limb_space()` above and not freed since.
        unsafe { mpi_free_limb_space(marker[markidx]) };
    }

    err
}
