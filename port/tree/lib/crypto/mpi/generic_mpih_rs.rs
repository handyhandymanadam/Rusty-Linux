// SPDX-License-Identifier: GPL-2.0-or-later

//! Multiprecision limb primitives -- the Rust bodies replacing eight files
//! in `lib/crypto/mpi/`.
//!
//! Ported from `generic_mpih-{mul1,mul2,mul3,add1,sub1,lshift,rshift}.c` and
//! `mpih-cmp.c` (6.18.49), which the kernel inherited from GMP.
//!
//! # Eight C files became one Rust file, and no C is left
//!
//! Each of those eight holds exactly one function, none is `EXPORT_SYMBOL`,
//! and they are one family of primitives over the same limb array. So there
//! is no CRC to preserve and no thunk to keep — the same position as
//! `lib/union_find_rs.rs` and `lib/earlycpio_rs.rs` — and the one-function-
//! per-file split is a GMP inheritance rather than anything the kernel
//! needs. `lib/crypto/mpi/Makefile` now builds this instead of the eight.
//!
//! This is a structural divergence and it is recorded in STATUS.md. It is
//! only defensible *because* nothing outside can see where these functions
//! live: no exported symbol, no CRC, no header promising a file layout.
//!
//! # Forward indices, not negative ones
//!
//! The C runs its loop counter from `-size` to `-1` and offsets the base
//! pointers to compensate — GMP's trick for making the loop bound a compare
//! against zero. Its own comment says "this way the loop becomes faster".
//! Here the loops are forward over slices. Same arithmetic, same results,
//! same carries, and every index is bounds-checked instead of being a
//! negative offset from an adjusted pointer.
//!
//! # `umul_ppmm`
//!
//! The C's 64x64→128 multiply macro is `(a as u128) * (b as u128)` here,
//! which is what it compiles to anyway.
//!
//! Replaces: lib/crypto/mpi/generic_mpih-add1.c lib/crypto/mpi/generic_mpih-lshift.c lib/crypto/mpi/generic_mpih-mul1.c lib/crypto/mpi/generic_mpih-mul2.c lib/crypto/mpi/generic_mpih-mul3.c lib/crypto/mpi/generic_mpih-rshift.c lib/crypto/mpi/generic_mpih-sub1.c lib/crypto/mpi/mpih-cmp.c

/// `mpi_limb_t` from `include/linux/mpi.h`.
type Limb = usize;
/// `mpi_size_t` from `lib/crypto/mpi/mpi-internal.h` -- a **signed int**.
type Size = core::ffi::c_int;
/// `BITS_PER_MPI_LIMB`.
const LIMB_BITS: u32 = usize::BITS;

/// `res = s1 * s2_limb`, returning the carry out.
///
/// # Safety
/// `res_ptr` must be writable and `s1_ptr` readable for `s1_size` limbs,
/// with `s1_size` positive. Same contract as the C.
#[no_mangle]
pub unsafe extern "C" fn mpihelp_mul_1(
    res_ptr: *mut Limb,
    s1_ptr: *const Limb,
    s1_size: Size,
    s2_limb: Limb,
) -> Limb {
    let n = s1_size as usize;
    // SAFETY: the caller guarantees `s1_size` limbs on both sides.
    let (res, s1) = unsafe {
        (
            core::slice::from_raw_parts_mut(res_ptr, n),
            core::slice::from_raw_parts(s1_ptr, n),
        )
    };
    let mut cy: Limb = 0;

    for i in 0..n {
        let prod = (s1[i] as u128) * (s2_limb as u128);
        let (low, carry) = (prod as Limb).overflowing_add(cy);

        cy = (carry as Limb) + (prod >> LIMB_BITS) as Limb;
        res[i] = low;
    }
    cy
}

/// `res += s1 * s2_limb`, returning the carry out.
///
/// # Safety
/// As [`mpihelp_mul_1`], and `res_ptr` must also be readable.
#[no_mangle]
pub unsafe extern "C" fn mpihelp_addmul_1(
    res_ptr: *mut Limb,
    s1_ptr: *const Limb,
    s1_size: Size,
    s2_limb: Limb,
) -> Limb {
    let n = s1_size as usize;
    // SAFETY: as above.
    let (res, s1) = unsafe {
        (
            core::slice::from_raw_parts_mut(res_ptr, n),
            core::slice::from_raw_parts(s1_ptr, n),
        )
    };
    let mut cy: Limb = 0;

    for i in 0..n {
        let prod = (s1[i] as u128) * (s2_limb as u128);
        let (low, carry) = (prod as Limb).overflowing_add(cy);

        cy = (carry as Limb) + (prod >> LIMB_BITS) as Limb;

        let x = res[i];
        let (sum, carry2) = x.overflowing_add(low);

        cy += carry2 as Limb;
        res[i] = sum;
    }
    cy
}

/// `res -= s1 * s2_limb`, returning the borrow out.
///
/// # Safety
/// As [`mpihelp_addmul_1`].
#[no_mangle]
pub unsafe extern "C" fn mpihelp_submul_1(
    res_ptr: *mut Limb,
    s1_ptr: *const Limb,
    s1_size: Size,
    s2_limb: Limb,
) -> Limb {
    let n = s1_size as usize;
    // SAFETY: as above.
    let (res, s1) = unsafe {
        (
            core::slice::from_raw_parts_mut(res_ptr, n),
            core::slice::from_raw_parts(s1_ptr, n),
        )
    };
    let mut cy: Limb = 0;

    for i in 0..n {
        let prod = (s1[i] as u128) * (s2_limb as u128);
        let (low, carry) = (prod as Limb).overflowing_add(cy);

        cy = (carry as Limb) + (prod >> LIMB_BITS) as Limb;

        let x = res[i];
        let (diff, borrow) = x.overflowing_sub(low);

        cy += borrow as Limb;
        res[i] = diff;
    }
    cy
}

/// `res = s1 + s2`, returning the carry out.
///
/// # Safety
/// All three must be valid for `size` limbs, `size` positive.
#[no_mangle]
pub unsafe extern "C" fn mpihelp_add_n(
    res_ptr: *mut Limb,
    s1_ptr: *const Limb,
    s2_ptr: *const Limb,
    size: Size,
) -> Limb {
    let n = size as usize;
    // SAFETY: the caller guarantees `size` limbs in all three.
    let (res, s1, s2) = unsafe {
        (
            core::slice::from_raw_parts_mut(res_ptr, n),
            core::slice::from_raw_parts(s1_ptr, n),
            core::slice::from_raw_parts(s2_ptr, n),
        )
    };
    let mut cy: Limb = 0;

    for i in 0..n {
        // The C's two-step carry, written as two checked adds. `y + cy`
        // can carry, and `y + x` can carry, and at most one of them does.
        let (y, c1) = s2[i].overflowing_add(cy);
        let (sum, c2) = y.overflowing_add(s1[i]);

        cy = c1 as Limb + c2 as Limb;
        res[i] = sum;
    }
    cy
}

/// `res = s1 - s2`, returning the borrow out.
///
/// # Safety
/// As [`mpihelp_add_n`].
#[no_mangle]
pub unsafe extern "C" fn mpihelp_sub_n(
    res_ptr: *mut Limb,
    s1_ptr: *const Limb,
    s2_ptr: *const Limb,
    size: Size,
) -> Limb {
    let n = size as usize;
    // SAFETY: as above.
    let (res, s1, s2) = unsafe {
        (
            core::slice::from_raw_parts_mut(res_ptr, n),
            core::slice::from_raw_parts(s1_ptr, n),
            core::slice::from_raw_parts(s2_ptr, n),
        )
    };
    let mut cy: Limb = 0;

    for i in 0..n {
        let (y, c1) = s2[i].overflowing_add(cy);
        let (diff, c2) = s1[i].overflowing_sub(y);

        cy = c1 as Limb + c2 as Limb;
        res[i] = diff;
    }
    cy
}

/// Shift `up[..usize_]` left by `cnt` bits into `wp`, returning the bits
/// shifted out of the top.
///
/// # Safety
/// `wp` must be writable and `up` readable for `usize_` limbs, `usize_`
/// positive, and **`cnt` must be in 1..LIMB_BITS**. The C is undefined at
/// `cnt == 0` too -- it shifts a limb by the full width -- so this is the
/// same contract, not a new one.
#[no_mangle]
pub unsafe extern "C" fn mpihelp_lshift(
    wp: *mut Limb,
    up: *const Limb,
    usize_: Size,
    cnt: core::ffi::c_uint,
) -> Limb {
    let n = usize_ as usize;
    // SAFETY: the caller guarantees `usize_` limbs on both sides.
    let (w, u) = unsafe {
        (
            core::slice::from_raw_parts_mut(wp, n),
            core::slice::from_raw_parts(up, n),
        )
    };
    let sh_1 = cnt;
    let sh_2 = LIMB_BITS - sh_1;

    // The C offsets wp by +1 and indexes down from usize-1 to -1, so it
    // writes w[0..n]. Forward and explicit here.
    let retval = u[n - 1] >> sh_2;

    for i in (1..n).rev() {
        w[i] = (u[i] << sh_1) | (u[i - 1] >> sh_2);
    }
    w[0] = u[0] << sh_1;

    retval
}

/// Shift `up[..usize_]` right by `cnt` bits into `wp`, returning the bits
/// shifted out of the bottom.
///
/// # Safety
/// As [`mpihelp_lshift`].
#[no_mangle]
pub unsafe extern "C" fn mpihelp_rshift(
    wp: *mut Limb,
    up: *const Limb,
    usize_: Size,
    cnt: core::ffi::c_uint,
) -> Limb {
    let n = usize_ as usize;
    // SAFETY: as above.
    let (w, u) = unsafe {
        (
            core::slice::from_raw_parts_mut(wp, n),
            core::slice::from_raw_parts(up, n),
        )
    };
    let sh_1 = cnt;
    let sh_2 = LIMB_BITS - sh_1;

    let retval = u[0] << sh_2;

    for i in 0..n - 1 {
        w[i] = (u[i] >> sh_1) | (u[i + 1] << sh_2);
    }
    w[n - 1] = u[n - 1] >> sh_1;

    retval
}

/// Compare two limb arrays of equal length. Returns 1, 0 or -1.
///
/// # Safety
/// Both must be readable for `size` limbs.
#[no_mangle]
pub unsafe extern "C" fn mpihelp_cmp(
    op1_ptr: *const Limb,
    op2_ptr: *const Limb,
    size: Size,
) -> core::ffi::c_int {
    let n = size as usize;
    // SAFETY: the caller guarantees `size` limbs in both.
    let (a, b) = unsafe {
        (
            core::slice::from_raw_parts(op1_ptr, n),
            core::slice::from_raw_parts(op2_ptr, n),
        )
    };

    // Most significant limb first.
    for i in (0..n).rev() {
        if a[i] != b[i] {
            // The C's comment warns this cannot be simplified to a
            // subtraction: the limbs are unsigned and the difference would
            // not fit in an int. Kept as a comparison.
            return if a[i] > b[i] { 1 } else { -1 };
        }
    }
    0
}
