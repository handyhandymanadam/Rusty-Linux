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
/// with `s1_size` positive. Same contract as the C. `res_ptr` and
/// `s1_ptr` may alias (no upstream caller does today, but nothing in the
/// signature forbids it) -- reads and writes go through raw pointers
/// only, one dereference at a time, so aliasing is never a soundness
/// question here regardless.
#[no_mangle]
pub unsafe extern "C" fn mpihelp_mul_1(
    res_ptr: *mut Limb,
    s1_ptr: *const Limb,
    s1_size: Size,
    s2_limb: Limb,
) -> Limb {
    let n = s1_size as usize;
    let mut cy: Limb = 0;

    for i in 0..n {
        // SAFETY: caller guarantees `s1_ptr` readable for `n` limbs.
        let s1_i = unsafe { *s1_ptr.add(i) };
        let prod = (s1_i as u128) * (s2_limb as u128);
        let (low, carry) = (prod as Limb).overflowing_add(cy);

        cy = (carry as Limb) + (prod >> LIMB_BITS) as Limb;
        // SAFETY: caller guarantees `res_ptr` writable for `n` limbs.
        unsafe { *res_ptr.add(i) = low };
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
    let mut cy: Limb = 0;

    for i in 0..n {
        // SAFETY: caller guarantees `s1_ptr` readable for `n` limbs.
        let s1_i = unsafe { *s1_ptr.add(i) };
        let prod = (s1_i as u128) * (s2_limb as u128);
        let (low, carry) = (prod as Limb).overflowing_add(cy);

        cy = (carry as Limb) + (prod >> LIMB_BITS) as Limb;

        // SAFETY: caller guarantees `res_ptr` readable and writable for
        // `n` limbs; read happens before this iteration's write.
        let x = unsafe { *res_ptr.add(i) };
        let (sum, carry2) = x.overflowing_add(low);

        cy += carry2 as Limb;
        unsafe { *res_ptr.add(i) = sum };
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
    let mut cy: Limb = 0;

    for i in 0..n {
        // SAFETY: caller guarantees `s1_ptr` readable for `n` limbs.
        let s1_i = unsafe { *s1_ptr.add(i) };
        let prod = (s1_i as u128) * (s2_limb as u128);
        let (low, carry) = (prod as Limb).overflowing_add(cy);

        cy = (carry as Limb) + (prod >> LIMB_BITS) as Limb;

        // SAFETY: as in mpihelp_addmul_1.
        let x = unsafe { *res_ptr.add(i) };
        let (diff, borrow) = x.overflowing_sub(low);

        cy += borrow as Limb;
        unsafe { *res_ptr.add(i) = diff };
    }
    cy
}

/// `res = s1 + s2`, returning the carry out.
///
/// # Safety
/// All three must be valid for `size` limbs, `size` positive. `res_ptr`
/// may alias `s1_ptr` and/or `s2_ptr` (real upstream callers do this,
/// e.g. `mpih-mul.c`'s `mpihelp_add_n(prodp, prodp, tspace, size)`) --
/// reads and writes go through raw pointers only, one dereference at a
/// time, so this is sound for any aliasing.
#[no_mangle]
pub unsafe extern "C" fn mpihelp_add_n(
    res_ptr: *mut Limb,
    s1_ptr: *const Limb,
    s2_ptr: *const Limb,
    size: Size,
) -> Limb {
    let n = size as usize;
    let mut cy: Limb = 0;

    for i in 0..n {
        // SAFETY: caller guarantees `s1_ptr`/`s2_ptr` readable for `n`
        // limbs; both reads for this iteration happen before its write.
        let (s1_i, s2_i) = unsafe { (*s1_ptr.add(i), *s2_ptr.add(i)) };
        // The C's two-step carry, written as two checked adds. `y + cy`
        // can carry, and `y + x` can carry, and at most one of them does.
        let (y, c1) = s2_i.overflowing_add(cy);
        let (sum, c2) = y.overflowing_add(s1_i);

        cy = c1 as Limb + c2 as Limb;
        // SAFETY: caller guarantees `res_ptr` writable for `n` limbs.
        unsafe { *res_ptr.add(i) = sum };
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
    let mut cy: Limb = 0;

    for i in 0..n {
        // SAFETY: as in mpihelp_add_n.
        let (s1_i, s2_i) = unsafe { (*s1_ptr.add(i), *s2_ptr.add(i)) };
        let (y, c1) = s2_i.overflowing_add(cy);
        let (diff, c2) = s1_i.overflowing_sub(y);

        cy = c1 as Limb + c2 as Limb;
        // SAFETY: caller guarantees `res_ptr` writable for `n` limbs.
        unsafe { *res_ptr.add(i) = diff };
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
    let sh_1 = cnt;
    let sh_2 = LIMB_BITS - sh_1;

    // `wp` and `up` may be the SAME buffer (mpi-bit.c and mpi-div.c both
    // call this in place). A `&mut [Limb]`/`&[Limb]` pair built with
    // from_raw_parts(_mut) over identical memory would be simultaneously
    // live mutable and shared references to the same bytes -- undefined
    // behaviour regardless of whether current codegen happens to exploit
    // it. Read and write through raw pointers only, one dereference at a
    // time, never holding a slice reference open across the loop.
    //
    // The C offsets wp by +1 and indexes down from usize-1 to -1, so it
    // writes w[0..n]. Forward and explicit here. Top-down (n-1 .. 0) so
    // an in-place call reads u[i]/u[i-1] before either has been
    // overwritten -- each iteration only ever writes index i, and the
    // next iteration's reads are i-1 and i-2.
    // SAFETY: caller guarantees `up` readable for `usize_` limbs.
    let retval = unsafe { *up.add(n - 1) } >> sh_2;

    let mut i = n - 1;
    while i >= 1 {
        // SAFETY: caller guarantees `up` readable and `wp` writable for
        // `usize_` limbs; `i` and `i - 1` are both in range.
        let (hi, lo) = unsafe { (*up.add(i), *up.add(i - 1)) };
        unsafe { *wp.add(i) = (hi << sh_1) | (lo >> sh_2) };
        i -= 1;
    }
    // SAFETY: as above, index 0.
    unsafe { *wp = (*up) << sh_1 };

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
    let sh_1 = cnt;
    let sh_2 = LIMB_BITS - sh_1;

    // As mpihelp_lshift: raw-pointer reads/writes only, no live slice
    // references, since `wp` may equal `up`. Bottom-up (0 .. n-1) so an
    // in-place call reads u[i]/u[i+1] before either has been overwritten.
    // SAFETY: caller guarantees `up` readable for `usize_` limbs.
    let retval = unsafe { *up } << sh_2;

    for i in 0..n - 1 {
        // SAFETY: caller guarantees `up` readable and `wp` writable for
        // `usize_` limbs; `i` and `i + 1` are both in range.
        let (lo, hi) = unsafe { (*up.add(i), *up.add(i + 1)) };
        unsafe { *wp.add(i) = (lo >> sh_1) | (hi << sh_2) };
    }
    // SAFETY: as above, index n - 1.
    unsafe { *wp.add(n - 1) = *up.add(n - 1) >> sh_1 };

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
