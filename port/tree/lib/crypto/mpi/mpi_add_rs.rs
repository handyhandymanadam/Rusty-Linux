// SPDX-License-Identifier: GPL-2.0-or-later

//! MPI addition and subtraction -- the Rust behind
//! `lib/crypto/mpi/mpi-add.c`.
//!
//! Ported from `lib/crypto/mpi/mpi-add.c` (6.18.49).
//!
//! Replaces: lib/crypto/mpi/mpi-add.c
//!
//! # `mpihelp_add_1`/`mpihelp_add`/`mpihelp_sub_1`/`mpihelp_sub` are
//! # reproduced here, not called
//!
//! These four are `static inline` in `lib/crypto/mpi/mpi-inline.h`, so they
//! have no linkable symbol -- every C translation unit that includes the
//! header gets its own private copy, and this file does the same thing in
//! Rust: a private reimplementation, not an `extern "C"` call. Every C file
//! that needs `mpihelp_sub_1` (this one, and `mpi-sub-ui_rs.rs`) carries its
//! own copy for the identical reason the C's copies are separate --
//! nothing links them together, in either language.
//!
//! `mpihelp_add_n`/`mpihelp_sub_n`/`mpihelp_cmp`, by contrast, are real
//! out-of-line functions (`lib/crypto/mpi/generic_mpih_rs.rs`), so those
//! ARE called via `extern "C"`.
//!
//! # `MPN_COPY`/`MPN_NORMALIZE` are reproduced as plain code, not macros
//!
//! Rust has no text-substitution macro that would read as naturally at the
//! call site; a copy loop and a small helper function say the same thing.

use core::ffi::{c_int, c_uint, c_ulong};

/// `ENOMEM` (`include/uapi/asm-generic/errno-base.h`).
const ENOMEM: c_int = 12;

/// Mirrors `struct gcry_mpi` (`include/linux/mpi.h`). See `mpi_cmp_rs.rs`'s
/// module doc for why layout has to match; named distinctly from every
/// other file's own mirror of the same C struct so `rig/layout-check.sh`'s
/// pahole lookup (by Rust type name, across the whole `vmlinux`) is never
/// again asked to disambiguate two same-named types in different crates --
/// the exact gap `mpiutil_rs.rs`'s `GcryMpi` hit and was renamed out of.
#[repr(C)]
pub struct MpiAddGcryMpi {
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
    fn mpihelp_add_n(res_ptr: *mut c_ulong, s1_ptr: *const c_ulong, s2_ptr: *const c_ulong, size: c_int) -> c_ulong;
    fn mpihelp_sub_n(res_ptr: *mut c_ulong, s1_ptr: *const c_ulong, s2_ptr: *const c_ulong, size: c_int) -> c_ulong;
    fn mpihelp_cmp(op1_ptr: *const c_ulong, op2_ptr: *const c_ulong, size: c_int) -> c_int;
    fn mpi_copy(a: *const MpiAddGcryMpi) -> *mut MpiAddGcryMpi;
    fn mpi_free(a: *mut MpiAddGcryMpi);
    fn mpi_resize(a: *mut MpiAddGcryMpi, nlimbs: c_uint) -> c_int;
    fn mpi_mod(rem: *mut MpiAddGcryMpi, dividend: *mut MpiAddGcryMpi, divisor: *mut MpiAddGcryMpi) -> c_int;
}

/// `mpihelp_add_1()` (`mpi-inline.h`). See the module doc comment.
///
/// # Safety
/// `res_ptr` must be writable and `s1_ptr` readable for `s1_size` limbs
/// (`s1_size >= 1`); if they overlap, it must be the same relationship the
/// C's own pointer walk tolerates (aliasing forward through the same
/// buffer, which is the only pattern any caller in this project uses).
unsafe fn mpihelp_add_1(
    res_ptr: *mut c_ulong,
    s1_ptr: *const c_ulong,
    mut s1_size: c_int,
    s2_limb: c_ulong,
) -> c_ulong {
    let mut res_ptr = res_ptr;
    let mut s1_ptr = s1_ptr;

    // SAFETY: caller guarantees `s1_size >= 1` readable/writable limbs.
    let x0 = unsafe { *s1_ptr };
    s1_ptr = unsafe { s1_ptr.add(1) };
    let s2_limb = s2_limb.wrapping_add(x0);
    // SAFETY: caller guarantees `res_ptr` writable for `s1_size` limbs.
    unsafe { *res_ptr = s2_limb };
    res_ptr = unsafe { res_ptr.add(1) };

    if s2_limb < x0 {
        loop {
            s1_size -= 1;
            if s1_size == 0 {
                return 1;
            }
            // SAFETY: `s1_size` limbs remain, by the loop's own invariant.
            let x = unsafe { *s1_ptr }.wrapping_add(1);
            s1_ptr = unsafe { s1_ptr.add(1) };
            unsafe { *res_ptr = x };
            res_ptr = unsafe { res_ptr.add(1) };
            if x != 0 {
                break;
            }
        }
    }

    if (res_ptr as *const c_ulong) != s1_ptr {
        // SAFETY: `s1_size - 1` limbs remain readable/writable at these
        // positions -- the same invariant the C's own copy relies on.
        for i in 0..(s1_size - 1) as usize {
            unsafe { *res_ptr.add(i) = *s1_ptr.add(i) };
        }
    }
    0
}

/// `mpihelp_sub_1()` (`mpi-inline.h`). See [`mpihelp_add_1`]'s doc comment
/// and safety contract; identical shape, subtraction instead of addition.
unsafe fn mpihelp_sub_1(
    res_ptr: *mut c_ulong,
    s1_ptr: *const c_ulong,
    mut s1_size: c_int,
    s2_limb: c_ulong,
) -> c_ulong {
    let mut res_ptr = res_ptr;
    let mut s1_ptr = s1_ptr;

    // SAFETY: as `mpihelp_add_1`.
    let x0 = unsafe { *s1_ptr };
    s1_ptr = unsafe { s1_ptr.add(1) };
    let s2_limb_out = x0.wrapping_sub(s2_limb);
    unsafe { *res_ptr = s2_limb_out };
    res_ptr = unsafe { res_ptr.add(1) };

    if s2_limb_out > x0 {
        loop {
            s1_size -= 1;
            if s1_size == 0 {
                return 1;
            }
            // SAFETY: as above.
            let x = unsafe { *s1_ptr };
            s1_ptr = unsafe { s1_ptr.add(1) };
            unsafe { *res_ptr = x.wrapping_sub(1) };
            res_ptr = unsafe { res_ptr.add(1) };
            if x != 0 {
                break;
            }
        }
    }

    if (res_ptr as *const c_ulong) != s1_ptr {
        // SAFETY: as `mpihelp_add_1`.
        for i in 0..(s1_size - 1) as usize {
            unsafe { *res_ptr.add(i) = *s1_ptr.add(i) };
        }
    }
    0
}

/// `mpihelp_add()` (`mpi-inline.h`): `res = s1 + s2`, `s1_size >= s2_size`.
///
/// # Safety
/// `res_ptr`/`s1_ptr` valid for `s1_size` limbs, `s2_ptr` valid for
/// `s2_size` limbs, `s1_size >= s2_size`.
unsafe fn mpihelp_add(
    res_ptr: *mut c_ulong,
    s1_ptr: *const c_ulong,
    s1_size: c_int,
    s2_ptr: *const c_ulong,
    s2_size: c_int,
) -> c_ulong {
    let mut cy: c_ulong = 0;
    if s2_size != 0 {
        // SAFETY: caller guarantees `s2_size` limbs at all three.
        cy = unsafe { mpihelp_add_n(res_ptr, s1_ptr, s2_ptr, s2_size) };
    }
    if s1_size != s2_size {
        // SAFETY: `s1_size >= s2_size` (caller contract), so the offset
        // pointers have `s1_size - s2_size` valid limbs remaining.
        cy = unsafe {
            mpihelp_add_1(
                res_ptr.add(s2_size as usize),
                s1_ptr.add(s2_size as usize),
                s1_size - s2_size,
                cy,
            )
        };
    }
    cy
}

/// `mpihelp_sub()` (`mpi-inline.h`): `res = s1 - s2`, `s1_size >= s2_size`.
/// See [`mpihelp_add`]'s safety contract; identical shape.
unsafe fn mpihelp_sub(
    res_ptr: *mut c_ulong,
    s1_ptr: *const c_ulong,
    s1_size: c_int,
    s2_ptr: *const c_ulong,
    s2_size: c_int,
) -> c_ulong {
    let mut cy: c_ulong = 0;
    if s2_size != 0 {
        // SAFETY: as `mpihelp_add`.
        cy = unsafe { mpihelp_sub_n(res_ptr, s1_ptr, s2_ptr, s2_size) };
    }
    if s1_size != s2_size {
        // SAFETY: as `mpihelp_add`.
        cy = unsafe {
            mpihelp_sub_1(
                res_ptr.add(s2_size as usize),
                s1_ptr.add(s2_size as usize),
                s1_size - s2_size,
                cy,
            )
        };
    }
    cy
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

/// `RESIZE_IF_NEEDED(a, b)` (`mpi-internal.h`).
///
/// # Safety
/// `a` must be valid.
unsafe fn resize_if_needed(a: *mut MpiAddGcryMpi, b: c_int) -> c_int {
    // SAFETY: caller guarantees `a` valid.
    if unsafe { (*a).alloced } < b {
        // SAFETY: as above.
        unsafe { mpi_resize(a, b as c_uint) }
    } else {
        0
    }
}

kernel::kabi_rule!("type_string", "s#gcry_mpi",
    "structure_type gcry_mpi { member base_type int byte_size(4) encoding(5) alloced data_member_location(0) , member base_type int byte_size(4) encoding(5) nlimbs data_member_location(4) , member base_type int byte_size(4) encoding(5) nbits data_member_location(8) , member base_type int byte_size(4) encoding(5) sign data_member_location(12) , member base_type unsigned int byte_size(4) encoding(7) flags data_member_location(16) , member pointer_type { t#mpi_limb_t } d data_member_location(24) } byte_size(32)");
kernel::kabi_rule!("type_string", "t#MPI",
    "typedef_type MPI { pointer_type { s#gcry_mpi } }");
kernel::kabi_rule!("type_string", "t#mpi_limb_t",
    "typedef_type mpi_limb_t { base_type unsigned long byte_size(8) encoding(7) }");

kernel::kabi_export! {
    mpi_add,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter t#MPI w , formal_parameter t#MPI u , formal_parameter t#MPI v ) -> base_type int byte_size(4) encoding(5)",
}

/// `mpi_add()` -- `w = u + v`.
///
/// # Safety
/// `w`, `u`, `v` must be valid, initialized `MpiAddGcryMpi`s. `w` may alias
/// `u` and/or `v` (the C relies on this: `mpi_sub()` passes the same `w`
/// and `u`).
#[no_mangle]
pub unsafe extern "C" fn mpi_add(
    w: *mut MpiAddGcryMpi,
    u: *mut MpiAddGcryMpi,
    v: *mut MpiAddGcryMpi,
) -> c_int {
    // SAFETY: caller guarantees `u`, `v` valid.
    let (u_nlimbs, v_nlimbs) = unsafe { ((*u).nlimbs, (*v).nlimbs) };

    let usize_: c_int;
    let usign: c_int;
    let vsize: c_int;
    let vsign: c_int;
    let up: *const c_ulong;
    let vp: *const c_ulong;

    if u_nlimbs < v_nlimbs {
        usize_ = v_nlimbs;
        // SAFETY: `v` valid.
        usign = unsafe { (*v).sign };
        vsize = u_nlimbs;
        // SAFETY: `u` valid.
        vsign = unsafe { (*u).sign };
        // SAFETY: `w` valid (caller contract).
        let err = unsafe { resize_if_needed(w, usize_ + 1) };
        if err != 0 {
            return err;
        }
        // SAFETY: `v`, `u` valid; read AFTER the resize above, matching
        // the C's own comment that this must happen after realloc since
        // `w` may alias `u` or `v`.
        up = unsafe { (*v).d };
        vp = unsafe { (*u).d };
    } else {
        usize_ = u_nlimbs;
        usign = unsafe { (*u).sign };
        vsize = v_nlimbs;
        vsign = unsafe { (*v).sign };
        let err = unsafe { resize_if_needed(w, usize_ + 1) };
        if err != 0 {
            return err;
        }
        up = unsafe { (*u).d };
        vp = unsafe { (*v).d };
    }
    // SAFETY: `w` valid; read after the resize above, for the same reason.
    let wp = unsafe { (*w).d };
    let mut wsign: c_int = 0;
    let wsize: c_int;

    if vsize == 0 {
        // SAFETY: `wp` has room for `usize_` limbs (resized above), `up`
        // has `usize_` readable limbs.
        unsafe { core::ptr::copy_nonoverlapping(up, wp, usize_ as usize) };
        wsize = usize_;
        wsign = usign;
    } else if usign != vsign {
        if usize_ != vsize {
            // SAFETY: `usize_ >= vsize` here (the branch above chose the
            // larger operand as `usize_`), matching `mpihelp_sub`'s
            // contract.
            unsafe { mpihelp_sub(wp, up, usize_, vp, vsize) };
            // SAFETY: `wp` has `usize_` limbs written above.
            wsize = unsafe { mpn_normalize(wp, usize_) };
            wsign = usign;
        } else if unsafe { mpihelp_cmp(up, vp, usize_) } < 0 {
            // SAFETY: `up`, `vp`, `wp` each have `usize_` limbs.
            unsafe { mpihelp_sub_n(wp, vp, up, usize_) };
            wsize = unsafe { mpn_normalize(wp, usize_) };
            if usign == 0 {
                wsign = 1;
            }
        } else {
            // SAFETY: as above.
            unsafe { mpihelp_sub_n(wp, up, vp, usize_) };
            wsize = unsafe { mpn_normalize(wp, usize_) };
            if usign != 0 {
                wsign = 1;
            }
        }
    } else {
        // SAFETY: `up` has `usize_` limbs, `vp` has `vsize` limbs,
        // `usize_ >= vsize`.
        let cy = unsafe { mpihelp_add(wp, up, usize_, vp, vsize) };
        // SAFETY: `wp` was resized to `usize_ + 1` limbs above.
        unsafe { *wp.add(usize_ as usize) = cy };
        wsize = usize_ + cy as c_int;
        if usign != 0 {
            wsign = 1;
        }
    }

    // SAFETY: `w` valid.
    unsafe {
        (*w).nlimbs = wsize;
        (*w).sign = wsign;
    }
    0
}

kernel::kabi_export! {
    mpi_sub,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter t#MPI w , formal_parameter t#MPI u , formal_parameter t#MPI v ) -> base_type int byte_size(4) encoding(5)",
}

/// `mpi_sub()` -- `w = u - v`, via a sign-flipped copy of `v` and
/// `mpi_add()`.
///
/// # Safety
/// `w`, `u`, `v` must be valid, initialized `MpiAddGcryMpi`s.
#[no_mangle]
pub unsafe extern "C" fn mpi_sub(
    w: *mut MpiAddGcryMpi,
    u: *mut MpiAddGcryMpi,
    v: *mut MpiAddGcryMpi,
) -> c_int {
    // SAFETY: caller guarantees `v` valid.
    let vv = unsafe { mpi_copy(v) };
    if vv.is_null() {
        return -ENOMEM;
    }
    // SAFETY: `vv` freshly allocated by `mpi_copy` above.
    unsafe { (*vv).sign = ((*vv).sign == 0) as c_int }; /* !vv->sign */
    // SAFETY: `w`, `u` are the caller's, `vv` just built.
    let err = unsafe { mpi_add(w, u, vv) };
    // SAFETY: `vv` was allocated by `mpi_copy` above and not freed since.
    unsafe { mpi_free(vv) };
    err
}

kernel::kabi_export! {
    mpi_addm,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter t#MPI w , formal_parameter t#MPI u , formal_parameter t#MPI v , formal_parameter t#MPI m ) -> base_type int byte_size(4) encoding(5)",
}

/// `mpi_addm()` -- `w = (u + v) mod m`.
///
/// # Safety
/// `w`, `u`, `v`, `m` must be valid, initialized `MpiAddGcryMpi`s.
#[no_mangle]
pub unsafe extern "C" fn mpi_addm(
    w: *mut MpiAddGcryMpi,
    u: *mut MpiAddGcryMpi,
    v: *mut MpiAddGcryMpi,
    m: *mut MpiAddGcryMpi,
) -> c_int {
    // SAFETY: caller guarantees all four valid.
    let r = unsafe { mpi_add(w, u, v) };
    if r != 0 {
        r
    } else {
        // SAFETY: `mpi_add` above wrote `w`; `mpi_mod` reads and rewrites it.
        unsafe { mpi_mod(w, w, m) }
    }
}

kernel::kabi_export! {
    mpi_subm,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter t#MPI w , formal_parameter t#MPI u , formal_parameter t#MPI v , formal_parameter t#MPI m ) -> base_type int byte_size(4) encoding(5)",
}

/// `mpi_subm()` -- `w = (u - v) mod m`.
///
/// # Safety
/// `w`, `u`, `v`, `m` must be valid, initialized `MpiAddGcryMpi`s.
#[no_mangle]
pub unsafe extern "C" fn mpi_subm(
    w: *mut MpiAddGcryMpi,
    u: *mut MpiAddGcryMpi,
    v: *mut MpiAddGcryMpi,
    m: *mut MpiAddGcryMpi,
) -> c_int {
    // SAFETY: caller guarantees all four valid.
    let r = unsafe { mpi_sub(w, u, v) };
    if r != 0 {
        r
    } else {
        // SAFETY: as `mpi_addm`.
        unsafe { mpi_mod(w, w, m) }
    }
}
