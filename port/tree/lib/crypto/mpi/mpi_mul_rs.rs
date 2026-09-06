// SPDX-License-Identifier: GPL-2.0-or-later

//! MPI multiplication -- the Rust behind `lib/crypto/mpi/mpi-mul.c`.
//!
//! Ported from `lib/crypto/mpi/mpi-mul.c` (6.18.49).
//!
//! Replaces: lib/crypto/mpi/mpi-mul.c
//!
//! # Both symbols are `EXPORT_SYMBOL_GPL`
//!
//! Unlike every other file in this pass, `mpi_mul()`/`mpi_mulm()` are
//! real exported symbols. Pins captured via `rig/kabi-pin.sh --capture
//! mpi_mul mpi_mulm mpi_powm build-full` before this file replaced the C
//! (`logs/pins/mpi-mul-pow.pins`, `.err` empty) -- `mpi_powm` was captured
//! in the same pass since it shares the type graph and is ported in the
//! same commit (`mpi_pow_rs.rs`).
//!
//! # `mpi_mulm()`'s `?:` tail call
//!
//! `mpi_mul(w, u, v) ?: mpi_tdiv_r(w, w, m)` -- the second call only runs
//! if the first returns 0, same shape as `mpi_add_rs.rs`'s `mpi_addm()`/
//! `mpi_subm()`. `mpi_tdiv_r` is `mpi_div_rs.rs`'s, called via `extern
//! "C"` across the crate boundary like everywhere else in this pass.
//!
//! # `MPN_COPY` is a forward loop, not a macro
//!
//! Same reasoning as every other file here -- see `mpi_add_rs.rs`'s
//! module doc comment.

use core::ffi::{c_int, c_uint, c_ulong};

const ENOMEM: c_int = 12;

/// Mirrors `struct gcry_mpi` (`include/linux/mpi.h`). Named distinctly
/// per file -- see `mpi_add_rs.rs`'s module doc comment for why.
#[repr(C)]
pub struct MpiMulGcryMpi {
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
    fn mpi_resize(a: *mut MpiMulGcryMpi, nlimbs: c_uint) -> c_int;
    fn mpi_alloc_limb_space(nlimbs: c_uint) -> *mut c_ulong;
    fn mpi_free_limb_space(a: *mut c_ulong);
    fn mpi_assign_limb_space(a: *mut MpiMulGcryMpi, ap: *mut c_ulong, nlimbs: c_uint);
    fn mpihelp_mul(
        prodp: *mut c_ulong,
        up: *const c_ulong,
        usize_: c_int,
        vp: *const c_ulong,
        vsize: c_int,
        result: *mut c_ulong,
    ) -> c_int;
    fn mpi_tdiv_r(rem: *mut MpiMulGcryMpi, num: *mut MpiMulGcryMpi, den: *mut MpiMulGcryMpi) -> c_int;
}

/// `MPN_COPY(d, s, n)` (`mpi-internal.h`).
///
/// # Safety
/// `d` writable and `s` readable for `n` limbs.
unsafe fn mpn_copy(d: *mut c_ulong, s: *const c_ulong, n: c_int) {
    let mut i = 0;
    while i < n {
        // SAFETY: caller guarantees `n` limbs on both sides.
        unsafe { *d.add(i as usize) = *s.add(i as usize) };
        i += 1;
    }
}

kernel::kabi_rule!("type_string", "t#MPI",
    "typedef_type MPI { pointer_type { s#gcry_mpi } }");
kernel::kabi_rule!("type_string", "s#gcry_mpi",
    "structure_type gcry_mpi { member base_type int byte_size(4) encoding(5) alloced data_member_location(0) , member base_type int byte_size(4) encoding(5) nlimbs data_member_location(4) , member base_type int byte_size(4) encoding(5) nbits data_member_location(8) , member base_type int byte_size(4) encoding(5) sign data_member_location(12) , member base_type unsigned int byte_size(4) encoding(7) flags data_member_location(16) , member pointer_type { t#mpi_limb_t } d data_member_location(24) } byte_size(32)");
kernel::kabi_rule!("type_string", "t#mpi_limb_t",
    "typedef_type mpi_limb_t { base_type unsigned long byte_size(8) encoding(7) }");

kernel::kabi_export! {
    mpi_mul,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter t#MPI w , formal_parameter t#MPI u , formal_parameter t#MPI v ) -> base_type int byte_size(4) encoding(5)",
}

/// `mpi_mul()` -- `w = u * v`.
///
/// # Safety
/// `w`, `u`, `v` must be valid, initialized `MpiMulGcryMpi`s. `w` may
/// alias `u` and/or `v` (the C's own overlap-handling branches exist
/// precisely to support this).
#[no_mangle]
pub unsafe extern "C" fn mpi_mul(
    w: *mut MpiMulGcryMpi,
    u: *mut MpiMulGcryMpi,
    v: *mut MpiMulGcryMpi,
) -> c_int {
    // SAFETY: caller guarantees `u`, `v` valid.
    let (usize0, usign0, up0) = unsafe { ((*u).nlimbs, (*u).sign, (*u).d) };
    let (vsize0, vsign0, vp0) = unsafe { ((*v).nlimbs, (*v).sign, (*v).d) };

    let (usize_, usign, mut up, vsize, vsign, mut vp);
    if usize0 < vsize0 {
        // Swap U and V.
        usize_ = vsize0;
        usign = vsign0;
        up = vp0;
        vsize = usize0;
        vsign = usign0;
        vp = up0;
    } else {
        usize_ = usize0;
        usign = usign0;
        up = up0;
        vsize = vsize0;
        vsign = vsign0;
        vp = vp0;
    }
    let sign_product = usign ^ vsign;
    // SAFETY: `w` valid.
    let mut wp = unsafe { (*w).d };

    let mut wsize = usize_ + vsize;
    let mut assign_wp = false;
    let mut tmp_limb: *mut c_ulong = core::ptr::null_mut();

    // SAFETY: `w` valid.
    if unsafe { (*w).alloced } < wsize {
        if wp == up || wp == vp {
            wp = unsafe { mpi_alloc_limb_space(wsize as c_uint) };
            if wp.is_null() {
                return -ENOMEM;
            }
            assign_wp = true;
        } else {
            let err = unsafe { mpi_resize(w, wsize as c_uint) };
            if err != 0 {
                return err;
            }
            wp = unsafe { (*w).d };
        }
    } else {
        // Make U and V not overlap with W.
        if wp == up {
            // W and U are identical. Allocate temp space for U.
            up = unsafe { mpi_alloc_limb_space(usize_ as c_uint) };
            tmp_limb = up;
            if up.is_null() {
                return -ENOMEM;
            }
            // Is V identical too? Keep it identical with U.
            if wp == vp {
                vp = up;
            }
            unsafe { mpn_copy(up, wp, usize_) };
        } else if wp == vp {
            // W and V are identical. Allocate temp space for V.
            vp = unsafe { mpi_alloc_limb_space(vsize as c_uint) };
            tmp_limb = vp;
            if vp.is_null() {
                return -ENOMEM;
            }
            unsafe { mpn_copy(vp, wp, vsize) };
        }
    }

    let mut err: c_int = 0;
    if vsize == 0 {
        wsize = 0;
    } else {
        let mut cy: c_ulong = 0;
        err = unsafe { mpihelp_mul(wp, up, usize_, vp, vsize, &mut cy) };
        if err != 0 {
            if assign_wp {
                unsafe { mpi_free_limb_space(wp) };
            }
        } else {
            wsize -= if cy != 0 { 0 } else { 1 };
        }
    }

    if err == 0 {
        if assign_wp {
            unsafe { mpi_assign_limb_space(w, wp, wsize as c_uint) };
        }
        unsafe {
            (*w).nlimbs = wsize;
            (*w).sign = sign_product;
        }
    }

    if !tmp_limb.is_null() {
        unsafe { mpi_free_limb_space(tmp_limb) };
    }
    err
}

kernel::kabi_export! {
    mpi_mulm,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter t#MPI w , formal_parameter t#MPI u , formal_parameter t#MPI v , formal_parameter t#MPI m ) -> base_type int byte_size(4) encoding(5)",
}

/// `mpi_mulm()` -- `w = (u * v) mod m`.
///
/// # Safety
/// As [`mpi_mul`], plus `m` valid.
#[no_mangle]
pub unsafe extern "C" fn mpi_mulm(
    w: *mut MpiMulGcryMpi,
    u: *mut MpiMulGcryMpi,
    v: *mut MpiMulGcryMpi,
    m: *mut MpiMulGcryMpi,
) -> c_int {
    // SAFETY: caller guarantees all four valid.
    let r = unsafe { mpi_mul(w, u, v) };
    if r != 0 {
        return r;
    }
    // SAFETY: `w` valid (just written by mpi_mul); `m` valid.
    unsafe { mpi_tdiv_r(w, w, m) }
}
