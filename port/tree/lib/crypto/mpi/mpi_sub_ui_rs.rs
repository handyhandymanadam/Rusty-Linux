// SPDX-License-Identifier: GPL-2.0-or-later

//! Subtract an unsigned integer from an MPI -- the Rust behind
//! `lib/crypto/mpi/mpi-sub-ui.c`.
//!
//! Ported from `lib/crypto/mpi/mpi-sub-ui.c` (6.18.49).
//!
//! Replaces: lib/crypto/mpi/mpi-sub-ui.c
//!
//! # `mpihelp_add_1`/`mpihelp_sub_1` are reproduced here too
//!
//! Same reasoning as `mpi_add_rs.rs`'s module doc comment: both are
//! `static inline` in `mpi-inline.h` with no linkable symbol, so every
//! file that needs them carries its own private copy -- this one included,
//! since the C's `mpi_sub_ui()` calls both directly rather than through
//! `mpihelp_add()`/`mpihelp_sub()`.

use core::ffi::{c_int, c_uint, c_ulong};

/// `ENOMEM` (`include/uapi/asm-generic/errno-base.h`).
const ENOMEM: c_int = 12;

/// Mirrors `struct gcry_mpi` (`include/linux/mpi.h`). Named distinctly per
/// file -- see `mpi_add_rs.rs`'s module doc comment for why.
#[repr(C)]
pub struct MpiSubUiGcryMpi {
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
    fn mpi_resize(a: *mut MpiSubUiGcryMpi, nlimbs: c_uint) -> c_int;
    fn mpi_normalize(a: *mut MpiSubUiGcryMpi);
}

/// `mpihelp_add_1()` (`mpi-inline.h`). See `mpi_add_rs.rs`'s copy for the
/// full derivation; identical body.
///
/// # Safety
/// `res_ptr` writable and `s1_ptr` readable for `s1_size` limbs
/// (`s1_size >= 1`).
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
    unsafe { *res_ptr = s2_limb };
    res_ptr = unsafe { res_ptr.add(1) };

    if s2_limb < x0 {
        loop {
            s1_size = s1_size.wrapping_sub(1);
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
        // SAFETY: `s1_size - 1` limbs remain readable/writable.
        for i in 0..(s1_size.wrapping_sub(1)) as usize {
            unsafe { *res_ptr.add(i) = *s1_ptr.add(i) };
        }
    }
    0
}

/// `mpihelp_sub_1()` (`mpi-inline.h`). See `mpi_add_rs.rs`'s copy.
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
            s1_size = s1_size.wrapping_sub(1);
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
        for i in 0..(s1_size.wrapping_sub(1)) as usize {
            unsafe { *res_ptr.add(i) = *s1_ptr.add(i) };
        }
    }
    0
}

kernel::kabi_rule!("type_string", "s#gcry_mpi",
    "structure_type gcry_mpi { member base_type int byte_size(4) encoding(5) alloced data_member_location(0) , member base_type int byte_size(4) encoding(5) nlimbs data_member_location(4) , member base_type int byte_size(4) encoding(5) nbits data_member_location(8) , member base_type int byte_size(4) encoding(5) sign data_member_location(12) , member base_type unsigned int byte_size(4) encoding(7) flags data_member_location(16) , member pointer_type { t#mpi_limb_t } d data_member_location(24) } byte_size(32)");
kernel::kabi_rule!("type_string", "t#MPI",
    "typedef_type MPI { pointer_type { s#gcry_mpi } }");
kernel::kabi_rule!("type_string", "t#mpi_limb_t",
    "typedef_type mpi_limb_t { base_type unsigned long byte_size(8) encoding(7) }");

kernel::kabi_export! {
    mpi_sub_ui,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter t#MPI w , formal_parameter t#MPI u , formal_parameter base_type unsigned long byte_size(8) encoding(7) vval ) -> base_type int byte_size(4) encoding(5)",
}

/// `mpi_sub_ui()` -- `w = u - vval`, for a plain `unsigned long vval`.
///
/// # Safety
/// `w`, `u` must be valid, initialized `MpiSubUiGcryMpi`s. `w` may alias
/// `u`.
#[no_mangle]
pub unsafe extern "C" fn mpi_sub_ui(
    w: *mut MpiSubUiGcryMpi,
    u: *mut MpiSubUiGcryMpi,
    vval: c_ulong,
) -> c_int {
    // SAFETY: caller guarantees `u` valid.
    let u_nlimbs = unsafe { (*u).nlimbs };

    if u_nlimbs == 0 {
        // SAFETY: `w` valid (caller contract).
        if unsafe { mpi_resize(w, 1) } < 0 {
            return -ENOMEM;
        }
        let nz = (vval != 0) as c_int;
        // SAFETY: `w` was just resized to at least 1 limb.
        unsafe {
            *(*w).d = vval;
            (*w).nlimbs = nz;
            (*w).sign = nz;
        }
        return 0;
    }

    // SAFETY: `w` valid.
    if unsafe { mpi_resize(w, u_nlimbs.wrapping_add(1) as c_uint) } != 0 {
        return -ENOMEM;
    }

    // SAFETY: caller guarantees `u` valid.
    if unsafe { (*u).sign } != 0 {
        // SAFETY: `w` resized to `u_nlimbs + 1` limbs above; `u` has
        // `u_nlimbs` readable limbs.
        let cy = unsafe { mpihelp_add_1((*w).d, (*u).d, u_nlimbs, vval) };
        // SAFETY: `w` has room for `u_nlimbs + 1` limbs.
        unsafe {
            *(*w).d.add(u_nlimbs as usize) = cy;
            (*w).nlimbs = u_nlimbs.wrapping_add(cy as c_int);
            (*w).sign = 1;
        }
    } else {
        // SAFETY: `u` has at least 1 limb (`u_nlimbs != 0`, checked above).
        let u_d0 = unsafe { *(*u).d };
        if u_nlimbs == 1 && u_d0 < vval {
            // SAFETY: `w` has room for at least 1 limb.
            unsafe {
                *(*w).d = vval.wrapping_sub(u_d0);
                (*w).nlimbs = 1;
                (*w).sign = 1;
            }
        } else {
            // SAFETY: `w` and `u` each have `u_nlimbs` limbs.
            unsafe { mpihelp_sub_1((*w).d, (*u).d, u_nlimbs, vval) };
            // SAFETY: `u_nlimbs >= 1` here, so index `u_nlimbs - 1` is
            // in bounds of `w`'s just-written limbs.
            let last = unsafe { *(*w).d.add((u_nlimbs.wrapping_sub(1)) as usize) };
            unsafe {
                (*w).nlimbs = u_nlimbs.wrapping_sub((last == 0) as c_int);
                (*w).sign = 0;
            }
        }
    }

    // SAFETY: `w` valid.
    unsafe { mpi_normalize(w) };
    0
}
