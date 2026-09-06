// SPDX-License-Identifier: GPL-2.0-or-later

//! Multiprecision-integer comparison -- the Rust behind `lib/crypto/mpi/mpi-cmp.c`.
//!
//! Ported from `lib/crypto/mpi/mpi-cmp.c` (6.18.49).
//!
//! Replaces: lib/crypto/mpi/mpi-cmp.c
//!
//! # Why this one, first, out of the whole `mpi/` cluster
//!
//! Every other file in `lib/crypto/mpi/` either allocates through
//! `mpi_resize`/`mpi_alloc_limb_space` (`kzalloc`-backed, `logs/allocation.md`'s
//! standing exception) or calls a `static inline` helper with no linkable
//! symbol (`mpihelp_add_1`/`sub_1` in `mpi-inline.h`). This file does neither:
//! it reads two `MPI`s and returns an `int`, calling only `mpi_normalize()`
//! (a real out-of-line symbol, still C, in `lib/crypto/mpi/mpi-bit.c`) and
//! `mpihelp_cmp()` (already Rust, `generic_mpih_rs.rs`).
//!
//! # `struct gcry_mpi` is mirrored, not opaque
//!
//! Both functions read `nlimbs`/`sign`/`d` directly, so the layout has to
//! match, not just the pointer. `Mirrors `struct gcry_mpi`` below is
//! `#[repr(C)]` with the exact field order and types from
//! `include/linux/mpi.h`; the padding between `flags` (ends at offset 20)
//! and `d` (offset 24) falls out of `repr(C)` alignment automatically given
//! matching field types, and is confirmed against the captured pin in
//! `logs/pins/mpi-cmp.pins` (`byte_size(32)`, `d` at
//! `data_member_location(24)`).
//!
//! # `mpi_cmp`'s size-difference return value
//!
//! `usize - vsize` in the C is `int - int` with both operands already
//! bounded well inside `i32` (a limb count, never remotely close to
//! `i32::MAX`), so the subtraction cannot overflow; translated as plain `i32`
//! subtraction rather than a checked/wrapping variant.

use core::ffi::{c_int, c_ulong};

/// Mirrors `struct gcry_mpi` (`include/linux/mpi.h`). See the module doc
/// comment for why layout, not just the pointer, has to match.
#[repr(C)]
pub struct GcryMpi {
    /// Allocated array size, in limbs.
    pub alloced: c_int,
    /// Number of valid limbs.
    pub nlimbs: c_int,
    /// The real number of valid bits (info only).
    pub nbits: c_int,
    /// Nonzero if this value is negative.
    pub sign: c_int,
    /// Bit 0: array must be allocated in secure memory. Bit 2: `d` points
    /// at `m_alloced` data. Not read by the functions in this file.
    pub flags: u32,
    /// The limb array itself.
    pub d: *mut c_ulong,
}

unsafe extern "C" {
    fn mpi_normalize(a: *mut GcryMpi);
    fn mpihelp_cmp(
        op1_ptr: *const c_ulong,
        op2_ptr: *const c_ulong,
        size: c_int,
    ) -> c_int;
}

kernel::kabi_export! {
    mpi_cmp_ui,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter t#MPI u , formal_parameter base_type unsigned long byte_size(8) encoding(7) v ) -> base_type int byte_size(4) encoding(5)",
}

kernel::kabi_rule!("type_string", "t#MPI",
    "typedef_type MPI { pointer_type { s#gcry_mpi } }");

kernel::kabi_rule!("type_string", "s#gcry_mpi",
    "structure_type gcry_mpi { member base_type int byte_size(4) encoding(5) alloced data_member_location(0) , member base_type int byte_size(4) encoding(5) nlimbs data_member_location(4) , member base_type int byte_size(4) encoding(5) nbits data_member_location(8) , member base_type int byte_size(4) encoding(5) sign data_member_location(12) , member base_type unsigned int byte_size(4) encoding(7) flags data_member_location(16) , member pointer_type { t#mpi_limb_t } d data_member_location(24) } byte_size(32)");

kernel::kabi_rule!("type_string", "t#mpi_limb_t",
    "typedef_type mpi_limb_t { base_type unsigned long byte_size(8) encoding(7) }");

/// `mpi_cmp_ui() -- compare `u` against the small unsigned value `v`.
///
/// # Safety
/// `u` must point at a valid, initialized `GcryMpi` whose `d` points at
/// `nlimbs` readable limbs.
#[no_mangle]
pub unsafe extern "C" fn mpi_cmp_ui(u: *mut GcryMpi, v: c_ulong) -> c_int {
    // SAFETY: caller guarantees `u` is valid; `mpi_normalize` has the same
    // contract as the C call it replaces.
    unsafe { mpi_normalize(u) };
    // SAFETY: `mpi_normalize` above establishes `u` is still valid.
    let u = unsafe { &*u };

    if u.nlimbs == 0 {
        return if v == 0 { 0 } else { -1 };
    }
    if u.sign != 0 {
        return -1;
    }
    if u.nlimbs > 1 {
        return 1;
    }

    // SAFETY: `nlimbs == 1` here, so `d[0]` is in bounds.
    let limb0 = unsafe { *u.d };
    if limb0 == v {
        0
    } else if limb0 > v {
        1
    } else {
        -1
    }
}

kernel::kabi_export! {
    mpi_cmp,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter t#MPI u , formal_parameter t#MPI v ) -> base_type int byte_size(4) encoding(5)",
}

/// `mpi_cmp()` -- three-way compare of two multiprecision integers.
///
/// # Safety
/// `u` and `v` must each point at a valid, initialized `GcryMpi` whose `d`
/// points at `nlimbs` readable limbs.
#[no_mangle]
pub unsafe extern "C" fn mpi_cmp(u: *mut GcryMpi, v: *mut GcryMpi) -> c_int {
    // SAFETY: caller guarantees both are valid.
    unsafe {
        mpi_normalize(u);
        mpi_normalize(v);
    }
    // SAFETY: normalized above; both still valid, non-overlapping (the C
    // has the same aliasing assumption -- two distinct MPI arguments).
    let (ur, vr) = unsafe { (&*u, &*v) };

    let usize_ = ur.nlimbs;
    let vsize = vr.nlimbs;

    if ur.sign == 0 && vr.sign != 0 {
        return 1;
    }
    if ur.sign != 0 && vr.sign == 0 {
        return -1;
    }
    if usize_ != vsize && ur.sign == 0 && vr.sign == 0 {
        return usize_ - vsize;
    }
    if usize_ != vsize && ur.sign != 0 && vr.sign != 0 {
        return vsize - usize_;
    }
    if usize_ == 0 {
        return 0;
    }

    // SAFETY: `usize_ == vsize > 0`, and both `d` point at that many limbs.
    let cmp = unsafe { mpihelp_cmp(ur.d, vr.d, usize_) };
    if ur.sign != 0 {
        -cmp
    } else {
        cmp
    }
}
