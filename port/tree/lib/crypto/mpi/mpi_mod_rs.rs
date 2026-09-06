// SPDX-License-Identifier: GPL-2.0-or-later

//! Modular reduction -- the Rust behind `lib/crypto/mpi/mpi-mod.c`.
//!
//! Ported from `lib/crypto/mpi/mpi-mod.c` (6.18.49): one function, one
//! line, a direct call to `mpi_fdiv_r()` (`mpi_div_rs.rs`, already
//! ported).
//!
//! Replaces: lib/crypto/mpi/mpi-mod.c
//!
//! Not `EXPORT_SYMBOL`, but a real symbol -- `mpi_add_rs.rs`'s
//! `mpi_addm()`/`mpi_subm()` already call it via `extern "C"`.

use core::ffi::{c_int, c_ulong};

/// Mirrors `struct gcry_mpi` (`include/linux/mpi.h`). Named distinctly per
/// file -- see `mpi_add_rs.rs`'s module doc comment for why. This file
/// never reads a field of it directly (everything is passed straight
/// through to `mpi_fdiv_r()`), but `rig/layout-check.sh` matches any
/// `*GcryMpi`-named struct against the real `gcry_mpi`'s DWARF layout by
/// convention, so an opaque zero-sized stand-in reads as a genuine
/// geometry mismatch rather than "not applicable here" -- give it the
/// full field list like every other file, even though nothing here
/// touches a field by name.
#[repr(C)]
pub struct MpiModGcryMpi {
    /// Allocated array size, in limbs.
    pub alloced: c_int,
    /// Number of valid limbs.
    pub nlimbs: c_int,
    /// The real number of valid bits (info only).
    pub nbits: c_int,
    /// Nonzero if this value is negative.
    pub sign: c_int,
    /// Flag bits; not read by the function in this file.
    pub flags: u32,
    /// The limb array itself.
    pub d: *mut c_ulong,
}

unsafe extern "C" {
    fn mpi_fdiv_r(rem: *mut MpiModGcryMpi, dividend: *mut MpiModGcryMpi, divisor: *mut MpiModGcryMpi) -> c_int;
}

/// `mpi_mod()` -- `rem = dividend mod divisor` (floor division's
/// remainder; sign follows `divisor`, via `mpi_fdiv_r()`).
///
/// # Safety
/// `rem`, `dividend`, `divisor` must be valid, initialized `MpiModGcryMpi`s
/// (i.e. `struct gcry_mpi`s -- see the struct doc comment).
#[no_mangle]
pub unsafe extern "C" fn mpi_mod(
    rem: *mut MpiModGcryMpi,
    dividend: *mut MpiModGcryMpi,
    divisor: *mut MpiModGcryMpi,
) -> c_int {
    // SAFETY: caller guarantees all three valid; forwarded unchanged.
    unsafe { mpi_fdiv_r(rem, dividend, divisor) }
}
