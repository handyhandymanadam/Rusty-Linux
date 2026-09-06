// SPDX-License-Identifier: GPL-2.0-or-later

//! MPI bit-level functions -- the Rust behind `lib/crypto/mpi/mpi-bit.c`.
//!
//! Ported from `lib/crypto/mpi/mpi-bit.c` (6.18.49).
//!
//! Replaces: lib/crypto/mpi/mpi-bit.c
//!
//! # Four of five symbols are `EXPORT_SYMBOL_GPL`
//!
//! `mpi_get_nbits`/`mpi_test_bit`/`mpi_set_bit`/`mpi_rshift` are all
//! exported; pins captured via `rig/kabi-pin.sh --capture mpi_get_nbits
//! mpi_test_bit mpi_set_bit mpi_rshift build-full` before this file
//! replaced the C (`logs/pins/mpi-bit.pins`, `.err` empty).
//! `mpi_normalize` is not exported, but is a real (non-`static`) symbol:
//! `mpi_cmp_rs.rs` (already ported) and `mpi_sub_ui_rs.rs` (already
//! ported) both already call it via `extern "C"`, and continue to
//! resolve against this crate's definition without any change on their
//! side -- cross-crate linking is by symbol name, not by which crate
//! happens to define it.
//!
//! # `RESIZE_IF_NEEDED` is `static inline`, duplicated again
//!
//! Same reasoning as every other file in this pass: `mpi-internal.h`
//! gives every translation unit its own private copy.
//!
//! # `MPN_NORMALIZE` is reproduced as plain code, not a macro
//!
//! Same reasoning as every other file here.

use core::ffi::{c_int, c_uint, c_ulong};

const BITS_PER_MPI_LIMB: c_uint = c_ulong::BITS;

/// Mirrors `struct gcry_mpi` (`include/linux/mpi.h`). Named distinctly
/// per file -- see `mpi_add_rs.rs`'s module doc comment for why.
#[repr(C)]
pub struct MpiBitGcryMpi {
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
    fn mpi_resize(a: *mut MpiBitGcryMpi, nlimbs: c_uint) -> c_int;
    fn mpihelp_rshift(wp: *mut c_ulong, up: *const c_ulong, usize_: c_int, cnt: c_uint) -> c_ulong;
}

fn count_leading_zeros(x: c_ulong) -> u32 {
    x.leading_zeros()
}

/// `RESIZE_IF_NEEDED(a, b)` (`mpi-internal.h`).
///
/// # Safety
/// `a` valid.
unsafe fn resize_if_needed(a: *mut MpiBitGcryMpi, b: c_uint) -> c_int {
    // SAFETY: caller guarantees `a` valid.
    if unsafe { (*a).alloced } < b as c_int {
        return unsafe { mpi_resize(a, b) };
    }
    0
}

/// `MPN_NORMALIZE(d, n)` (`mpi-internal.h`): shrink `n` while the top limb
/// is zero, returning the new size.
///
/// # Safety
/// `d` readable for `n` limbs.
unsafe fn mpn_normalize(d: *const c_ulong, mut n: c_int) -> c_int {
    while n > 0 {
        // SAFETY: `n` limbs readable, `n > 0` here.
        if unsafe { *d.add((n - 1) as usize) } != 0 {
            break;
        }
        n -= 1;
    }
    n
}

/// `mpi_normalize()` -- shrink `a->nlimbs` while its top limb is zero.
/// Real (non-`static`) symbol: `mpi_cmp_rs.rs` and `mpi_sub_ui_rs.rs`
/// both call it directly.
///
/// # Safety
/// `a` valid.
#[no_mangle]
pub unsafe extern "C" fn mpi_normalize(a: *mut MpiBitGcryMpi) {
    // SAFETY: caller guarantees `a` valid.
    unsafe {
        (*a).nlimbs = mpn_normalize((*a).d, (*a).nlimbs);
    }
}

kernel::kabi_rule!("type_string", "t#MPI",
    "typedef_type MPI { pointer_type { s#gcry_mpi } }");
kernel::kabi_rule!("type_string", "s#gcry_mpi",
    "structure_type gcry_mpi { member base_type int byte_size(4) encoding(5) alloced data_member_location(0) , member base_type int byte_size(4) encoding(5) nlimbs data_member_location(4) , member base_type int byte_size(4) encoding(5) nbits data_member_location(8) , member base_type int byte_size(4) encoding(5) sign data_member_location(12) , member base_type unsigned int byte_size(4) encoding(7) flags data_member_location(16) , member pointer_type { t#mpi_limb_t } d data_member_location(24) } byte_size(32)");
kernel::kabi_rule!("type_string", "t#mpi_limb_t",
    "typedef_type mpi_limb_t { base_type unsigned long byte_size(8) encoding(7) }");

kernel::kabi_export! {
    mpi_get_nbits,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter t#MPI a ) -> base_type unsigned int byte_size(4) encoding(7)",
}

/// `mpi_get_nbits()` -- the number of bits in `a`, normalizing first.
///
/// # Safety
/// `a` valid.
#[no_mangle]
pub unsafe extern "C" fn mpi_get_nbits(a: *mut MpiBitGcryMpi) -> c_uint {
    // SAFETY: `a` valid.
    unsafe { mpi_normalize(a) };

    // SAFETY: `a` valid.
    let nlimbs = unsafe { (*a).nlimbs };
    if nlimbs != 0 {
        // SAFETY: `nlimbs > 0`, so index `nlimbs - 1` is valid.
        let alimb = unsafe { *(*a).d.add((nlimbs - 1) as usize) };
        let n = if alimb != 0 {
            count_leading_zeros(alimb)
        } else {
            BITS_PER_MPI_LIMB
        };
        BITS_PER_MPI_LIMB - n + (nlimbs as c_uint - 1) * BITS_PER_MPI_LIMB
    } else {
        0
    }
}

kernel::kabi_export! {
    mpi_test_bit,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter t#MPI a , formal_parameter base_type unsigned int byte_size(4) encoding(7) n ) -> base_type int byte_size(4) encoding(5)",
}

/// `mpi_test_bit()` -- is bit `n` of `a` set?
///
/// # Safety
/// `a` valid.
#[no_mangle]
pub unsafe extern "C" fn mpi_test_bit(a: *mut MpiBitGcryMpi, n: c_uint) -> c_int {
    let limbno = n / BITS_PER_MPI_LIMB;
    let bitno = n % BITS_PER_MPI_LIMB;

    // SAFETY: `a` valid.
    if limbno >= unsafe { (*a).nlimbs } as c_uint {
        return 0; // too far left: this is a 0
    }
    // SAFETY: `limbno < nlimbs`, so this index is valid.
    let limb = unsafe { *(*a).d.add(limbno as usize) };
    if limb & (1u64 << bitno) != 0 {
        1
    } else {
        0
    }
}

kernel::kabi_export! {
    mpi_set_bit,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter t#MPI a , formal_parameter base_type unsigned int byte_size(4) encoding(7) n ) -> base_type int byte_size(4) encoding(5)",
}

/// `mpi_set_bit()` -- set bit `n` of `a`, growing it if necessary.
///
/// # Safety
/// `a` valid.
#[no_mangle]
pub unsafe extern "C" fn mpi_set_bit(a: *mut MpiBitGcryMpi, n: c_uint) -> c_int {
    let limbno = n / BITS_PER_MPI_LIMB;
    let bitno = n % BITS_PER_MPI_LIMB;

    // SAFETY: `a` valid.
    if limbno >= unsafe { (*a).nlimbs } as c_uint {
        // SAFETY: `a->d` writable for `a->alloced` limbs (the allocator's
        // own invariant); zero the newly-exposed limbs before growing
        // `nlimbs` to cover them, matching the C exactly.
        unsafe {
            let mut i = (*a).nlimbs;
            while i < (*a).alloced {
                *(*a).d.add(i as usize) = 0;
                i += 1;
            }
            let err = mpi_resize(a, limbno + 1);
            if err != 0 {
                return err;
            }
            (*a).nlimbs = (limbno + 1) as c_int;
        }
    }
    // SAFETY: `limbno < nlimbs` now, so this index is valid.
    unsafe { *(*a).d.add(limbno as usize) |= 1u64 << bitno };
    0
}

kernel::kabi_export! {
    mpi_rshift,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter t#MPI x , formal_parameter t#MPI a , formal_parameter base_type unsigned int byte_size(4) encoding(7) n ) -> base_type int byte_size(4) encoding(5)",
}

/// `mpi_rshift()` -- `x = a >> n`. `x` may alias `a`.
///
/// # Safety
/// `x`, `a` valid.
#[no_mangle]
pub unsafe extern "C" fn mpi_rshift(x: *mut MpiBitGcryMpi, a: *mut MpiBitGcryMpi, n: c_uint) -> c_int {
    let nlimbs = n / BITS_PER_MPI_LIMB;
    let nbits = n % BITS_PER_MPI_LIMB;

    if x == a {
        // In-place operation.
        // SAFETY: `x` valid.
        if nlimbs >= unsafe { (*x).nlimbs } as c_uint {
            unsafe { (*x).nlimbs = 0 };
            return 0;
        }

        if nlimbs != 0 {
            // SAFETY: `x->d` readable/writable for `x->nlimbs` limbs;
            // shifting down by `nlimbs` whole limbs, forward index order
            // is safe since each write is to an index at or before the
            // one just read.
            unsafe {
                let mut i: c_uint = 0;
                while i < (*x).nlimbs as c_uint - nlimbs {
                    *(*x).d.add(i as usize) = *(*x).d.add((i + nlimbs) as usize);
                    i += 1;
                }
                *(*x).d.add(i as usize) = 0;
                (*x).nlimbs -= nlimbs as c_int;
            }
        }
        // SAFETY: `x` valid.
        if unsafe { (*x).nlimbs } != 0 && nbits != 0 {
            unsafe { mpihelp_rshift((*x).d, (*x).d, (*x).nlimbs, nbits) };
        }
    } else if nlimbs != 0 {
        // Copy and shift by more or equal bits than in a limb.
        // SAFETY: `a` valid.
        let xsize = unsafe { (*a).nlimbs };
        unsafe { (*x).sign = (*a).sign };
        let err = unsafe { resize_if_needed(x, xsize as c_uint) };
        if err != 0 {
            return err;
        }
        // SAFETY: `x`, `a` valid; `x->d` writable for `xsize` limbs
        // (just ensured), `a->d` readable for `a->nlimbs == xsize` limbs.
        unsafe {
            let mut i: c_int = 0;
            while i < (*a).nlimbs {
                *(*x).d.add(i as usize) = *(*a).d.add(i as usize);
                i += 1;
            }
            (*x).nlimbs = i;
        }

        if nlimbs >= unsafe { (*x).nlimbs } as c_uint {
            unsafe { (*x).nlimbs = 0 };
            return 0;
        }

        // SAFETY: as the in-place branch above.
        unsafe {
            let mut i: c_uint = 0;
            while i < (*x).nlimbs as c_uint - nlimbs {
                *(*x).d.add(i as usize) = *(*x).d.add((i + nlimbs) as usize);
                i += 1;
            }
            *(*x).d.add(i as usize) = 0;
            (*x).nlimbs -= nlimbs as c_int;
        }

        if unsafe { (*x).nlimbs } != 0 && nbits != 0 {
            unsafe { mpihelp_rshift((*x).d, (*x).d, (*x).nlimbs, nbits) };
        }
    } else {
        // Copy and shift by less than the bits in a limb.
        // SAFETY: `a` valid.
        let xsize = unsafe { (*a).nlimbs };
        unsafe { (*x).sign = (*a).sign };
        let err = unsafe { resize_if_needed(x, xsize as c_uint) };
        if err != 0 {
            return err;
        }
        unsafe { (*x).nlimbs = xsize };

        if xsize != 0 {
            if nbits != 0 {
                unsafe { mpihelp_rshift((*x).d, (*a).d, (*x).nlimbs, nbits) };
            } else {
                // mpihelp_rshift is not specified for cnt == 0; plain copy.
                unsafe {
                    let mut i: c_int = 0;
                    while i < (*x).nlimbs {
                        *(*x).d.add(i as usize) = *(*a).d.add(i as usize);
                        i += 1;
                    }
                }
            }
        }
    }

    // SAFETY: `x` valid.
    unsafe {
        (*x).nlimbs = mpn_normalize((*x).d, (*x).nlimbs);
    }
    0
}
