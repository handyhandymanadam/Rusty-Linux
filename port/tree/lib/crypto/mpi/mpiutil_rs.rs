// SPDX-License-Identifier: GPL-2.0-or-later

//! MPI allocation and freeing -- the Rust behind `lib/crypto/mpi/mpiutil.c`.
//!
//! Ported from `lib/crypto/mpi/mpiutil.c` (6.18.49).
//!
//! Replaces: lib/crypto/mpi/mpiutil.c (except the retained allocation
//! thunks, see that file's own header comment and `logs/allocation.md`)
//!
//! # `struct gcry_mpi` is mirrored, not opaque
//!
//! Same reasoning as `mpi_cmp_rs.rs`: both functions read and write
//! `nlimbs`/`sign`/`flags`/`alloced`/`d` directly, so the layout has to
//! match. `MpiUtilGcryMpi` below is `#[repr(C)]` with the exact field order and
//! types from `include/linux/mpi.h`, confirmed against the captured pin in
//! `logs/pins/mpiutil.pins` (`byte_size(32)`).
//!
//! # `mpi_alloc`/`mpi_free`/`mpi_resize`/`mpi_copy`'s `int`-vs-`unsigned`
//! # conversions are reproduced, not "fixed"
//!
//! The C compares and assigns between `int` (`alloced`, `nlimbs`) and
//! `unsigned` (`nlimbs` parameters) throughout, relying on C's usual
//! arithmetic conversions. Every `as` cast below reproduces the exact
//! conversion the C performs at that point -- e.g. `mpi_resize`'s
//! `nlimbs <= a->alloced` compares an `unsigned` against an `int` promoted
//! to `unsigned`, which is what `a.alloced as c_uint` does here. Neither
//! field is ever negative in any caller this project has found, so this
//! never bites in practice; it is reproduced anyway because GOALS.md §5
//! only licenses a change nothing outside can observe, and a construct that
//! is merely never exercised is not the same as one that cannot matter.
//!
//! # `mpi_resize`'s two branches share one allocation, unlike the C
//!
//! The C's `if (a->d) {...} else {...}` calls the identical `kcalloc(nlimbs,
//! sizeof(mpi_limb_t), GFP_KERNEL)` in both arms and differs only in whether
//! the old buffer is copied and freed afterward. Hoisting that one call
//! above the branch changes no observable behaviour (same allocator, same
//! size, same flags, every time) and removes the duplication.

use core::ffi::{c_char, c_int, c_uint, c_ulong, c_void};

/// `ENOMEM` (`include/uapi/asm-generic/errno-base.h`).
const ENOMEM: c_int = 12;

/// Mirrors `struct gcry_mpi` (`include/linux/mpi.h`). See the module doc
/// comment for why layout, not just the pointer, has to match.
#[repr(C)]
pub struct MpiUtilGcryMpi {
    /// Allocated array size, in limbs.
    pub alloced: c_int,
    /// Number of valid limbs.
    pub nlimbs: c_int,
    /// The real number of valid bits (info only).
    pub nbits: c_int,
    /// Nonzero if this value is negative.
    pub sign: c_int,
    /// Bit 2: `d` was allocated with `kmalloc` directly (wiped with
    /// `kfree_sensitive` on free, rather than through
    /// `mpi_free_limb_space()`). Bits outside 0-2 are invalid.
    pub flags: u32,
    /// The limb array itself.
    pub d: *mut c_ulong,
}

unsafe extern "C" {
    fn rust_mpi_kmalloc(len: usize) -> *mut c_void;
    fn rust_mpi_kcalloc(n: usize, size: usize) -> *mut c_void;
    fn rust_mpi_kfree(p: *mut c_void);
    fn rust_mpi_kfree_sensitive(p: *mut c_void);
    fn _printk(fmt: *const c_char, ...) -> c_int;
}

kernel::kabi_rule!("type_string", "t#MPI",
    "typedef_type MPI { pointer_type { s#gcry_mpi } }");

kernel::kabi_rule!("type_string", "s#gcry_mpi",
    "structure_type gcry_mpi { member base_type int byte_size(4) encoding(5) alloced data_member_location(0) , member base_type int byte_size(4) encoding(5) nlimbs data_member_location(4) , member base_type int byte_size(4) encoding(5) nbits data_member_location(8) , member base_type int byte_size(4) encoding(5) sign data_member_location(12) , member base_type unsigned int byte_size(4) encoding(7) flags data_member_location(16) , member pointer_type { t#mpi_limb_t } d data_member_location(24) } byte_size(32)");

kernel::kabi_rule!("type_string", "t#mpi_limb_t",
    "typedef_type mpi_limb_t { base_type unsigned long byte_size(8) encoding(7) }");

kernel::kabi_export! {
    mpi_alloc,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter base_type unsigned int byte_size(4) encoding(7) nlimbs ) -> t#MPI",
}

/// `mpi_alloc()` -- allocate an MPI with room for `nlimbs` limbs.
///
/// # Safety
/// No preconditions beyond ordinary allocation-call safety; this function
/// allocates its own state.
#[no_mangle]
pub unsafe extern "C" fn mpi_alloc(nlimbs: c_uint) -> *mut MpiUtilGcryMpi {
    // SAFETY: allocating a fixed-size buffer for `MpiUtilGcryMpi`.
    let a = unsafe { rust_mpi_kmalloc(core::mem::size_of::<MpiUtilGcryMpi>()) } as *mut MpiUtilGcryMpi;
    if a.is_null() {
        return a;
    }

    if nlimbs != 0 {
        // SAFETY: `nlimbs` is the caller's own value.
        let d = unsafe { mpi_alloc_limb_space(nlimbs) };
        if d.is_null() {
            // SAFETY: `a` was just allocated by `rust_mpi_kmalloc` above.
            unsafe { rust_mpi_kfree(a as *mut c_void) };
            return core::ptr::null_mut();
        }
        // SAFETY: `a` is valid, freshly allocated.
        unsafe { (*a).d = d };
    } else {
        // SAFETY: see above.
        unsafe { (*a).d = core::ptr::null_mut() };
    }

    // SAFETY: `a` is valid.
    unsafe {
        (*a).alloced = nlimbs as c_int;
        (*a).nlimbs = 0;
        (*a).sign = 0;
        (*a).flags = 0;
        (*a).nbits = 0;
    }
    a
}

/// `mpi_alloc_limb_space()` -- allocate room for `nlimbs` limbs, unattached
/// to any `MpiUtilGcryMpi`. Not exported, but called from other C files in
/// `lib/crypto/mpi/` not yet ported, so it keeps a real, non-`static`
/// symbol.
///
/// # Safety
/// No preconditions beyond ordinary allocation-call safety.
#[no_mangle]
pub unsafe extern "C" fn mpi_alloc_limb_space(nlimbs: c_uint) -> *mut c_ulong {
    let len = nlimbs as usize * core::mem::size_of::<c_ulong>();
    if len == 0 {
        return core::ptr::null_mut();
    }
    // SAFETY: `len` is a plain byte count.
    unsafe { rust_mpi_kmalloc(len) as *mut c_ulong }
}

/// `mpi_free_limb_space()` -- free a buffer `mpi_alloc_limb_space()`
/// returned.
///
/// # Safety
/// `a` must be a pointer `mpi_alloc_limb_space()` returned, or null.
#[no_mangle]
pub unsafe extern "C" fn mpi_free_limb_space(a: *mut c_ulong) {
    if a.is_null() {
        return;
    }
    // SAFETY: caller guarantees `a` came from `mpi_alloc_limb_space()`.
    unsafe { rust_mpi_kfree_sensitive(a as *mut c_void) };
}

/// `mpi_assign_limb_space()` -- replace `a`'s limb buffer with `ap`,
/// freeing the old one.
///
/// # Safety
/// `a` must be valid; `ap` must be a pointer `mpi_alloc_limb_space()`
/// returned (or null) with room for `nlimbs` limbs.
#[no_mangle]
pub unsafe extern "C" fn mpi_assign_limb_space(a: *mut MpiUtilGcryMpi, ap: *mut c_ulong, nlimbs: c_uint) {
    // SAFETY: caller guarantees `a` valid; `(*a).d` was allocated by
    // `mpi_alloc_limb_space()` or is null, either of which
    // `mpi_free_limb_space()` accepts.
    unsafe {
        mpi_free_limb_space((*a).d);
        (*a).d = ap;
        (*a).alloced = nlimbs as c_int;
    }
}

kernel::kabi_rule!("type_string", "t#size_t",
    "typedef_type size_t { t#__kernel_size_t }");
kernel::kabi_rule!("type_string", "t#__kernel_size_t",
    "typedef_type __kernel_size_t { t#__kernel_ulong_t }");
kernel::kabi_rule!("type_string", "t#__kernel_ulong_t",
    "typedef_type __kernel_ulong_t { base_type unsigned long byte_size(8) encoding(7) }");

/// `mpi_resize()` -- grow `a`'s limb buffer to at least `nlimbs` limbs,
/// zero-extending. See the module doc comment for how this differs
/// structurally, but not observably, from the C.
///
/// # Safety
/// `a` must be valid, with `(*a).d` either null or a buffer
/// `mpi_alloc_limb_space()`/`mpi_resize()` returned, at least
/// `(*a).alloced` limbs long.
#[no_mangle]
pub unsafe extern "C" fn mpi_resize(a: *mut MpiUtilGcryMpi, nlimbs: c_uint) -> c_int {
    // SAFETY: caller guarantees `a` valid.
    if nlimbs <= unsafe { (*a).alloced } as c_uint {
        return 0; /* no need to do it */
    }

    // SAFETY: a plain byte count.
    let p = unsafe {
        rust_mpi_kcalloc(nlimbs as usize, core::mem::size_of::<c_ulong>())
    } as *mut c_ulong;
    if p.is_null() {
        return -ENOMEM;
    }

    // SAFETY: caller guarantees `a` valid.
    unsafe {
        if !(*a).d.is_null() {
            let old_len = ((*a).alloced as usize).wrapping_mul(core::mem::size_of::<c_ulong>());
            // SAFETY: `(*a).d` is `(*a).alloced` limbs long (caller
            // contract), `p` is freshly allocated for at least that many
            // (since `nlimbs > (*a).alloced` was established above).
            core::ptr::copy_nonoverlapping((*a).d as *const u8, p as *mut u8, old_len);
            rust_mpi_kfree_sensitive((*a).d as *mut c_void);
        }
        (*a).d = p;
        (*a).alloced = nlimbs as c_int;
    }
    0
}

kernel::kabi_export! {
    mpi_free,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter t#MPI a ) -> base_type void",
}

/// `mpi_free()` -- free an MPI and its limb buffer.
///
/// # Safety
/// `a` must be a pointer `mpi_alloc()`/`mpi_copy()` returned, or null.
#[no_mangle]
pub unsafe extern "C" fn mpi_free(a: *mut MpiUtilGcryMpi) {
    if a.is_null() {
        return;
    }

    // SAFETY: caller guarantees `a` valid.
    unsafe {
        if (*a).flags & 4 != 0 {
            rust_mpi_kfree_sensitive((*a).d as *mut c_void);
        } else {
            mpi_free_limb_space((*a).d);
        }

        if (*a).flags & !7u32 != 0 {
            // SAFETY: a fixed, NUL-terminated format string and no
            // varargs -- the same call `_printk()`'s other callers in this
            // tree make.
            _printk(c"\x016invalid flag value in mpi\n".as_ptr());
        }

        rust_mpi_kfree(a as *mut c_void);
    }
}

/// `mpi_copy()` -- deep-copy an MPI. Not exported, but called from other
/// C files in `lib/crypto/mpi/` not yet ported, so it keeps a real,
/// non-`static` symbol.
///
/// # Safety
/// `a` must be a valid, initialized `MpiUtilGcryMpi` whose `d` points at
/// `(*a).nlimbs` readable limbs, or null.
#[no_mangle]
pub unsafe extern "C" fn mpi_copy(a: *const MpiUtilGcryMpi) -> *mut MpiUtilGcryMpi {
    if a.is_null() {
        return core::ptr::null_mut();
    }

    // SAFETY: caller guarantees `a` valid.
    let nlimbs = unsafe { (*a).nlimbs };
    // SAFETY: allocates a fresh `MpiUtilGcryMpi`.
    let b = unsafe { mpi_alloc(nlimbs as c_uint) };
    if b.is_null() {
        return b;
    }

    // SAFETY: `a` and `b` both valid; `b` was just allocated with room for
    // `nlimbs` limbs by `mpi_alloc()` above, and `a`'s `d` has `nlimbs`
    // readable limbs per this function's own contract.
    unsafe {
        (*b).nlimbs = nlimbs;
        (*b).sign = (*a).sign;
        (*b).flags = (*a).flags & !(16 | 32); /* Reset the immutable and constant flags. */
        for i in 0..nlimbs {
            *(*b).d.add(i as usize) = *(*a).d.add(i as usize);
        }
    }
    b
}
