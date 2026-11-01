// SPDX-License-Identifier: GPL-2.0-or-later

//! Multiprecision multiplication (Karatsuba) -- the Rust behind
//! `lib/crypto/mpi/mpih-mul.c`.
//!
//! Ported from `lib/crypto/mpi/mpih-mul.c` (6.18.49).
//!
//! Replaces: lib/crypto/mpi/mpih-mul.c
//!
//! # No exported symbols here
//!
//! None of `mpihelp_mul`/`mpihelp_mul_karatsuba_case`/
//! `mpihelp_release_karatsuba_ctx`/`mpih_sqr_n`/`mpih_sqr_n_basecase` is
//! `EXPORT_SYMBOL`, but all five are real (non-`static`) symbols the still-C
//! `mpi-mul.c` (`mpihelp_mul`) and `mpi-pow.c` (all five) call directly.
//! `mul_n_basecase`/`mul_n` stay `static` (private to this file), matching
//! the C.
//!
//! # `KARATSUBA_THRESHOLD` is an unconditional constant, not an arch axis
//!
//! `mpi-internal.h` defines it to 16 unless already defined, and nothing in
//! this tree (or upstream) defines it first -- confirmed by grep, not
//! assumed. The `#if KARATSUBA_THRESHOLD < 2` guard right below it in the
//! header is therefore always false and stays dead on every config this
//! project builds, the same shape as `mpih-div.c`'s pre-inverted-divisor
//! fast path.
//!
//! # `mpihelp_add_1` is `static inline`, duplicated again
//!
//! Same reasoning as `mpi_add_rs.rs`/`mpi_sub_ui_rs.rs`: `mpi-inline.h`
//! gives every translation unit its own private copy, so this file gets one
//! too rather than an `extern "C"` call into another crate.
//!
//! # `struct karatsuba_ctx` is layout-exact, not opaque
//!
//! `mpi-pow.c` (still C) declares `struct karatsuba_ctx karactx = {};` on
//! its own stack and passes `&karactx` into `mpihelp_mul_karatsuba_case()`
//! across the FFI boundary -- so `MpihMulKaratsubaCtx` must mirror the C's
//! five fields exactly, the same requirement as every `*GcryMpi` mirror
//! elsewhere in this pass. Named distinctly (`MpihMul` prefix) per this
//! session's established fix for `rig/layout-check.sh`'s by-name struct
//! matching.
//!
//! # `ctx->next` reuses the existing `kzalloc`/`kfree` thunk, no new one
//!
//! `kzalloc(sizeof *ctx, GFP_KERNEL)` in the C is exactly
//! `rust_mpi_kcalloc(1, size_of::<MpihMulKaratsubaCtx>())` -- `kcalloc`
//! already zero-initializes, and `mpiutil.c`'s retained thunk takes a
//! generic byte size, not a limb count, so it needed no change to serve a
//! completely different allocation shape (a fixed-size struct rather than a
//! limb buffer). `mpihelp_release_karatsuba_ctx()`'s matching `kfree(ctx)`
//! reuses `rust_mpi_kfree` the same way.
//!
//! # `MPN_MUL_N_RECURSE`/`MPN_SQR_N_RECURSE` become ordinary functions
//!
//! Each C macro dispatches to a basecase or a recursive call depending on
//! `size` vs `KARATSUBA_THRESHOLD`; `mpn_mul_n_recurse()`/
//! `mpn_sqr_n_recurse()` are the direct translation. Rust needs no forward
//! declaration for the mutual recursion this creates (`mul_n` calls
//! `mpn_mul_n_recurse` which can call `mul_n` again), unlike the C which
//! relies on `mpi-internal.h`'s prototypes.
//!
//! # Raw-pointer reads/writes only, never a live slice pair
//!
//! This file's own algorithm routinely calls `mpihelp_add_n`/`mpihelp_sub_n`/
//! `mpihelp_add_1` with the result pointer aliasing a source pointer
//! (`res = res + other`, the ordinary Karatsuba accumulation pattern) --
//! exactly the shape that turned out to be undefined behavior in
//! `mpihelp_lshift`/`mpihelp_rshift` before this session's fix, and in
//! `mpihelp_add_n`/`mpihelp_sub_n` themselves (already latent, and already
//! live via `mpih_div_rs.rs`'s in-place calls, per the same review). Every
//! function below reads through a raw pointer once and writes through
//! another raw pointer once, never constructing a `&mut [T]`/`&[T]` pair
//! over memory the caller may have aliased.
//!
//! # `mpihelp_mul_karatsuba_case`'s local reassignment of `prodp`/`up`/`usize_`
//!
//! The C mutates its own by-value copies of these three parameters as it
//! walks forward through the operands (`prodp += vsize; up += vsize; usize
//! -= vsize;`) -- ordinary C pass-by-value semantics, not a callback into
//! the caller's variables. Rust shadows each with `let mut` for the same
//! effect. `usize` collides with the primitive type name, so every such
//! parameter is `usize_` here, matching `mpih_div_rs.rs`'s convention for
//! its own shift-count parameter of the same name.

use core::ffi::{c_int, c_uint, c_ulong, c_void};

const ENOMEM: c_int = 12;
const KARATSUBA_THRESHOLD: c_int = 16;

/// Mirrors `struct karatsuba_ctx` (`lib/crypto/mpi/mpi-internal.h`). See
/// the module doc comment for why this must be layout-exact rather than
/// opaque, and why it is named distinctly from every other file's structs.
#[repr(C)]
pub struct MpihMulKaratsubaCtx {
    /// The next cached scratch context in the chain, or null. Heap-
    /// allocated lazily by `mpihelp_mul_karatsuba_case()` and freed by
    /// `mpihelp_release_karatsuba_ctx()`.
    pub next: *mut MpihMulKaratsubaCtx,
    /// Scratch limb buffer, or null if never yet allocated.
    pub tspace: *mut c_ulong,
    /// Limb count `tspace` was sized for (valid only if `tspace` is
    /// non-null).
    pub tspace_size: c_int,
    /// A second scratch limb buffer, or null if never yet allocated.
    pub tp: *mut c_ulong,
    /// Limb count `tp` was sized for (valid only if `tp` is non-null).
    pub tp_size: c_int,
}

unsafe extern "C" {
    fn mpihelp_mul_1(res_ptr: *mut c_ulong, s1_ptr: *const c_ulong, s1_size: c_int, s2_limb: c_ulong) -> c_ulong;
    fn mpihelp_addmul_1(res_ptr: *mut c_ulong, s1_ptr: *const c_ulong, s1_size: c_int, s2_limb: c_ulong) -> c_ulong;
    fn mpihelp_add_n(res_ptr: *mut c_ulong, s1_ptr: *const c_ulong, s2_ptr: *const c_ulong, size: c_int) -> c_ulong;
    fn mpihelp_sub_n(res_ptr: *mut c_ulong, s1_ptr: *const c_ulong, s2_ptr: *const c_ulong, size: c_int) -> c_ulong;
    fn mpihelp_cmp(op1_ptr: *const c_ulong, op2_ptr: *const c_ulong, size: c_int) -> c_int;
    fn mpi_alloc_limb_space(nlimbs: c_uint) -> *mut c_ulong;
    fn mpi_free_limb_space(a: *mut c_ulong);
    fn rust_mpi_kcalloc(n: usize, size: usize) -> *mut c_void;
    fn rust_mpi_kfree(p: *mut c_void);
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
        // SAFETY: `s1_size - 1` limbs remain readable/writable at these
        // positions -- the same invariant the C's own copy relies on.
        for i in 0..(s1_size.wrapping_sub(1)) as usize {
            unsafe { *res_ptr.add(i) = *s1_ptr.add(i) };
        }
    }
    0
}

/// `MPN_COPY(d, s, n)` (`mpi-internal.h`) -- a forward copy loop, not
/// `copy_nonoverlapping`, so a zero-limb call never needs a non-null
/// pointer (the same class of issue this session already fixed once in
/// `mpi_div_rs.rs`).
///
/// # Safety
/// `d` writable and `s` readable for `n` limbs.
unsafe fn mpn_copy(d: *mut c_ulong, s: *const c_ulong, n: c_int) {
    let mut i = 0;
    while i < n {
        // SAFETY: caller guarantees `n` limbs on both sides.
        unsafe { *d.add(i as usize) = *s.add(i as usize) };
        i = i.wrapping_add(1);
    }
}

/// `MPN_ZERO(d, n)` (`mpi-internal.h`).
///
/// # Safety
/// `d` writable for `n` limbs.
unsafe fn mpn_zero(d: *mut c_ulong, n: c_int) {
    let mut i = 0;
    while i < n {
        // SAFETY: caller guarantees `n` limbs writable.
        unsafe { *d.add(i as usize) = 0 };
        i = i.wrapping_add(1);
    }
}

/// `mul_n_basecase()` -- schoolbook multiply, the base case both Karatsuba
/// recursions (`mul_n` and `mpihelp_mul_karatsuba_case`) bottom out to.
///
/// # Safety
/// `prodp` writable for `2 * size` limbs; `up`/`vp` readable for `size`
/// limbs; `prodp` must not overlap `up` or `vp` (the file's own documented
/// precondition -- see the C's header comment on `mpihelp_mul`).
unsafe fn mul_n_basecase(prodp: *mut c_ulong, up: *const c_ulong, vp: *const c_ulong, size: c_int) -> c_ulong {
    // SAFETY: `vp` readable for `size >= 1` limbs.
    let v_limb0 = unsafe { *vp };
    let mut cy: c_ulong;
    if v_limb0 <= 1 {
        if v_limb0 == 1 {
            unsafe { mpn_copy(prodp, up, size) };
        } else {
            unsafe { mpn_zero(prodp, size) };
        }
        cy = 0;
    } else {
        cy = unsafe { mpihelp_mul_1(prodp, up, size, v_limb0) };
    }
    // SAFETY: `prodp[size]` is within the caller-guaranteed `2*size` limbs.
    unsafe { *prodp.add(size as usize) = cy };
    let mut prodp = unsafe { prodp.add(1) };

    let mut i = 1;
    while i < size {
        // SAFETY: `vp` readable for `size` limbs.
        let v_limb = unsafe { *vp.add(i as usize) };
        if v_limb <= 1 {
            cy = 0;
            if v_limb == 1 {
                cy = unsafe { mpihelp_add_n(prodp, prodp, up, size) };
            }
        } else {
            cy = unsafe { mpihelp_addmul_1(prodp, up, size, v_limb) };
        }
        unsafe { *prodp.add(size as usize) = cy };
        prodp = unsafe { prodp.add(1) };
        i = i.wrapping_add(1);
    }
    cy
}

/// `MPN_MUL_N_RECURSE(prodp, up, vp, size, tspace)` (`mpi-internal.h`).
///
/// # Safety
/// As [`mul_n_basecase`]/[`mul_n`], whichever this dispatches to.
unsafe fn mpn_mul_n_recurse(prodp: *mut c_ulong, up: *const c_ulong, vp: *const c_ulong, size: c_int, tspace: *mut c_ulong) {
    if size < KARATSUBA_THRESHOLD {
        unsafe { mul_n_basecase(prodp, up, vp, size) };
    } else {
        unsafe { mul_n(prodp, up, vp, size, tspace) };
    }
}

/// `mul_n()` -- Karatsuba multiply for two equal-`size` operands.
///
/// # Safety
/// `prodp` writable for `2 * size` limbs, `up`/`vp` readable for `size`
/// limbs, none overlapping each other; `tspace` writable for at least
/// `2 * size` limbs (the caller's scratch allocation).
unsafe fn mul_n(prodp: *mut c_ulong, up: *const c_ulong, vp: *const c_ulong, size: c_int, tspace: *mut c_ulong) {
    if size & 1 != 0 {
        // The size is odd; multiply the low (size - 1) limbs recursively
        // and handle the top limb of each operand separately.
        let esize = size.wrapping_sub(1);
        unsafe { mpn_mul_n_recurse(prodp, up, vp, esize, tspace) };
        // SAFETY: `esize < size`, so `vp[esize]`/`up[esize]` are in range.
        let vp_esize = unsafe { *vp.add(esize as usize) };
        let cy_limb = unsafe { mpihelp_addmul_1(prodp.add(esize as usize), up, esize, vp_esize) };
        unsafe { *prodp.add((esize.wrapping_add(esize)) as usize) = cy_limb };
        let up_esize = unsafe { *up.add(esize as usize) };
        let cy_limb = unsafe { mpihelp_addmul_1(prodp.add(esize as usize), vp, size, up_esize) };
        unsafe { *prodp.add((esize.wrapping_add(size)) as usize) = cy_limb };
        return;
    }

    // Karatsuba's divide-and-conquer identity:
    //   UV = (B^2n + B^n) U1 V1  +  B^n (U1-U0)(V0-V1)  +  (B^n + 1) U0 V0
    let hsize = size >> 1;
    let mut negflg;
    let mut cy: c_ulong;

    // Product H = U1 * V1, into the upper half of prodp.
    unsafe { mpn_mul_n_recurse(prodp.add(size as usize), up.add(hsize as usize), vp.add(hsize as usize), hsize, tspace) };

    // Product M's two factors: |U1-U0| and |V0-V1|, into the low half of
    // prodp (safe: product H above never touches it).
    if unsafe { mpihelp_cmp(up.add(hsize as usize), up, hsize) } >= 0 {
        unsafe { mpihelp_sub_n(prodp, up.add(hsize as usize), up, hsize) };
        negflg = false;
    } else {
        unsafe { mpihelp_sub_n(prodp, up, up.add(hsize as usize), hsize) };
        negflg = true;
    }
    if unsafe { mpihelp_cmp(vp.add(hsize as usize), vp, hsize) } >= 0 {
        unsafe { mpihelp_sub_n(prodp.add(hsize as usize), vp.add(hsize as usize), vp, hsize) };
        negflg = !negflg;
    } else {
        unsafe { mpihelp_sub_n(prodp.add(hsize as usize), vp, vp.add(hsize as usize), hsize) };
        // No change of negflg.
    }
    // Product M itself, reading the two factors just written into prodp's
    // low half, writing into tspace's low half.
    unsafe { mpn_mul_n_recurse(tspace, prodp, prodp.add(hsize as usize), hsize, tspace.add(size as usize)) };

    // Add/copy product H.
    unsafe { mpn_copy(prodp.add(hsize as usize), prodp.add(size as usize), hsize) };
    cy = unsafe { mpihelp_add_n(prodp.add(size as usize), prodp.add(size as usize), prodp.add((size.wrapping_add(hsize)) as usize), hsize) };

    // Add product M (subtract if it was negative).
    if negflg {
        cy = cy.wrapping_sub(unsafe { mpihelp_sub_n(prodp.add(hsize as usize), prodp.add(hsize as usize), tspace, size) });
    } else {
        cy = cy.wrapping_add(unsafe { mpihelp_add_n(prodp.add(hsize as usize), prodp.add(hsize as usize), tspace, size) });
    }

    // Product L = U0 * V0.
    unsafe { mpn_mul_n_recurse(tspace, up, vp, hsize, tspace.add(size as usize)) };

    // Add/copy product L (twice, per the identity's "+1" term).
    cy = cy.wrapping_add(unsafe { mpihelp_add_n(prodp.add(hsize as usize), prodp.add(hsize as usize), tspace, size) });
    if cy != 0 {
        unsafe { mpihelp_add_1(prodp.add((hsize.wrapping_add(size)) as usize), prodp.add((hsize.wrapping_add(size)) as usize), hsize, cy) };
    }

    unsafe { mpn_copy(prodp, tspace, hsize) };
    cy = unsafe { mpihelp_add_n(prodp.add(hsize as usize), prodp.add(hsize as usize), tspace.add(hsize as usize), hsize) };
    if cy != 0 {
        unsafe { mpihelp_add_1(prodp.add(size as usize), prodp.add(size as usize), size, 1) };
    }
}

/// `mpih_sqr_n_basecase()` -- schoolbook square, the base case for
/// [`mpih_sqr_n`]. Real (non-`static`) symbol: `mpi-pow.c` calls it
/// directly for modular exponentiation's repeated squaring.
///
/// # Safety
/// `prodp` writable for `2 * size` limbs; `up` readable for `size` limbs,
/// not overlapping `prodp`.
#[no_mangle]
pub unsafe extern "C" fn mpih_sqr_n_basecase(prodp: *mut c_ulong, up: *const c_ulong, size: c_int) {
    // SAFETY: `up` readable for `size >= 1` limbs.
    let v_limb0 = unsafe { *up };
    let mut cy_limb: c_ulong;
    if v_limb0 <= 1 {
        if v_limb0 == 1 {
            unsafe { mpn_copy(prodp, up, size) };
        } else {
            unsafe { mpn_zero(prodp, size) };
        }
        cy_limb = 0;
    } else {
        cy_limb = unsafe { mpihelp_mul_1(prodp, up, size, v_limb0) };
    }
    unsafe { *prodp.add(size as usize) = cy_limb };
    let mut prodp = unsafe { prodp.add(1) };

    let mut i = 1;
    while i < size {
        // SAFETY: `up` readable for `size` limbs.
        let v_limb = unsafe { *up.add(i as usize) };
        if v_limb <= 1 {
            cy_limb = 0;
            if v_limb == 1 {
                cy_limb = unsafe { mpihelp_add_n(prodp, prodp, up, size) };
            }
        } else {
            cy_limb = unsafe { mpihelp_addmul_1(prodp, up, size, v_limb) };
        }
        unsafe { *prodp.add(size as usize) = cy_limb };
        prodp = unsafe { prodp.add(1) };
        i = i.wrapping_add(1);
    }
}

/// `MPN_SQR_N_RECURSE(prodp, up, size, tspace)` (`mpi-internal.h`).
///
/// # Safety
/// As [`mpih_sqr_n_basecase`]/[`mpih_sqr_n`], whichever this dispatches to.
unsafe fn mpn_sqr_n_recurse(prodp: *mut c_ulong, up: *const c_ulong, size: c_int, tspace: *mut c_ulong) {
    if size < KARATSUBA_THRESHOLD {
        unsafe { mpih_sqr_n_basecase(prodp, up, size) };
    } else {
        unsafe { mpih_sqr_n(prodp, up, size, tspace) };
    }
}

/// `mpih_sqr_n()` -- Karatsuba square. Real (non-`static`) symbol:
/// `mpi-pow.c` calls it directly.
///
/// # Safety
/// As [`mul_n`], with `up` playing the role of both operands (squaring).
#[no_mangle]
pub unsafe extern "C" fn mpih_sqr_n(prodp: *mut c_ulong, up: *const c_ulong, size: c_int, tspace: *mut c_ulong) {
    if size & 1 != 0 {
        let esize = size.wrapping_sub(1);
        let mut cy_limb: c_ulong;

        unsafe { mpn_sqr_n_recurse(prodp, up, esize, tspace) };
        // SAFETY: `esize < size`, so `up[esize]` is in range.
        let up_esize = unsafe { *up.add(esize as usize) };
        cy_limb = unsafe { mpihelp_addmul_1(prodp.add(esize as usize), up, esize, up_esize) };
        unsafe { *prodp.add((esize.wrapping_add(esize)) as usize) = cy_limb };
        cy_limb = unsafe { mpihelp_addmul_1(prodp.add(esize as usize), up, size, up_esize) };
        unsafe { *prodp.add((esize.wrapping_add(size)) as usize) = cy_limb };
        return;
    }

    let hsize = size >> 1;
    let mut cy: c_ulong;

    // Product H = U1^2, into the upper half of prodp.
    unsafe { mpn_sqr_n_recurse(prodp.add(size as usize), up.add(hsize as usize), hsize, tspace) };

    // |U1 - U0|, into the low half of prodp.
    if unsafe { mpihelp_cmp(up.add(hsize as usize), up, hsize) } >= 0 {
        unsafe { mpihelp_sub_n(prodp, up.add(hsize as usize), up, hsize) };
    } else {
        unsafe { mpihelp_sub_n(prodp, up, up.add(hsize as usize), hsize) };
    }

    // Product M = -(U1-U0)^2, always non-positive, hence always
    // subtracted below (no negflg needed -- unlike mul_n, the two factors
    // here are identical up to sign, so the product's sign never varies).
    unsafe { mpn_sqr_n_recurse(tspace, prodp, hsize, tspace.add(size as usize)) };

    unsafe { mpn_copy(prodp.add(hsize as usize), prodp.add(size as usize), hsize) };
    cy = unsafe { mpihelp_add_n(prodp.add(size as usize), prodp.add(size as usize), prodp.add((size.wrapping_add(hsize)) as usize), hsize) };

    cy = cy.wrapping_sub(unsafe { mpihelp_sub_n(prodp.add(hsize as usize), prodp.add(hsize as usize), tspace, size) });

    // Product L = U0^2.
    unsafe { mpn_sqr_n_recurse(tspace, up, hsize, tspace.add(size as usize)) };

    cy = cy.wrapping_add(unsafe { mpihelp_add_n(prodp.add(hsize as usize), prodp.add(hsize as usize), tspace, size) });
    if cy != 0 {
        unsafe { mpihelp_add_1(prodp.add((hsize.wrapping_add(size)) as usize), prodp.add((hsize.wrapping_add(size)) as usize), hsize, cy) };
    }

    unsafe { mpn_copy(prodp, tspace, hsize) };
    cy = unsafe { mpihelp_add_n(prodp.add(hsize as usize), prodp.add(hsize as usize), tspace.add(hsize as usize), hsize) };
    if cy != 0 {
        unsafe { mpihelp_add_1(prodp.add(size as usize), prodp.add(size as usize), size, 1) };
    }
}

/// `mpihelp_mul_karatsuba_case()` -- the unequal-length Karatsuba driver.
/// Real (non-`static`) symbol: `mpi-pow.c` calls it directly (as does
/// [`mpihelp_mul`], recursively, below).
///
/// See the module doc comment on `ctx`'s scratch-buffer caching and the
/// local reassignment of `prodp`/`up`/`usize_`.
///
/// # Safety
/// `prodp` writable for `usize_ + vsize` limbs; `up` readable for `usize_`
/// limbs, `vp` readable for `vsize` limbs, `usize_ >= vsize >= 1`; `ctx`
/// valid and either freshly zeroed or previously produced by this same
/// function.
#[no_mangle]
pub unsafe extern "C" fn mpihelp_mul_karatsuba_case(
    prodp: *mut c_ulong,
    up: *const c_ulong,
    usize_: c_int,
    vp: *const c_ulong,
    vsize: c_int,
    ctx: *mut MpihMulKaratsubaCtx,
) -> c_int {
    let mut prodp = prodp;
    let mut up = up;
    let mut usize_ = usize_;

    // SAFETY: caller guarantees `ctx` valid.
    let need_tspace = unsafe { (*ctx).tspace.is_null() || (*ctx).tspace_size < vsize };
    if need_tspace {
        // SAFETY: as above.
        if !unsafe { (*ctx).tspace }.is_null() {
            unsafe { mpi_free_limb_space((*ctx).tspace) };
        }
        // Assign unconditionally, matching the C's own
        // `ctx->tspace = mpi_alloc_limb_space(...)` -- the freed pointer
        // above must never be left in `ctx->tspace` on failure, or a
        // later `mpihelp_release_karatsuba_ctx()` double-frees it.
        unsafe { (*ctx).tspace = mpi_alloc_limb_space((2_i32.wrapping_mul(vsize)) as c_uint) };
        if unsafe { (*ctx).tspace }.is_null() {
            return -ENOMEM;
        }
        unsafe { (*ctx).tspace_size = vsize };
    }

    // SAFETY: `ctx.tspace` sized for at least `2*vsize` limbs, just ensured.
    unsafe { mpn_mul_n_recurse(prodp, up, vp, vsize, (*ctx).tspace) };

    prodp = unsafe { prodp.add(vsize as usize) };
    up = unsafe { up.add(vsize as usize) };
    usize_ = usize_.wrapping_sub(vsize);

    if usize_ >= vsize {
        let need_tp = unsafe { (*ctx).tp.is_null() || (*ctx).tp_size < vsize };
        if need_tp {
            if !unsafe { (*ctx).tp }.is_null() {
                unsafe { mpi_free_limb_space((*ctx).tp) };
            }
            // Assign unconditionally -- same reasoning as `tspace` above.
            unsafe { (*ctx).tp = mpi_alloc_limb_space((2_i32.wrapping_mul(vsize)) as c_uint) };
            if unsafe { (*ctx).tp }.is_null() {
                if !unsafe { (*ctx).tspace }.is_null() {
                    unsafe { mpi_free_limb_space((*ctx).tspace) };
                }
                unsafe { (*ctx).tspace = core::ptr::null_mut() };
                return -ENOMEM;
            }
            unsafe { (*ctx).tp_size = vsize };
        }

        loop {
            unsafe { mpn_mul_n_recurse((*ctx).tp, up, vp, vsize, (*ctx).tspace) };
            let cy = unsafe { mpihelp_add_n(prodp, prodp, (*ctx).tp, vsize) };
            unsafe { mpihelp_add_1(prodp.add(vsize as usize), (*ctx).tp.add(vsize as usize), vsize, cy) };
            prodp = unsafe { prodp.add(vsize as usize) };
            up = unsafe { up.add(vsize as usize) };
            usize_ = usize_.wrapping_sub(vsize);
            if usize_ < vsize {
                break;
            }
        }
    }

    if usize_ != 0 {
        if usize_ < KARATSUBA_THRESHOLD {
            let mut tmp: c_ulong = 0;
            // SAFETY: `ctx.tspace` sized for at least `2*vsize` limbs,
            // which covers `vsize + usize_` since `usize_ < vsize` here
            // is NOT guaranteed in general, but matches the C's own
            // reuse of this buffer -- see mpihelp_mul's own contract
            // (usize_ >= vsize there is the caller's, not this one's).
            if unsafe { mpihelp_mul((*ctx).tspace, vp, vsize, up, usize_, &mut tmp) } < 0 {
                return -ENOMEM;
            }
        } else {
            // SAFETY: `ctx` valid.
            if unsafe { (*ctx).next }.is_null() {
                let next = unsafe { rust_mpi_kcalloc(1, core::mem::size_of::<MpihMulKaratsubaCtx>()) } as *mut MpihMulKaratsubaCtx;
                if next.is_null() {
                    return -ENOMEM;
                }
                unsafe { (*ctx).next = next };
            }
            // SAFETY: `(*ctx).next` non-null, just ensured.
            if unsafe { mpihelp_mul_karatsuba_case((*ctx).tspace, vp, vsize, up, usize_, (*ctx).next) } < 0 {
                return -ENOMEM;
            }
        }

        let cy = unsafe { mpihelp_add_n(prodp, prodp, (*ctx).tspace, vsize) };
        unsafe { mpihelp_add_1(prodp.add(vsize as usize), (*ctx).tspace.add(vsize as usize), usize_, cy) };
    }

    0
}

/// `mpihelp_release_karatsuba_ctx()` -- frees every scratch buffer this
/// `ctx` (and its cached `next` chain) accumulated, and every heap-
/// allocated `next` node itself. The top-level `ctx` is never `kfree`d
/// here: its caller (`mpi-pow.c`, `mpihelp_mul` below) owns that memory,
/// typically on its own stack. Real (non-`static`) symbol: `mpi-pow.c`
/// calls it directly.
///
/// # Safety
/// `ctx` valid, produced by (possibly repeated calls to)
/// [`mpihelp_mul_karatsuba_case`] or freshly zeroed.
#[no_mangle]
pub unsafe extern "C" fn mpihelp_release_karatsuba_ctx(ctx: *mut MpihMulKaratsubaCtx) {
    // SAFETY: caller guarantees `ctx` valid.
    unsafe {
        if !(*ctx).tp.is_null() {
            mpi_free_limb_space((*ctx).tp);
        }
        if !(*ctx).tspace.is_null() {
            mpi_free_limb_space((*ctx).tspace);
        }
    }
    // SAFETY: as above.
    let mut cur = unsafe { (*ctx).next };
    while !cur.is_null() {
        // SAFETY: `cur` non-null, was itself produced by a prior
        // `kcalloc`-backed allocation in `mpihelp_mul_karatsuba_case`.
        let next = unsafe { (*cur).next };
        unsafe {
            if !(*cur).tp.is_null() {
                mpi_free_limb_space((*cur).tp);
            }
            if !(*cur).tspace.is_null() {
                mpi_free_limb_space((*cur).tspace);
            }
            rust_mpi_kfree(cur as *mut c_void);
        }
        cur = next;
    }
}

/// `mpihelp_mul()` -- multiply `up[..usize_]` by `vp[..vsize]`, store
/// `usize_ + vsize` limbs at `prodp`, return the most significant limb via
/// `result`. Real (non-`static`) symbol: `mpi-mul.c` calls it directly, and
/// [`mpihelp_mul_karatsuba_case`] calls it recursively for its own small
/// tail case.
///
/// # Safety
/// `prodp` writable for `usize_ + vsize` limbs, `up` readable for `usize_`
/// limbs, `vp` readable for `vsize` limbs, `usize_ >= vsize`, `prodp` not
/// overlapping `up` or `vp`, `result` writable for one limb.
#[no_mangle]
pub unsafe extern "C" fn mpihelp_mul(
    prodp: *mut c_ulong,
    up: *const c_ulong,
    usize_: c_int,
    vp: *const c_ulong,
    vsize: c_int,
    result: *mut c_ulong,
) -> c_int {
    // SAFETY: `usize_ + vsize` limbs writable at `prodp` (caller contract).
    let prod_endp = unsafe { prodp.add((usize_.wrapping_add(vsize).wrapping_sub(1)) as usize) };

    if vsize < KARATSUBA_THRESHOLD {
        if vsize == 0 {
            unsafe { *result = 0 };
            return 0;
        }

        // SAFETY: `vp` readable for `vsize >= 1` limbs.
        let v_limb0 = unsafe { *vp };
        let mut cy: c_ulong;
        let mut prodp = prodp;
        if v_limb0 <= 1 {
            if v_limb0 == 1 {
                unsafe { mpn_copy(prodp, up, usize_) };
            } else {
                unsafe { mpn_zero(prodp, usize_) };
            }
            cy = 0;
        } else {
            cy = unsafe { mpihelp_mul_1(prodp, up, usize_, v_limb0) };
        }
        unsafe { *prodp.add(usize_ as usize) = cy };
        prodp = unsafe { prodp.add(1) };

        let mut i = 1;
        while i < vsize {
            // SAFETY: `vp` readable for `vsize` limbs.
            let v_limb = unsafe { *vp.add(i as usize) };
            if v_limb <= 1 {
                cy = 0;
                if v_limb == 1 {
                    cy = unsafe { mpihelp_add_n(prodp, prodp, up, usize_) };
                }
            } else {
                cy = unsafe { mpihelp_addmul_1(prodp, up, usize_, v_limb) };
            }
            unsafe { *prodp.add(usize_ as usize) = cy };
            prodp = unsafe { prodp.add(1) };
            i = i.wrapping_add(1);
        }

        unsafe { *result = cy };
        return 0;
    }

    let mut ctx = MpihMulKaratsubaCtx {
        next: core::ptr::null_mut(),
        tspace: core::ptr::null_mut(),
        tspace_size: 0,
        tp: core::ptr::null_mut(),
        tp_size: 0,
    };
    if unsafe { mpihelp_mul_karatsuba_case(prodp, up, usize_, vp, vsize, &mut ctx) } < 0 {
        return -ENOMEM;
    }
    unsafe { mpihelp_release_karatsuba_ctx(&mut ctx) };
    // SAFETY: `prod_endp` is within the caller-guaranteed output range.
    unsafe { *result = *prod_endp };
    0
}
