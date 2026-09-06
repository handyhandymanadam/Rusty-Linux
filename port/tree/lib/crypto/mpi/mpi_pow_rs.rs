// SPDX-License-Identifier: GPL-2.0-or-later

//! Modular exponentiation -- the Rust behind `lib/crypto/mpi/mpi-pow.c`.
//!
//! Ported from `lib/crypto/mpi/mpi-pow.c` (6.18.49).
//!
//! Replaces: lib/crypto/mpi/mpi-pow.c (except `cond_resched()`, see below)
//!
//! # `EXPORT_SYMBOL_GPL`, pins captured with `mpi_mul`/`mpi_mulm`
//!
//! `logs/pins/mpi-mul-pow.pins` (`.err` empty), captured before this file
//! replaced the C -- see `mpi_mul_rs.rs`'s module doc comment.
//!
//! # `cond_resched()` stays a tiny retained C thunk
//!
//! `cond_resched()` is a scheduling primitive that, under
//! `CONFIG_PREEMPT_DYNAMIC`, is a static call patched at boot -- not
//! something Rust can reach directly. `lib/sort.c`/`lib/sort_rs.rs`
//! already established this exact shape (`rust_sort_cond_resched()`);
//! this file's own retained `mpi-pow.c` does the same
//! (`rust_mpi_pow_cond_resched()`), and carries nothing else -- `mpi_mul`/
//! `mpi_mulm` needed no such thunk, so this is not folded into a shared
//! file with them.
//!
//! # `struct karatsuba_ctx` and `mpihelp_sub`/`mpihelp_sub_1`, duplicated again
//!
//! Same reasoning as `mpih_mul_rs.rs` (layout-exact mirror, uniquely
//! named `MpiPowKaratsubaCtx`) and `mpi_sub_ui_rs.rs` (`mpihelp_sub`/
//! `mpihelp_sub_1` are `static inline` in `mpi-inline.h`, so every file
//! that calls them gets its own private copy).
//!
//! # `BUG_ON(bp_marker)`/`BUG_ON(mp_marker)` become `panic!`
//!
//! Both are internal consistency assertions on states the surrounding
//! control flow already makes impossible (the C's own comment: these
//! branches only run when `bp`/`mp` was not already given temporary
//! space this call). `panic!` is the established reproduction for a C
//! "should not happen" -- see `mpihelp_divrem`'s `dsize == 0` case
//! (`mpih_div_rs.rs`).
//!
//! # The `goto enomem`/`goto leave` cleanup funnel becomes a labeled loop
//!
//! Every marker (`mp_marker`, `bp_marker`, `ep_marker`, `xp_marker`,
//! `tspace`) and `karactx` are declared once, at the top, exactly as the
//! C does (not nested in blocks), so the single cleanup section after the
//! loop can see all of them regardless of which `break` fired. Every C
//! `goto enomem` is `break 'body -ENOMEM`; every path that falls through
//! to `leave:` (including the early "exponent is zero" case, which
//! `goto leave`s directly) is `break 'body 0` after doing whatever that
//! specific path's own `res->nlimbs`/`res->sign` assignment was. The one
//! path that returns *before* any marker exists (`!msize`) is a plain
//! early `return`, matching the C exactly (nothing to clean up).
//!
//! # `MPN_COPY`/`MPN_NORMALIZE` are reproduced as plain code, not macros
//!
//! Same reasoning as every other file in this pass.

use core::ffi::{c_int, c_uint, c_ulong};

const ENOMEM: c_int = 12;
const EINVAL: c_int = 22;
const KARATSUBA_THRESHOLD: c_int = 16;
const BITS_PER_MPI_LIMB: c_int = c_ulong::BITS as c_int;

/// Mirrors `struct gcry_mpi` (`include/linux/mpi.h`). Named distinctly
/// per file -- see `mpi_add_rs.rs`'s module doc comment for why.
#[repr(C)]
pub struct MpiPowGcryMpi {
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

/// Mirrors `struct karatsuba_ctx` (`lib/crypto/mpi/mpi-internal.h`). See
/// `mpih_mul_rs.rs`'s module doc comment for why this must be
/// layout-exact, and why it is named distinctly from that file's own copy.
#[repr(C)]
pub struct MpiPowKaratsubaCtx {
    /// The next cached scratch context in the chain, or null.
    pub next: *mut MpiPowKaratsubaCtx,
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
    fn mpi_resize(a: *mut MpiPowGcryMpi, nlimbs: c_uint) -> c_int;
    fn mpi_alloc_limb_space(nlimbs: c_uint) -> *mut c_ulong;
    fn mpi_free_limb_space(a: *mut c_ulong);
    fn mpi_assign_limb_space(a: *mut MpiPowGcryMpi, ap: *mut c_ulong, nlimbs: c_uint);
    fn mpihelp_lshift(wp: *mut c_ulong, up: *const c_ulong, usize_: c_int, cnt: c_uint) -> c_ulong;
    fn mpihelp_rshift(wp: *mut c_ulong, up: *const c_ulong, usize_: c_int, cnt: c_uint) -> c_ulong;
    fn mpihelp_sub_n(res_ptr: *mut c_ulong, s1_ptr: *const c_ulong, s2_ptr: *const c_ulong, size: c_int) -> c_ulong;
    fn mpihelp_divrem(qp: *mut c_ulong, qextra_limbs: c_int, np: *mut c_ulong, nsize: c_int, dp: *const c_ulong, dsize: c_int) -> c_ulong;
    fn mpihelp_mul(prodp: *mut c_ulong, up: *const c_ulong, usize_: c_int, vp: *const c_ulong, vsize: c_int, result: *mut c_ulong) -> c_int;
    fn mpihelp_mul_karatsuba_case(prodp: *mut c_ulong, up: *const c_ulong, usize_: c_int, vp: *const c_ulong, vsize: c_int, ctx: *mut MpiPowKaratsubaCtx) -> c_int;
    fn mpihelp_release_karatsuba_ctx(ctx: *mut MpiPowKaratsubaCtx);
    fn mpih_sqr_n_basecase(prodp: *mut c_ulong, up: *const c_ulong, size: c_int);
    fn mpih_sqr_n(prodp: *mut c_ulong, up: *const c_ulong, size: c_int, tspace: *mut c_ulong);
    /// `lib/crypto/mpi/mpi-pow.c` (the tiny retained C thunk left behind).
    fn rust_mpi_pow_cond_resched();
}

fn count_leading_zeros(x: c_ulong) -> u32 {
    x.leading_zeros()
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

/// `mpihelp_sub_1()` (`mpi-inline.h`). See the module doc comment.
///
/// # Safety
/// `res_ptr` must be writable and `s1_ptr` readable for `s1_size` limbs
/// (`s1_size >= 1`).
unsafe fn mpihelp_sub_1(
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
    let s2_limb_out = x0.wrapping_sub(s2_limb);
    unsafe { *res_ptr = s2_limb_out };
    res_ptr = unsafe { res_ptr.add(1) };

    if s2_limb_out > x0 {
        loop {
            s1_size -= 1;
            if s1_size == 0 {
                return 1;
            }
            // SAFETY: `s1_size` limbs remain, by the loop's own invariant.
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
        // SAFETY: `s1_size - 1` limbs remain readable/writable.
        for i in 0..(s1_size - 1) as usize {
            unsafe { *res_ptr.add(i) = *s1_ptr.add(i) };
        }
    }
    0
}

/// `mpihelp_sub()` (`mpi-inline.h`).
///
/// # Safety
/// `res_ptr` writable for `max(s1_size, s2_size)` limbs; `s1_ptr` readable
/// for `s1_size`, `s2_ptr` readable for `s2_size`; `s1_size >= s2_size`.
unsafe fn mpihelp_sub(
    res_ptr: *mut c_ulong,
    s1_ptr: *const c_ulong,
    s1_size: c_int,
    s2_ptr: *const c_ulong,
    s2_size: c_int,
) -> c_ulong {
    let mut cy: c_ulong = 0;
    if s2_size != 0 {
        // SAFETY: caller guarantees `s2_size` limbs on all three.
        cy = unsafe { mpihelp_sub_n(res_ptr, s1_ptr, s2_ptr, s2_size) };
    }
    if s1_size - s2_size != 0 {
        // SAFETY: `s1_size - s2_size` limbs remain at the offset positions.
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

kernel::kabi_rule!("type_string", "t#MPI",
    "typedef_type MPI { pointer_type { s#gcry_mpi } }");
kernel::kabi_rule!("type_string", "s#gcry_mpi",
    "structure_type gcry_mpi { member base_type int byte_size(4) encoding(5) alloced data_member_location(0) , member base_type int byte_size(4) encoding(5) nlimbs data_member_location(4) , member base_type int byte_size(4) encoding(5) nbits data_member_location(8) , member base_type int byte_size(4) encoding(5) sign data_member_location(12) , member base_type unsigned int byte_size(4) encoding(7) flags data_member_location(16) , member pointer_type { t#mpi_limb_t } d data_member_location(24) } byte_size(32)");
kernel::kabi_rule!("type_string", "t#mpi_limb_t",
    "typedef_type mpi_limb_t { base_type unsigned long byte_size(8) encoding(7) }");

kernel::kabi_export! {
    mpi_powm,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter t#MPI res , formal_parameter t#MPI base , formal_parameter t#MPI exp , formal_parameter t#MPI mod ) -> base_type int byte_size(4) encoding(5)",
}

/// `mpi_powm()` -- `res = base^exp mod mod`.
///
/// # Safety
/// `res`, `base`, `exp`, `mod_` must be valid, initialized
/// `MpiPowGcryMpi`s (aliasing among them is handled the same way the C
/// handles it).
#[no_mangle]
pub unsafe extern "C" fn mpi_powm(
    res: *mut MpiPowGcryMpi,
    base: *mut MpiPowGcryMpi,
    exp: *mut MpiPowGcryMpi,
    mod_: *mut MpiPowGcryMpi,
) -> c_int {
    let mut mp_marker: *mut c_ulong = core::ptr::null_mut();
    let mut bp_marker: *mut c_ulong = core::ptr::null_mut();
    let mut ep_marker: *mut c_ulong = core::ptr::null_mut();
    let mut karactx = MpiPowKaratsubaCtx {
        next: core::ptr::null_mut(),
        tspace: core::ptr::null_mut(),
        tspace_size: 0,
        tp: core::ptr::null_mut(),
        tp_size: 0,
    };
    let mut xp_marker: *mut c_ulong = core::ptr::null_mut();
    let mut tspace: *mut c_ulong = core::ptr::null_mut();
    let mut tsize: c_int = 0;

    // SAFETY: caller guarantees `exp`, `mod_` valid.
    let esize = unsafe { (*exp).nlimbs };
    let msize = unsafe { (*mod_).nlimbs };
    let size = 2 * msize;
    let msign = unsafe { (*mod_).sign };

    // SAFETY: caller guarantees `res`, `exp` valid.
    let mut rp = unsafe { (*res).d };
    let mut ep = unsafe { (*exp).d };

    if msize == 0 {
        return -EINVAL;
    }

    let mut assign_rp = false;
    let mut mp: *mut c_ulong;
    let mut bp: *mut c_ulong;

    let rc: c_int = 'body: loop {
        if esize == 0 {
            // Exponent is zero, result is 1 mod MOD.
            let nlimbs;
            // SAFETY: `mod_` valid.
            unsafe {
                nlimbs = if msize == 1 && *(*mod_).d == 1 { 0 } else { 1 };
                (*res).nlimbs = nlimbs;
                if nlimbs != 0 {
                    if mpi_resize(res, 1) < 0 {
                        break 'body -ENOMEM;
                    }
                    rp = (*res).d;
                    *rp = 1;
                }
                (*res).sign = 0;
            }
            break 'body 0;
        }

        // Normalize MOD (make its top bit set), as mpihelp_divrem requires.
        // SAFETY: `msize >= 1` here.
        mp = unsafe { mpi_alloc_limb_space(msize as c_uint) };
        mp_marker = mp;
        if mp.is_null() {
            break 'body -ENOMEM;
        }
        // SAFETY: `mod_` valid, `msize >= 1`.
        let mod_top = unsafe { *(*mod_).d.add((msize - 1) as usize) };
        let mod_shift_cnt = count_leading_zeros(mod_top);
        if mod_shift_cnt != 0 {
            // SAFETY: `mp`/`mod_->d` valid for `msize` limbs.
            unsafe { mpihelp_lshift(mp, (*mod_).d, msize, mod_shift_cnt) };
        } else {
            // SAFETY: as above.
            unsafe { mpn_copy(mp, (*mod_).d, msize) };
        }

        // SAFETY: `base` valid.
        let mut bsize = unsafe { (*base).nlimbs };
        let bsign = unsafe { (*base).sign };
        if bsize > msize {
            // The base is larger than the modulus. Reduce it.
            bp = unsafe { mpi_alloc_limb_space((bsize + 1) as c_uint) };
            bp_marker = bp;
            if bp.is_null() {
                break 'body -ENOMEM;
            }
            unsafe { mpn_copy(bp, (*base).d, bsize) };
            unsafe { mpihelp_divrem(bp.add(msize as usize), 0, bp, bsize, mp, msize) };
            bsize = msize;
            bsize = unsafe { mpn_normalize(bp, bsize) };
        } else {
            bp = unsafe { (*base).d };
        }

        if bsize == 0 {
            unsafe {
                (*res).nlimbs = 0;
                (*res).sign = 0;
            }
            break 'body 0;
        }

        // SAFETY: `res` valid.
        if unsafe { (*res).alloced } < size {
            // Have to allocate more space for RES.
            if rp == ep || rp == mp || rp == bp {
                rp = unsafe { mpi_alloc_limb_space(size as c_uint) };
                if rp.is_null() {
                    break 'body -ENOMEM;
                }
                assign_rp = true;
            } else {
                if unsafe { mpi_resize(res, size as c_uint) } < 0 {
                    break 'body -ENOMEM;
                }
                rp = unsafe { (*res).d };
            }
        } else {
            // Make BASE, EXP and MOD not overlap with RES.
            if rp == bp {
                if !bp_marker.is_null() {
                    panic!("mpi_powm: BUG_ON(bp_marker) -- rp==bp with bp already given temp space");
                }
                bp = unsafe { mpi_alloc_limb_space(bsize as c_uint) };
                bp_marker = bp;
                if bp.is_null() {
                    break 'body -ENOMEM;
                }
                unsafe { mpn_copy(bp, rp, bsize) };
            }
            if rp == ep {
                ep = unsafe { mpi_alloc_limb_space(esize as c_uint) };
                ep_marker = ep;
                if ep.is_null() {
                    break 'body -ENOMEM;
                }
                unsafe { mpn_copy(ep, rp, esize) };
            }
            if rp == mp {
                if !mp_marker.is_null() {
                    panic!("mpi_powm: BUG_ON(mp_marker) -- rp==mp with mp already given temp space");
                }
                mp = unsafe { mpi_alloc_limb_space(msize as c_uint) };
                mp_marker = mp;
                if mp.is_null() {
                    break 'body -ENOMEM;
                }
                unsafe { mpn_copy(mp, rp, msize) };
            }
        }

        unsafe { mpn_copy(rp, bp, bsize) };
        let mut rsize = bsize;
        let mut rsign = bsign;

        let negative_result;
        {
            let mut xp = unsafe { mpi_alloc_limb_space((2 * (msize + 1)) as c_uint) };
            xp_marker = xp;
            if xp.is_null() {
                break 'body -ENOMEM;
            }

            // SAFETY: `ep` valid, `esize >= 1`.
            negative_result = (unsafe { *ep } & 1 != 0) && unsafe { (*base).sign } != 0;

            let mut i = esize - 1;
            // SAFETY: `ep` readable for `esize` limbs, `i` in range.
            let mut e = unsafe { *ep.add(i as usize) };
            let c = count_leading_zeros(e) as c_int;
            e = (e << c) << 1; // shift the exp bits left, lose the msb
            let mut c = BITS_PER_MPI_LIMB - 1 - c;

            // Main loop. XP and RP alternate holding the result.
            'outer: loop {
                while c != 0 {
                    if rsize < KARATSUBA_THRESHOLD {
                        unsafe { mpih_sqr_n_basecase(xp, rp, rsize) };
                    } else {
                        if tspace.is_null() {
                            tsize = 2 * rsize;
                            tspace = unsafe { mpi_alloc_limb_space(tsize as c_uint) };
                            if tspace.is_null() {
                                break 'body -ENOMEM;
                            }
                        } else if tsize < 2 * rsize {
                            unsafe { mpi_free_limb_space(tspace) };
                            tsize = 2 * rsize;
                            tspace = unsafe { mpi_alloc_limb_space(tsize as c_uint) };
                            if tspace.is_null() {
                                break 'body -ENOMEM;
                            }
                        }
                        unsafe { mpih_sqr_n(xp, rp, rsize, tspace) };
                    }

                    let mut xsize = 2 * rsize;
                    if xsize > msize {
                        unsafe { mpihelp_divrem(xp.add(msize as usize), 0, xp, xsize, mp, msize) };
                        xsize = msize;
                    }

                    core::mem::swap(&mut rp, &mut xp);
                    rsize = xsize;

                    if (e as i64) < 0 {
                        if bsize < KARATSUBA_THRESHOLD {
                            let mut tmp: c_ulong = 0;
                            if unsafe { mpihelp_mul(xp, rp, rsize, bp, bsize, &mut tmp) } < 0 {
                                break 'body -ENOMEM;
                            }
                        } else {
                            if unsafe { mpihelp_mul_karatsuba_case(xp, rp, rsize, bp, bsize, &mut karactx) } < 0 {
                                break 'body -ENOMEM;
                            }
                        }

                        xsize = rsize + bsize;
                        if xsize > msize {
                            unsafe { mpihelp_divrem(xp.add(msize as usize), 0, xp, xsize, mp, msize) };
                            xsize = msize;
                        }

                        core::mem::swap(&mut rp, &mut xp);
                        rsize = xsize;
                    }
                    e <<= 1;
                    c -= 1;
                    // SAFETY: no memory access; a scheduling yield point.
                    unsafe { rust_mpi_pow_cond_resched() };
                }

                i -= 1;
                if i < 0 {
                    break 'outer;
                }
                // SAFETY: `ep` readable for `esize` limbs, `i` in range.
                e = unsafe { *ep.add(i as usize) };
                c = BITS_PER_MPI_LIMB;
            }

            // MOD was shifted mod_shift_cnt steps left; reduce the result
            // by the original MOD and make sure it ends up in res->d.
            if mod_shift_cnt != 0 {
                // SAFETY: `res->d` writable for `rsize + 1` limbs (it has
                // `size >= 2*msize` limbs and rsize <= msize here).
                let carry_limb = unsafe { mpihelp_lshift((*res).d, rp, rsize, mod_shift_cnt) };
                rp = unsafe { (*res).d };
                if carry_limb != 0 {
                    unsafe { *rp.add(rsize as usize) = carry_limb };
                    rsize += 1;
                }
            } else {
                unsafe { mpn_copy((*res).d, rp, rsize) };
                rp = unsafe { (*res).d };
            }

            if rsize >= msize {
                unsafe { mpihelp_divrem(rp.add(msize as usize), 0, rp, rsize, mp, msize) };
                rsize = msize;
            }

            if mod_shift_cnt != 0 {
                unsafe { mpihelp_rshift(rp, rp, rsize, mod_shift_cnt) };
            }
            rsize = unsafe { mpn_normalize(rp, rsize) };
        }

        if negative_result && rsize != 0 {
            if mod_shift_cnt != 0 {
                unsafe { mpihelp_rshift(mp, mp, msize, mod_shift_cnt) };
            }
            unsafe { mpihelp_sub(rp, mp, msize, rp, rsize) };
            rsize = msize;
            rsign = msign;
            rsize = unsafe { mpn_normalize(rp, rsize) };
        }
        unsafe {
            (*res).nlimbs = rsize;
            (*res).sign = rsign;
        }

        break 'body 0;
    };

    // Unconditional cleanup, matching the C's "enomem:" label.
    unsafe { mpihelp_release_karatsuba_ctx(&mut karactx) };
    if assign_rp {
        unsafe { mpi_assign_limb_space(res, rp, size as c_uint) };
    }
    if !mp_marker.is_null() {
        unsafe { mpi_free_limb_space(mp_marker) };
    }
    if !bp_marker.is_null() {
        unsafe { mpi_free_limb_space(bp_marker) };
    }
    if !ep_marker.is_null() {
        unsafe { mpi_free_limb_space(ep_marker) };
    }
    if !xp_marker.is_null() {
        unsafe { mpi_free_limb_space(xp_marker) };
    }
    if !tspace.is_null() {
        unsafe { mpi_free_limb_space(tspace) };
    }
    rc
}
