// SPDX-License-Identifier: GPL-2.0-only

//! The iterator bookkeeping -- the Rust behind part of `lib/iov_iter.c`.
//!
//! Ported from `lib/iov_iter.c` (6.18.49), Copyright (C) Linus Torvalds / Al Viro and others. In Rust: `iov_iter_advance` (with the iovec,
//! bvec and folio-queue steppers), `iov_iter_revert` (with the folio-queue reverse stepper), `iov_iter_single_seg_count`,
//! `iov_iter_alignment` (iovec and bvec helpers), `iov_iter_gap_alignment`, `iov_iter_npages` (iovec and bvec helpers) and
//! `iov_iter_restore`. In C (`iov_iter_glue.c`, which is upstream's file with those bodies replaced by thunks): everything that copies
//! (the `iterate_and_advance` templates in `include/linux/iov_iter.h` take callbacks and touch user memory), page pinning and extraction,
//! the `iov_iter_*` initialisers, `dup_iter`, `import_iovec` and friends; plus one-line wrappers (`rust_iw_*`) for the folio-queue accessors
//! and the `WARN_ON` / `BUG` sites.
//!
//! # Notes
//! * `struct iov_iter` is accessed by offset (the glue `static_assert`s every offset used): `iter_type` 0, `iov_offset` 8, the segment
//!   pointer (`__iov` / `kvec` / `bvec` / `folioq` / `xarray` / `ubuf`) 16, `count` 24, `nr_segs` / `folioq_slot` / `xarray_start` 32 (one union).
//!   An ITER_UBUF iterator keeps its single iovec inline at offset 16 (`iter_iov()` returns that address).
//! * Arithmetic follows the C types: `size_t` wraps, `unsigned` is `u32`.
//!
//! Replaces: part of lib/iov_iter.c (the exports and everything that touches user memory stay C)

use core::ffi::{c_int, c_uint, c_ulong, c_void};

const ITER_UBUF: u8 = 0;
const ITER_IOVEC: u8 = 1;
const ITER_BVEC: u8 = 2;
const ITER_KVEC: u8 = 3;
const ITER_FOLIOQ: u8 = 4;
const ITER_XARRAY: u8 = 5;
const ITER_DISCARD: u8 = 6;

const PAGE_SIZE: usize = 4096;

/// `struct iovec` / `struct kvec`.
#[repr(C)]
struct Iovec {
    base: usize,
    len: usize,
}

/// `struct bio_vec`.
#[repr(C)]
struct BioVec {
    page: usize,
    len: c_uint,
    offset: c_uint,
}

/// `struct iov_iter`, by offset.
#[repr(C)]
pub struct IovIter {
    iter_type: u8,
    nofault: bool,
    data_source: bool,
    _pad: [u8; 5],
    iov_offset: usize,
    seg: usize,
    count: usize,
    nr_segs: usize, // a union with folioq_slot (low byte) and xarray_start
}

/// `struct iov_iter_state`.
#[repr(C)]
pub struct IovIterState {
    iov_offset: usize,
    count: usize,
    nr_segs: c_ulong,
}

extern "C" {
    static rust_iw_folioq_next_off: usize;
    static rust_iw_folioq_prev_off: usize;
    static rust_iw_max_rw_count: usize;
    fn rust_iw_folioq_nr_slots(folioq: *const c_void) -> c_uint;
    fn rust_iw_folioq_folio_size(folioq: *const c_void, slot: c_uint) -> usize;
    fn rust_iw_warn_revert(cond: bool) -> bool;
    fn rust_iw_bug_revert();
    fn rust_iw_warn_gap(cond: bool) -> bool;
    fn rust_iw_warn_restore(cond: bool) -> bool;
}

#[inline(always)]
fn is_ubuf(i: &IovIter) -> bool {
    i.iter_type == ITER_UBUF
}
#[inline(always)]
fn is_iovec(i: &IovIter) -> bool {
    i.iter_type == ITER_IOVEC
}
#[inline(always)]
fn is_kvec(i: &IovIter) -> bool {
    i.iter_type == ITER_KVEC
}
#[inline(always)]
fn is_bvec(i: &IovIter) -> bool {
    i.iter_type == ITER_BVEC
}
#[inline(always)]
fn is_folioq(i: &IovIter) -> bool {
    i.iter_type == ITER_FOLIOQ
}
#[inline(always)]
fn is_xarray(i: &IovIter) -> bool {
    i.iter_type == ITER_XARRAY
}
#[inline(always)]
fn is_discard(i: &IovIter) -> bool {
    i.iter_type == ITER_DISCARD
}

/// `iter_iov()`: the current vec (an ITER_UBUF iterator holds its iovec inline).
#[inline(always)]
unsafe fn iter_iov(i: *mut IovIter) -> *const Iovec {
    // SAFETY: `i` is a valid iterator; the inline iovec is at offset 16.
    unsafe {
        if (*i).iter_type == ITER_UBUF {
            core::ptr::addr_of!((*i).seg) as *const Iovec
        } else {
            (*i).seg as *const Iovec
        }
    }
}

#[inline(always)]
unsafe fn folioq_next(f: usize) -> usize {
    // SAFETY: `f` is a folio_queue segment; the offset comes from the glue.
    unsafe { *((f + rust_iw_folioq_next_off) as *const usize) }
}
#[inline(always)]
unsafe fn folioq_prev(f: usize) -> usize {
    // SAFETY: as above.
    unsafe { *((f + rust_iw_folioq_prev_off) as *const usize) }
}

/// `iov_iter_bvec_advance()`.
unsafe fn bvec_advance(i: *mut IovIter, mut size: usize) {
    // SAFETY: the caller's contract is iov_iter_advance()'s.
    unsafe {
        if (*i).count == 0 {
            return;
        }
        (*i).count = (*i).count.wrapping_sub(size);
        size = size.wrapping_add((*i).iov_offset);

        let start = (*i).seg as *const BioVec;
        let mut bvec = start;
        let end = start.add((*i).nr_segs);
        while bvec < end {
            if size < (*bvec).len as usize {
                break;
            }
            size = size.wrapping_sub((*bvec).len as usize);
            bvec = bvec.add(1);
        }
        (*i).iov_offset = size;
        (*i).nr_segs = (*i).nr_segs.wrapping_sub(bvec.offset_from(start) as usize);
        (*i).seg = bvec as usize;
    }
}

/// `iov_iter_iovec_advance()` (iovec and kvec have identical layouts).
unsafe fn iovec_advance(i: *mut IovIter, mut size: usize) {
    // SAFETY: as above.
    unsafe {
        if (*i).count == 0 {
            return;
        }
        (*i).count = (*i).count.wrapping_sub(size);
        size = size.wrapping_add((*i).iov_offset);

        let start = iter_iov(i);
        let mut iov = start;
        let end = start.add((*i).nr_segs);
        while iov < end {
            if size < (*iov).len {
                break;
            }
            size = size.wrapping_sub((*iov).len);
            iov = iov.add(1);
        }
        (*i).iov_offset = size;
        (*i).nr_segs = (*i).nr_segs.wrapping_sub(iov.offset_from(start) as usize);
        (*i).seg = iov as usize;
    }
}

/// `iov_iter_folioq_advance()`.
unsafe fn folioq_advance(i: *mut IovIter, mut size: usize) {
    // SAFETY: as above.
    unsafe {
        let mut folioq = (*i).seg;
        let mut slot = ((*i).nr_segs & 0xff) as c_uint;

        if (*i).count == 0 {
            return;
        }
        (*i).count = (*i).count.wrapping_sub(size);

        if slot >= rust_iw_folioq_nr_slots(folioq as *const c_void) {
            folioq = folioq_next(folioq);
            slot = 0;
        }

        size = size.wrapping_add((*i).iov_offset); // From beginning of current segment.
        loop {
            let fsize = rust_iw_folioq_folio_size(folioq as *const c_void, slot);

            if size < fsize {
                break;
            }
            size = size.wrapping_sub(fsize);
            slot = slot.wrapping_add(1);
            if slot >= rust_iw_folioq_nr_slots(folioq as *const c_void) && folioq_next(folioq) != 0 {
                folioq = folioq_next(folioq);
                slot = 0;
            }
            if size == 0 {
                break;
            }
        }

        (*i).iov_offset = size;
        (*i).nr_segs = ((*i).nr_segs & !0xff) | (slot as usize & 0xff); // folioq_slot is the low byte of the union
        (*i).seg = folioq;
    }
}

/// `iov_iter_advance()`.
#[no_mangle]
pub unsafe extern "C" fn rust_iov_iter_advance(i: *mut IovIter, mut size: usize) {
    // SAFETY: `i` is the caller's iterator.
    unsafe {
        if (*i).count < size {
            size = (*i).count;
        }
        if is_ubuf(&*i) || is_xarray(&*i) {
            (*i).iov_offset = (*i).iov_offset.wrapping_add(size);
            (*i).count = (*i).count.wrapping_sub(size);
        } else if is_iovec(&*i) || is_kvec(&*i) {
            // iovec and kvec have identical layouts
            iovec_advance(i, size);
        } else if is_bvec(&*i) {
            bvec_advance(i, size);
        } else if is_folioq(&*i) {
            folioq_advance(i, size);
        } else if is_discard(&*i) {
            (*i).count = (*i).count.wrapping_sub(size);
        }
    }
}

/// `iov_iter_folioq_revert()`.
unsafe fn folioq_revert(i: *mut IovIter, mut unroll: usize) {
    // SAFETY: as above.
    unsafe {
        let mut folioq = (*i).seg;
        let mut slot = ((*i).nr_segs & 0xff) as c_uint;

        loop {
            if slot == 0 {
                folioq = folioq_prev(folioq);
                slot = rust_iw_folioq_nr_slots(folioq as *const c_void);
            }
            slot = slot.wrapping_sub(1);

            let fsize = rust_iw_folioq_folio_size(folioq as *const c_void, slot);
            if unroll <= fsize {
                (*i).iov_offset = fsize.wrapping_sub(unroll);
                break;
            }
            unroll = unroll.wrapping_sub(fsize);
        }

        (*i).nr_segs = ((*i).nr_segs & !0xff) | (slot as usize & 0xff);
        (*i).seg = folioq;
    }
}

/// `iov_iter_revert()`.
#[no_mangle]
pub unsafe extern "C" fn rust_iov_iter_revert(i: *mut IovIter, mut unroll: usize) {
    // SAFETY: `i` is the caller's iterator.
    unsafe {
        if unroll == 0 {
            return;
        }
        if rust_iw_warn_revert(unroll > rust_iw_max_rw_count) {
            return;
        }
        (*i).count = (*i).count.wrapping_add(unroll);
        if is_discard(&*i) {
            return;
        }
        if unroll <= (*i).iov_offset {
            (*i).iov_offset -= unroll;
            return;
        }
        unroll = unroll.wrapping_sub((*i).iov_offset);
        if is_xarray(&*i) || is_ubuf(&*i) {
            // We should never go beyond the start of the specified range since we might then be straying into pages that aren't pinned.
            rust_iw_bug_revert();
        } else if is_bvec(&*i) {
            let mut bvec = (*i).seg as *const BioVec;
            loop {
                bvec = bvec.sub(1);
                let n = (*bvec).len as usize;
                (*i).nr_segs = (*i).nr_segs.wrapping_add(1);
                if unroll <= n {
                    (*i).seg = bvec as usize;
                    (*i).iov_offset = n.wrapping_sub(unroll);
                    return;
                }
                unroll = unroll.wrapping_sub(n);
            }
        } else if is_folioq(&*i) {
            (*i).iov_offset = 0;
            folioq_revert(i, unroll);
        } else {
            // same logics for iovec and kvec
            let mut iov = iter_iov(i);
            loop {
                iov = iov.sub(1);
                let n = (*iov).len;
                (*i).nr_segs = (*i).nr_segs.wrapping_add(1);
                if unroll <= n {
                    (*i).seg = iov as usize;
                    (*i).iov_offset = n.wrapping_sub(unroll);
                    return;
                }
                unroll = unroll.wrapping_sub(n);
            }
        }
    }
}

/// `iov_iter_single_seg_count()`: the count of just the current segment.
#[no_mangle]
pub unsafe extern "C" fn rust_iov_iter_single_seg_count(i: *const IovIter) -> usize {
    // SAFETY: `i` is the caller's iterator.
    unsafe {
        let it = &*i;
        if it.nr_segs > 1 {
            if is_iovec(it) || is_kvec(it) {
                let iov = iter_iov(i as *mut IovIter);
                return core::cmp::min(it.count, (*iov).len.wrapping_sub(it.iov_offset));
            }
            if is_bvec(it) {
                let bvec = it.seg as *const BioVec;
                return core::cmp::min(it.count, ((*bvec).len as usize).wrapping_sub(it.iov_offset));
            }
        }
        if is_folioq(it) {
            return if it.count == 0 {
                0
            } else {
                core::cmp::min(rust_iw_folioq_folio_size(it.seg as *const c_void, (it.nr_segs & 0xff) as c_uint), it.count)
            };
        }
        it.count
    }
}

/// `iov_iter_alignment_iovec()`.
unsafe fn alignment_iovec(i: *const IovIter) -> c_ulong {
    // SAFETY: as above.
    unsafe {
        let mut iov = iter_iov(i as *mut IovIter);
        let mut res: c_ulong = 0;
        let mut size = (*i).count;
        let mut skip = (*i).iov_offset;

        loop {
            let mut len = (*iov).len.wrapping_sub(skip);
            if len != 0 {
                res |= ((*iov).base as c_ulong).wrapping_add(skip as c_ulong);
                if len > size {
                    len = size;
                }
                res |= len as c_ulong;
                size = size.wrapping_sub(len);
            }
            iov = iov.add(1);
            skip = 0;
            if size == 0 {
                break;
            }
        }
        res
    }
}

/// `iov_iter_alignment_bvec()` (the C keeps `res` and `skip` as `unsigned`).
unsafe fn alignment_bvec(i: *const IovIter) -> c_ulong {
    // SAFETY: as above.
    unsafe {
        let mut bvec = (*i).seg as *const BioVec;
        let mut res: c_uint = 0;
        let mut size = (*i).count;
        let mut skip = (*i).iov_offset as c_uint;

        loop {
            let mut len = ((*bvec).len as usize).wrapping_sub(skip as usize);
            res |= (*bvec).offset.wrapping_add(skip);
            if len > size {
                len = size;
            }
            res |= len as c_uint;
            bvec = bvec.add(1);
            size = size.wrapping_sub(len);
            skip = 0;
            if size == 0 {
                break;
            }
        }
        res as c_ulong
    }
}

/// `iov_iter_alignment()`.
#[no_mangle]
pub unsafe extern "C" fn rust_iov_iter_alignment(i: *const IovIter) -> c_ulong {
    // SAFETY: `i` is the caller's iterator.
    unsafe {
        let it = &*i;
        if is_ubuf(it) {
            let size = it.count;
            if size != 0 {
                return (it.seg as c_ulong).wrapping_add(it.iov_offset as c_ulong) | size as c_ulong;
            }
            return 0;
        }

        // iovec and kvec have identical layouts
        if is_iovec(it) || is_kvec(it) {
            return alignment_iovec(i);
        }

        if is_bvec(it) {
            return alignment_bvec(i);
        }

        // With both xarray and folioq types, we're dealing with whole folios.
        if is_folioq(it) {
            return it.iov_offset as c_ulong | it.count as c_ulong;
        }
        if is_xarray(it) {
            return (it.nr_segs as c_ulong).wrapping_add(it.iov_offset as c_ulong) | it.count as c_ulong;
        }

        0
    }
}

/// `iov_iter_gap_alignment()`.
#[no_mangle]
pub unsafe extern "C" fn rust_iov_iter_gap_alignment(i: *const IovIter) -> c_ulong {
    // SAFETY: `i` is the caller's iterator.
    unsafe {
        let it = &*i;
        let mut res: c_ulong = 0;
        let mut v: c_ulong = 0;
        let mut size = it.count;

        if is_ubuf(it) {
            return 0;
        }

        if rust_iw_warn_gap(!is_iovec(it)) {
            return c_uint::MAX as c_ulong; // ~0U
        }

        let mut k: c_uint = 0;
        while (k as usize) < it.nr_segs {
            let iov = iter_iov(i as *mut IovIter).add(k as usize);
            if (*iov).len != 0 {
                let base = (*iov).base as c_ulong;
                if v != 0 {
                    // if not the first one
                    res |= base | v; // this start | previous end
                }
                v = base.wrapping_add((*iov).len as c_ulong);
                if size <= (*iov).len {
                    break;
                }
                size = size.wrapping_sub((*iov).len);
            }
            k += 1;
        }
        res
    }
}

/// `iov_npages()`.
unsafe fn iov_npages(i: *const IovIter, maxpages: c_int) -> c_int {
    // SAFETY: as above.
    unsafe {
        let mut skip = (*i).iov_offset;
        let mut size = (*i).count;
        let mut p = iter_iov(i as *mut IovIter);
        let mut npages: c_int = 0;

        while size != 0 {
            let offs = (((*p).base.wrapping_add(skip)) & (PAGE_SIZE - 1)) as usize;
            let len = core::cmp::min((*p).len.wrapping_sub(skip), size);

            if len != 0 {
                size = size.wrapping_sub(len);
                npages = npages.wrapping_add((offs.wrapping_add(len).wrapping_add(PAGE_SIZE - 1) / PAGE_SIZE) as c_int);
                if npages > maxpages {
                    return maxpages;
                }
            }
            skip = 0;
            p = p.add(1);
        }
        npages
    }
}

/// `bvec_npages()`.
unsafe fn bvec_npages(i: *const IovIter, maxpages: c_int) -> c_int {
    // SAFETY: as above.
    unsafe {
        let mut skip = (*i).iov_offset;
        let mut size = (*i).count;
        let mut p = (*i).seg as *const BioVec;
        let mut npages: c_int = 0;

        while size != 0 {
            let offs = ((*p).offset as usize).wrapping_add(skip) % PAGE_SIZE;
            let len = core::cmp::min(((*p).len as usize).wrapping_sub(skip), size);

            size = size.wrapping_sub(len);
            npages = npages.wrapping_add((offs.wrapping_add(len).wrapping_add(PAGE_SIZE - 1) / PAGE_SIZE) as c_int);
            if npages > maxpages {
                return maxpages;
            }
            skip = 0;
            p = p.add(1);
        }
        npages
    }
}

/// `iov_iter_npages()`.
#[no_mangle]
pub unsafe extern "C" fn rust_iov_iter_npages(i: *const IovIter, maxpages: c_int) -> c_int {
    // SAFETY: `i` is the caller's iterator.
    unsafe {
        let it = &*i;
        if it.count == 0 {
            return 0;
        }
        if is_ubuf(it) {
            let offs = (it.seg.wrapping_add(it.iov_offset) & (PAGE_SIZE - 1)) as usize;
            let npages = (offs.wrapping_add(it.count).wrapping_add(PAGE_SIZE - 1) / PAGE_SIZE) as c_int;
            return core::cmp::min(npages, maxpages);
        }
        // iovec and kvec have identical layouts
        if is_iovec(it) || is_kvec(it) {
            return iov_npages(i, maxpages);
        }
        if is_bvec(it) {
            return bvec_npages(i, maxpages);
        }
        if is_folioq(it) {
            let offset = it.iov_offset % PAGE_SIZE;
            let npages = (offset.wrapping_add(it.count).wrapping_add(PAGE_SIZE - 1) / PAGE_SIZE) as c_int;
            return core::cmp::min(npages, maxpages);
        }
        if is_xarray(it) {
            let offset = (it.nr_segs).wrapping_add(it.iov_offset) % PAGE_SIZE;
            let npages = (offset.wrapping_add(it.count).wrapping_add(PAGE_SIZE - 1) / PAGE_SIZE) as c_int;
            return core::cmp::min(npages, maxpages);
        }
        0
    }
}

/// `iov_iter_restore()`.
#[no_mangle]
pub unsafe extern "C" fn rust_iov_iter_restore(i: *mut IovIter, state: *const IovIterState) {
    // SAFETY: the caller's contract is the C function's.
    unsafe {
        let it = &mut *i;
        // WARN_ON_ONCE(!bvec && !iovec && !ubuf) && !kvec -- the C's parenthesisation, kept
        if rust_iw_warn_restore(!is_bvec(it) && !is_iovec(it) && !is_ubuf(it)) && !is_kvec(it) {
            return;
        }
        it.iov_offset = (*state).iov_offset;
        it.count = (*state).count;
        if is_ubuf(it) {
            return;
        }
        // For the *vec iters, nr_segs + iov is constant: step the pointer back by the number of segments consumed. iovec/kvec are 16 bytes
        // (the glue asserts it); bio_vec is handled separately because it need not be the same size.
        let back = ((*state).nr_segs as usize).wrapping_sub(it.nr_segs);
        if is_bvec(it) {
            it.seg = it.seg.wrapping_sub(back.wrapping_mul(core::mem::size_of::<BioVec>()));
        } else {
            it.seg = it.seg.wrapping_sub(back.wrapping_mul(core::mem::size_of::<Iovec>()));
        }
        it.nr_segs = (*state).nr_segs as usize;
    }
}
