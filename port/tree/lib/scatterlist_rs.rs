// SPDX-License-Identifier: GPL-2.0-only

//! The scatterlist algorithms -- the Rust behind `lib/scatterlist.c`.
//!
//! Ported from `lib/scatterlist.c` (6.18.49), Copyright (C) 2007 Jens Axboe. In Rust: `sg_nents`, `sg_nents_for_len`, `sg_last`,
//! `sg_init_table`, `__sg_free_table`, `__sg_alloc_table`, `get_next_sg`, `sg_alloc_append_table_from_pages`, `sgl_alloc_order`,
//! `sgl_free_n_order`, the page iterators (`__sg_page_iter_start/next`, `__sg_page_iter_dma_next`), the mapping iterator
//! (`sg_miter_start/skip/next/stop`), `sg_copy_buffer` and `sg_zero_buffer`. In C (`scatterlist_glue.c`): every exported entry point
//! (the MODVERSIONS fingerprint comes from the DWARF of the definition), `sg_init_one`, `sg_alloc_table`, `sg_free_table`,
//! `sg_free_append_table`, `sg_alloc_table_from_pages_segment`, the thin `sg_copy_*` and `sg_pcopy_*` wrappers, and one-line wrappers
//! (`rust_sgw_*`) for every header inline or macro whose body depends on the configuration (`sg_next`, `sg_set_page`, `sg_page`,
//! `sg_chain`, `kmap*`, `BUG_ON`/`WARN_ON` sites, `sizeof(struct scatterlist)`). `extract_iter_to_sg` and its five helpers are
//! upstream C, unchanged, in `scatterlist_extract.c` (they walk `struct iov_iter` / `folio_queue` / `xarray`).
//!
//! # Notes
//! * `struct scatterlist` is handled through its first 16 bytes (`page_link`, `offset`, `length`), which do not vary; the stride between
//!   entries is `sizeof(struct scatterlist)` (it grows with `CONFIG_NEED_SG_DMA_LENGTH`/`_FLAGS`), reported by the glue.
//! * `struct sg_table`, `sg_append_table`, `sg_page_iter` and `sg_mapping_iter` have fixed layouts; the glue asserts every offset
//!   used here with `static_assert`.
//! * Arithmetic follows the C types: `unsigned int` is `wrapping_*`, `unsigned long` is `u64`, `off_t` is `i64`.
//!
//! Replaces: lib/scatterlist.c (the algorithms; the exports and the configuration-dependent glue stay C)

use core::ffi::{c_int, c_long, c_uint, c_ulong, c_void};

const PAGE_SHIFT: u32 = 12;
const PAGE_SIZE: u64 = 1 << PAGE_SHIFT;
const EINVAL: c_int = 22;
const ENOMEM: c_int = 12;
const EOPNOTSUPP: c_int = 95;

const SG_MITER_ATOMIC: c_uint = 1 << 0;
const SG_MITER_TO_SG: c_uint = 1 << 1;
const SG_MITER_FROM_SG: c_uint = 1 << 2;
const SG_MITER_LOCAL: c_uint = 1 << 3;

/// The part of `struct scatterlist` that does not depend on the configuration.
#[repr(C)]
pub struct Sg {
    page_link: c_ulong,
    offset: c_uint,
    length: c_uint,
}

/// `struct page`: only ever used by pointer.
#[repr(C)]
pub struct Page {
    _opaque: [u8; 0],
}

/// `struct sg_table`.
#[repr(C)]
pub struct SgTable {
    sgl: *mut Sg,
    nents: c_uint,
    orig_nents: c_uint,
}

/// `struct sg_append_table`.
#[repr(C)]
pub struct SgAppendTable {
    sgt: SgTable,
    prv: *mut Sg,
    total_nents: c_uint,
}

/// `struct sg_page_iter`.
#[repr(C)]
pub struct SgPageIter {
    sg: *mut Sg,
    sg_pgoffset: c_uint,
    nents: c_uint,
    pg_advance: c_int,
}

/// `struct sg_dma_page_iter`.
#[repr(C)]
pub struct SgDmaPageIter {
    base: SgPageIter,
}

/// `struct sg_mapping_iter`.
#[repr(C)]
pub struct SgMiter {
    page: *mut Page,
    addr: *mut c_void,
    length: usize,
    consumed: usize,
    piter: SgPageIter,
    offset: c_uint,
    remaining: c_uint,
    flags: c_uint,
}

type AllocFn = unsafe extern "C" fn(c_uint, c_uint) -> *mut Sg;
type FreeFn = unsafe extern "C" fn(*mut Sg, c_uint);

extern "C" {
    fn rust_sgw_size() -> usize;
    fn rust_sgw_max_single_alloc() -> usize;
    fn rust_sgw_next(sg: *mut Sg) -> *mut Sg;
    fn rust_sgw_is_last(sg: *mut Sg) -> bool;
    fn rust_sgw_init_marker(sgl: *mut Sg, nents: c_uint);
    fn rust_sgw_mark_end(sg: *mut Sg);
    fn rust_sgw_chain_ptr(sg: *mut Sg) -> *mut Sg;
    fn rust_sgw_chain(prv: *mut Sg, prv_nents: c_uint, sgl: *mut Sg);
    fn rust_sgw___chain(chain_sg: *mut Sg, sgl: *mut Sg);
    fn rust_sgw_set_page(sg: *mut Sg, page: *mut Page, len: c_uint, offset: c_uint);
    fn rust_sgw_page(sg: *mut Sg) -> *mut Page;
    fn rust_sgw_phys(sg: *mut Sg) -> u64;
    fn rust_sgw_dma_len(sg: *mut Sg) -> c_uint;
    fn rust_sgw_page_to_pfn(page: *mut Page) -> c_ulong;
    fn rust_sgw_pfn_to_page(pfn: c_ulong) -> *mut Page;
    fn rust_sgw_pages_mergeable(a: *mut Page, b: *mut Page) -> bool;
    fn rust_sgw_iter_page(piter: *mut SgPageIter) -> *mut Page;
    fn rust_sgw_kmalloc(nents: c_uint, gfp: c_uint) -> *mut Sg;
    fn rust_sgw_kmalloc_array_nodma(n: c_uint, gfp: c_uint) -> *mut Sg;
    fn rust_sgw_kfree(p: *mut c_void);
    fn rust_sgw_alloc_pages(gfp: c_uint, order: c_uint) -> *mut Page;
    fn rust_sgw_free_pages(page: *mut Page, order: c_uint);
    fn rust_sgw_kmap(page: *mut Page, flags: c_uint) -> *mut c_void;
    fn rust_sgw_kunmap(addr: *mut c_void, page: *mut Page, flags: c_uint);
    fn rust_sgw_flush_dcache_page(page: *mut Page);
    fn rust_sgw_no_chain() -> bool;
    fn rust_sgw_nents_gt_max(cond: bool) -> bool;
    fn rust_sgw_bug_not_last(sg: *mut Sg);
    fn rust_sgw_warn_max_segment(cond: bool);
    fn rust_sgw_warn_offset(cond: bool);
    fn rust_sgw_warn_miter_flags(cond: bool);
    fn rust_sgw_warn_consumed(cond: bool);
    fn rust_sgw_warn_once_length(length: u64);
    /// `sgl_free_order()`, which exists only under `CONFIG_SGL_ALLOC` (the glue's wrapper is empty without it; `sgl_alloc_order()`, its only
    /// caller, is then never called either).
    fn rust_sgw_sgl_free_order(sgl: *mut Sg, order: c_int);
}

/// `&sgl[i]`: the stride is `sizeof(struct scatterlist)`.
#[inline(always)]
unsafe fn sg_at(sgl: *mut Sg, i: usize) -> *mut Sg {
    // SAFETY: the stride comes from the glue; the caller keeps `i` inside the list, as the C does.
    unsafe { sgl.cast::<u8>().add(rust_sgw_size().wrapping_mul(i)).cast::<Sg>() }
}

/// `IS_ERR()`.
#[inline(always)]
fn is_err(p: *mut Sg) -> bool {
    (p as usize) >= (-4095_isize) as usize
}

/// `sg_nents()`.
#[no_mangle]
pub unsafe extern "C" fn rust_scatterlist_nents(mut sg: *mut Sg) -> c_int {
    // SAFETY: caller contract (a valid, terminated list).
    unsafe {
        let mut nents: c_int = 0;

        while !sg.is_null() {
            nents = nents.wrapping_add(1);
            sg = rust_sgw_next(sg);
        }
        nents
    }
}

/// `sg_nents_for_len()`.
#[no_mangle]
pub unsafe extern "C" fn rust_scatterlist_nents_for_len(mut sg: *mut Sg, len: u64) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let mut nents: c_int = 0;
        let mut total: u64 = 0;

        if len == 0 {
            return 0;
        }
        while !sg.is_null() {
            nents = nents.wrapping_add(1);
            total = total.wrapping_add((*sg).length as u64);
            if total >= len {
                return nents;
            }
            sg = rust_sgw_next(sg);
        }
        -EINVAL
    }
}

/// `sg_last()`.
#[no_mangle]
pub unsafe extern "C" fn rust_scatterlist_last(sgl: *mut Sg, nents: c_uint) -> *mut Sg {
    // SAFETY: caller contract.
    unsafe {
        let mut ret: *mut Sg = core::ptr::null_mut();
        let mut sg = sgl;
        let mut i: c_uint = 0;

        while i < nents {
            ret = sg;
            i += 1;
            sg = rust_sgw_next(sg);
        }
        rust_sgw_bug_not_last(ret);
        ret
    }
}

/// `sg_init_table()`.
#[no_mangle]
pub unsafe extern "C" fn rust_scatterlist_init_table(sgl: *mut Sg, nents: c_uint) {
    // SAFETY: caller contract (`nents` entries are writable).
    unsafe {
        core::ptr::write_bytes(sgl.cast::<u8>(), 0, rust_sgw_size().wrapping_mul(nents as usize));
        rust_sgw_init_marker(sgl, nents);
    }
}

/// `__sg_free_table()`.
#[no_mangle]
pub unsafe extern "C" fn rust_scatterlist_free_table(
    table: *mut SgTable,
    max_ents: c_uint,
    mut nents_first_chunk: c_uint,
    free_fn: FreeFn,
    mut num_ents: c_uint,
) {
    // SAFETY: caller contract.
    unsafe {
        let mut curr_max_ents = if nents_first_chunk != 0 { nents_first_chunk } else { max_ents };
        let mut sgl: *mut Sg;
        let mut next: *mut Sg;

        if (*table).sgl.is_null() {
            return;
        }

        sgl = (*table).sgl;
        while num_ents != 0 {
            let mut alloc_size = num_ents;
            let sg_size: c_uint;

            // More than `max_ents` left: `next` is the table after this one, and the last element of this one is the chain pointer.
            if alloc_size > curr_max_ents {
                next = rust_sgw_chain_ptr(sg_at(sgl, curr_max_ents.wrapping_sub(1) as usize));
                alloc_size = curr_max_ents;
                sg_size = alloc_size.wrapping_sub(1);
            } else {
                sg_size = alloc_size;
                next = core::ptr::null_mut();
            }

            num_ents = num_ents.wrapping_sub(sg_size);
            if nents_first_chunk != 0 {
                nents_first_chunk = 0;
            } else {
                free_fn(sgl, alloc_size);
            }
            sgl = next;
            curr_max_ents = max_ents;
        }

        (*table).sgl = core::ptr::null_mut();
    }
}

/// `__sg_alloc_table()`.
#[no_mangle]
pub unsafe extern "C" fn rust_scatterlist_alloc_table(
    table: *mut SgTable,
    nents: c_uint,
    max_ents: c_uint,
    mut first_chunk: *mut Sg,
    nents_first_chunk: c_uint,
    gfp_mask: c_uint,
    alloc_fn: AllocFn,
) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let mut sg: *mut Sg;
        let mut prv: *mut Sg;
        let mut left: c_uint;
        let mut curr_max_ents = if nents_first_chunk != 0 { nents_first_chunk } else { max_ents };
        let mut prv_max_ents: c_uint = 0;

        core::ptr::write_bytes(table, 0, 1);

        if nents == 0 {
            return -EINVAL;
        }
        if rust_sgw_nents_gt_max(nents > max_ents) {
            return -EINVAL;
        }

        left = nents;
        prv = core::ptr::null_mut();
        loop {
            let mut alloc_size = left;
            let sg_size: c_uint;

            if alloc_size > curr_max_ents {
                alloc_size = curr_max_ents;
                sg_size = alloc_size.wrapping_sub(1);
            } else {
                sg_size = alloc_size;
            }

            left = left.wrapping_sub(sg_size);

            if !first_chunk.is_null() {
                sg = first_chunk;
                first_chunk = core::ptr::null_mut();
            } else {
                sg = alloc_fn(alloc_size, gfp_mask);
            }
            if sg.is_null() {
                // The last entry of the previous table won't be used for linkage: count it, so the free side is not confused.
                if !prv.is_null() {
                    (*table).orig_nents = (*table).orig_nents.wrapping_add(1);
                    (*table).nents = (*table).orig_nents;
                }

                return -ENOMEM;
            }

            rust_scatterlist_init_table(sg, alloc_size);
            (*table).orig_nents = (*table).orig_nents.wrapping_add(sg_size);
            (*table).nents = (*table).orig_nents;

            // First mapping: set the header; later ones: chain the previous part.
            if !prv.is_null() {
                rust_sgw_chain(prv, prv_max_ents, sg);
            } else {
                (*table).sgl = sg;
            }

            // No more entries after this one: mark the end.
            if left == 0 {
                rust_sgw_mark_end(sg_at(sg, sg_size.wrapping_sub(1) as usize));
            }

            prv = sg;
            prv_max_ents = curr_max_ents;
            curr_max_ents = max_ents;
            if left == 0 {
                break;
            }
        }

        0
    }
}

/// `get_next_sg()`.
unsafe fn get_next_sg(table: *mut SgAppendTable, cur: *mut Sg, needed_sges: c_ulong, gfp_mask: c_uint) -> *mut Sg {
    // SAFETY: caller contract.
    unsafe {
        let mut next_sg: *mut Sg = core::ptr::null_mut();

        if !cur.is_null() {
            next_sg = rust_sgw_next(cur);
            // Keep the last entry for chaining.
            if !rust_sgw_is_last(next_sg) || needed_sges == 1 {
                return next_sg;
            }
        }

        let alloc_size = core::cmp::min(needed_sges, rust_sgw_max_single_alloc() as c_ulong) as c_uint;
        let new_sg = rust_sgw_kmalloc(alloc_size, gfp_mask);
        if new_sg.is_null() {
            return (-(ENOMEM as isize)) as usize as *mut Sg;
        }
        rust_scatterlist_init_table(new_sg, alloc_size);
        if !cur.is_null() {
            (*table).total_nents = (*table).total_nents.wrapping_add(alloc_size.wrapping_sub(1));
            rust_sgw___chain(next_sg, new_sg);
        } else {
            (*table).sgt.sgl = new_sg;
            (*table).total_nents = alloc_size;
        }
        new_sg
    }
}

/// `sg_alloc_append_table_from_pages()`.
#[no_mangle]
pub unsafe extern "C" fn rust_scatterlist_alloc_append(
    sgt_append: *mut SgAppendTable,
    mut pages: *mut *mut Page,
    mut n_pages: c_uint,
    mut offset: c_uint,
    mut size: c_ulong,
    mut max_segment: c_uint,
    left_pages: c_uint,
    gfp_mask: c_uint,
) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let mut chunks: c_uint;
        let mut cur_page: c_uint;
        let mut seg_len: c_uint;
        let mut i: c_uint;
        let mut prv_len: c_uint = 0;
        let mut added_nents: c_uint = 0;
        let mut s = (*sgt_append).prv;

        // The algorithm below requires max_segment to be aligned to PAGE_SIZE, otherwise it can overshoot.
        max_segment &= !((PAGE_SIZE - 1) as c_uint);
        rust_sgw_warn_max_segment(max_segment < PAGE_SIZE as c_uint);
        if max_segment < PAGE_SIZE as c_uint {
            return -EINVAL;
        }

        if rust_sgw_no_chain() && !(*sgt_append).prv.is_null() {
            return -EOPNOTSUPP;
        }

        'out: {
            if !(*sgt_append).prv.is_null() {
                let next_pfn: c_ulong;

                rust_sgw_warn_offset(offset != 0);
                if offset != 0 {
                    return -EINVAL;
                }

                // Merge contiguous pages into the last SG.
                prv_len = (*(*sgt_append).prv).length;
                next_pfn = ((rust_sgw_phys((*sgt_append).prv).wrapping_add(prv_len as u64)) / PAGE_SIZE) as c_ulong;
                if rust_sgw_page_to_pfn(*pages) == next_pfn {
                    let mut last_pg = rust_sgw_pfn_to_page(next_pfn.wrapping_sub(1));
                    while n_pages != 0 && rust_sgw_pages_mergeable(*pages, last_pg) {
                        if ((*(*sgt_append).prv).length as u64).wrapping_add(PAGE_SIZE) > max_segment as u64 {
                            break;
                        }
                        (*(*sgt_append).prv).length = (*(*sgt_append).prv).length.wrapping_add(PAGE_SIZE as c_uint);
                        last_pg = *pages;
                        pages = pages.add(1);
                        n_pages -= 1;
                    }
                    if n_pages == 0 {
                        break 'out;
                    }
                }
            }

            // Compute the number of contiguous chunks.
            chunks = 1;
            seg_len = 0;
            i = 1;
            while i < n_pages {
                seg_len = seg_len.wrapping_add(PAGE_SIZE as c_uint);
                if seg_len >= max_segment || !rust_sgw_pages_mergeable(*pages.add(i as usize), *pages.add(i as usize - 1)) {
                    chunks = chunks.wrapping_add(1);
                    seg_len = 0;
                }
                i += 1;
            }

            // Merge the chunks and put them into the scatterlist.
            cur_page = 0;
            i = 0;
            while i < chunks {
                let mut j: c_uint;
                let chunk_size: c_uint;

                // Look for the end of the current chunk.
                seg_len = 0;
                j = cur_page.wrapping_add(1);
                while j < n_pages {
                    seg_len = seg_len.wrapping_add(PAGE_SIZE as c_uint);
                    if seg_len >= max_segment || !rust_sgw_pages_mergeable(*pages.add(j as usize), *pages.add(j as usize - 1)) {
                        break;
                    }
                    j += 1;
                }

                // Pass how many chunks might be left.
                s = get_next_sg(
                    sgt_append,
                    s,
                    chunks.wrapping_sub(i).wrapping_add(left_pages) as c_ulong,
                    gfp_mask,
                );
                if is_err(s) {
                    // Put the entry length back as it was before the call.
                    if !(*sgt_append).prv.is_null() {
                        (*(*sgt_append).prv).length = prv_len;
                    }
                    return (s as isize) as c_int;
                }
                chunk_size = (j.wrapping_sub(cur_page) << PAGE_SHIFT).wrapping_sub(offset);
                rust_sgw_set_page(
                    s,
                    *pages.add(cur_page as usize),
                    core::cmp::min(size, chunk_size as c_ulong) as c_uint,
                    offset,
                );
                added_nents = added_nents.wrapping_add(1);
                size = size.wrapping_sub(chunk_size as c_ulong);
                offset = 0;
                cur_page = j;
                i += 1;
            }
            (*sgt_append).sgt.nents = (*sgt_append).sgt.nents.wrapping_add(added_nents);
            (*sgt_append).sgt.orig_nents = (*sgt_append).sgt.nents;
            (*sgt_append).prv = s;
        }
        if left_pages == 0 {
            rust_sgw_mark_end(s);
        }
        0
    }
}

/// `sgl_alloc_order()`.
#[no_mangle]
pub unsafe extern "C" fn rust_scatterlist_sgl_alloc_order(
    mut length: u64,
    order: c_uint,
    chainable: bool,
    gfp: c_uint,
    nent_p: *mut c_uint,
) -> *mut Sg {
    // SAFETY: caller contract.
    unsafe {
        let mut nalloc: c_uint;
        let psz = PAGE_SIZE.wrapping_shl(order);

        // round_up(length, PAGE_SIZE << order) >> (PAGE_SHIFT + order)
        let nent = ((length.wrapping_sub(1) | psz.wrapping_sub(1)).wrapping_add(1)).wrapping_shr(PAGE_SHIFT.wrapping_add(order)) as c_uint;
        // Check for integer overflow.
        if length > nent.wrapping_shl(PAGE_SHIFT.wrapping_add(order)) as u64 {
            return core::ptr::null_mut();
        }
        nalloc = nent;
        if chainable {
            // Check for integer overflow.
            if nalloc.wrapping_add(1) < nalloc {
                return core::ptr::null_mut();
            }
            nalloc += 1;
        }
        let sgl = rust_sgw_kmalloc_array_nodma(nalloc, gfp);
        if sgl.is_null() {
            return core::ptr::null_mut();
        }

        rust_scatterlist_init_table(sgl, nalloc);
        let mut sg = sgl;
        while length != 0 {
            let elem_len = core::cmp::min(length, psz) as u32;
            let page = rust_sgw_alloc_pages(gfp, order);
            if page.is_null() {
                rust_sgw_sgl_free_order(sgl, order as c_int);
                return core::ptr::null_mut();
            }

            rust_sgw_set_page(sg, page, elem_len, 0);
            length = length.wrapping_sub(elem_len as u64);
            sg = rust_sgw_next(sg);
        }
        rust_sgw_warn_once_length(length);
        if !nent_p.is_null() {
            *nent_p = nent;
        }
        sgl
    }
}

/// `sgl_free_n_order()`.
#[no_mangle]
pub unsafe extern "C" fn rust_scatterlist_sgl_free_n_order(sgl: *mut Sg, nents: c_int, order: c_int) {
    // SAFETY: caller contract.
    unsafe {
        let mut sg = sgl;
        let mut i: c_int = 0;

        while i < nents {
            if sg.is_null() {
                break;
            }
            let page = rust_sgw_page(sg);
            if !page.is_null() {
                rust_sgw_free_pages(page, order as c_uint);
            }
            i += 1;
            sg = rust_sgw_next(sg);
        }
        rust_sgw_kfree(sgl.cast());
    }
}

/// `__sg_page_iter_start()`.
#[no_mangle]
pub unsafe extern "C" fn rust_scatterlist_page_iter_start(piter: *mut SgPageIter, sglist: *mut Sg, nents: c_uint, pgoffset: c_ulong) {
    // SAFETY: caller contract.
    unsafe {
        (*piter).pg_advance = 0;
        (*piter).nents = nents;

        (*piter).sg = sglist;
        (*piter).sg_pgoffset = pgoffset as c_uint;
    }
}

/// `PAGE_ALIGN(a + b) >> PAGE_SHIFT`, as the C computes it: `ALIGN()` casts the page size to the type of its argument, which here is
/// `unsigned int`, so the sum, the rounding and the shift all wrap at 32 bits.
#[inline(always)]
fn page_count(a: c_uint, b: c_uint) -> c_int {
    let sum = a.wrapping_add(b);
    ((sum.wrapping_add((PAGE_SIZE - 1) as c_uint) & !((PAGE_SIZE - 1) as c_uint)) >> PAGE_SHIFT) as c_int
}

/// `__sg_page_iter_next()`.
#[no_mangle]
pub unsafe extern "C" fn rust_scatterlist_page_iter_next(piter: *mut SgPageIter) -> bool {
    // SAFETY: caller contract.
    unsafe {
        if (*piter).nents == 0 || (*piter).sg.is_null() {
            return false;
        }

        (*piter).sg_pgoffset = (*piter).sg_pgoffset.wrapping_add((*piter).pg_advance as c_uint);
        (*piter).pg_advance = 1;

        while (*piter).sg_pgoffset >= page_count((*(*piter).sg).offset, (*(*piter).sg).length) as c_uint {
            (*piter).sg_pgoffset = (*piter).sg_pgoffset.wrapping_sub(page_count((*(*piter).sg).offset, (*(*piter).sg).length) as c_uint);
            (*piter).sg = rust_sgw_next((*piter).sg);
            (*piter).nents = (*piter).nents.wrapping_sub(1);
            if (*piter).nents == 0 || (*piter).sg.is_null() {
                return false;
            }
        }

        true
    }
}

/// `__sg_page_iter_dma_next()`.
#[no_mangle]
pub unsafe extern "C" fn rust_scatterlist_page_iter_dma_next(dma_iter: *mut SgDmaPageIter) -> bool {
    // SAFETY: caller contract.
    unsafe {
        let piter = &raw mut (*dma_iter).base;

        if (*piter).nents == 0 || (*piter).sg.is_null() {
            return false;
        }

        (*piter).sg_pgoffset = (*piter).sg_pgoffset.wrapping_add((*piter).pg_advance as c_uint);
        (*piter).pg_advance = 1;

        while (*piter).sg_pgoffset >= page_count((*(*piter).sg).offset, rust_sgw_dma_len((*piter).sg)) as c_uint {
            (*piter).sg_pgoffset = (*piter).sg_pgoffset.wrapping_sub(page_count((*(*piter).sg).offset, rust_sgw_dma_len((*piter).sg)) as c_uint);
            (*piter).sg = rust_sgw_next((*piter).sg);
            (*piter).nents = (*piter).nents.wrapping_sub(1);
            if (*piter).nents == 0 || (*piter).sg.is_null() {
                return false;
            }
        }

        true
    }
}

/// `sg_miter_start()`.
#[no_mangle]
pub unsafe extern "C" fn rust_scatterlist_miter_start(miter: *mut SgMiter, sgl: *mut Sg, nents: c_uint, flags: c_uint) {
    // SAFETY: caller contract.
    unsafe {
        core::ptr::write_bytes(miter, 0, 1);

        rust_scatterlist_page_iter_start(&raw mut (*miter).piter, sgl, nents, 0);
        rust_sgw_warn_miter_flags(flags & (SG_MITER_TO_SG | SG_MITER_FROM_SG) == 0);
        (*miter).flags = flags;
    }
}

/// `sg_miter_get_next_page()`.
unsafe fn miter_get_next_page(miter: *mut SgMiter) -> bool {
    // SAFETY: caller contract.
    unsafe {
        if (*miter).remaining == 0 {
            if !rust_scatterlist_page_iter_next(&raw mut (*miter).piter) {
                return false;
            }

            let sg = (*miter).piter.sg;

            (*miter).offset = if (*miter).piter.sg_pgoffset != 0 { 0 } else { (*sg).offset };
            (*miter).piter.sg_pgoffset = (*miter).piter.sg_pgoffset.wrapping_add((*miter).offset >> PAGE_SHIFT);
            (*miter).offset &= (PAGE_SIZE - 1) as c_uint;
            (*miter).remaining = (*sg)
                .offset
                .wrapping_add((*sg).length)
                .wrapping_sub((*miter).piter.sg_pgoffset << PAGE_SHIFT)
                .wrapping_sub((*miter).offset);
            (*miter).remaining = core::cmp::min((*miter).remaining as c_ulong, PAGE_SIZE.wrapping_sub((*miter).offset as u64)) as c_uint;
        }

        true
    }
}

/// `sg_miter_skip()`.
#[no_mangle]
pub unsafe extern "C" fn rust_scatterlist_miter_skip(miter: *mut SgMiter, mut offset: c_long) -> bool {
    // SAFETY: caller contract.
    unsafe {
        rust_scatterlist_miter_stop(miter);

        while offset != 0 {
            if !miter_get_next_page(miter) {
                return false;
            }

            let consumed: c_long = core::cmp::min(offset, (*miter).remaining as c_long);
            (*miter).offset = (*miter).offset.wrapping_add(consumed as c_uint);
            (*miter).remaining = (*miter).remaining.wrapping_sub(consumed as c_uint);
            offset = offset.wrapping_sub(consumed);
        }

        true
    }
}

/// `sg_miter_next()`.
#[no_mangle]
pub unsafe extern "C" fn rust_scatterlist_miter_next(miter: *mut SgMiter) -> bool {
    // SAFETY: caller contract.
    unsafe {
        rust_scatterlist_miter_stop(miter);

        // Get to the next page if necessary; remaining and offset were adjusted by the stop.
        if !miter_get_next_page(miter) {
            return false;
        }

        (*miter).page = rust_sgw_iter_page(&raw mut (*miter).piter);
        (*miter).length = (*miter).remaining as usize;
        (*miter).consumed = (*miter).length;

        (*miter).addr = rust_sgw_kmap((*miter).page, (*miter).flags).cast::<u8>().add((*miter).offset as usize).cast();

        true
    }
}

/// `sg_miter_stop()`.
#[no_mangle]
pub unsafe extern "C" fn rust_scatterlist_miter_stop(miter: *mut SgMiter) {
    // SAFETY: caller contract.
    unsafe {
        rust_sgw_warn_consumed((*miter).consumed > (*miter).length);

        // Drop the resources of the last iteration.
        if !(*miter).addr.is_null() {
            (*miter).offset = (*miter).offset.wrapping_add((*miter).consumed as c_uint);
            (*miter).remaining = (*miter).remaining.wrapping_sub((*miter).consumed as c_uint);

            if (*miter).flags & SG_MITER_TO_SG != 0 {
                rust_sgw_flush_dcache_page((*miter).page);
            }

            rust_sgw_kunmap((*miter).addr, (*miter).page, (*miter).flags);

            (*miter).page = core::ptr::null_mut();
            (*miter).addr = core::ptr::null_mut();
            (*miter).length = 0;
            (*miter).consumed = 0;
        }
    }
}

/// `sg_copy_buffer()`.
#[no_mangle]
pub unsafe extern "C" fn rust_scatterlist_copy_buffer(
    sgl: *mut Sg,
    nents: c_uint,
    buf: *mut c_void,
    buflen: usize,
    skip: c_long,
    to_buffer: bool,
) -> usize {
    // SAFETY: caller contract.
    unsafe {
        let mut offset: c_uint = 0;
        let mut miter = core::mem::MaybeUninit::<SgMiter>::uninit();
        let m = miter.as_mut_ptr();
        let sg_flags = SG_MITER_LOCAL | if to_buffer { SG_MITER_FROM_SG } else { SG_MITER_TO_SG };

        rust_scatterlist_miter_start(m, sgl, nents, sg_flags);

        if !rust_scatterlist_miter_skip(m, skip) {
            return 0;
        }

        while (offset as usize) < buflen && rust_scatterlist_miter_next(m) {
            let len = core::cmp::min((*m).length, buflen.wrapping_sub(offset as usize)) as c_uint;

            if to_buffer {
                core::ptr::copy_nonoverlapping((*m).addr.cast::<u8>(), buf.cast::<u8>().add(offset as usize), len as usize);
            } else {
                core::ptr::copy_nonoverlapping(buf.cast::<u8>().add(offset as usize), (*m).addr.cast::<u8>(), len as usize);
            }

            offset = offset.wrapping_add(len);
        }

        rust_scatterlist_miter_stop(m);

        offset as usize
    }
}

/// `sg_zero_buffer()`.
#[no_mangle]
pub unsafe extern "C" fn rust_scatterlist_zero_buffer(sgl: *mut Sg, nents: c_uint, buflen: usize, skip: c_long) -> usize {
    // SAFETY: caller contract.
    unsafe {
        let mut offset: c_uint = 0;
        let mut miter = core::mem::MaybeUninit::<SgMiter>::uninit();
        let m = miter.as_mut_ptr();
        let sg_flags = SG_MITER_LOCAL | SG_MITER_TO_SG;

        rust_scatterlist_miter_start(m, sgl, nents, sg_flags);

        if !rust_scatterlist_miter_skip(m, skip) {
            return 0;
        }

        while (offset as usize) < buflen && rust_scatterlist_miter_next(m) {
            let len = core::cmp::min((*m).length, buflen.wrapping_sub(offset as usize)) as c_uint;

            core::ptr::write_bytes((*m).addr.cast::<u8>(), 0, len as usize);

            offset = offset.wrapping_add(len);
        }

        rust_scatterlist_miter_stop(m);
        offset as usize
    }
}

const _: () = {
    assert!(core::mem::size_of::<SgTable>() == 16);
    assert!(core::mem::size_of::<SgAppendTable>() == 32);
    assert!(core::mem::size_of::<SgPageIter>() == 24);
    assert!(core::mem::size_of::<SgMiter>() == 72);
    assert!(SG_MITER_ATOMIC == 1);
};
