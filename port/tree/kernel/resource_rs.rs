// SPDX-License-Identifier: GPL-2.0-only

//! The resource-tree algorithms of `kernel/resource.c` -- the Rust behind them.
//!
//! Ported from `kernel/resource.c` (6.18.49): the lock-free tree operations that the exported functions call with `resource_lock` held: `__request_resource()`,
//! `__release_resource()`, `__release_child_resources()`, `__insert_resource()`, `__adjust_resource()`, the search in `find_next_iomem_res()`, `__region_intersects()`,
//! `__find_resource_space()` (free-space search with alignment and clipping), the body of `reallocate_resource()` and `resource_alignment()`. In C (`resource_glue.c`):
//! the rwlock, allocation, `/proc/iomem`, devres, the `request_region()` family, memory hot-remove (`release_mem_region_adjustable()`), the walk callbacks, the setup
//! parameters, the exports (as thunks), and wrappers for what is configuration-dependent or an indirect call (the alignment callback, `arch_remove_reservations()`,
//! `printk(%pR)`, `WARN_ON`, `BUG_ON`).
//!
//! `struct resource` is `{ start, end, name, flags, desc, parent, sibling, child }` with 64-bit addresses on x86-64.
//!
//! Replaces: kernel/resource.c (the tree algorithms)

use core::ffi::{c_char, c_int, c_ulong, c_void};
use core::ptr::{null_mut, read, write};

const EBUSY: c_int = 16;
const EINVAL: c_int = 22;
const ENODEV: c_int = 19;
const IORESOURCE_TYPE_BITS: c_ulong = 0x0000_1f00;
const IORESOURCE_SIZEALIGN: c_ulong = 0x0004_0000;
const IORESOURCE_STARTALIGN: c_ulong = 0x0008_0000;
const IORESOURCE_UNSET: c_ulong = 0x2000_0000;
const IORES_DESC_NONE: c_ulong = 0;
const REGION_INTERSECTS: c_int = 0;
const REGION_DISJOINT: c_int = 1;
const REGION_MIXED: c_int = 2;

/// Mirrors `struct resource`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Res {
    start: u64,
    end: u64,
    name: *const c_char,
    flags: c_ulong,
    desc: c_ulong,
    parent: *mut Res,
    sibling: *mut Res,
    child: *mut Res,
}

/// Mirrors `struct resource_constraint`.
#[repr(C)]
pub struct Constraint {
    min: u64,
    max: u64,
    align: u64,
    alignf: *const c_void,
    alignf_data: *mut c_void,
}

extern "C" {
    fn rust_res_warn_dup();
    fn rust_res_bug();
    fn rust_res_dbg_release(r: *mut Res);
    fn rust_res_alignf(alignf: *const c_void, data: *mut c_void, avail: *const Res, size: u64, align: u64) -> u64;
    fn rust_res_arch_remove_reservations(r: *mut Res);
}

impl Res {
    const fn zero() -> Res {
        Res { start: 0, end: 0, name: core::ptr::null(), flags: 0, desc: 0, parent: null_mut(), sibling: null_mut(), child: null_mut() }
    }
    fn size(&self) -> u64 {
        self.end.wrapping_sub(self.start).wrapping_add(1)
    }
    fn rtype(&self) -> c_ulong {
        self.flags & IORESOURCE_TYPE_BITS
    }
}

fn contains(r1: &Res, r2: &Res) -> bool {
    if r1.rtype() != r2.rtype() {
        return false;
    }
    if r1.flags & IORESOURCE_UNSET != 0 || r2.flags & IORESOURCE_UNSET != 0 {
        return false;
    }
    r1.start <= r2.start && r1.end >= r2.end
}

fn overlaps(r1: &Res, r2: &Res) -> bool {
    r1.start <= r2.end && r1.end >= r2.start
}

/// `next_resource()`: next node in pre-order, bounded by `subtree_root`.
unsafe fn next_resource(mut p: *mut Res, skip_children: bool, subtree_root: *mut Res) -> *mut Res {
    unsafe {
        if !skip_children && !(*p).child.is_null() {
            return (*p).child;
        }
        while (*p).sibling.is_null() && !(*p).parent.is_null() {
            p = (*p).parent;
            if p == subtree_root {
                return null_mut();
            }
        }
        (*p).sibling
    }
}

fn is_type_match(p: &Res, flags: c_ulong, desc: c_ulong) -> bool {
    (p.flags & flags) == flags && (desc == IORES_DESC_NONE || desc == p.desc)
}

/// `__request_resource()`: NULL on success, else the conflicting resource.
#[no_mangle]
pub unsafe extern "C" fn rust_res_request(root: *mut Res, new: *mut Res) -> *mut Res {
    unsafe {
        let start = (*new).start;
        let end = (*new).end;
        if end < start {
            return root;
        }
        if start < (*root).start {
            return root;
        }
        if end > (*root).end {
            return root;
        }
        let mut p: *mut *mut Res = &mut (*root).child;
        loop {
            let tmp = *p;
            if tmp.is_null() || (*tmp).start > end {
                (*new).sibling = tmp;
                *p = new;
                (*new).parent = root;
                return null_mut();
            }
            p = &mut (*tmp).sibling;
            if (*tmp).end < start {
                continue;
            }
            return tmp;
        }
    }
}

/// `__release_resource()`.
#[no_mangle]
pub unsafe extern "C" fn rust_res_release(old: *mut Res, release_child: bool) -> c_int {
    unsafe {
        let mut p: *mut *mut Res = &mut (*(*old).parent).child;
        loop {
            let tmp = *p;
            if tmp.is_null() {
                break;
            }
            if tmp == old {
                if release_child || (*tmp).child.is_null() {
                    *p = (*tmp).sibling;
                } else {
                    let mut chd = (*tmp).child;
                    loop {
                        (*chd).parent = (*tmp).parent;
                        if (*chd).sibling.is_null() {
                            break;
                        }
                        chd = (*chd).sibling;
                    }
                    *p = (*tmp).child;
                    (*chd).sibling = (*tmp).sibling;
                }
                (*old).parent = null_mut();
                return 0;
            }
            p = &mut (*tmp).sibling;
        }
        -EINVAL
    }
}

/// `__release_child_resources()`.
#[no_mangle]
pub unsafe extern "C" fn rust_res_release_children(r: *mut Res) {
    unsafe {
        let mut p = (*r).child;
        (*r).child = null_mut();
        while !p.is_null() {
            let tmp = p;
            p = (*p).sibling;
            (*tmp).parent = null_mut();
            (*tmp).sibling = null_mut();
            rust_res_release_children(tmp);
            rust_res_dbg_release(tmp);
            // need to restore size, and keep flags
            let size = (*tmp).size();
            (*tmp).start = 0;
            (*tmp).end = size.wrapping_sub(1);
        }
    }
}

/// The scan of `find_next_iomem_res()` (the caller holds the read lock): 0 and `*res` filled, `-ENODEV` if nothing matches, `-EINVAL` for bad arguments.
#[no_mangle]
pub unsafe extern "C" fn rust_res_find_next(iomem: *mut Res, start: u64, end: u64, flags: c_ulong, desc: c_ulong, res: *mut Res) -> c_int {
    unsafe {
        if res.is_null() {
            return -EINVAL;
        }
        if start >= end {
            return -EINVAL;
        }
        let mut skip_children = true;
        let mut p = (*iomem).child;
        while !p.is_null() {
            if (*p).start > end {
                p = null_mut();
                break;
            }
            if (*p).end < start {
                p = next_resource(p, skip_children, iomem);
                continue;
            }
            skip_children = false;
            if is_type_match(&*p, flags, desc) {
                break;
            }
            p = next_resource(p, skip_children, iomem);
        }
        if p.is_null() {
            return -ENODEV;
        }
        write(res, Res { start: start.max((*p).start), end: end.min((*p).end), flags: (*p).flags, desc: (*p).desc, parent: (*p).parent, ..Res::zero() });
        0
    }
}

/// `__region_intersects()`.
#[no_mangle]
pub unsafe extern "C" fn rust_res_region_intersects(parent: *mut Res, start: u64, size: usize, flags: c_ulong, desc: c_ulong) -> c_int {
    unsafe {
        let mut ty = 0;
        let mut other = 0;
        let res = Res { start, end: start.wrapping_add(size as u64).wrapping_sub(1), ..Res::zero() };
        let mut p = (*parent).child;
        while !p.is_null() {
            let pr = &*p;
            if !overlaps(pr, &res) {
                p = pr.sibling;
                continue;
            }
            let mut o_start = pr.start.max(res.start);
            let o_end = pr.end.min(res.end);
            if is_type_match(pr, flags, desc) {
                ty += 1;
                p = pr.sibling;
                continue;
            }
            // Search the descendants as if the matching ones covered some ranges of 'p'.
            let mut covered = false;
            let mut dp = pr.child;
            while !dp.is_null() {
                let d = &*dp;
                if overlaps(d, &res) && is_type_match(d, flags, desc) {
                    ty += 1;
                    if d.start > o_start {
                        break;
                    }
                    if d.end >= o_end {
                        covered = true;
                        break;
                    }
                    o_start = o_start.max(d.end.wrapping_add(1));
                }
                dp = next_resource(dp, false, p);
            }
            if !covered {
                other += 1;
            }
            p = pr.sibling;
        }
        if ty == 0 {
            return REGION_DISJOINT;
        }
        if other == 0 {
            return REGION_INTERSECTS;
        }
        REGION_MIXED
    }
}

fn resource_clip(res: &mut Res, min: u64, max: u64) {
    if res.start < min {
        res.start = min;
    }
    if res.end > max {
        res.end = max;
    }
}

/// `__find_resource_space()`: 0 and `new->start/end` set, or `-EBUSY`.
#[no_mangle]
pub unsafe extern "C" fn rust_res_find_space(root: *mut Res, old: *mut Res, new: *mut Res, size: u64, c: *const Constraint) -> c_int {
    unsafe {
        let mut this = (*root).child;
        let mut tmp = read(new);
        let alignf = (*c).alignf;
        tmp.start = (*root).start;
        // Skip past an allocated resource that starts at 0, since this->start - 1 would underflow.
        if !this.is_null() && (*this).start == (*root).start {
            tmp.start = if this == old { (*old).start } else { (*this).end.wrapping_add(1) };
            this = (*this).sibling;
        }
        loop {
            'next: {
                tmp.end = if !this.is_null() {
                    if this == old {
                        (*this).end
                    } else {
                        (*this).start.wrapping_sub(1)
                    }
                } else {
                    (*root).end
                };
                if tmp.end < tmp.start {
                    break 'next;
                }
                resource_clip(&mut tmp, (*c).min, (*c).max);
                rust_res_arch_remove_reservations(&mut tmp);

                // Check for overflow after ALIGN().
                let mask = (*c).align.wrapping_sub(1);
                let avail = Res { start: tmp.start.wrapping_add(mask) & !mask, end: tmp.end, flags: (*new).flags & !IORESOURCE_UNSET, ..Res::zero() };
                if avail.start >= tmp.start {
                    let a_start = if !alignf.is_null() { rust_res_alignf(alignf, (*c).alignf_data, &avail, size, (*c).align) } else { avail.start };
                    let alloc = Res { start: a_start, end: a_start.wrapping_add(size).wrapping_sub(1), flags: avail.flags, ..Res::zero() };
                    if alloc.start <= alloc.end && contains(&avail, &alloc) {
                        (*new).start = alloc.start;
                        (*new).end = alloc.end;
                        return 0;
                    }
                }
            }
            if this.is_null() || (*this).end == (*root).end {
                break;
            }
            if this != old {
                tmp.start = (*this).end.wrapping_add(1);
            }
            this = (*this).sibling;
        }
        -EBUSY
    }
}

/// The body of `reallocate_resource()` between the lock calls.
#[no_mangle]
pub unsafe extern "C" fn rust_res_reallocate(root: *mut Res, old: *mut Res, newsize: u64, c: *const Constraint) -> c_int {
    unsafe {
        let mut new = read(old);
        let err = rust_res_find_space(root, old, &mut new, newsize, c);
        if err != 0 {
            return err;
        }
        if contains(&new, &*old) {
            (*old).start = new.start;
            (*old).end = new.end;
            return 0;
        }
        if !(*old).child.is_null() {
            return -EBUSY;
        }
        if contains(&*old, &new) {
            (*old).start = new.start;
            (*old).end = new.end;
        } else {
            rust_res_release(old, true);
            write(old, new);
            let conflict = rust_res_request(root, old);
            if !conflict.is_null() {
                rust_res_bug();
            }
        }
        0
    }
}

/// `__insert_resource()`: NULL on success, else the conflicting resource.
#[no_mangle]
pub unsafe extern "C" fn rust_res_insert(mut parent: *mut Res, new: *mut Res) -> *mut Res {
    unsafe {
        let mut first;
        loop {
            first = rust_res_request(parent, new);
            if first.is_null() {
                return first;
            }
            if first == parent {
                return first;
            }
            if first == new {
                rust_res_warn_dup(); // WARN_ON(first == new): duplicated insertion
                return first;
            }
            if (*first).start > (*new).start || (*first).end < (*new).end {
                break;
            }
            if (*first).start == (*new).start && (*first).end == (*new).end {
                break;
            }
            parent = first;
        }

        let mut next = first;
        loop {
            // Partial overlap? Bad, and unfixable.
            if (*next).start < (*new).start || (*next).end > (*new).end {
                return next;
            }
            if (*next).sibling.is_null() {
                break;
            }
            if (*(*next).sibling).start > (*new).end {
                break;
            }
            next = (*next).sibling;
        }

        (*new).parent = parent;
        (*new).sibling = (*next).sibling;
        (*new).child = first;

        (*next).sibling = null_mut();
        next = first;
        while !next.is_null() {
            (*next).parent = new;
            next = (*next).sibling;
        }

        if (*parent).child == first {
            (*parent).child = new;
        } else {
            next = (*parent).child;
            while (*next).sibling != first {
                next = (*next).sibling;
            }
            (*next).sibling = new;
        }
        null_mut()
    }
}

/// `__adjust_resource()`.
#[no_mangle]
pub unsafe extern "C" fn rust_res_adjust(res: *mut Res, start: u64, size: u64) -> c_int {
    unsafe {
        let parent = (*res).parent;
        let end = start.wrapping_add(size).wrapping_sub(1);
        let mut skip = false;
        if parent.is_null() {
            skip = true;
        }
        if !skip {
            if start < (*parent).start || end > (*parent).end {
                return -EBUSY;
            }
            if !(*res).sibling.is_null() && (*(*res).sibling).start <= end {
                return -EBUSY;
            }
            let mut tmp = (*parent).child;
            if tmp != res {
                while (*tmp).sibling != res {
                    tmp = (*tmp).sibling;
                }
                if start <= (*tmp).end {
                    return -EBUSY;
                }
            }
        }
        let mut tmp = (*res).child;
        while !tmp.is_null() {
            if (*tmp).start < start || (*tmp).end > end {
                return -EBUSY;
            }
            tmp = (*tmp).sibling;
        }
        (*res).start = start;
        (*res).end = end;
        0
    }
}

/// `resource_alignment()`.
#[no_mangle]
pub unsafe extern "C" fn rust_res_alignment(res: *mut Res) -> u64 {
    unsafe {
        match (*res).flags & (IORESOURCE_SIZEALIGN | IORESOURCE_STARTALIGN) {
            IORESOURCE_SIZEALIGN => (*res).size(),
            IORESOURCE_STARTALIGN => (*res).start,
            _ => 0,
        }
    }
}
