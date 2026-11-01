// SPDX-License-Identifier: GPL-2.0-only

//! The id-map machinery of `kernel/user_namespace.c` -- the Rust behind it.
//!
//! Ported from `kernel/user_namespace.c` (6.18.49): the lookups behind `map_id_down()`, `map_id_up()` and `map_id_range_up()` (linear scan of the five inline extents, binary
//! search of the sorted `forward` / `reverse` arrays beyond that), and the three phases of `map_write()` that carry its logic: parsing the text a process writes to
//! `/proc/PID/{uid,gid,projid}_map` (`rust_userns_parse()`, which holds `mappings_overlap()` and `insert_extent()`), translating the lower ids through the parent map
//! (`rust_userns_remap()`), and sorting (`rust_userns_sort()` = `sort_idmaps()`). In C (`user_namespace_glue.c`): everything with capabilities, credentials, files, seq_file,
//! work queues and ucounts, the `make_k*id()` / `from_k*id()` family (one call into these lookups each), the exports as thunks (the MODVERSIONS fingerprint comes from the
//! DWARF of the definition), and one-line wrappers for what depends on configuration (`kmalloc_array()`, `kmemdup_array()`, `bsearch()`, the kernel's `isspace()` table).
//!
//! `struct uid_gid_map` is 64 bytes: `extent[5]` then `nr_extents` (offset 60), overlaid by `forward` (offset 0) and `reverse` (offset 8); its layout does not depend on the
//! configuration.
//!
//! Replaces: kernel/user_namespace.c (the lookup and map-building half)

use core::ffi::{c_char, c_int, c_ulong, c_void};
use core::ptr::{null_mut, read_volatile};
use core::sync::atomic::{fence, Ordering};

const MAX_BASE_EXTENTS: u32 = 5;
const MAX_EXTENTS: u32 = 340;
const EPERM: c_int = 1;
const ENOMEM: c_int = 12;
const EINVAL: c_int = 22;

/// Mirrors `struct uid_gid_extent`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Extent {
    first: u32,
    lower_first: u32,
    count: u32,
}

/// Mirrors `struct uid_gid_map` (the union is read through byte offsets, as the C reads it through its members).
#[repr(C)]
pub struct IdMap {
    extent: [Extent; 5],
    nr_extents: u32,
}

/// `struct idmap_key`.
#[repr(C)]
struct Key {
    map_up: bool,
    id: u32,
    count: u32,
}

type CmpFn = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;

extern "C" {
    fn rust_un_bsearch(key: *const c_void, base: *const c_void, num: usize, cmp: CmpFn) -> *mut c_void;
    fn rust_un_alloc_extents(n: usize) -> *mut Extent;
    fn rust_un_dup_extents(src: *const Extent, n: usize) -> *mut Extent;
    fn rust_un_isspace(c: c_char) -> bool;
    fn sort(base: *mut c_void, num: usize, size: usize, cmp: Option<CmpFn>, swap: *const c_void);
    fn skip_spaces(s: *const c_char) -> *mut c_char;
    fn strchr(s: *const c_char, c: c_int) -> *mut c_char;
    fn simple_strtoul(cp: *const c_char, endp: *mut *mut c_char, base: u32) -> c_ulong;
}

impl IdMap {
    unsafe fn forward(&self) -> *mut Extent {
        unsafe { read_volatile((self as *const IdMap as *const *mut Extent).add(0)) }
    }
    unsafe fn reverse(&self) -> *mut Extent {
        unsafe { read_volatile((self as *const IdMap as *const *mut Extent).add(1)) }
    }
    unsafe fn set_forward(&mut self, p: *mut Extent) {
        unsafe { (self as *mut IdMap as *mut *mut Extent).add(0).write(p) }
    }
    unsafe fn set_reverse(&mut self, p: *mut Extent) {
        unsafe { (self as *mut IdMap as *mut *mut Extent).add(1).write(p) }
    }
}

/// `cmp_map_id()`: the bsearch comparison; 0 when the whole requested range lies inside the element's range.
unsafe extern "C" fn cmp_map_id(k: *const c_void, e: *const c_void) -> c_int {
    let key = unsafe { &*(k as *const Key) };
    let el = unsafe { &*(e as *const Extent) };
    let id2 = key.id.wrapping_add(key.count).wrapping_sub(1);
    let first = if key.map_up { el.lower_first } else { el.first };
    let last = first.wrapping_add(el.count).wrapping_sub(1);
    if key.id >= first && key.id <= last && (id2 >= first && id2 <= last) {
        return 0;
    }
    if key.id < first || id2 < first {
        return -1;
    }
    1
}

/// `map_id_range_down_base()` / `map_id_range_up_base()`: scan of the inline extents.
unsafe fn find_base(extents: u32, map: &IdMap, id: u32, count: u32, up: bool) -> *const Extent {
    let id2 = id.wrapping_add(count).wrapping_sub(1);
    for idx in 0..extents as usize {
        let e = &map.extent[idx];
        let first = if up { e.lower_first } else { e.first };
        let last = first.wrapping_add(e.count).wrapping_sub(1);
        if id >= first && id <= last && (id2 >= first && id2 <= last) {
            return e;
        }
    }
    core::ptr::null()
}

unsafe fn find(map: &IdMap, id: u32, count: u32, up: bool) -> *const Extent {
    let extents = unsafe { read_volatile(&map.nr_extents) };
    fence(Ordering::Acquire); // smp_rmb()
    if extents <= MAX_BASE_EXTENTS {
        unsafe { find_base(extents, map, id, count, up) }
    } else {
        let key = Key { map_up: up, id, count };
        let base = if up { unsafe { map.reverse() } } else { unsafe { map.forward() } };
        unsafe { rust_un_bsearch(&key as *const Key as *const c_void, base as *const c_void, extents as usize, cmp_map_id) as *const Extent }
    }
}

/// Body of `map_id_range_down()` (static in C; `map_write()` uses it through `rust_userns_remap()`).
unsafe fn map_id_range_down(map: &IdMap, id: u32, count: u32) -> u32 {
    let e = unsafe { find(map, id, count, false) };
    if e.is_null() {
        u32::MAX
    } else {
        unsafe { id.wrapping_sub((*e).first).wrapping_add((*e).lower_first) }
    }
}

/// Body of `map_id_down()`.
#[no_mangle]
pub unsafe extern "C" fn rust_map_id_down(map: *mut IdMap, id: u32) -> u32 {
    unsafe { map_id_range_down(&*map, id, 1) }
}

/// Body of `map_id_range_up()`.
#[no_mangle]
pub unsafe extern "C" fn rust_map_id_range_up(map: *mut IdMap, id: u32, count: u32) -> u32 {
    let e = unsafe { find(&*map, id, count, true) };
    if e.is_null() {
        u32::MAX
    } else {
        unsafe { id.wrapping_sub((*e).lower_first).wrapping_add((*e).first) }
    }
}

/// Body of `map_id_up()`.
#[no_mangle]
pub unsafe extern "C" fn rust_map_id_up(map: *mut IdMap, id: u32) -> u32 {
    unsafe { rust_map_id_range_up(map, id, 1) }
}

/// `mappings_overlap()`.
unsafe fn mappings_overlap(new_map: &IdMap, extent: &Extent) -> bool {
    let upper_first = extent.first;
    let lower_first = extent.lower_first;
    let upper_last = upper_first.wrapping_add(extent.count).wrapping_sub(1);
    let lower_last = lower_first.wrapping_add(extent.count).wrapping_sub(1);
    for idx in 0..new_map.nr_extents as usize {
        let prev = if new_map.nr_extents <= MAX_BASE_EXTENTS { &new_map.extent[idx] } else { unsafe { &*new_map.forward().add(idx) } };
        let prev_upper_first = prev.first;
        let prev_lower_first = prev.lower_first;
        let prev_upper_last = prev_upper_first.wrapping_add(prev.count).wrapping_sub(1);
        let prev_lower_last = prev_lower_first.wrapping_add(prev.count).wrapping_sub(1);
        if prev_upper_first <= upper_last && prev_upper_last >= upper_first {
            return true;
        }
        if prev_lower_first <= lower_last && prev_lower_last >= lower_first {
            return true;
        }
    }
    false
}

/// `insert_extent()`: the sixth extent moves the map to a 340-entry heap array.
unsafe fn insert_extent(map: &mut IdMap, extent: &Extent) -> c_int {
    if map.nr_extents == MAX_BASE_EXTENTS {
        let forward = unsafe { rust_un_alloc_extents(MAX_EXTENTS as usize) };
        if forward.is_null() {
            return -ENOMEM;
        }
        unsafe { core::ptr::copy_nonoverlapping(map.extent.as_ptr(), forward, map.nr_extents as usize) };
        unsafe {
            map.set_forward(forward);
            map.set_reverse(null_mut());
        }
    }
    let dest = if map.nr_extents < MAX_BASE_EXTENTS { unsafe { map.extent.as_mut_ptr().add(map.nr_extents as usize) } } else { unsafe { map.forward().add(map.nr_extents as usize) } };
    unsafe { *dest = *extent };
    map.nr_extents += 1;
    0
}

unsafe extern "C" fn cmp_extents_forward(a: *const c_void, b: *const c_void) -> c_int {
    let (e1, e2) = unsafe { (&*(a as *const Extent), &*(b as *const Extent)) };
    if e1.first < e2.first {
        return -1;
    }
    if e1.first > e2.first {
        return 1;
    }
    0
}

unsafe extern "C" fn cmp_extents_reverse(a: *const c_void, b: *const c_void) -> c_int {
    let (e1, e2) = unsafe { (&*(a as *const Extent), &*(b as *const Extent)) };
    if e1.lower_first < e2.lower_first {
        return -1;
    }
    if e1.lower_first > e2.lower_first {
        return 1;
    }
    0
}

/// `sort_idmaps()`.
#[no_mangle]
pub unsafe extern "C" fn rust_userns_sort(map: *mut IdMap) -> c_int {
    let map = unsafe { &mut *map };
    if map.nr_extents <= MAX_BASE_EXTENTS {
        return 0;
    }
    let n = map.nr_extents as usize;
    unsafe { sort(map.forward() as *mut c_void, n, core::mem::size_of::<Extent>(), Some(cmp_extents_forward), core::ptr::null()) };
    let rev = unsafe { rust_un_dup_extents(map.forward(), n) };
    unsafe { map.set_reverse(rev) };
    if rev.is_null() {
        return -ENOMEM;
    }
    unsafe { sort(rev as *mut c_void, n, core::mem::size_of::<Extent>(), Some(cmp_extents_reverse), core::ptr::null()) };
    0
}

/// The parsing loop of `map_write()`. `kbuf` is the NUL-terminated user text (modified in place). Returns 0 with `new_map` filled, or the negative errno
/// (`-EINVAL` for any malformed line, `-ENOMEM` from the extent array); on failure `new_map` may hold a heap array, which the caller frees.
#[no_mangle]
pub unsafe extern "C" fn rust_userns_parse(kbuf: *mut c_char, new_map: *mut IdMap) -> c_int {
    let new_map = unsafe { &mut *new_map };
    let mut pos = kbuf;
    while !pos.is_null() {
        // Find the end of line and ensure I don't look past it.
        let mut next_line = unsafe { strchr(pos, b'\n' as c_int) };
        if !next_line.is_null() {
            unsafe { *next_line = 0 };
            next_line = unsafe { next_line.add(1) };
            if unsafe { *next_line } == 0 {
                next_line = null_mut();
            }
        }

        pos = unsafe { skip_spaces(pos) };
        let first = unsafe { simple_strtoul(pos, &mut pos, 10) } as u32;
        if !unsafe { rust_un_isspace(*pos) } {
            return -EINVAL;
        }
        pos = unsafe { skip_spaces(pos) };
        let lower_first = unsafe { simple_strtoul(pos, &mut pos, 10) } as u32;
        if !unsafe { rust_un_isspace(*pos) } {
            return -EINVAL;
        }
        pos = unsafe { skip_spaces(pos) };
        let count = unsafe { simple_strtoul(pos, &mut pos, 10) } as u32;
        if unsafe { *pos } != 0 && !unsafe { rust_un_isspace(*pos) } {
            return -EINVAL;
        }
        // Verify there is not trailing junk on the line.
        pos = unsafe { skip_spaces(pos) };
        if unsafe { *pos } != 0 {
            return -EINVAL;
        }
        // Verify we have been given valid starting values.
        if first == u32::MAX || lower_first == u32::MAX {
            return -EINVAL;
        }
        // Verify count is not zero and does not cause the extent to wrap.
        if first.wrapping_add(count) <= first {
            return -EINVAL;
        }
        if lower_first.wrapping_add(count) <= lower_first {
            return -EINVAL;
        }
        let extent = Extent { first, lower_first, count };
        // Do the ranges in extent overlap any previous extents?
        if unsafe { mappings_overlap(new_map, &extent) } {
            return -EINVAL;
        }
        if new_map.nr_extents + 1 == MAX_EXTENTS && !next_line.is_null() {
            return -EINVAL;
        }
        let r = unsafe { insert_extent(new_map, &extent) };
        if r < 0 {
            return r;
        }
        pos = next_line;
    }
    // Be very certain the new map actually exists.
    if new_map.nr_extents == 0 {
        return -EINVAL;
    }
    0
}

/// The translation loop of `map_write()`: each extent's lower ids go through the parent's map into kernel ids. 0, or `-EPERM` when one cannot be mapped.
#[no_mangle]
pub unsafe extern "C" fn rust_userns_remap(new_map: *mut IdMap, parent_map: *mut IdMap) -> c_int {
    let new_map = unsafe { &mut *new_map };
    for idx in 0..new_map.nr_extents as usize {
        let e = if new_map.nr_extents <= MAX_BASE_EXTENTS { unsafe { new_map.extent.as_mut_ptr().add(idx) } } else { unsafe { new_map.forward().add(idx) } };
        let lower_first = unsafe { map_id_range_down(&*parent_map, (*e).lower_first, (*e).count) };
        if lower_first == u32::MAX {
            return -EPERM;
        }
        unsafe { (*e).lower_first = lower_first };
    }
    0
}
