// SPDX-License-Identifier: GPL-2.0

//! Range add and subtract -- the Rust behind `kernel/range.c`.
//!
//! Ported from `kernel/range.c` (6.18.49), "Range add and subtract". The file is
//! five plain functions over an array of `struct range { u64 start; u64 end; }`
//! (the callers -- e820/MTRR/PCI/mm init -- own the array). None has an
//! `EXPORT_SYMBOL`, a guard, a WARN or a static key, so no C entry stays.
//!
//! The one message, in `subtract_range()` ("%s: run out of slot in ranges\n",
//! `__func__` = "subtract_range", level KERN_ERR), is byte-identical to the C's
//! `pr_err()` (the file defines no `pr_fmt`, so the prefix is empty).
//! `clean_sort_range()`/`sort_range()` call the kernel's own `sort()` with the
//! same comparison and no swap function, as the C does.
//!
//! Replaces: kernel/range.c

use core::ffi::{c_char, c_int, c_void};

/// Mirrors `struct range` (`include/linux/range.h`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Range {
    start: u64,
    end: u64,
}

extern "C" {
    fn _printk(fmt: *const c_char, ...) -> c_int;
    fn sort(
        base: *mut c_void,
        num: usize,
        size: usize,
        cmp_func: Option<unsafe extern "C" fn(*const c_void, *const c_void) -> c_int>,
        swap_func: Option<unsafe extern "C" fn(*mut c_void, *mut c_void, c_int)>,
    );
}

/// `add_range()`: append `[start, end)` if there is room. Returns the new count.
///
/// # Safety
/// `range` must point to `az` writable entries, `nr_range <= az` of them in use.
#[no_mangle]
pub unsafe extern "C" fn add_range(range: *mut Range, az: c_int, nr_range: c_int, start: u64, end: u64) -> c_int {
    if start >= end {
        return nr_range;
    }

    /* Out of slots: */
    if nr_range >= az {
        return nr_range;
    }

    unsafe {
        (*range.offset(nr_range as isize)).start = start;
        (*range.offset(nr_range as isize)).end = end;
    }

    nr_range + 1
}

/// `add_range_with_merge()`: append `[start, end)`, merging any overlapping entry.
///
/// # Safety
/// As [`add_range`].
#[no_mangle]
pub unsafe extern "C" fn add_range_with_merge(
    range: *mut Range,
    az: c_int,
    nr_range: c_int,
    start: u64,
    end: u64,
) -> c_int {
    let (mut start, mut end, mut nr_range) = (start, end, nr_range);

    if start >= end {
        return nr_range;
    }

    /* get new start/end: */
    let mut i: c_int = 0;
    while i < nr_range {
        let ri = unsafe { range.offset(i as isize) };
        if unsafe { (*ri).end } == 0 {
            i += 1;
            continue;
        }

        let common_start = core::cmp::max(unsafe { (*ri).start }, start);
        let common_end = core::cmp::min(unsafe { (*ri).end }, end);
        if common_start > common_end {
            i += 1;
            continue;
        }

        /* new start/end, will add it back at last */
        start = core::cmp::min(unsafe { (*ri).start }, start);
        end = core::cmp::max(unsafe { (*ri).end }, end);

        unsafe {
            core::ptr::copy(
                ri.add(1),
                ri,
                (nr_range - (i + 1)) as usize,
            );
            (*range.offset((nr_range - 1) as isize)).start = 0;
            (*range.offset((nr_range - 1) as isize)).end = 0;
        }
        nr_range -= 1;
        i -= 1;
        i += 1;
    }

    /* Need to add it: */
    unsafe { add_range(range, az, nr_range, start, end) }
}

/// `subtract_range()`: remove `[start, end)` from every entry.
///
/// # Safety
/// `range` must point to `az` writable entries.
#[no_mangle]
pub unsafe extern "C" fn subtract_range(range: *mut Range, az: c_int, start: u64, end: u64) {
    if start >= end {
        return;
    }

    let mut j: c_int = 0;
    while j < az {
        let rj = unsafe { &mut *range.offset(j as isize) };
        j += 1;
        if rj.end == 0 {
            continue;
        }

        if start <= rj.start && end >= rj.end {
            rj.start = 0;
            rj.end = 0;
            continue;
        }

        if start <= rj.start && end < rj.end && rj.start < end {
            rj.start = end;
            continue;
        }

        if start > rj.start && end >= rj.end && rj.end > start {
            rj.end = start;
            continue;
        }

        if start > rj.start && end < rj.end {
            /* Find the new spare: */
            let mut i: c_int = 0;
            while i < az {
                if unsafe { (*range.offset(i as isize)).end } == 0 {
                    break;
                }
                i += 1;
            }
            if i < az {
                /* `rj` may alias entry `i`'s neighbour only, never entry i (end != 0 for j, == 0 for i) */
                let ri = unsafe { &mut *range.offset(i as isize) };
                ri.end = rj.end;
                ri.start = end;
            } else {
                unsafe {
                    _printk(
                        c"\x013%s: run out of slot in ranges\n".as_ptr(),
                        c"subtract_range".as_ptr(),
                    )
                };
            }
            rj.end = start;
            continue;
        }
    }
}

/// `cmp_range()`: order by `start`.
unsafe extern "C" fn cmp_range(x1: *const c_void, x2: *const c_void) -> c_int {
    let r1 = unsafe { &*(x1 as *const Range) };
    let r2 = unsafe { &*(x2 as *const Range) };

    if r1.start < r2.start {
        return -1;
    }
    if r1.start > r2.start {
        return 1;
    }
    0
}

/// `clean_sort_range()`: compact the array, then sort it. Returns the count in use.
///
/// # Safety
/// `range` must point to `az` writable entries.
#[no_mangle]
pub unsafe extern "C" fn clean_sort_range(range: *mut Range, az: c_int) -> c_int {
    let mut k: c_int = az - 1;
    let mut nr_range: c_int = az;
    let mut i: c_int = 0;

    while i < k {
        if unsafe { (*range.offset(i as isize)).end } != 0 {
            i += 1;
            continue;
        }
        let mut j: c_int = k;
        while j > i {
            if unsafe { (*range.offset(j as isize)).end } != 0 {
                k = j;
                break;
            }
            j -= 1;
        }
        if j == i {
            break;
        }
        unsafe {
            (*range.offset(i as isize)).start = (*range.offset(k as isize)).start;
            (*range.offset(i as isize)).end = (*range.offset(k as isize)).end;
            (*range.offset(k as isize)).start = 0;
            (*range.offset(k as isize)).end = 0;
        }
        k -= 1;
        i += 1;
    }
    /* count it */
    i = 0;
    while i < az {
        if unsafe { (*range.offset(i as isize)).end } == 0 {
            nr_range = i;
            break;
        }
        i += 1;
    }

    /* sort them */
    unsafe {
        sort(
            range as *mut c_void,
            nr_range as usize,
            core::mem::size_of::<Range>(),
            Some(cmp_range),
            None,
        )
    };

    nr_range
}

/// `sort_range()`: sort the first `nr_range` entries by `start`.
///
/// # Safety
/// `range` must point to `nr_range` writable entries.
#[no_mangle]
pub unsafe extern "C" fn sort_range(range: *mut Range, nr_range: c_int) {
    /* sort them */
    unsafe {
        sort(
            range as *mut c_void,
            nr_range as usize,
            core::mem::size_of::<Range>(),
            Some(cmp_range),
            None,
        )
    };
}
