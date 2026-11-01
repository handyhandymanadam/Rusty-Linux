// SPDX-License-Identifier: GPL-2.0-only

//! The ID allocator (IDA) half of `lib/idr.c` -- the Rust behind `ida_alloc_range`, `ida_find_first_range`, `ida_free` and `ida_destroy`.
//!
//! Ported from `lib/idr.c` (6.18.49). An IDA stores one bit per ID in an XArray whose entries are either a *value entry* (the low 63 bits of a
//! bitmap, tagged `(v << 1) | 1`) or a pointer to a 128-byte `struct ida_bitmap`; the `XA_FREE_MARK` is cleared only on a full bitmap. In Rust: the
//! four functions, the bit searches and the `xa_state` handling. In C (`idr_glue.c`): the exports as thunks (MODVERSIONS fingerprints come from the
//! DWARF of the definition), the IDR half (it sits on `lib/radix-tree.c`, which is not ported) verbatim, and one-line wrappers for what Rust cannot
//! express: `spin_lock_irqsave` on `xa->xa_lock` (the type depends on the configuration), `kzalloc`/`kfree` (allocation-profiling macros),
//! `xas_next_entry` (a header inline) and the `WARN` site.
//!
//! Replaces: lib/idr.c (the IDA functions; the IDR functions stay C)

use core::ffi::{c_int, c_ulong, c_void};
use core::ptr::null_mut;

const ENOMEM: c_int = 12;
const ENOSPC: c_int = 28;
const ENOENT: c_int = 2;
const EINVAL: c_int = 22;
const INT_MAX: u32 = 0x7fff_ffff;
const MAX_ERRNO: c_ulong = 4095;

/// `IDA_BITMAP_LONGS` (128 bytes of `unsigned long`).
const IDA_BITMAP_LONGS: usize = 16;
/// `IDA_BITMAP_BITS`.
const IDA_BITMAP_BITS: u32 = (IDA_BITMAP_LONGS * 64) as u32;
/// `BITS_PER_XA_VALUE`: a value entry keeps `BITS_PER_LONG - 1` bits.
const BITS_PER_XA_VALUE: u32 = 63;

/// `XA_FREE_MARK` (= `XA_MARK_0`).
const XA_FREE_MARK: u32 = 0;
/// `XA_PRESENT`.
const XA_PRESENT: u32 = 8;
/// `XAS_RESTART`.
const XAS_RESTART: *mut c_void = 3 as *mut c_void;

/// `struct ida_bitmap`.
#[repr(C)]
pub struct IdaBitmap {
    bitmap: [c_ulong; IDA_BITMAP_LONGS],
}

/// `struct xa_state` (checked against the C layout by `idr_glue.c`).
#[repr(C)]
pub struct XaState {
    xa: *mut c_void,
    xa_index: c_ulong,
    xa_shift: u8,
    xa_sibs: u8,
    xa_offset: u8,
    xa_pad: u8,
    xa_node: *mut c_void,
    xa_alloc: *mut c_void,
    xa_update: *mut c_void,
    xa_lru: *mut c_void,
}

extern "C" {
    // lib/xarray.c (exports)
    fn xas_find_marked(xas: *mut XaState, max: c_ulong, mark: u32) -> *mut c_void;
    fn xas_find(xas: *mut XaState, max: c_ulong) -> *mut c_void;
    fn xas_store(xas: *mut XaState, entry: *mut c_void) -> *mut c_void;
    fn xas_load(xas: *mut XaState) -> *mut c_void;
    fn xas_clear_mark(xas: *mut XaState, mark: u32);
    fn xas_set_mark(xas: *mut XaState, mark: u32);
    fn xas_nomem(xas: *mut XaState, gfp: u32) -> bool;
    fn xa_find(xa: *mut c_void, indexp: *mut c_ulong, max: c_ulong, filter: u32) -> *mut c_void;

    // idr_glue.c
    fn rust_ida_lock(xa: *mut c_void, flags: *mut c_ulong);
    fn rust_ida_unlock(xa: *mut c_void, flags: c_ulong);
    fn rust_ida_kzalloc(gfp: u32) -> *mut IdaBitmap;
    fn rust_ida_kzalloc_nowait() -> *mut IdaBitmap;
    fn rust_ida_kfree(p: *mut c_void);
    fn rust_ida_xas_next_entry(xas: *mut XaState, max: c_ulong) -> *mut c_void;
    fn rust_ida_warn_not_allocated(id: u32);
}

/// `index * IDA_BITMAP_BITS + bit`, wrapping like the C.
#[inline(always)]
fn id_of(index: c_ulong, bit: u32) -> c_ulong {
    index.wrapping_mul(IDA_BITMAP_BITS as c_ulong).wrapping_add(bit as c_ulong)
}

/// `xa_is_value()`.
#[inline(always)]
fn xa_is_value(entry: *mut c_void) -> bool {
    (entry as c_ulong) & 1 != 0
}

/// `xa_to_value()`.
#[inline(always)]
fn xa_to_value(entry: *mut c_void) -> c_ulong {
    (entry as c_ulong) >> 1
}

/// `xa_mk_value()`.
#[inline(always)]
fn xa_mk_value(v: c_ulong) -> *mut c_void {
    ((v << 1) | 1) as *mut c_void
}

/// `xa_err()`: the errno stored in `xa_node`, or 0.
#[inline(always)]
fn xas_error(xas: &XaState) -> c_int {
    let entry = xas.xa_node as c_ulong;
    // xa_is_internal() is (entry & 3) == 2; xa_mk_internal(-MAX_ERRNO) is ((-MAX_ERRNO) << 2) | 2.
    if entry & 3 == 2 && entry >= ((0 as c_ulong).wrapping_sub(MAX_ERRNO) << 2 | 2) {
        ((entry as i64) >> 2) as c_int
    } else {
        0
    }
}

/// `xas_set()`.
#[inline(always)]
fn xas_set(xas: &mut XaState, index: c_ulong) {
    xas.xa_index = index;
    xas.xa_node = XAS_RESTART;
}

/// `XA_STATE()`.
#[inline(always)]
fn xa_state(xa: *mut c_void, index: c_ulong) -> XaState {
    XaState {
        xa,
        xa_index: index,
        xa_shift: 0,
        xa_sibs: 0,
        xa_offset: 0,
        xa_pad: 0,
        xa_node: XAS_RESTART,
        xa_alloc: null_mut(),
        xa_update: null_mut(),
        xa_lru: null_mut(),
    }
}

/// `find_next_zero_bit()` over the low `size` bits of `words`; `size` if there is none at or after `start`.
fn find_next_zero_bit(words: &[c_ulong], size: u32, start: u32) -> u32 {
    let mut i = start;
    while i < size {
        if (words[(i / 64) as usize] >> (i % 64)) & 1 == 0 {
            return i;
        }
        i += 1;
    }
    size
}

/// `find_next_bit()`, likewise.
fn find_next_bit(words: &[c_ulong], size: u32, start: u32) -> u32 {
    let mut i = start;
    while i < size {
        if (words[(i / 64) as usize] >> (i % 64)) & 1 != 0 {
            return i;
        }
        i += 1;
    }
    size
}

/// `bitmap_full()` for a whole `ida_bitmap`.
fn bitmap_full(b: &IdaBitmap) -> bool {
    b.bitmap.iter().all(|w| *w == !0)
}

/// `bitmap_empty()` for a whole `ida_bitmap`.
fn bitmap_empty(b: &IdaBitmap) -> bool {
    b.bitmap.iter().all(|w| *w == 0)
}

/// How the body of the locked section of `ida_alloc_range()` ends: the labels `out`, `alloc` and `nospc` of the C.
enum Exit {
    Out,
    Alloc,
    NoSpc,
}

/// `ida_alloc_range()`.
#[no_mangle]
pub unsafe extern "C" fn rust_ida_alloc_range(xa: *mut c_void, min: u32, max: u32, gfp: u32) -> c_int {
    unsafe {
        let mut xas = xa_state(xa, (min / IDA_BITMAP_BITS) as c_ulong);
        let mut bit: u32 = min % IDA_BITMAP_BITS;
        let mut flags: c_ulong = 0;
        let mut bitmap: *mut c_void;
        let mut alloc: *mut IdaBitmap = null_mut();
        let mut max = max;

        if (min as i32) < 0 {
            return -ENOSPC;
        }
        if (max as i32) < 0 {
            max = INT_MAX;
        }

        'retry: loop {
            rust_ida_lock(xa, &mut flags);
            let exit = 'next: loop {
                bitmap = xas_find_marked(&mut xas, (max / IDA_BITMAP_BITS) as c_ulong, XA_FREE_MARK);
                if xas.xa_index > (min / IDA_BITMAP_BITS) as c_ulong {
                    bit = 0;
                }
                if id_of(xas.xa_index, bit) > max as c_ulong {
                    break 'next Exit::NoSpc;
                }

                if xa_is_value(bitmap) {
                    let tmp: [c_ulong; 1] = [xa_to_value(bitmap)];

                    if bit < BITS_PER_XA_VALUE {
                        bit = find_next_zero_bit(&tmp, BITS_PER_XA_VALUE, bit);
                        if id_of(xas.xa_index, bit) > max as c_ulong {
                            break 'next Exit::NoSpc;
                        }
                        if bit < BITS_PER_XA_VALUE {
                            let v = tmp[0] | (1 as c_ulong) << bit;
                            xas_store(&mut xas, xa_mk_value(v));
                            break 'next Exit::Out;
                        }
                    }
                    let mut b = alloc;
                    if b.is_null() {
                        b = rust_ida_kzalloc_nowait();
                    }
                    if b.is_null() {
                        break 'next Exit::Alloc;
                    }
                    (*b).bitmap[0] = tmp[0];
                    bitmap = b as *mut c_void;
                    xas_store(&mut xas, bitmap);
                    if xas_error(&xas) != 0 {
                        (*b).bitmap[0] = 0;
                        break 'next Exit::Out;
                    }
                }

                if !bitmap.is_null() {
                    let b = bitmap as *mut IdaBitmap;
                    bit = find_next_zero_bit(&(*b).bitmap, IDA_BITMAP_BITS, bit);
                    if id_of(xas.xa_index, bit) > max as c_ulong {
                        break 'next Exit::NoSpc;
                    }
                    if bit == IDA_BITMAP_BITS {
                        continue 'next;
                    }

                    (*b).bitmap[(bit / 64) as usize] |= (1 as c_ulong) << (bit % 64);
                    if bitmap_full(&*b) {
                        xas_clear_mark(&mut xas, XA_FREE_MARK);
                    }
                } else {
                    if bit < BITS_PER_XA_VALUE {
                        bitmap = xa_mk_value((1 as c_ulong) << bit);
                    } else {
                        let mut b = alloc;
                        if b.is_null() {
                            b = rust_ida_kzalloc_nowait();
                        }
                        if b.is_null() {
                            break 'next Exit::Alloc;
                        }
                        (*b).bitmap[(bit / 64) as usize] |= (1 as c_ulong) << (bit % 64);
                        bitmap = b as *mut c_void;
                    }
                    xas_store(&mut xas, bitmap);
                }
                break 'next Exit::Out;
            };

            match exit {
                Exit::Out => {
                    rust_ida_unlock(xa, flags);
                    if xas_nomem(&mut xas, gfp) {
                        xas.xa_index = (min / IDA_BITMAP_BITS) as c_ulong;
                        bit = min % IDA_BITMAP_BITS;
                        continue 'retry;
                    }
                    if bitmap != alloc as *mut c_void {
                        rust_ida_kfree(alloc as *mut c_void);
                    }
                    let err = xas_error(&xas);
                    if err != 0 {
                        return err;
                    }
                    return (id_of(xas.xa_index, bit)) as c_int;
                }
                Exit::Alloc => {
                    rust_ida_unlock(xa, flags);
                    alloc = rust_ida_kzalloc(gfp);
                    if alloc.is_null() {
                        return -ENOMEM;
                    }
                    xas_set(&mut xas, (min / IDA_BITMAP_BITS) as c_ulong);
                    bit = min % IDA_BITMAP_BITS;
                    continue 'retry;
                }
                Exit::NoSpc => {
                    rust_ida_unlock(xa, flags);
                    rust_ida_kfree(alloc as *mut c_void);
                    return -ENOSPC;
                }
            }
        }
    }
}

/// `ida_find_first_range()`.
#[no_mangle]
pub unsafe extern "C" fn rust_ida_find_first_range(xa: *mut c_void, min: u32, max: u32) -> c_int {
    unsafe {
        let mut index: c_ulong = (min / IDA_BITMAP_BITS) as c_ulong;
        let mut offset: u32 = min % IDA_BITMAP_BITS;
        let mut flags: c_ulong = 0;
        let mut max = max;

        if (min as i32) < 0 {
            return -EINVAL;
        }
        if (max as i32) < 0 {
            max = INT_MAX;
        }

        rust_ida_lock(xa, &mut flags);

        let entry = xa_find(xa, &mut index, (max / IDA_BITMAP_BITS) as c_ulong, XA_PRESENT);
        if entry.is_null() {
            rust_ida_unlock(xa, flags);
            return -ENOENT;
        }

        if index > (min / IDA_BITMAP_BITS) as c_ulong {
            offset = 0;
        }
        if id_of(index, offset) > max as c_ulong {
            rust_ida_unlock(xa, flags);
            return -ENOENT;
        }

        let tmp: [c_ulong; 1];
        let (words, size): (&[c_ulong], u32) = if xa_is_value(entry) {
            tmp = [xa_to_value(entry)];
            (&tmp, BITS_PER_XA_VALUE)
        } else {
            (&(*(entry as *mut IdaBitmap)).bitmap, IDA_BITMAP_BITS)
        };

        let bit = find_next_bit(words, size, offset);

        rust_ida_unlock(xa, flags);

        if bit == size || id_of(index, bit) > max as c_ulong {
            return -ENOENT;
        }

        (id_of(index, bit)) as c_int
    }
}

/// `ida_free()`.
#[no_mangle]
pub unsafe extern "C" fn rust_ida_free(xa: *mut c_void, id: u32) {
    unsafe {
        let mut xas = xa_state(xa, (id / IDA_BITMAP_BITS) as c_ulong);
        let bit: u32 = id % IDA_BITMAP_BITS;
        let mut flags: c_ulong = 0;

        if (id as i32) < 0 {
            return;
        }

        rust_ida_lock(xa, &mut flags);
        let bitmap = xas_load(&mut xas);

        let mut ok = true;
        if xa_is_value(bitmap) {
            let mut v = xa_to_value(bitmap);
            if bit >= BITS_PER_XA_VALUE {
                ok = false;
            } else if v & ((1 as c_ulong) << bit) == 0 {
                ok = false;
            } else {
                v &= !((1 as c_ulong) << bit);
                if v == 0 {
                    xas_store(&mut xas, null_mut());
                } else {
                    xas_store(&mut xas, xa_mk_value(v));
                }
            }
        } else {
            let b = bitmap as *mut IdaBitmap;
            if b.is_null() || (*b).bitmap[(bit / 64) as usize] >> (bit % 64) & 1 == 0 {
                ok = false;
            } else {
                (*b).bitmap[(bit / 64) as usize] &= !((1 as c_ulong) << (bit % 64));
                xas_set_mark(&mut xas, XA_FREE_MARK);
                if bitmap_empty(&*b) {
                    rust_ida_kfree(b as *mut c_void);
                    xas_store(&mut xas, null_mut());
                }
            }
        }
        rust_ida_unlock(xa, flags);
        if !ok {
            rust_ida_warn_not_allocated(id);
        }
    }
}

/// `ida_destroy()`.
#[no_mangle]
pub unsafe extern "C" fn rust_ida_destroy(xa: *mut c_void) {
    unsafe {
        let mut xas = xa_state(xa, 0);
        let mut flags: c_ulong = 0;

        rust_ida_lock(xa, &mut flags);
        let mut bitmap = xas_find(&mut xas, c_ulong::MAX);
        while !bitmap.is_null() {
            if !xa_is_value(bitmap) {
                rust_ida_kfree(bitmap);
            }
            xas_store(&mut xas, null_mut());
            bitmap = rust_ida_xas_next_entry(&mut xas, c_ulong::MAX);
        }
        rust_ida_unlock(xa, flags);
    }
}
