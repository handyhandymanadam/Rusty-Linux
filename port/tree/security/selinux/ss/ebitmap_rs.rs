// SPDX-License-Identifier: GPL-2.0

//! The SELinux extensible bitmap -- the Rust behind `security/selinux/ss/ebitmap.c`.
//!
//! Ported from `security/selinux/ss/ebitmap.c` (6.18.49, Stephen Smalley): a bitmap kept as a sorted singly linked list of fixed-size nodes, each covering `EBITMAP_SIZE` (384)
//! bits from an aligned start bit. In Rust (the symbols keep their C names, nothing here is exported to modules): `ebitmap_equal`, `ebitmap_cpy`, `ebitmap_and`, `ebitmap_contains`,
//! `ebitmap_get_bit`, `ebitmap_set_bit`, `ebitmap_destroy`, `ebitmap_read`, `ebitmap_write` and `ebitmap_hash`, with the header's iteration helpers (`ebitmap_start_positive`,
//! `ebitmap_next_positive`) and the `find_first_bit` / `find_next_bit` calls they make re-written over the six map words of a node. In C (`ebitmap_glue.c`): the node cache and
//! `ebitmap_cache_init`, the NetLabel import and export, and one-line wrappers for the slab allocator, `jhash`, `pr_err` and `BUG`.
//!
//! The integer types follow the C expressions: `EBITMAP_SIZE` is an `unsigned long`, so `startbit + EBITMAP_SIZE` is a 64-bit sum that does not wrap, while a store of it into the
//! 32-bit `highbit` truncates; `bit - startbit` and the `rounddown` / `roundup` of the writer are 32-bit and wrap.
//!
//! Replaces: security/selinux/ss/ebitmap.c (everything except ebitmap_netlbl_export, ebitmap_netlbl_import and ebitmap_cache_init)

use core::ffi::{c_int, c_void};
use core::ptr::null_mut;

const ENOMEM: c_int = 12;
const EINVAL: c_int = 22;

/// `EBITMAP_UNIT_NUMS` on a 64-bit kernel: (64 - 8 - 4) / 8.
const UNIT_NUMS: usize = 6;
/// `EBITMAP_UNIT_SIZE` (`BITS_PER_LONG`).
const UNIT_SIZE: u32 = 64;
/// `EBITMAP_SIZE`, an `unsigned long`.
const SIZE: u64 = UNIT_NUMS as u64 * UNIT_SIZE as u64;
/// `BITS_PER_U64`.
const BITS_PER_U64: u32 = 64;

/// `struct ebitmap_node` (checked by `ebitmap_glue.c`).
#[repr(C)]
pub struct Node {
    next: *mut Node,
    maps: [u64; UNIT_NUMS],
    startbit: u32,
}

/// `struct ebitmap`.
#[repr(C)]
pub struct Ebitmap {
    node: *mut Node,
    highbit: u32,
}

/// `struct policy_file`.
#[repr(C)]
pub struct PolicyFile {
    data: *mut u8,
    len: usize,
}

const _: () = assert!(core::mem::size_of::<Node>() == 64 && core::mem::size_of::<Ebitmap>() == 16);

extern "C" {
    /// `kmem_cache_zalloc(ebitmap_node_cachep, atomic ? GFP_ATOMIC : GFP_KERNEL)`
    fn rust_eb_node_alloc(atomic: c_int) -> *mut c_void;
    /// `kmem_cache_free(ebitmap_node_cachep, n)`
    fn rust_eb_node_free(n: *mut c_void);
    fn rust_eb_jhash_1word(a: u32, initval: u32) -> u32;
    fn rust_eb_jhash(key: *const c_void, length: u32, initval: u32) -> u32;
    /// The `pr_err()` calls of `ebitmap_read()`, by number (see the glue for the texts).
    fn rust_eb_err(which: c_int, a: u32, b: u32, c: u64);
    /// `BUG()`
    fn rust_eb_bug() -> !;
}

/// Messages of `rust_eb_err`.
const ERR_MAPSIZE: c_int = 0;
const ERR_TRUNCATED: c_int = 1;
const ERR_START_ALIGN: c_int = 2;
const ERR_START_BEYOND: c_int = 3;
const ERR_OOM: c_int = 4;
const ERR_START_ORDER: c_int = 5;
const ERR_EMPTY: c_int = 6;
const ERR_HIGHBIT: c_int = 7;

/// `find_first_bit(maps, EBITMAP_SIZE)`: the lowest set bit, or `SIZE` if none.
fn find_first_bit(maps: &[u64; UNIT_NUMS]) -> u64 {
    find_next_bit(maps, 0)
}

/// `find_next_bit(maps, EBITMAP_SIZE, offset)`.
fn find_next_bit(maps: &[u64; UNIT_NUMS], offset: u64) -> u64 {
    if offset >= SIZE {
        return SIZE;
    }
    let mut w = (offset / 64) as usize;
    let mut cur = maps[w] & (!0u64 << (offset % 64));
    loop {
        if cur != 0 {
            return w as u64 * 64 + cur.trailing_zeros() as u64;
        }
        w += 1;
        if w == UNIT_NUMS {
            return SIZE;
        }
        cur = maps[w];
    }
}

/// `ebitmap_start_positive()`.
unsafe fn start_positive(e: *const Ebitmap, n: &mut *mut Node) -> u32 {
    unsafe {
        *n = (*e).node;
        while !(*n).is_null() {
            let ofs = find_first_bit(&(**n).maps);
            if ofs < SIZE {
                return (**n).startbit.wrapping_add(ofs as u32);
            }
            *n = (**n).next;
        }
        (*e).highbit
    }
}

/// `ebitmap_next_positive()`.
unsafe fn next_positive(e: *const Ebitmap, n: &mut *mut Node, bit: u32) -> u32 {
    unsafe {
        let ofs = find_next_bit(&(**n).maps, bit.wrapping_sub((**n).startbit).wrapping_add(1) as u64);
        if ofs < SIZE {
            return (ofs as u32).wrapping_add((**n).startbit);
        }
        *n = (**n).next;
        while !(*n).is_null() {
            let ofs = find_first_bit(&(**n).maps);
            if ofs < SIZE {
                return (ofs as u32).wrapping_add((**n).startbit);
            }
            *n = (**n).next;
        }
        (*e).highbit
    }
}

/// `EBITMAP_NODE_INDEX`, `EBITMAP_NODE_OFFSET` (both 32-bit) with the `BUG_ON(index >= EBITMAP_UNIT_NUMS)` of the callers.
unsafe fn index_offset(n: *const Node, bit: u32) -> (usize, u32) {
    unsafe {
        let d = bit.wrapping_sub((*n).startbit);
        let index = d / UNIT_SIZE;
        if index as usize >= UNIT_NUMS {
            rust_eb_bug();
        }
        (index as usize, d % UNIT_SIZE)
    }
}

/// `ebitmap_node_get_bit()`.
unsafe fn node_get_bit(n: *const Node, bit: u32) -> c_int {
    unsafe {
        let (index, ofs) = index_offset(n, bit);
        ((*n).maps[index] & (1u64 << ofs) != 0) as c_int
    }
}

/// `ebitmap_node_set_bit()`.
unsafe fn node_set_bit(n: *mut Node, bit: u32) {
    unsafe {
        let (index, ofs) = index_offset(n, bit);
        (*n).maps[index] |= 1u64 << ofs;
    }
}

/// `ebitmap_node_clr_bit()`.
unsafe fn node_clr_bit(n: *mut Node, bit: u32) {
    unsafe {
        let (index, ofs) = index_offset(n, bit);
        (*n).maps[index] &= !(1u64 << ofs);
    }
}

/// `ebitmap_init()`.
unsafe fn init(e: *mut Ebitmap) {
    unsafe {
        (*e).node = null_mut();
        (*e).highbit = 0;
    }
}

/// `ebitmap_equal()`.
#[no_mangle]
pub unsafe extern "C" fn ebitmap_equal(e1: *const Ebitmap, e2: *const Ebitmap) -> bool {
    unsafe {
        if (*e1).highbit != (*e2).highbit {
            return false;
        }
        let mut n1 = (*e1).node;
        let mut n2 = (*e2).node;
        while !n1.is_null() && !n2.is_null() && (*n1).startbit == (*n2).startbit && (*n1).maps == (*n2).maps {
            n1 = (*n1).next;
            n2 = (*n2).next;
        }
        !(!n1.is_null() || !n2.is_null())
    }
}

/// `ebitmap_cpy()`.
#[no_mangle]
pub unsafe extern "C" fn ebitmap_cpy(dst: *mut Ebitmap, src: *const Ebitmap) -> c_int {
    unsafe {
        init(dst);
        let mut n = (*src).node;
        let mut prev: *mut Node = null_mut();
        while !n.is_null() {
            let new = rust_eb_node_alloc(1) as *mut Node;
            if new.is_null() {
                ebitmap_destroy(dst);
                return -ENOMEM;
            }
            (*new).startbit = (*n).startbit;
            (*new).maps = (*n).maps;
            (*new).next = null_mut();
            if !prev.is_null() {
                (*prev).next = new;
            } else {
                (*dst).node = new;
            }
            prev = new;
            n = (*n).next;
        }
        (*dst).highbit = (*src).highbit;
        0
    }
}

/// `ebitmap_and()`.
#[no_mangle]
pub unsafe extern "C" fn ebitmap_and(dst: *mut Ebitmap, e1: *const Ebitmap, e2: *const Ebitmap) -> c_int {
    unsafe {
        let mut n: *mut Node = null_mut();
        init(dst);
        let mut bit = start_positive(e1, &mut n);
        while bit < (*e1).highbit {
            if ebitmap_get_bit(e2, bit) != 0 {
                let rc = ebitmap_set_bit(dst, bit, 1);
                if rc < 0 {
                    return rc;
                }
            }
            bit = next_positive(e1, &mut n, bit);
        }
        0
    }
}

/// `ebitmap_contains()`.
#[no_mangle]
pub unsafe extern "C" fn ebitmap_contains(e1: *const Ebitmap, e2: *const Ebitmap, last_e2bit: u32) -> c_int {
    unsafe {
        if (*e1).highbit < (*e2).highbit {
            return 0;
        }
        let mut n1 = (*e1).node;
        let mut n2 = (*e2).node;
        while !n1.is_null() && !n2.is_null() && (*n1).startbit <= (*n2).startbit {
            if (*n1).startbit < (*n2).startbit {
                n1 = (*n1).next;
                continue;
            }
            // Skip trailing NULL map entries
            let mut i: i32 = UNIT_NUMS as i32 - 1;
            while i >= 0 && (*n2).maps[i as usize] == 0 {
                i -= 1;
            }
            if last_e2bit != 0 && i >= 0 {
                let fls = 63 - (*n2).maps[i as usize].leading_zeros();
                let lastsetbit = (*n2).startbit.wrapping_add((i as u32).wrapping_mul(UNIT_SIZE)).wrapping_add(fls);
                if lastsetbit > last_e2bit {
                    return 0;
                }
            }
            while i >= 0 {
                if (*n1).maps[i as usize] & (*n2).maps[i as usize] != (*n2).maps[i as usize] {
                    return 0;
                }
                i -= 1;
            }
            n1 = (*n1).next;
            n2 = (*n2).next;
        }
        if !n2.is_null() {
            return 0;
        }
        1
    }
}

/// `ebitmap_get_bit()`.
#[no_mangle]
pub unsafe extern "C" fn ebitmap_get_bit(e: *const Ebitmap, bit: u32) -> c_int {
    unsafe {
        if (*e).highbit < bit {
            return 0;
        }
        let mut n = (*e).node;
        while !n.is_null() && (*n).startbit <= bit {
            if (*n).startbit as u64 + SIZE > bit as u64 {
                return node_get_bit(n, bit);
            }
            n = (*n).next;
        }
        0
    }
}

/// `ebitmap_set_bit()`.
#[no_mangle]
pub unsafe extern "C" fn ebitmap_set_bit(e: *mut Ebitmap, bit: u32, value: c_int) -> c_int {
    unsafe {
        let mut prev: *mut Node = null_mut();
        let mut n = (*e).node;
        while !n.is_null() && (*n).startbit <= bit {
            if (*n).startbit as u64 + SIZE > bit as u64 {
                if value != 0 {
                    node_set_bit(n, bit);
                } else {
                    node_clr_bit(n, bit);

                    let s = find_first_bit(&(*n).maps);
                    if s < SIZE {
                        return 0;
                    }

                    // drop this node from the bitmap
                    if (*n).next.is_null() {
                        // this was the highest map within the bitmap
                        if !prev.is_null() {
                            (*e).highbit = ((*prev).startbit as u64 + SIZE) as u32;
                        } else {
                            (*e).highbit = 0;
                        }
                    }
                    if !prev.is_null() {
                        (*prev).next = (*n).next;
                    } else {
                        (*e).node = (*n).next;
                    }
                    rust_eb_node_free(n as *mut c_void);
                }
                return 0;
            }
            prev = n;
            n = (*n).next;
        }

        if value == 0 {
            return 0;
        }

        let new = rust_eb_node_alloc(1) as *mut Node;
        if new.is_null() {
            return -ENOMEM;
        }

        (*new).startbit = (bit as u64 - (bit as u64 % SIZE)) as u32;
        node_set_bit(new, bit);

        if n.is_null() {
            // this node will be the highest map within the bitmap
            (*e).highbit = ((*new).startbit as u64 + SIZE) as u32;
        }

        if !prev.is_null() {
            (*new).next = (*prev).next;
            (*prev).next = new;
        } else {
            (*new).next = (*e).node;
            (*e).node = new;
        }
        0
    }
}

/// `ebitmap_destroy()`.
#[no_mangle]
pub unsafe extern "C" fn ebitmap_destroy(e: *mut Ebitmap) {
    unsafe {
        if e.is_null() {
            return;
        }
        let mut n = (*e).node;
        while !n.is_null() {
            let temp = n;
            n = (*n).next;
            rust_eb_node_free(temp as *mut c_void);
        }
        (*e).highbit = 0;
        (*e).node = null_mut();
    }
}

/// `next_entry()` of policydb.h.
unsafe fn next_entry(buf: *mut u8, fp: *mut PolicyFile, bytes: usize) -> c_int {
    unsafe {
        if bytes > (*fp).len {
            return -EINVAL;
        }
        core::ptr::copy_nonoverlapping((*fp).data, buf, bytes);
        (*fp).data = (*fp).data.add(bytes);
        (*fp).len -= bytes;
        0
    }
}

/// `put_entry()` of policydb.h.
unsafe fn put_entry(buf: *const u8, bytes: usize, num: usize, fp: *mut PolicyFile) -> c_int {
    unsafe {
        let len = match bytes.checked_mul(num) {
            Some(l) => l,
            None => return -EINVAL,
        };
        if len > (*fp).len {
            return -EINVAL;
        }
        core::ptr::copy_nonoverlapping(buf, (*fp).data, len);
        (*fp).data = (*fp).data.add(len);
        (*fp).len -= len;
        0
    }
}

/// `ebitmap_read()`.
#[no_mangle]
pub unsafe extern "C" fn ebitmap_read(e: *mut Ebitmap, fp: *mut PolicyFile) -> c_int {
    unsafe {
        let mut n: *mut Node = null_mut();
        let mut buf = [0u32; 3];
        let mut rc: c_int;

        init(e);

        rc = next_entry(buf.as_mut_ptr() as *mut u8, fp, 12);
        if rc < 0 {
            return rc;
        }

        let mapunit = u32::from_le(buf[0]);
        (*e).highbit = u32::from_le(buf[1]);
        let count = u32::from_le(buf[2]);

        'bad: {
            if mapunit != BITS_PER_U64 {
                rust_eb_err(ERR_MAPSIZE, mapunit, BITS_PER_U64, (*e).highbit as u64);
                break 'bad;
            }

            // round up e->highbit
            (*e).highbit = ((*e).highbit as u64 + (SIZE - 1)) as u32;
            (*e).highbit = ((*e).highbit as u64 - ((*e).highbit as u64 % SIZE)) as u32;

            if (*e).highbit == 0 {
                (*e).node = null_mut();
                return 0;
            }

            if (*e).highbit != 0 && count == 0 {
                break 'bad;
            }

            for _ in 0..count {
                let mut start_le: u32 = 0;
                rc = next_entry(&mut start_le as *mut u32 as *mut u8, fp, 4);
                if rc < 0 {
                    rust_eb_err(ERR_TRUNCATED, 0, 0, 0);
                    break 'bad;
                }
                let startbit = u32::from_le(start_le);

                if startbit & (mapunit - 1) != 0 {
                    rust_eb_err(ERR_START_ALIGN, startbit, mapunit, 0);
                    break 'bad;
                }
                if startbit > (*e).highbit.wrapping_sub(mapunit) {
                    rust_eb_err(ERR_START_BEYOND, startbit, (*e).highbit.wrapping_sub(mapunit), 0);
                    break 'bad;
                }

                if n.is_null() || startbit as u64 >= (*n).startbit as u64 + SIZE {
                    let tmp = rust_eb_node_alloc(0) as *mut Node;
                    if tmp.is_null() {
                        rust_eb_err(ERR_OOM, 0, 0, 0);
                        rc = -ENOMEM;
                        break 'bad;
                    }
                    // round down
                    (*tmp).startbit = (startbit as u64 - (startbit as u64 % SIZE)) as u32;
                    if !n.is_null() {
                        (*n).next = tmp;
                    } else {
                        (*e).node = tmp;
                    }
                    n = tmp;
                } else if startbit <= (*n).startbit {
                    rust_eb_err(ERR_START_ORDER, startbit, (*n).startbit, 0);
                    break 'bad;
                }

                let mut map_le: u64 = 0;
                rc = next_entry(&mut map_le as *mut u64 as *mut u8, fp, 8);
                if rc < 0 {
                    rust_eb_err(ERR_TRUNCATED, 0, 0, 0);
                    break 'bad;
                }
                let mut map = u64::from_le(map_le);
                if map == 0 {
                    rust_eb_err(ERR_EMPTY, 0, 0, 0);
                    break 'bad;
                }

                let mut index = (startbit.wrapping_sub((*n).startbit) / UNIT_SIZE) as usize;
                while map != 0 {
                    (*n).maps[index] = map;
                    index += 1;
                    // EBITMAP_SHIFT_UNIT_SIZE(map): (map >> 32) >> 32
                    map = (map >> 32) >> 32;
                }
            }

            if !n.is_null() && (*n).startbit as u64 + SIZE != (*e).highbit as u64 {
                rust_eb_err(ERR_HIGHBIT, (*e).highbit, 0, (*n).startbit as u64 + SIZE);
                break 'bad;
            }

            return 0;
        }

        // bad:
        if rc == 0 {
            rc = -EINVAL;
        }
        ebitmap_destroy(e);
        rc
    }
}

/// `rounddown(bit, BITS_PER_U64)` on a `u32`.
fn rounddown64(bit: u32) -> u32 {
    bit - bit % BITS_PER_U64
}

/// `roundup(bit + 1, BITS_PER_U64)` on a `u32` (the C sum wraps).
fn roundup64_next(bit: u32) -> u32 {
    (bit.wrapping_add(1).wrapping_add(BITS_PER_U64 - 1) / BITS_PER_U64).wrapping_mul(BITS_PER_U64)
}

/// `ebitmap_write()`.
#[no_mangle]
pub unsafe extern "C" fn ebitmap_write(e: *const Ebitmap, fp: *mut PolicyFile) -> c_int {
    unsafe {
        let mut n: *mut Node = null_mut();
        let mut buf = [0u32; 3];

        buf[0] = BITS_PER_U64.to_le();

        let mut count: u32 = 0;
        let mut last_bit: u32 = 0;
        let mut last_startbit: u32 = u32::MAX;
        let mut bit = start_positive(e, &mut n);
        while bit < (*e).highbit {
            if last_startbit == u32::MAX || rounddown64(bit) > last_startbit {
                count = count.wrapping_add(1);
                last_startbit = rounddown64(bit);
            }
            last_bit = roundup64_next(bit);
            bit = next_positive(e, &mut n, bit);
        }
        buf[1] = last_bit.to_le();
        buf[2] = count.to_le();

        let rc = put_entry(buf.as_ptr() as *const u8, 4, 3, fp);
        if rc != 0 {
            return rc;
        }

        let mut map: u64 = 0;
        last_startbit = u32::MAX;
        bit = start_positive(e, &mut n);
        while bit < (*e).highbit {
            if last_startbit == u32::MAX || rounddown64(bit) > last_startbit {
                // this is the very first bit
                if map == 0 {
                    last_startbit = rounddown64(bit);
                    map = 1u64 << (bit - last_startbit);
                    bit = next_positive(e, &mut n, bit);
                    continue;
                }

                // write the last node
                buf[0] = last_startbit.to_le();
                let rc = put_entry(buf.as_ptr() as *const u8, 4, 1, fp);
                if rc != 0 {
                    return rc;
                }

                let buf64 = map.to_le();
                let rc = put_entry(&buf64 as *const u64 as *const u8, 8, 1, fp);
                if rc != 0 {
                    return rc;
                }

                // set up for the next node
                map = 0;
                last_startbit = rounddown64(bit);
            }
            map |= 1u64 << (bit - last_startbit);
            bit = next_positive(e, &mut n, bit);
        }
        // write the last node
        if map != 0 {
            buf[0] = last_startbit.to_le();
            let rc = put_entry(buf.as_ptr() as *const u8, 4, 1, fp);
            if rc != 0 {
                return rc;
            }

            let buf64 = map.to_le();
            let rc = put_entry(&buf64 as *const u64 as *const u8, 8, 1, fp);
            if rc != 0 {
                return rc;
            }
        }
        0
    }
}

/// `ebitmap_hash()`.
#[no_mangle]
pub unsafe extern "C" fn ebitmap_hash(e: *const Ebitmap, hash: u32) -> u32 {
    unsafe {
        // need to change hash even if ebitmap is empty
        let mut hash = rust_eb_jhash_1word((*e).highbit, hash);
        let mut node = (*e).node;
        while !node.is_null() {
            hash = rust_eb_jhash_1word((*node).startbit, hash);
            hash = rust_eb_jhash((*node).maps.as_ptr() as *const c_void, core::mem::size_of::<[u64; UNIT_NUMS]>() as u32, hash);
            node = (*node).next;
        }
        hash
    }
}
