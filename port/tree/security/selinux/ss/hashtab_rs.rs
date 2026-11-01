// SPDX-License-Identifier: GPL-2.0

//! The SELinux generic hash table -- the Rust behind `security/selinux/ss/hashtab.c`.
//!
//! Ported from `security/selinux/ss/hashtab.c` (6.18.49): sizing and allocating the slot array (`hashtab_init`), linking a new node (`__hashtab_insert`), `hashtab_destroy`,
//! `hashtab_map` (apply a callback to every entry until one returns non-zero) and `hashtab_duplicate` (copy a table through caller callbacks, undoing it on failure). The lookup
//! and insert fast paths, `hashtab_insert()` / `hashtab_search()`, are header inlines taking the hash and compare functions by value; they stay C. In C (`hashtab_glue.c`): the
//! node cache and `hashtab_cache_init`, `hashtab_stat` (debug only) and `rust_ht_*` wrappers for the slab allocator and `kcalloc` / `kfree`.
//!
//! Replaces: security/selinux/ss/hashtab.c (everything except hashtab_cache_init and hashtab_stat)

use core::ffi::{c_int, c_void};
use core::ptr::null_mut;

const ENOMEM: c_int = 12;

/// `struct hashtab_node` (checked by the glue).
#[repr(C)]
pub struct Node {
    key: *mut c_void,
    datum: *mut c_void,
    next: *mut Node,
}

/// `struct hashtab`.
#[repr(C)]
pub struct Hashtab {
    htable: *mut *mut Node,
    size: u32,
    nel: u32,
}

const _: () = assert!(core::mem::size_of::<Node>() == 24 && core::mem::size_of::<Hashtab>() == 16);

extern "C" {
    /// `kmem_cache_zalloc(hashtab_node_cachep, GFP_KERNEL)`
    fn rust_ht_node_alloc() -> *mut Node;
    fn rust_ht_node_free(n: *mut Node);
    /// `kcalloc(n, sizeof(void *), GFP_KERNEL | __GFP_NOWARN)`
    fn rust_ht_kcalloc_nowarn(n: u32) -> *mut c_void;
    /// `kcalloc(n, sizeof(void *), GFP_KERNEL)`
    fn rust_ht_kcalloc(n: u32) -> *mut c_void;
    fn rust_ht_kfree(p: *mut c_void);
}

/// `hashtab_compute_size()`: `roundup_pow_of_two(nel)` stored in a `u32` (so 2^32 becomes 0).
fn hashtab_compute_size(nel: u32) -> u32 {
    if nel == 0 {
        0
    } else {
        (nel as u64).next_power_of_two() as u32
    }
}

/// `hashtab_init()`.
#[no_mangle]
pub unsafe extern "C" fn hashtab_init(h: *mut Hashtab, nel_hint: u32) -> c_int {
    unsafe {
        let size = hashtab_compute_size(nel_hint);

        // should already be zeroed, but better be safe
        (*h).nel = 0;
        (*h).size = 0;
        (*h).htable = null_mut();

        if size != 0 {
            (*h).htable = rust_ht_kcalloc_nowarn(size) as *mut *mut Node;
            if (*h).htable.is_null() {
                return -ENOMEM;
            }
            (*h).size = size;
        }
        0
    }
}

/// `__hashtab_insert()`: link a new node holding `key` / `datum` at `*dst`.
#[no_mangle]
pub unsafe extern "C" fn __hashtab_insert(h: *mut Hashtab, dst: *mut *mut Node, key: *mut c_void, datum: *mut c_void) -> c_int {
    unsafe {
        let newnode = rust_ht_node_alloc();
        if newnode.is_null() {
            return -ENOMEM;
        }
        (*newnode).key = key;
        (*newnode).datum = datum;
        (*newnode).next = *dst;
        *dst = newnode;

        (*h).nel += 1;
        0
    }
}

/// `hashtab_destroy()`.
#[no_mangle]
pub unsafe extern "C" fn hashtab_destroy(h: *mut Hashtab) {
    unsafe {
        let mut i = 0;
        while i < (*h).size {
            let mut cur = *(*h).htable.add(i as usize);
            while !cur.is_null() {
                let temp = cur;
                cur = (*cur).next;
                rust_ht_node_free(temp);
            }
            *(*h).htable.add(i as usize) = null_mut();
            i += 1;
        }

        rust_ht_kfree((*h).htable as *mut c_void);
        (*h).htable = null_mut();
    }
}

/// `hashtab_map()`.
#[no_mangle]
pub unsafe extern "C" fn hashtab_map(h: *mut Hashtab, apply: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> c_int, args: *mut c_void) -> c_int {
    unsafe {
        let mut i = 0;
        while i < (*h).size {
            let mut cur = *(*h).htable.add(i as usize);
            while !cur.is_null() {
                let ret = apply((*cur).key, (*cur).datum, args);
                if ret != 0 {
                    return ret;
                }
                cur = (*cur).next;
            }
            i += 1;
        }
        0
    }
}

/// `hashtab_duplicate()`.
#[no_mangle]
pub unsafe extern "C" fn hashtab_duplicate(
    new: *mut Hashtab,
    orig: *const Hashtab,
    copy: unsafe extern "C" fn(*mut Node, *const Node, *mut c_void) -> c_int,
    destroy: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> c_int,
    args: *mut c_void,
) -> c_int {
    unsafe {
        core::ptr::write_bytes(new as *mut u8, 0, core::mem::size_of::<Hashtab>());

        (*new).htable = rust_ht_kcalloc((*orig).size) as *mut *mut Node;
        if (*new).htable.is_null() {
            return -ENOMEM;
        }

        (*new).size = (*orig).size;

        let mut i = 0;
        'error: {
            while i < (*orig).size {
                let mut tail: *mut Node = null_mut();
                let mut orig_cur = *(*orig).htable.add(i as usize) as *const Node;
                while !orig_cur.is_null() {
                    let tmp = rust_ht_node_alloc();
                    if tmp.is_null() {
                        break 'error;
                    }
                    let rc = copy(tmp, orig_cur, args);
                    if rc != 0 {
                        rust_ht_node_free(tmp);
                        break 'error;
                    }
                    (*tmp).next = null_mut();
                    if tail.is_null() {
                        *(*new).htable.add(i as usize) = tmp;
                    } else {
                        (*tail).next = tmp;
                    }
                    tail = tmp;
                    (*new).nel += 1;
                    orig_cur = (*orig_cur).next;
                }
                i += 1;
            }

            return 0;
        }

        // error:
        let mut j = 0;
        while j < (*new).size {
            let mut cur = *(*new).htable.add(j as usize);
            while !cur.is_null() {
                let tmp = (*cur).next;
                destroy((*cur).key, (*cur).datum, args);
                rust_ht_node_free(cur);
                cur = tmp;
            }
            j += 1;
        }
        rust_ht_kfree((*new).htable as *mut c_void);
        core::ptr::write_bytes(new as *mut u8, 0, core::mem::size_of::<Hashtab>());
        -ENOMEM
    }
}
