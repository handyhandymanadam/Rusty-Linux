// SPDX-License-Identifier: GPL-2.0

//! The SELinux symbol table -- the Rust behind `security/selinux/ss/symtab.c`.
//!
//! Ported from `security/selinux/ss/symtab.c` (6.18.49): a hash table keyed on NUL-terminated names with the djb2a hash and `strcmp` ordering. `symtab_insert()` and
//! `symtab_search()` are `hashtab_insert()` / `hashtab_search()` (header inlines) with those two functions, written out here; `__hashtab_insert()` and `hashtab_init()` are the Rust of
//! `hashtab_rs.rs`. In C (`symtab_glue.c`): only the layout checks and the `cond_resched()` wrapper.
//!
//! Replaces: security/selinux/ss/symtab.c

use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;

const EEXIST: c_int = 17;
const EINVAL: c_int = 22;

/// `struct hashtab_node`.
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

/// `struct symtab`.
#[repr(C)]
pub struct Symtab {
    table: Hashtab,
    nprim: u32,
}

extern "C" {
    fn hashtab_init(h: *mut Hashtab, nel_hint: u32) -> c_int;
    fn __hashtab_insert(h: *mut Hashtab, dst: *mut *mut Node, key: *mut c_void, datum: *mut c_void) -> c_int;
    /// `cond_resched()`
    fn rust_st_cond_resched();
}

/// `symhash()`: djb2a.
unsafe fn symhash(key: *const c_char) -> u32 {
    unsafe {
        let mut hash: u32 = 5381;
        let mut p = key as *const u8;
        while *p != 0 {
            hash = ((hash << 5).wrapping_add(hash)) ^ (*p as u32);
            p = p.add(1);
        }
        hash
    }
}

/// `symcmp()`: the sign of `strcmp()`.
unsafe fn symcmp(key1: *const c_char, key2: *const c_char) -> c_int {
    unsafe {
        let mut a = key1 as *const u8;
        let mut b = key2 as *const u8;
        loop {
            if *a != *b {
                return *a as c_int - *b as c_int;
            }
            if *a == 0 {
                return 0;
            }
            a = a.add(1);
            b = b.add(1);
        }
    }
}

/// `symtab_init()`.
#[no_mangle]
pub unsafe extern "C" fn symtab_init(s: *mut Symtab, size: u32) -> c_int {
    unsafe {
        (*s).nprim = 0;
        hashtab_init(&mut (*s).table, size)
    }
}

/// `symtab_insert()`: `hashtab_insert()` with the symbol hash and compare.
#[no_mangle]
pub unsafe extern "C" fn symtab_insert(s: *mut Symtab, name: *mut c_char, datum: *mut c_void) -> c_int {
    unsafe {
        let h = &mut (*s).table as *mut Hashtab;

        rust_st_cond_resched();

        if (*h).size == 0 || (*h).nel == u32::MAX {
            return -EINVAL;
        }

        let hvalue = symhash(name) & ((*h).size - 1);
        let mut prev: *mut Node = null_mut();
        let mut cur = *(*h).htable.add(hvalue as usize);
        while !cur.is_null() {
            let cmp = symcmp(name, (*cur).key as *const c_char);

            if cmp == 0 {
                return -EEXIST;
            }
            if cmp < 0 {
                break;
            }
            prev = cur;
            cur = (*cur).next;
        }

        let dst = if !prev.is_null() { &mut (*prev).next as *mut *mut Node } else { (*h).htable.add(hvalue as usize) };
        __hashtab_insert(h, dst, name as *mut c_void, datum)
    }
}

/// `symtab_search()`: `hashtab_search()` with the symbol hash and compare.
#[no_mangle]
pub unsafe extern "C" fn symtab_search(s: *mut Symtab, name: *const c_char) -> *mut c_void {
    unsafe {
        let h = &mut (*s).table as *mut Hashtab;

        if (*h).size == 0 {
            return null_mut();
        }

        let hvalue = symhash(name) & ((*h).size - 1);
        let mut cur = *(*h).htable.add(hvalue as usize);
        while !cur.is_null() {
            let cmp = symcmp(name, (*cur).key as *const c_char);

            if cmp == 0 {
                return (*cur).datum;
            }
            if cmp < 0 {
                break;
            }
            cur = (*cur).next;
        }
        null_mut()
    }
}
