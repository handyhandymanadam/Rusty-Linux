// SPDX-License-Identifier: GPL-2.0-only

//! The SELinux access vector table -- the Rust behind `security/selinux/ss/avtab.c`.
//!
//! Ported from `security/selinux/ss/avtab.c` (6.18.49, Stephen Smalley et al.): a hash table of (source type, target type, target class, specifier) keys kept in sorted chains,
//! with the MurmurHash3-style hash, ordered insert (unique and non-unique), search and search-next, allocation sizing, destroy, and the policy file reader / writer including the
//! pre-version-20 combined format. In C (`avtab_glue.c`): the two slab caches and `avtab_cache_init`, `avtab_hash_eval` (debug only), and `rust_av_*` wrappers for the slab
//! allocator, `kvcalloc` / `kvfree`, the `policydb` validity checks and version, the `pr_err` texts and the warn-once xperm message.
//!
//! `pr_debug("... avtab hash slots ...")` in `avtab_alloc()` is not carried over (it is off unless dynamic debug is switched on for that call site).
//!
//! Replaces: security/selinux/ss/avtab.c (everything except avtab_cache_init and avtab_hash_eval)

use core::ffi::{c_int, c_void};
use core::ptr::null_mut;

const ENOMEM: c_int = 12;
const EEXIST: c_int = 17;
const EINVAL: c_int = 22;

const AVTAB_ALLOWED: u16 = 0x0001;
const AVTAB_AUDITALLOW: u16 = 0x0002;
const AVTAB_AUDITDENY: u16 = 0x0004;
const AVTAB_AV: u32 = 0x0007;
const AVTAB_TRANSITION: u16 = 0x0010;
const AVTAB_MEMBER: u16 = 0x0020;
const AVTAB_CHANGE: u16 = 0x0040;
const AVTAB_TYPE: u32 = 0x0070;
const AVTAB_XPERMS_ALLOWED: u16 = 0x0100;
const AVTAB_XPERMS_AUDITALLOW: u16 = 0x0200;
const AVTAB_XPERMS_DONTAUDIT: u16 = 0x0400;
const AVTAB_XPERMS: u32 = 0x0700;
const AVTAB_ENABLED_OLD: u32 = 0x8000_0000;
const AVTAB_ENABLED: u16 = 0x8000;
const AVTAB_SPECIFIER_MASK: u32 = AVTAB_AV | AVTAB_TYPE | AVTAB_XPERMS | AVTAB_ENABLED as u32;

const AVTAB_XPERMS_IOCTLFUNCTION: u8 = 0x01;
const AVTAB_XPERMS_IOCTLDRIVER: u8 = 0x02;
const AVTAB_XPERMS_NLMSG: u8 = 0x03;

const POLICYDB_VERSION_AVTAB: u32 = 20;
const POLICYDB_VERSION_XPERMS_IOCTL: u32 = 30;
const POLICYDB_VERSION_COND_XPERMS: u32 = 34;

const MAX_AVTAB_HASH_BUCKETS: u32 = 1 << 16;

/// `struct avtab_key`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Key {
    source_type: u16,
    target_type: u16,
    target_class: u16,
    specified: u16,
}

/// `struct avtab_extended_perms`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Xperms {
    specified: u8,
    driver: u8,
    perms: [u32; 8],
}

/// `struct avtab_datum`.
#[repr(C)]
#[derive(Clone, Copy)]
pub union Datum {
    data: u32,
    xperms: *mut Xperms,
}

/// `struct avtab_node`.
#[repr(C)]
pub struct Node {
    key: Key,
    datum: Datum,
    next: *mut Node,
}

/// `struct avtab`.
#[repr(C)]
pub struct Avtab {
    htable: *mut *mut Node,
    nel: u32,
    nslot: u32,
    mask: u32,
}

/// `struct policy_file`.
#[repr(C)]
pub struct PolicyFile {
    data: *mut u8,
    len: usize,
}

const _: () = assert!(core::mem::size_of::<Key>() == 8 && core::mem::size_of::<Xperms>() == 36 && core::mem::size_of::<Datum>() == 8);
const _: () = assert!(core::mem::size_of::<Node>() == 24 && core::mem::size_of::<Avtab>() == 24);

type InsertFn = unsafe extern "C" fn(*mut Avtab, *const Key, *const Datum, *mut c_void) -> c_int;

extern "C" {
    fn rust_av_node_alloc() -> *mut Node;
    fn rust_av_node_free(n: *mut Node);
    fn rust_av_xperms_alloc() -> *mut Xperms;
    fn rust_av_xperms_free(x: *mut Xperms);
    fn rust_av_kvcalloc(n: u32) -> *mut c_void;
    fn rust_av_kvfree(p: *mut c_void);
    fn rust_av_type_isvalid(pol: *const c_void, t: u32) -> c_int;
    fn rust_av_class_isvalid(pol: *const c_void, c: u32) -> c_int;
    fn rust_av_policyvers(pol: *const c_void) -> u32;
    /// The `pr_err()` calls, by number (see the glue for the texts).
    fn rust_av_err(which: c_int, a: u32, b: u32);
    /// `pr_warn_once_policyload(pol, "... unsupported xperm specifier %#x\n", specified)`
    fn rust_av_warn_xperm(pol: *const c_void, specified: u8);
}

const E_TRUNCATED: c_int = 0;
const E_ITEM_COUNT: c_int = 1;
const E_TRUNC_SRC: c_int = 2;
const E_TRUNC_TGT: c_int = 3;
const E_TRUNC_CLASS: c_int = 4;
const E_TYPE_OR_CLASS: c_int = 5;
const E_NULL_ENTRY: c_int = 6;
const E_BOTH: c_int = 7;
const E_HAS_XPERMS: c_int = 8;
const E_TOO_MANY: c_int = 9;
const E_ONLY_HAD: c_int = 10;
const E_ONE_SPEC: c_int = 11;
const E_INVALID_SPEC: c_int = 12;
const E_VER_XPERMS: c_int = 13;
const E_VER_COND_XPERMS: c_int = 14;
const E_INVALID_TYPE: c_int = 15;
const E_OOM: c_int = 16;
const E_DUP: c_int = 17;
const E_TRUNC_TABLE: c_int = 18;
const E_EMPTY_TABLE: c_int = 19;

/// `avtab_hash()`: MurmurHash3 over the three key fields.
fn avtab_hash(keyp: &Key, mask: u32) -> u32 {
    const C1: u32 = 0xcc9e2d51;
    const C2: u32 = 0x1b873593;
    const R1: u32 = 15;
    const R2: u32 = 13;
    const M: u32 = 5;
    const N: u32 = 0xe6546b64;

    let mut hash: u32 = 0;
    let mut mix = |input: u32| {
        let mut v = input;
        v = v.wrapping_mul(C1);
        v = (v << R1) | (v >> (32 - R1));
        v = v.wrapping_mul(C2);
        hash ^= v;
        hash = (hash << R2) | (hash >> (32 - R2));
        hash = hash.wrapping_mul(M).wrapping_add(N);
    };

    mix(keyp.target_class as u32);
    mix(keyp.target_type as u32);
    mix(keyp.source_type as u32);

    hash ^= hash >> 16;
    hash = hash.wrapping_mul(0x85ebca6b);
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(0xc2b2ae35);
    hash ^= hash >> 16;

    hash & mask
}

/// `avtab_insert_node()`.
unsafe fn avtab_insert_node(h: *mut Avtab, dst: *mut *mut Node, key: *const Key, datum: *const Datum) -> *mut Node {
    unsafe {
        let newnode = rust_av_node_alloc();
        if newnode.is_null() {
            return null_mut();
        }
        (*newnode).key = *key;

        if (*key).specified as u32 & AVTAB_XPERMS != 0 {
            let xperms = rust_av_xperms_alloc();
            if xperms.is_null() {
                rust_av_node_free(newnode);
                return null_mut();
            }
            *xperms = *(*datum).xperms;
            (*newnode).datum.xperms = xperms;
        } else {
            (*newnode).datum.data = (*datum).data;
        }

        (*newnode).next = *dst;
        *dst = newnode;

        (*h).nel += 1;
        newnode
    }
}

/// `avtab_node_cmp()`.
fn avtab_node_cmp(key1: &Key, key2: &Key) -> c_int {
    let specified = key1.specified & !(AVTAB_ENABLED | (AVTAB_ENABLED_OLD as u16));

    if key1.source_type == key2.source_type && key1.target_type == key2.target_type && key1.target_class == key2.target_class && (specified & key2.specified) != 0 {
        return 0;
    }
    if key1.source_type < key2.source_type {
        return -1;
    }
    if key1.source_type == key2.source_type && key1.target_type < key2.target_type {
        return -1;
    }
    if key1.source_type == key2.source_type && key1.target_type == key2.target_type && key1.target_class < key2.target_class {
        return -1;
    }
    1
}

/// `avtab_insert()`.
unsafe fn avtab_insert(h: *mut Avtab, key: *const Key, datum: *const Datum) -> c_int {
    unsafe {
        if h.is_null() || (*h).nslot == 0 || (*h).nel == u32::MAX {
            return -EINVAL;
        }

        let hvalue = avtab_hash(&*key, (*h).mask);
        let mut prev: *mut Node = null_mut();
        let mut cur = *(*h).htable.add(hvalue as usize);
        while !cur.is_null() {
            let cmp = avtab_node_cmp(&*key, &(*cur).key);
            // extended perms may not be unique
            if cmp == 0 && (*key).specified as u32 & AVTAB_XPERMS == 0 {
                return -EEXIST;
            }
            if cmp <= 0 {
                break;
            }
            prev = cur;
            cur = (*cur).next;
        }
        let dst = if !prev.is_null() { &mut (*prev).next as *mut *mut Node } else { (*h).htable.add(hvalue as usize) };
        let newnode = avtab_insert_node(h, dst, key, datum);
        if newnode.is_null() {
            return -ENOMEM;
        }
        0
    }
}

/// `avtab_insert_nonunique()`: like `avtab_insert()` but the same key may be inserted again; returns the new node.
#[no_mangle]
pub unsafe extern "C" fn avtab_insert_nonunique(h: *mut Avtab, key: *const Key, datum: *const Datum) -> *mut Node {
    unsafe {
        if h.is_null() || (*h).nslot == 0 || (*h).nel == u32::MAX {
            return null_mut();
        }
        let hvalue = avtab_hash(&*key, (*h).mask);
        let mut prev: *mut Node = null_mut();
        let mut cur = *(*h).htable.add(hvalue as usize);
        while !cur.is_null() {
            let cmp = avtab_node_cmp(&*key, &(*cur).key);
            if cmp <= 0 {
                break;
            }
            prev = cur;
            cur = (*cur).next;
        }
        let dst = if !prev.is_null() { &mut (*prev).next as *mut *mut Node } else { (*h).htable.add(hvalue as usize) };
        avtab_insert_node(h, dst, key, datum)
    }
}

/// `avtab_search_node()`.
#[no_mangle]
pub unsafe extern "C" fn avtab_search_node(h: *mut Avtab, key: *const Key) -> *mut Node {
    unsafe {
        if h.is_null() || (*h).nslot == 0 {
            return null_mut();
        }

        let hvalue = avtab_hash(&*key, (*h).mask);
        let mut cur = *(*h).htable.add(hvalue as usize);
        while !cur.is_null() {
            let cmp = avtab_node_cmp(&*key, &(*cur).key);
            if cmp == 0 {
                return cur;
            }
            if cmp < 0 {
                break;
            }
            cur = (*cur).next;
        }
        null_mut()
    }
}

/// `avtab_search_node_next()`.
#[no_mangle]
pub unsafe extern "C" fn avtab_search_node_next(node: *mut Node, specified: u16) -> *mut Node {
    unsafe {
        if node.is_null() {
            return null_mut();
        }
        let mut tmp_key = (*node).key;
        tmp_key.specified = specified;
        let mut cur = (*node).next;
        while !cur.is_null() {
            let cmp = avtab_node_cmp(&tmp_key, &(*cur).key);
            if cmp == 0 {
                return cur;
            }
            if cmp < 0 {
                break;
            }
            cur = (*cur).next;
        }
        null_mut()
    }
}

/// `avtab_destroy()`.
#[no_mangle]
pub unsafe extern "C" fn avtab_destroy(h: *mut Avtab) {
    unsafe {
        if h.is_null() {
            return;
        }

        let mut i = 0;
        while i < (*h).nslot {
            let mut cur = *(*h).htable.add(i as usize);
            while !cur.is_null() {
                let temp = cur;
                cur = (*cur).next;
                if (*temp).key.specified as u32 & AVTAB_XPERMS != 0 {
                    rust_av_xperms_free((*temp).datum.xperms);
                }
                rust_av_node_free(temp);
            }
            i += 1;
        }
        rust_av_kvfree((*h).htable as *mut c_void);
        (*h).htable = null_mut();
        (*h).nel = 0;
        (*h).nslot = 0;
        (*h).mask = 0;
    }
}

/// `avtab_init()`.
#[no_mangle]
pub unsafe extern "C" fn avtab_init(h: *mut Avtab) {
    unsafe {
        (*h).htable = null_mut();
        (*h).nel = 0;
        (*h).nslot = 0;
        (*h).mask = 0;
    }
}

/// `avtab_alloc_common()`.
unsafe fn avtab_alloc_common(h: *mut Avtab, nslot: u32) -> c_int {
    unsafe {
        if nslot == 0 {
            return 0;
        }

        (*h).htable = rust_av_kvcalloc(nslot) as *mut *mut Node;
        if (*h).htable.is_null() {
            return -ENOMEM;
        }

        (*h).nslot = nslot;
        (*h).mask = nslot - 1;
        0
    }
}

/// `avtab_alloc()`.
#[no_mangle]
pub unsafe extern "C" fn avtab_alloc(h: *mut Avtab, nrules: u32) -> c_int {
    unsafe {
        if nrules != 0 {
            // rounddown_pow_of_two(nrules / 2) for nrules > 3, else 2
            let mut nslot: u32 = if nrules > 3 { 1u32 << (31 - (nrules / 2).leading_zeros()) } else { 2 };
            if nslot > MAX_AVTAB_HASH_BUCKETS {
                nslot = MAX_AVTAB_HASH_BUCKETS;
            }

            let rc = avtab_alloc_common(h, nslot);
            if rc != 0 {
                return rc;
            }
        }
        0
    }
}

/// `avtab_alloc_dup()`.
#[no_mangle]
pub unsafe extern "C" fn avtab_alloc_dup(new: *mut Avtab, orig: *const Avtab) -> c_int {
    unsafe { avtab_alloc_common(new, (*orig).nslot) }
}

const SPEC_ORDER: [u16; 9] = [
    AVTAB_ALLOWED,
    AVTAB_AUDITDENY,
    AVTAB_AUDITALLOW,
    AVTAB_TRANSITION,
    AVTAB_CHANGE,
    AVTAB_MEMBER,
    AVTAB_XPERMS_ALLOWED,
    AVTAB_XPERMS_AUDITALLOW,
    AVTAB_XPERMS_DONTAUDIT,
];

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

/// `avtab_is_valid_xperm_specified()`.
fn is_valid_xperm_specified(specified: u8) -> bool {
    matches!(specified, AVTAB_XPERMS_IOCTLFUNCTION | AVTAB_XPERMS_IOCTLDRIVER | AVTAB_XPERMS_NLMSG)
}

/// `avtab_read_item()`: read one table entry from the policy file and hand it to `insertf` (once per access vector of an old-format entry).
#[no_mangle]
pub unsafe extern "C" fn avtab_read_item(a: *mut Avtab, fp: *mut PolicyFile, pol: *const c_void, insertf: InsertFn, p: *mut c_void, conditional: bool) -> c_int {
    unsafe {
        let mut buf16 = [0u16; 4];
        let mut buf32 = [0u32; 8];
        let mut key = Key { source_type: 0, target_type: 0, target_class: 0, specified: 0 };
        let mut datum = Datum { data: 0 };
        let mut xperms = Xperms { specified: 0, driver: 0, perms: [0; 8] };
        let vers = rust_av_policyvers(pol);
        let mut rc;

        if vers < POLICYDB_VERSION_AVTAB {
            rc = next_entry(buf32.as_mut_ptr() as *mut u8, fp, 4);
            if rc != 0 {
                rust_av_err(E_TRUNCATED, 0, 0);
                return rc;
            }
            // Read five or more items: source type, target type, target class, AV type, and at least one datum.
            let items2 = u32::from_le(buf32[0]);
            if items2 < 5 || items2 > 8 {
                rust_av_err(E_ITEM_COUNT, 0, 0);
                return -EINVAL;
            }
            rc = next_entry(buf32.as_mut_ptr() as *mut u8, fp, 4 * items2 as usize);
            if rc != 0 {
                rust_av_err(E_TRUNCATED, 0, 0);
                return rc;
            }
            let mut items: u32 = 0;

            let mut val = u32::from_le(buf32[items as usize]);
            items += 1;
            key.source_type = val as u16;
            if key.source_type as u32 != val {
                rust_av_err(E_TRUNC_SRC, 0, 0);
                return -EINVAL;
            }
            val = u32::from_le(buf32[items as usize]);
            items += 1;
            key.target_type = val as u16;
            if key.target_type as u32 != val {
                rust_av_err(E_TRUNC_TGT, 0, 0);
                return -EINVAL;
            }
            val = u32::from_le(buf32[items as usize]);
            items += 1;
            key.target_class = val as u16;
            if key.target_class as u32 != val {
                rust_av_err(E_TRUNC_CLASS, 0, 0);
                return -EINVAL;
            }

            if rust_av_type_isvalid(pol, key.source_type as u32) == 0 || rust_av_type_isvalid(pol, key.target_type as u32) == 0 || rust_av_class_isvalid(pol, key.target_class as u32) == 0 {
                rust_av_err(E_TYPE_OR_CLASS, 0, 0);
                return -EINVAL;
            }

            val = u32::from_le(buf32[items as usize]);
            items += 1;
            let enabled: u16 = if val & AVTAB_ENABLED_OLD != 0 { AVTAB_ENABLED } else { 0 };

            if val & (AVTAB_AV | AVTAB_TYPE) == 0 {
                rust_av_err(E_NULL_ENTRY, 0, 0);
                return -EINVAL;
            }
            if val & AVTAB_AV != 0 && val & AVTAB_TYPE != 0 {
                rust_av_err(E_BOTH, 0, 0);
                return -EINVAL;
            }
            if val & AVTAB_XPERMS != 0 {
                rust_av_err(E_HAS_XPERMS, 0, 0);
                return -EINVAL;
            }

            for spec in SPEC_ORDER {
                if val & spec as u32 != 0 {
                    if items >= items2 {
                        rust_av_err(E_TOO_MANY, items + 1, items2);
                        return -EINVAL;
                    }
                    key.specified = spec | enabled;
                    datum.data = u32::from_le(buf32[items as usize]);
                    items += 1;
                    rc = insertf(a, &key, &datum, p);
                    if rc != 0 {
                        return rc;
                    }
                }
            }

            if items != items2 {
                rust_av_err(E_ONLY_HAD, items2, items);
                return -EINVAL;
            }
            return 0;
        }

        rc = next_entry(buf16.as_mut_ptr() as *mut u8, fp, 8);
        if rc != 0 {
            rust_av_err(E_TRUNCATED, 0, 0);
            return rc;
        }

        key.source_type = u16::from_le(buf16[0]);
        key.target_type = u16::from_le(buf16[1]);
        key.target_class = u16::from_le(buf16[2]);
        key.specified = u16::from_le(buf16[3]);

        if rust_av_type_isvalid(pol, key.source_type as u32) == 0 || rust_av_type_isvalid(pol, key.target_type as u32) == 0 || rust_av_class_isvalid(pol, key.target_class as u32) == 0 {
            rust_av_err(E_TYPE_OR_CLASS, 0, 0);
            return -EINVAL;
        }

        if (key.specified & !AVTAB_ENABLED).count_ones() != 1 {
            rust_av_err(E_ONE_SPEC, 0, 0);
            return -EINVAL;
        }

        if key.specified as u32 & !AVTAB_SPECIFIER_MASK != 0 {
            rust_av_err(E_INVALID_SPEC, 0, 0);
            return -EINVAL;
        }

        if vers < POLICYDB_VERSION_XPERMS_IOCTL && key.specified as u32 & AVTAB_XPERMS != 0 {
            rust_av_err(E_VER_XPERMS, vers, 0);
            return -EINVAL;
        } else if vers < POLICYDB_VERSION_COND_XPERMS && key.specified as u32 & AVTAB_XPERMS != 0 && conditional {
            rust_av_err(E_VER_COND_XPERMS, vers, 0);
            return -EINVAL;
        } else if key.specified as u32 & AVTAB_XPERMS != 0 {
            rc = next_entry(&mut xperms.specified, fp, 1);
            if rc != 0 {
                rust_av_err(E_TRUNCATED, 0, 0);
                return rc;
            }
            if !is_valid_xperm_specified(xperms.specified) {
                rust_av_warn_xperm(pol, xperms.specified);
            }
            rc = next_entry(&mut xperms.driver, fp, 1);
            if rc != 0 {
                rust_av_err(E_TRUNCATED, 0, 0);
                return rc;
            }
            rc = next_entry(buf32.as_mut_ptr() as *mut u8, fp, 4 * 8);
            if rc != 0 {
                rust_av_err(E_TRUNCATED, 0, 0);
                return rc;
            }
            for i in 0..8 {
                xperms.perms[i] = u32::from_le(buf32[i]);
            }
            datum.xperms = &mut xperms;
        } else {
            rc = next_entry(buf32.as_mut_ptr() as *mut u8, fp, 4);
            if rc != 0 {
                rust_av_err(E_TRUNCATED, 0, 0);
                return rc;
            }
            datum.data = u32::from_le(buf32[0]);
        }
        if key.specified as u32 & AVTAB_TYPE != 0 && rust_av_type_isvalid(pol, datum.data) == 0 {
            rust_av_err(E_INVALID_TYPE, 0, 0);
            return -EINVAL;
        }
        insertf(a, &key, &datum, p)
    }
}

/// `avtab_insertf()`.
unsafe extern "C" fn avtab_insertf(a: *mut Avtab, k: *const Key, d: *const Datum, _p: *mut c_void) -> c_int {
    unsafe { avtab_insert(a, k, d) }
}

/// `avtab_read()`.
#[no_mangle]
pub unsafe extern "C" fn avtab_read(a: *mut Avtab, fp: *mut PolicyFile, pol: *const c_void) -> c_int {
    unsafe {
        let mut buf = [0u32; 1];

        let mut rc = next_entry(buf.as_mut_ptr() as *mut u8, fp, 4);
        'bad: {
            if rc < 0 {
                rust_av_err(E_TRUNC_TABLE, 0, 0);
                break 'bad;
            }
            let nel = u32::from_le(buf[0]);
            if nel == 0 {
                rust_av_err(E_EMPTY_TABLE, 0, 0);
                rc = -EINVAL;
                break 'bad;
            }

            rc = avtab_alloc(a, nel);
            if rc != 0 {
                break 'bad;
            }

            for _ in 0..nel {
                rc = avtab_read_item(a, fp, pol, avtab_insertf, null_mut(), false);
                if rc != 0 {
                    if rc == -ENOMEM {
                        rust_av_err(E_OOM, 0, 0);
                    } else if rc == -EEXIST {
                        rust_av_err(E_DUP, 0, 0);
                    }
                    break 'bad;
                }
            }

            return 0;
        }
        avtab_destroy(a);
        rc
    }
}

/// `avtab_write_item()`.
#[no_mangle]
pub unsafe extern "C" fn avtab_write_item(_p: *const c_void, cur: *const Node, fp: *mut PolicyFile) -> c_int {
    unsafe {
        let buf16: [u16; 4] = [(*cur).key.source_type.to_le(), (*cur).key.target_type.to_le(), (*cur).key.target_class.to_le(), (*cur).key.specified.to_le()];
        let mut rc = put_entry(buf16.as_ptr() as *const u8, 2, 4, fp);
        if rc != 0 {
            return rc;
        }

        if (*cur).key.specified as u32 & AVTAB_XPERMS != 0 {
            let x = (*cur).datum.xperms;
            rc = put_entry(&(*x).specified, 1, 1, fp);
            if rc != 0 {
                return rc;
            }
            rc = put_entry(&(*x).driver, 1, 1, fp);
            if rc != 0 {
                return rc;
            }
            let mut buf32 = [0u32; 8];
            for i in 0..8 {
                buf32[i] = (*x).perms[i].to_le();
            }
            rc = put_entry(buf32.as_ptr() as *const u8, 4, 8, fp);
        } else {
            let buf32 = [(*cur).datum.data.to_le()];
            rc = put_entry(buf32.as_ptr() as *const u8, 4, 1, fp);
        }
        if rc != 0 {
            return rc;
        }
        0
    }
}

/// `avtab_write()`.
#[no_mangle]
pub unsafe extern "C" fn avtab_write(p: *const c_void, a: *mut Avtab, fp: *mut PolicyFile) -> c_int {
    unsafe {
        let buf = [(*a).nel.to_le()];
        let mut rc = put_entry(buf.as_ptr() as *const u8, 4, 1, fp);
        if rc != 0 {
            return rc;
        }

        let mut i = 0;
        while i < (*a).nslot {
            let mut cur = *(*a).htable.add(i as usize);
            while !cur.is_null() {
                rc = avtab_write_item(p, cur, fp);
                if rc != 0 {
                    return rc;
                }
                cur = (*cur).next;
            }
            i += 1;
        }

        rc
    }
}
