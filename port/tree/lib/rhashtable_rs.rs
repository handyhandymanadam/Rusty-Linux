// SPDX-License-Identifier: GPL-2.0-only

//! The resizable hash table algorithms -- the Rust behind `lib/rhashtable.c`.
//!
//! Ported from `lib/rhashtable.c` (6.18.49), "Resizable, Scalable, Concurrent Hash Table", Copyright (c) 2014-2015 Thomas Graf, Herbert Xu,
//! Patrick McHardy. This is the slow path of the table: bucket-table allocation and free (including the nested tables used when a big
//! allocation fails), the incremental rehash (one entry, one chain, the whole table), the deferred resize worker, the insert slow path
//! (`lookup_one`/`insert_one`/`try_insert`/`insert_rehash`), the walker (`enter`/`exit`/`start_check`/`next`/`peek`/`stop`), `init`, and
//! `free_and_destroy`. The fast paths (`rhashtable_lookup`, `rhashtable_insert_fast`, `rhashtable_remove_fast`, ...) are header inlines in
//! `rhashtable.h` and stay C.
//!
//! # Shape
//! * **In Rust**: every function of `rhashtable.c` except the lockdep exports and the thin wrappers.
//! * **In C** (`rhashtable_glue.c`): the exported entry points as thunks (MODVERSIONS fingerprints come from the DWARF of the definition),
//!   `rht_bucket_nested()` (it owns a static), `rhltable_init_noprof`, `rhashtable_destroy`, the lockdep exports, and one-line wrappers
//!   (`rust_rhw_*`) for everything that is a header inline or a macro whose body depends on the configuration: the bit-spin bucket lock with
//!   `local_irq_save` and the lockdep map, `rht_assign_unlock`, mutex / spinlock / RCU read side / `call_rcu` / workqueue calls, the
//!   allocator calls with the allocation tag, `list_add`/`list_del`, `rht_head_hashfn`, the compare callback, `BUG_ON`.
//! * `struct rhashtable` and `struct bucket_table` are not mirrored whole: the offsets that vary (`CONFIG_LOCKDEP`, `CONFIG_MEM_ALLOC_PROFILING`,
//!   debug spinlocks) are handed over as constants by the glue; the glue `static_assert`s every fixed offset used here.
//!
//! # The ordering contract (concurrency bar, item 1)
//! * A bucket is a pointer with bit 0 as a lock bit. Writers hold that bit (through `rhw_lock`) before they touch the chain; readers
//!   (`rht_ptr_rcu`) clear it and walk under `rcu_read_lock`.
//! * Chains are published with release stores (`rcu_assign_pointer`, or `rht_assign_unlock`'s) and read with `READ_ONCE` loads.
//! * `future_tbl` is attached with a full `cmpxchg` (no separate barrier, as the C says); a nested table slot is filled with `cmpxchg` too.
//! * The old table is handed to `call_rcu` while `ht->lock` is held, so `rhashtable_walk_stop` can use `rcu_head_after_call_rcu`.
//! * `rhashtable_walk_find_next` does `smp_rmb()` before reading `future_tbl`.
//! All of this follows the C one to one.
//!
//! Replaces: lib/rhashtable.c (the algorithms; the exports and the configuration-dependent glue stay C)

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals, clippy::missing_safety_doc)]

use core::ffi::{c_int, c_uint, c_ulong, c_void};
use core::ptr::{addr_of, addr_of_mut, null_mut, read_volatile, write_volatile};
use core::sync::atomic::{compiler_fence, fence, AtomicI32, AtomicUsize, Ordering};

#[cfg(not(all(target_arch = "x86_64", target_endian = "little")))]
compile_error!("rhashtable_rs.rs: x86-64 little-endian only (64-bit pointers, struct layouts)");

const ENOENT: c_int = 2;
const ENOMEM: c_int = 12;
const EEXIST: c_int = 17;
const EINVAL: c_int = 22;
const E2BIG: c_int = 7;
const EAGAIN: c_int = 11;
const EBUSY_: c_int = 16;

const PAGE_SHIFT: u32 = 12;
const SHIFT: u32 = PAGE_SHIFT - 3; // PAGE_SHIFT - ilog2(sizeof(void *))
const RHT_ELASTICITY: i32 = 16;
const HASH_DEFAULT_SIZE: u64 = 64;
const HASH_MIN_SIZE: u32 = 4;

type Gfp = c_uint;

/// `struct rhash_head`.
#[repr(C)]
pub struct RhashHead {
    next: usize,
}

/// `struct rhlist_head`.
#[repr(C)]
pub struct RhlistHead {
    rhead: RhashHead,
    next: *mut RhlistHead,
}

/// `struct list_head`.
#[repr(C)]
pub struct ListHead {
    next: *mut ListHead,
    prev: *mut ListHead,
}

/// `struct rhashtable_params`.
#[repr(C)]
pub struct Params {
    nelem_hint: u16,
    key_len: u16,
    key_offset: u16,
    head_offset: u16,
    max_size: c_uint,
    min_size: u16,
    automatic_shrinking: bool,
    hashfn: Option<unsafe extern "C" fn(*const c_void, u32, u32) -> u32>,
    obj_hashfn: Option<unsafe extern "C" fn(*const c_void, u32, u32) -> u32>,
    obj_cmpfn: Option<unsafe extern "C" fn(*mut c_void, *const c_void) -> c_int>,
}

/// The part of `struct rhashtable` that does not depend on the configuration.
#[repr(C)]
pub struct Rht {
    tbl: usize,
    key_len: c_uint,
    max_elems: c_uint,
    p: Params,
    rhlist: bool,
}

/// The part of `struct bucket_table` before `buckets[]`.
#[repr(C)]
pub struct Tbl {
    size: c_uint,
    nest: c_uint,
    hash_rnd: u32,
    walkers: ListHead,
    rcu: [usize; 2],
    future_tbl: usize,
}

/// `struct rhashtable_walker`.
#[repr(C)]
pub struct Walker {
    list: ListHead,
    tbl: *mut Tbl,
}

/// `struct rhashtable_iter`.
#[repr(C)]
pub struct Iter {
    ht: *mut Rht,
    p: *mut RhashHead,
    list: *mut RhlistHead,
    walker: Walker,
    slot: c_uint,
    skip: c_uint,
    end_of_table: bool,
}

type Bkt = *mut usize;
type FreeFn = unsafe extern "C" fn(*mut c_void, *mut c_void);

extern "C" {
    static rust_rhw_buckets_off: usize;
    static rust_rhw_tbl_sizeof: usize;
    static rust_rhw_nelems_off: usize;
    static rust_rhw_gfp_kernel: Gfp;
    static rust_rhw_gfp_kernel_nofail: Gfp;
    static rust_rhw_gfp_atomic_nowarn: Gfp;

    fn rust_rhw_lock(tbl: *mut Tbl, bkt: Bkt) -> c_ulong;
    fn rust_rhw_lock_nested(tbl: *mut Tbl, bkt: Bkt) -> c_ulong;
    fn rust_rhw_unlock(tbl: *mut Tbl, bkt: Bkt, flags: c_ulong);
    fn rust_rhw_assign_unlock(tbl: *mut Tbl, bkt: Bkt, obj: *mut RhashHead, flags: c_ulong);
    fn rust_rhw_head_hashfn(ht: *mut Rht, tbl: *const Tbl, he: *const RhashHead) -> u32;
    fn rust_rhw_cmp(ht: *mut Rht, key: *const c_void, he: *const RhashHead) -> c_int;
    fn rust_rhw_kmalloc_page(ht: *mut Rht) -> *mut c_void;
    fn rust_rhw_kmalloc_tbl(ht: *mut Rht, size: usize, gfp: Gfp) -> *mut Tbl;
    fn rust_rhw_kvmalloc_tbl(ht: *mut Rht, nbuckets: usize, gfp: Gfp) -> *mut Tbl;
    fn rust_rhw_kfree(p: *mut c_void);
    fn rust_rhw_kvfree(p: *const c_void);
    fn rust_rhw_gfp_allow_blocking(gfp: Gfp) -> bool;
    fn rust_rhw_tbl_prepare(tbl: *mut Tbl, size: usize);
    fn rust_rhw_call_rcu_free(tbl: *mut Tbl);
    fn rust_rhw_after_call_rcu(tbl: *mut Tbl) -> bool;
    fn rust_rhw_mutex_lock(ht: *mut Rht);
    fn rust_rhw_mutex_unlock(ht: *mut Rht);
    fn rust_rhw_spin_lock(ht: *mut Rht);
    fn rust_rhw_spin_unlock(ht: *mut Rht);
    fn rust_rhw_schedule_work(ht: *mut Rht);
    fn rust_rhw_cancel_work_sync(ht: *mut Rht);
    fn rust_rhw_rcu_read_lock();
    fn rust_rhw_rcu_read_unlock();
    fn rust_rhw_list_add(new: *mut ListHead, head: *mut ListHead);
    fn rust_rhw_list_del(entry: *mut ListHead);
    fn rust_rhw_cond_resched();
    fn rust_rhw_assert_mutex(ht: *mut Rht);
    fn rust_rhw_init_prep(ht: *mut Rht, params: *const Params);
    fn rust_rhw_init_work(ht: *mut Rht);
    fn rust_rhw_jhash_fn() -> unsafe extern "C" fn(*const c_void, u32, u32) -> u32;
    fn rust_rhw_jhash2_fn() -> unsafe extern "C" fn(*const c_void, u32, u32) -> u32;
    /// The exported `rht_bucket_nested()` (owns the static `rhnull`).
    fn rht_bucket_nested(tbl: *const Tbl, hash: c_uint) -> Bkt;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// small helpers: pointers, errors, RCU accessors
// ---------------------------------------------------------------------------------------------------------------------------------

/// `READ_ONCE()` / `rcu_dereference*()` (an address dependency orders what follows on every architecture but Alpha).
#[inline(always)]
unsafe fn ld(p: *const usize) -> usize {
    // SAFETY: the caller passes a valid, aligned word.
    unsafe { read_volatile(p) }
}

/// `rcu_assign_pointer()` / `smp_store_release()`.
#[inline(always)]
unsafe fn st_release(p: *mut usize, v: usize) {
    // SAFETY: the caller passes a valid, aligned word that is only ever accessed atomically or volatilely.
    unsafe { (*(p as *const AtomicUsize)).store(v, Ordering::Release) }
}

/// `RCU_INIT_POINTER()` / `WRITE_ONCE()`.
#[inline(always)]
unsafe fn st_once(p: *mut usize, v: usize) {
    // SAFETY: as above.
    unsafe { write_volatile(p, v) }
}

/// `cmpxchg()` (full barrier); true when the swap happened, `old` is the expected value.
#[inline(always)]
unsafe fn cmpxchg(p: *mut usize, old: usize, new: usize) -> usize {
    // SAFETY: as above.
    match unsafe { (*(p as *const AtomicUsize)).compare_exchange(old, new, Ordering::SeqCst, Ordering::SeqCst) } {
        Ok(v) | Err(v) => v,
    }
}

#[inline(always)]
fn is_err(p: usize) -> bool {
    p >= (-4095_isize) as usize
}

#[inline(always)]
fn is_err_or_null(p: usize) -> bool {
    p == 0 || is_err(p)
}

#[inline(always)]
fn err_ptr(e: c_int) -> usize {
    (e as isize) as usize
}

/// `PTR_ERR()`.
#[inline(always)]
fn ptr_err(p: usize) -> isize {
    p as isize
}

/// `rht_is_a_nulls()`.
#[inline(always)]
fn is_nulls(p: usize) -> bool {
    p & 1 != 0
}

/// `RHT_NULLS_MARKER(bkt)`: `NULLS_MARKER(bkt >> 1)` = `1UL | ((long)(bkt >> 1) << 1)`.
#[inline(always)]
fn nulls_marker(bkt: Bkt) -> usize {
    1 | (((bkt as usize) >> 1) << 1)
}

/// `__rht_ptr()`: clear the lock bit, or give the nulls marker of the bucket when the chain is empty.
#[inline(always)]
fn rht_ptr_of(p: usize, bkt: Bkt) -> usize {
    let v = p & !1usize;
    if v != 0 {
        v
    } else {
        nulls_marker(bkt)
    }
}

/// `rht_ptr()` / `rht_ptr_rcu()` / `rht_ptr_exclusive()` (all one load here).
#[inline(always)]
unsafe fn rht_ptr(bkt: Bkt) -> usize {
    // SAFETY: the caller passes a bucket of a live table.
    rht_ptr_of(unsafe { ld(bkt) }, bkt)
}

/// `rht_assign_locked()`: store the chain head with the lock bit kept.
#[inline(always)]
unsafe fn rht_assign_locked(bkt: Bkt, obj: usize) {
    let obj = if is_nulls(obj) { 0 } else { obj };
    // SAFETY: the caller holds the bucket lock.
    unsafe { st_release(bkt, obj | 1) }
}

#[inline(always)]
unsafe fn next_of(p: usize) -> *mut usize {
    p as *mut usize // struct rhash_head: next is the only field
}

#[inline(always)]
unsafe fn buckets(tbl: *mut Tbl) -> Bkt {
    // SAFETY: the offset comes from the glue (offsetof(struct bucket_table, buckets)).
    unsafe { (tbl as *mut u8).add(rust_rhw_buckets_off) as Bkt }
}

#[inline(always)]
unsafe fn nelems(ht: *mut Rht) -> *mut AtomicI32 {
    // SAFETY: the offset comes from the glue (offsetof(struct rhashtable, nelems)).
    unsafe { (ht as *mut u8).add(rust_rhw_nelems_off) as *mut AtomicI32 }
}

/// `atomic_read(&ht->nelems)`.
#[inline(always)]
unsafe fn nelems_read(ht: *mut Rht) -> i32 {
    // SAFETY: a live table.
    unsafe { read_volatile(nelems(ht) as *const i32) }
}

/// `rht_obj()`.
#[inline(always)]
unsafe fn rht_obj(ht: *mut Rht, he: usize) -> *mut c_void {
    // SAFETY: a live table.
    (he as *mut u8).wrapping_sub(unsafe { (*ht).p.head_offset } as usize) as *mut c_void
}

/// `rht_grow_above_75()`.
unsafe fn grow_above_75(ht: *mut Rht, tbl: *mut Tbl) -> bool {
    // SAFETY: live table and bucket table. `int > unsigned int` converts the int.
    unsafe {
        (nelems_read(ht) as u32) > ((*tbl).size / 4 * 3) && ((*ht).p.max_size == 0 || (*tbl).size < (*ht).p.max_size)
    }
}

/// `rht_shrink_below_30()`.
unsafe fn shrink_below_30(ht: *mut Rht, tbl: *mut Tbl) -> bool {
    // SAFETY: as above.
    unsafe {
        (nelems_read(ht) as u32) < ((*tbl).size.wrapping_mul(3) / 10) && (*tbl).size > (*ht).p.min_size as u32
    }
}

/// `rht_grow_above_100()`.
unsafe fn grow_above_100(ht: *mut Rht, tbl: *mut Tbl) -> bool {
    // SAFETY: as above.
    unsafe { (nelems_read(ht) as u32) > (*tbl).size && ((*ht).p.max_size == 0 || (*tbl).size < (*ht).p.max_size) }
}

/// `rht_grow_above_max()`.
unsafe fn grow_above_max(ht: *mut Rht, _tbl: *mut Tbl) -> bool {
    // SAFETY: as above.
    unsafe { (nelems_read(ht) as u32) >= (*ht).max_elems }
}

/// `rht_bucket_var()`.
unsafe fn rht_bucket_var(tbl: *mut Tbl, hash: c_uint) -> Bkt {
    // SAFETY: a live table; the hash is within `size`.
    unsafe {
        if (*tbl).nest != 0 {
            rust___rht_bucket_nested(tbl, hash)
        } else {
            buckets(tbl).add(hash as usize)
        }
    }
}

/// `rht_bucket_insert()`.
unsafe fn rht_bucket_insert(ht: *mut Rht, tbl: *mut Tbl, hash: c_uint) -> Bkt {
    // SAFETY: as above.
    unsafe {
        if (*tbl).nest != 0 {
            rust_rht_bucket_nested_insert(ht, tbl, hash)
        } else {
            buckets(tbl).add(hash as usize)
        }
    }
}

/// `rht_bucket()` (reader side: a missing nested bucket is the static empty one).
unsafe fn rht_bucket(tbl: *mut Tbl, hash: c_uint) -> Bkt {
    // SAFETY: as above.
    unsafe {
        if (*tbl).nest != 0 {
            rht_bucket_nested(tbl, hash)
        } else {
            buckets(tbl).add(hash as usize)
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------
// bucket tables
// ---------------------------------------------------------------------------------------------------------------------------------

/// `nested_table_free()`: `ntbl` points at a `union nested_table`.
unsafe fn nested_table_free(ntbl: *mut usize, mut size: c_uint) {
    let len: usize = 1 << SHIFT;
    // SAFETY: `ntbl` is a slot of a nested table of a table being freed; nobody else sees it.
    unsafe {
        let n = ld(ntbl) as *mut usize;
        if n.is_null() {
            return;
        }
        if size as usize > len {
            size >>= SHIFT;
            for i in 0..len {
                nested_table_free(n.add(i), size);
            }
        }
        rust_rhw_kfree(n as *mut c_void);
    }
}

/// `nested_bucket_table_free()`.
unsafe fn nested_bucket_table_free(tbl: *mut Tbl) {
    // SAFETY: the table is being freed.
    unsafe {
        let size = (*tbl).size >> (*tbl).nest;
        let len: usize = 1usize << (*tbl).nest;
        let ntbl = ld(buckets(tbl)) as *mut usize; // nested_table_top()
        for i in 0..len {
            nested_table_free(ntbl.add(i), size);
        }
        rust_rhw_kfree(ntbl as *mut c_void);
    }
}

/// `bucket_table_free()`.
#[no_mangle]
pub unsafe extern "C" fn rust_rht_bucket_table_free(tbl: *mut Tbl) {
    // SAFETY: the table is unreachable (freed under RCU, or never published).
    unsafe {
        if (*tbl).nest != 0 {
            nested_bucket_table_free(tbl);
        }
        rust_rhw_kvfree(tbl as *const c_void);
    }
}

/// `nested_table_alloc()`: `prev` is a slot holding a `union nested_table *`.
unsafe fn nested_table_alloc(ht: *mut Rht, prev: *mut usize, leaf: bool) -> *mut usize {
    // SAFETY: `prev` is a slot of a live nested table; everything it points at is a page allocated here.
    unsafe {
        let mut ntbl = ld(prev) as *mut usize;
        if !ntbl.is_null() {
            return ntbl;
        }
        ntbl = rust_rhw_kmalloc_page(ht) as *mut usize;
        if !ntbl.is_null() && leaf {
            for i in 0..(1usize << SHIFT) {
                st_once(ntbl.add(i), 0); // INIT_RHT_NULLS_HEAD
            }
        }
        if cmpxchg(prev, 0, ntbl as usize) == 0 {
            return ntbl;
        }
        // Raced with another thread.
        rust_rhw_kfree(ntbl as *mut c_void);
        ld(prev) as *mut usize
    }
}

/// `nested_bucket_table_alloc()`.
unsafe fn nested_bucket_table_alloc(ht: *mut Rht, nbuckets: usize, gfp: Gfp) -> *mut Tbl {
    if nbuckets < (1usize << (SHIFT + 1)) {
        return null_mut();
    }
    // SAFETY: `ht` is live; the allocation is zeroed and sized for one bucket slot.
    unsafe {
        let size = rust_rhw_tbl_sizeof + 8;
        let tbl = rust_rhw_kmalloc_tbl(ht, size, gfp);
        if tbl.is_null() {
            return null_mut();
        }
        if nested_table_alloc(ht, buckets(tbl), false).is_null() {
            rust_rhw_kfree(tbl as *mut c_void);
            return null_mut();
        }
        (*tbl).nest = (nbuckets.ilog2() - 1) % SHIFT + 1;
        tbl
    }
}

/// `bucket_table_alloc()`.
unsafe fn bucket_table_alloc(ht: *mut Rht, mut nbuckets: usize, gfp: Gfp) -> *mut Tbl {
    // SAFETY: `ht` is live; the table is private until published.
    unsafe {
        let mut tbl = rust_rhw_kvmalloc_tbl(ht, nbuckets, gfp);
        let size = nbuckets;

        if tbl.is_null() && !rust_rhw_gfp_allow_blocking(gfp) {
            tbl = nested_bucket_table_alloc(ht, nbuckets, gfp);
            nbuckets = 0;
        }
        if tbl.is_null() {
            return null_mut();
        }

        rust_rhw_tbl_prepare(tbl, size);

        let b = buckets(tbl);
        for i in 0..nbuckets {
            st_once(b.add(i), 0); // INIT_RHT_NULLS_HEAD
        }
        tbl
    }
}

/// `rhashtable_last_table()`.
unsafe fn rhashtable_last_table(_ht: *mut Rht, mut tbl: *mut Tbl) -> *mut Tbl {
    // SAFETY: tables on the future_tbl chain stay alive while the caller is in an RCU read section or holds ht->mutex.
    unsafe {
        let mut new_tbl;
        loop {
            new_tbl = tbl;
            tbl = ld(addr_of!((*tbl).future_tbl)) as *mut Tbl;
            if tbl.is_null() {
                break;
            }
        }
        new_tbl
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------
// rehash
// ---------------------------------------------------------------------------------------------------------------------------------

/// `rhashtable_rehash_one()`: move the last entry of one chain to the new table. Called with the old bucket locked.
unsafe fn rhashtable_rehash_one(ht: *mut Rht, bkt: Bkt, _old_hash: c_uint) -> c_int {
    // SAFETY: the caller holds the old bucket lock and ht->mutex.
    unsafe {
        let old_tbl = ld(addr_of!((*ht).tbl)) as *mut Tbl;
        let new_tbl = rhashtable_last_table(ht, old_tbl);
        let mut err = -EAGAIN;
        let mut pprev: *mut usize = null_mut();

        if (*new_tbl).nest != 0 {
            return err;
        }

        err = -ENOENT;

        // rht_for_each_from(entry, rht_ptr(bkt, old_tbl, old_hash), old_tbl, old_hash)
        let mut entry = rht_ptr(bkt);
        let mut next = 0;
        while !is_nulls(entry) {
            err = 0;
            next = ld(next_of(entry));
            if is_nulls(next) {
                break;
            }
            pprev = next_of(entry);
            entry = ld(next_of(entry));
        }
        if err != 0 {
            return err;
        }

        let new_hash = rust_rhw_head_hashfn(ht, new_tbl, entry as *const RhashHead);

        let nb = buckets(new_tbl).add(new_hash as usize);
        let flags = rust_rhw_lock_nested(new_tbl, nb);

        let head = rht_ptr(nb);

        st_once(next_of(entry), head); // RCU_INIT_POINTER(entry->next, head)

        rust_rhw_assign_unlock(new_tbl, nb, entry as *mut RhashHead, flags);

        if !pprev.is_null() {
            st_release(pprev, next);
        } else {
            // Need to preserve the bit lock.
            rht_assign_locked(bkt, next);
        }
        err
    }
}

/// `rhashtable_rehash_chain()`.
unsafe fn rhashtable_rehash_chain(ht: *mut Rht, old_hash: c_uint) -> c_int {
    // SAFETY: the caller holds ht->mutex.
    unsafe {
        let old_tbl = ld(addr_of!((*ht).tbl)) as *mut Tbl;
        let bkt = rht_bucket_var(old_tbl, old_hash);
        if bkt.is_null() {
            return 0;
        }
        let flags = rust_rhw_lock(old_tbl, bkt);

        let mut err;
        loop {
            err = rhashtable_rehash_one(ht, bkt, old_hash);
            if err != 0 {
                break;
            }
        }
        if err == -ENOENT {
            err = 0;
        }
        rust_rhw_unlock(old_tbl, bkt, flags);
        err
    }
}

/// `rhashtable_rehash_attach()`.
unsafe fn rhashtable_rehash_attach(_ht: *mut Rht, old_tbl: *mut Tbl, new_tbl: *mut Tbl) -> c_int {
    // Make insertions go into the new, empty table right away. Deletions and lookups will be attempted in both tables until we
    // synchronize. As cmpxchg() provides strong barriers, we do not need rcu_assign_pointer().
    // SAFETY: both tables are live.
    unsafe {
        if cmpxchg(addr_of_mut!((*old_tbl).future_tbl), 0, new_tbl as usize) != 0 {
            return -EEXIST;
        }
    }
    0
}

/// `rhashtable_rehash_table()`.
unsafe fn rhashtable_rehash_table(ht: *mut Rht) -> c_int {
    // SAFETY: the caller holds ht->mutex.
    unsafe {
        let old_tbl = ld(addr_of!((*ht).tbl)) as *mut Tbl;
        let new_tbl = ld(addr_of!((*old_tbl).future_tbl)) as *mut Tbl;
        if new_tbl.is_null() {
            return 0;
        }

        let mut old_hash: c_uint = 0;
        while old_hash < (*old_tbl).size {
            let err = rhashtable_rehash_chain(ht, old_hash);
            if err != 0 {
                return err;
            }
            rust_rhw_cond_resched();
            old_hash += 1;
        }

        // Publish the new table pointer.
        st_release(addr_of_mut!((*ht).tbl), new_tbl as usize);

        rust_rhw_spin_lock(ht);
        // list_for_each_entry(walker, &old_tbl->walkers, list) walker->tbl = NULL;
        let head: *mut ListHead = addr_of_mut!((*old_tbl).walkers);
        let mut pos = (*head).next;
        while pos != head {
            (*(pos as *mut Walker)).tbl = null_mut();
            pos = (*pos).next;
        }

        // Wait for readers. All new readers will see the new table, and thus no references to the old table will remain. We do this
        // inside the locked region so that rhashtable_walk_stop() can use rcu_head_after_call_rcu() to check if it should not re-link the
        // table.
        rust_rhw_call_rcu_free(old_tbl);
        rust_rhw_spin_unlock(ht);

        if ld(addr_of!((*new_tbl).future_tbl)) != 0 {
            -EAGAIN
        } else {
            0
        }
    }
}

/// `rhashtable_rehash_alloc()`.
unsafe fn rhashtable_rehash_alloc(ht: *mut Rht, old_tbl: *mut Tbl, size: c_uint) -> c_int {
    // SAFETY: the caller holds ht->mutex.
    unsafe {
        rust_rhw_assert_mutex(ht);

        let new_tbl = bucket_table_alloc(ht, size as usize, rust_rhw_gfp_kernel);
        if new_tbl.is_null() {
            return -ENOMEM;
        }

        let err = rhashtable_rehash_attach(ht, old_tbl, new_tbl);
        if err != 0 {
            rust_rht_bucket_table_free(new_tbl);
        }
        err
    }
}

/// `roundup_pow_of_two()` on an `unsigned long`.
fn roundup_pow_of_two(n: u64) -> u64 {
    if n <= 1 {
        1
    } else {
        1u64 << (64 - (n - 1).leading_zeros())
    }
}

/// `rounddown_pow_of_two()` on an `unsigned long` (n != 0).
fn rounddown_pow_of_two(n: u64) -> u64 {
    1u64 << (63 - n.leading_zeros())
}

/// `rhashtable_shrink()`.
unsafe fn rhashtable_shrink(ht: *mut Rht) -> c_int {
    // SAFETY: the caller holds ht->mutex.
    unsafe {
        let old_tbl = ld(addr_of!((*ht).tbl)) as *mut Tbl;
        let nelems = nelems_read(ht) as u32;
        let mut size: c_uint = 0;

        if nelems != 0 {
            size = roundup_pow_of_two((nelems.wrapping_mul(3) / 2) as u64) as c_uint;
        }
        if size < (*ht).p.min_size as c_uint {
            size = (*ht).p.min_size as c_uint;
        }

        if (*old_tbl).size <= size {
            return 0;
        }

        if ld(addr_of!((*old_tbl).future_tbl)) != 0 {
            return -EEXIST;
        }

        rhashtable_rehash_alloc(ht, old_tbl, size)
    }
}

/// `rht_deferred_worker()`: the glue's work function finds the table and calls this.
#[no_mangle]
pub unsafe extern "C" fn rust_rht_deferred_worker(ht: *mut Rht) {
    // SAFETY: `ht` is the live table the work belongs to.
    unsafe {
        let mut err: c_int = 0;
        rust_rhw_mutex_lock(ht);

        let mut tbl = ld(addr_of!((*ht).tbl)) as *mut Tbl;
        tbl = rhashtable_last_table(ht, tbl);

        if grow_above_75(ht, tbl) {
            err = rhashtable_rehash_alloc(ht, tbl, (*tbl).size.wrapping_mul(2));
        } else if (*ht).p.automatic_shrinking && shrink_below_30(ht, tbl) {
            err = rhashtable_shrink(ht);
        } else if (*tbl).nest != 0 {
            err = rhashtable_rehash_alloc(ht, tbl, (*tbl).size);
        }

        if err == 0 || err == -EEXIST {
            let nerr = rhashtable_rehash_table(ht);
            err = if err != 0 { err } else { nerr };
        }

        rust_rhw_mutex_unlock(ht);

        if err != 0 {
            rust_rhw_schedule_work(ht);
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------
// insert slow path
// ---------------------------------------------------------------------------------------------------------------------------------

/// `rhashtable_insert_rehash()`.
unsafe fn rhashtable_insert_rehash(ht: *mut Rht, tbl: *mut Tbl) -> c_int {
    // SAFETY: called in an RCU read section.
    unsafe {
        let old_tbl = ld(addr_of!((*ht).tbl)) as *mut Tbl;
        let mut size = (*tbl).size;
        let mut err = -EBUSY_;

        'fail: {
            if grow_above_75(ht, tbl) {
                size = size.wrapping_mul(2);
            } else if old_tbl != tbl {
                // Do not schedule more than one rehash
                break 'fail;
            }

            err = -ENOMEM;

            let new_tbl = bucket_table_alloc(ht, size as usize, rust_rhw_gfp_atomic_nowarn);
            if new_tbl.is_null() {
                break 'fail;
            }

            err = rhashtable_rehash_attach(ht, tbl, new_tbl);
            if err != 0 {
                rust_rht_bucket_table_free(new_tbl);
                if err == -EEXIST {
                    err = 0;
                }
            } else {
                rust_rhw_schedule_work(ht);
            }
            return err;
        }

        // fail: Do not fail the insert if someone else did a rehash.
        if ld(addr_of!((*tbl).future_tbl)) != 0 {
            return 0;
        }

        // Schedule async rehash to retry allocation in process context.
        if err == -ENOMEM {
            rust_rhw_schedule_work(ht);
        }
        err
    }
}

/// `rhashtable_lookup_one()`: returns the object found, NULL (list insert done), or an ERR_PTR.
unsafe fn rhashtable_lookup_one(
    ht: *mut Rht,
    bkt: Bkt,
    tbl: *mut Tbl,
    _hash: c_uint,
    key: *const c_void,
    obj: *mut RhashHead,
) -> usize {
    // SAFETY: the caller holds the bucket lock.
    unsafe {
        let mut pprev: *mut usize = null_mut();
        let mut elasticity = RHT_ELASTICITY;
        let _ = tbl;

        let mut head = rht_ptr(bkt);
        while !is_nulls(head) {
            elasticity -= 1;
            if key.is_null() || rust_rhw_cmp(ht, key, head as *const RhashHead) != 0 {
                pprev = next_of(head);
                head = ld(next_of(head));
                continue;
            }

            if !(*ht).rhlist {
                return rht_obj(ht, head) as usize;
            }

            let list = obj as *mut RhlistHead; // container_of(obj, struct rhlist_head, rhead): rhead is the first member
            let plist = head as *mut RhlistHead;

            st_once(addr_of_mut!((*list).next) as *mut usize, plist as usize);
            let nxt = ld(next_of(head));
            st_once(addr_of_mut!((*list).rhead.next), nxt);
            if !pprev.is_null() {
                st_release(pprev, obj as usize);
            } else {
                // Need to preserve the bit lock
                rht_assign_locked(bkt, obj as usize);
            }
            return 0;
        }

        if elasticity <= 0 {
            return err_ptr(-EAGAIN);
        }
        err_ptr(-ENOENT)
    }
}

/// `rhashtable_insert_one()`: returns NULL (inserted), the next table to try, or an ERR_PTR.
unsafe fn rhashtable_insert_one(
    ht: *mut Rht,
    bkt: Bkt,
    tbl: *mut Tbl,
    _hash: c_uint,
    obj: *mut RhashHead,
    data: usize,
) -> usize {
    // SAFETY: the caller holds the bucket lock.
    unsafe {
        if !is_err_or_null(data) {
            return err_ptr(-EEXIST);
        }

        if ptr_err(data) != -EAGAIN as isize && ptr_err(data) != -ENOENT as isize {
            return data;
        }

        let new_tbl = ld(addr_of!((*tbl).future_tbl));
        if new_tbl != 0 {
            return new_tbl;
        }

        if ptr_err(data) != -ENOENT as isize {
            return data;
        }

        if grow_above_max(ht, tbl) {
            return err_ptr(-E2BIG);
        }

        if grow_above_100(ht, tbl) {
            return err_ptr(-EAGAIN);
        }

        let head = rht_ptr(bkt);

        st_once(next_of(obj as usize), head);
        if (*ht).rhlist {
            let list = obj as *mut RhlistHead;
            st_once(addr_of_mut!((*list).next) as *mut usize, 0);
        }

        // bkt is always the head of the list, so it holds the lock, which we need to preserve
        rht_assign_locked(bkt, obj as usize);

        0
    }
}

/// `rhashtable_try_insert()`.
unsafe fn rhashtable_try_insert(ht: *mut Rht, key: *const c_void, obj: *mut RhashHead) -> usize {
    // SAFETY: called in an RCU read section.
    unsafe {
        let mut new_tbl = ld(addr_of!((*ht).tbl));
        let mut tbl: *mut Tbl;
        let mut data: usize;

        loop {
            tbl = new_tbl as *mut Tbl;
            let hash = rust_rhw_head_hashfn(ht, tbl, obj);
            let bkt = if ld(addr_of!((*tbl).future_tbl)) != 0 {
                // Failure is OK
                rht_bucket_var(tbl, hash)
            } else {
                rht_bucket_insert(ht, tbl, hash)
            };
            if bkt.is_null() {
                new_tbl = ld(addr_of!((*tbl).future_tbl));
                data = err_ptr(-EAGAIN);
            } else {
                let flags = rust_rhw_lock(tbl, bkt);
                data = rhashtable_lookup_one(ht, bkt, tbl, hash, key, obj);
                new_tbl = rhashtable_insert_one(ht, bkt, tbl, hash, obj, data);
                let inserted = data != 0 && new_tbl == 0;
                if inserted {
                    (*nelems(ht)).fetch_add(1, Ordering::SeqCst);
                }
                if ptr_err(new_tbl) != -EEXIST as isize {
                    data = new_tbl; // ERR_CAST(new_tbl)
                }

                rust_rhw_unlock(tbl, bkt, flags);

                if inserted && grow_above_75(ht, tbl) {
                    rust_rhw_schedule_work(ht);
                }
            }
            if is_err_or_null(new_tbl) {
                break;
            }
        }

        if ptr_err(data) == -EAGAIN as isize {
            let e = rhashtable_insert_rehash(ht, tbl);
            data = err_ptr(if e != 0 { e } else { -EAGAIN });
        }

        data
    }
}

/// `rhashtable_insert_slow()`.
#[no_mangle]
pub unsafe extern "C" fn rust_rhashtable_insert_slow(ht: *mut Rht, key: *const c_void, obj: *mut RhashHead) -> *mut c_void {
    // SAFETY: the caller's contract is the C function's.
    unsafe {
        let mut data;
        loop {
            rust_rhw_rcu_read_lock();
            data = rhashtable_try_insert(ht, key, obj);
            rust_rhw_rcu_read_unlock();
            if ptr_err(data) != -EAGAIN as isize {
                break;
            }
        }
        data as *mut c_void
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------
// walker
// ---------------------------------------------------------------------------------------------------------------------------------

/// `rhashtable_walk_enter()`.
#[no_mangle]
pub unsafe extern "C" fn rust_rhashtable_walk_enter(ht: *mut Rht, iter: *mut Iter) {
    // SAFETY: `iter` is the caller's.
    unsafe {
        (*iter).ht = ht;
        (*iter).p = null_mut();
        (*iter).slot = 0;
        (*iter).skip = 0;
        (*iter).end_of_table = false;

        rust_rhw_spin_lock(ht);
        (*iter).walker.tbl = ld(addr_of!((*ht).tbl)) as *mut Tbl;
        rust_rhw_list_add(addr_of_mut!((*iter).walker.list), addr_of_mut!((*(*iter).walker.tbl).walkers));
        rust_rhw_spin_unlock(ht);
    }
}

/// `rhashtable_walk_exit()`.
#[no_mangle]
pub unsafe extern "C" fn rust_rhashtable_walk_exit(iter: *mut Iter) {
    // SAFETY: `iter` is the caller's.
    unsafe {
        rust_rhw_spin_lock((*iter).ht);
        if !(*iter).walker.tbl.is_null() {
            rust_rhw_list_del(addr_of_mut!((*iter).walker.list));
        }
        rust_rhw_spin_unlock((*iter).ht);
    }
}

/// First entry of a chain for the readers (`rht_ptr_rcu(rht_bucket(tbl, hash))`).
#[inline(always)]
unsafe fn chain_head_rcu(tbl: *mut Tbl, hash: c_uint) -> usize {
    compiler_fence(Ordering::SeqCst); // barrier()
    // SAFETY: called in an RCU read section.
    unsafe { rht_ptr(rht_bucket(tbl, hash)) }
}

/// `rhashtable_walk_start_check()`.
#[no_mangle]
pub unsafe extern "C" fn rust_rhashtable_walk_start_check(iter: *mut Iter) -> c_int {
    // SAFETY: `iter` is the caller's; `rcu_read_lock` is taken here and released by walk_stop.
    unsafe {
        let ht = (*iter).ht;
        let rhlist = (*ht).rhlist;

        rust_rhw_rcu_read_lock();

        rust_rhw_spin_lock(ht);
        if !(*iter).walker.tbl.is_null() {
            rust_rhw_list_del(addr_of_mut!((*iter).walker.list));
        }
        rust_rhw_spin_unlock(ht);

        if (*iter).end_of_table {
            return 0;
        }
        if (*iter).walker.tbl.is_null() {
            (*iter).walker.tbl = ld(addr_of!((*ht).tbl)) as *mut Tbl;
            (*iter).slot = 0;
            (*iter).skip = 0;
            (*iter).p = null_mut();
            return -EAGAIN;
        }

        if !(*iter).p.is_null() && !rhlist {
            // We need to validate that 'p' is still in the table, and if so, update 'skip'
            let mut skip: c_int = 0;
            let mut p = chain_head_rcu((*iter).walker.tbl, (*iter).slot);
            while !is_nulls(p) {
                skip += 1;
                if p == (*iter).p as usize {
                    (*iter).skip = skip as c_uint;
                    return 0; // goto found
                }
                p = ld(next_of(p));
            }
            (*iter).p = null_mut();
        } else if !(*iter).p.is_null() && rhlist {
            // Need to validate that 'list' is still in the table, and if so, update 'skip' and 'p'.
            let mut skip: c_int = 0;
            let mut p = chain_head_rcu((*iter).walker.tbl, (*iter).slot);
            while !is_nulls(p) {
                let mut list = p as *mut RhlistHead;
                while !list.is_null() {
                    skip += 1;
                    if list == (*iter).list {
                        (*iter).p = p as *mut RhashHead;
                        (*iter).skip = skip as c_uint;
                        return 0; // goto found
                    }
                    list = ld(addr_of!((*list).next) as *const usize) as *mut RhlistHead;
                }
                p = ld(next_of(p));
            }
            (*iter).p = null_mut();
        }
        0
    }
}

/// `__rhashtable_walk_find_next()`: the found object, NULL at the end, or ERR_PTR(-EAGAIN).
unsafe fn walk_find_next(iter: *mut Iter) -> usize {
    // SAFETY: `iter` is the caller's, inside an RCU read section.
    unsafe {
        let tbl = (*iter).walker.tbl;
        let mut list = (*iter).list;
        let ht = (*iter).ht;
        let mut p;
        let rhlist = (*ht).rhlist;

        if tbl.is_null() {
            return 0;
        }

        while (*iter).slot < (*tbl).size {
            let mut skip = (*iter).skip as c_int;

            p = chain_head_rcu(tbl, (*iter).slot);
            'chain: while !is_nulls(p) {
                if rhlist {
                    list = p as *mut RhlistHead;
                    loop {
                        if skip == 0 {
                            break 'chain; // goto next
                        }
                        skip -= 1;
                        list = ld(addr_of!((*list).next) as *const usize) as *mut RhlistHead;
                        if list.is_null() {
                            break;
                        }
                    }
                    p = ld(next_of(p));
                    continue;
                }
                if skip == 0 {
                    break;
                }
                skip -= 1;
                p = ld(next_of(p));
            }

            // next:
            if !is_nulls(p) {
                (*iter).skip = (*iter).skip.wrapping_add(1);
                (*iter).p = p as *mut RhashHead;
                (*iter).list = list;
                return rht_obj(ht, if rhlist { list as usize } else { p }) as usize;
            }

            (*iter).skip = 0;
            (*iter).slot = (*iter).slot.wrapping_add(1);
        }

        (*iter).p = null_mut();

        // Ensure we see any new tables.
        fence(Ordering::Acquire); // smp_rmb()

        (*iter).walker.tbl = ld(addr_of!((*tbl).future_tbl)) as *mut Tbl;
        if !(*iter).walker.tbl.is_null() {
            (*iter).slot = 0;
            (*iter).skip = 0;
            return err_ptr(-EAGAIN);
        }
        (*iter).end_of_table = true;

        0
    }
}

/// `rhashtable_walk_next()`.
#[no_mangle]
pub unsafe extern "C" fn rust_rhashtable_walk_next(iter: *mut Iter) -> *mut c_void {
    // SAFETY: `iter` is the caller's, inside an RCU read section.
    unsafe {
        let mut list = (*iter).list;
        let ht = (*iter).ht;
        let mut p = (*iter).p as usize;
        let rhlist = (*ht).rhlist;

        if p != 0 {
            let advance = if !rhlist {
                true
            } else {
                list = ld(addr_of!((*list).next) as *const usize) as *mut RhlistHead;
                list.is_null()
            };
            if advance {
                p = ld(next_of(p));
                list = p as *mut RhlistHead;
            }
            if !is_nulls(p) {
                (*iter).skip = (*iter).skip.wrapping_add(1);
                (*iter).p = p as *mut RhashHead;
                (*iter).list = list;
                return rht_obj(ht, if rhlist { list as usize } else { p });
            }

            // At the end of this slot, switch to next one and then find next entry from that point.
            (*iter).skip = 0;
            (*iter).slot = (*iter).slot.wrapping_add(1);
        }

        walk_find_next(iter) as *mut c_void
    }
}

/// `rhashtable_walk_peek()`.
#[no_mangle]
pub unsafe extern "C" fn rust_rhashtable_walk_peek(iter: *mut Iter) -> *mut c_void {
    // SAFETY: `iter` is the caller's, inside an RCU read section.
    unsafe {
        let list = (*iter).list;
        let ht = (*iter).ht;
        let p = (*iter).p as usize;

        if p != 0 {
            return rht_obj(ht, if (*ht).rhlist { list as usize } else { p });
        }

        // No object found in current iter, find next one in the table.
        if (*iter).skip != 0 {
            // A nonzero skip value points to the next entry in the table beyond that last one that was found. Decrement skip so we
            // find the current value. __rhashtable_walk_find_next will restore the original value of skip assuming that the table hasn't
            // changed.
            (*iter).skip -= 1;
        }

        walk_find_next(iter) as *mut c_void
    }
}

/// `rhashtable_walk_stop()`.
#[no_mangle]
pub unsafe extern "C" fn rust_rhashtable_walk_stop(iter: *mut Iter) {
    // SAFETY: `iter` is the caller's.
    unsafe {
        let tbl = (*iter).walker.tbl;
        if !tbl.is_null() {
            let ht = (*iter).ht;

            rust_rhw_spin_lock(ht);
            if rust_rhw_after_call_rcu(tbl) {
                // This bucket table is being freed, don't re-link it.
                (*iter).walker.tbl = null_mut();
            } else {
                rust_rhw_list_add(addr_of_mut!((*iter).walker.list), addr_of_mut!((*tbl).walkers));
            }
            rust_rhw_spin_unlock(ht);
        }
        rust_rhw_rcu_read_unlock();
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------
// init / destroy
// ---------------------------------------------------------------------------------------------------------------------------------

/// `rounded_hashtable_size()`.
fn rounded_hashtable_size(params: &Params) -> usize {
    if params.nelem_hint != 0 {
        let n = (params.nelem_hint as c_int * 4 / 3) as u64;
        core::cmp::max(roundup_pow_of_two(n), params.min_size as u64) as usize
    } else {
        core::cmp::max(HASH_DEFAULT_SIZE, params.min_size as u64) as usize
    }
}

/// `rhashtable_init_noprof()`.
#[no_mangle]
pub unsafe extern "C" fn rust_rhashtable_init_noprof(ht: *mut Rht, params: *const Params) -> c_int {
    // SAFETY: the caller's contract is the C function's.
    unsafe {
        if ((*params).key_len == 0 && (*params).obj_hashfn.is_none()) || ((*params).obj_hashfn.is_some() && (*params).obj_cmpfn.is_none()) {
            return -EINVAL;
        }

        rust_rhw_init_prep(ht, params); // memset, mutex_init, spin_lock_init, memcpy(&ht->p, params), alloc_tag_record

        if (*params).min_size != 0 {
            (*ht).p.min_size = roundup_pow_of_two((*params).min_size as u64) as u16;
        }

        // Cap total entries at 2^31 to avoid nelems overflow.
        (*ht).max_elems = 1u32 << 31;

        if (*params).max_size != 0 {
            (*ht).p.max_size = rounddown_pow_of_two((*params).max_size as u64) as c_uint;
            if (*ht).p.max_size < (*ht).max_elems / 2 {
                (*ht).max_elems = (*ht).p.max_size * 2;
            }
        }

        (*ht).p.min_size = core::cmp::max((*ht).p.min_size, HASH_MIN_SIZE as u16);

        let mut size = rounded_hashtable_size(&*addr_of!((*ht).p));

        (*ht).key_len = (*ht).p.key_len as c_uint;
        if (*params).hashfn.is_none() {
            (*ht).p.hashfn = Some(rust_rhw_jhash_fn());

            if (*ht).key_len & (4 - 1) == 0 {
                (*ht).key_len /= 4;
                (*ht).p.hashfn = Some(rust_rhw_jhash2_fn());
            }
        }

        // This is api initialization and thus we need to guarantee the initial rhashtable allocation. Upon failure, retry with the
        // smallest possible size with __GFP_NOFAIL semantics.
        let mut tbl = bucket_table_alloc(ht, size, rust_rhw_gfp_kernel);
        if tbl.is_null() {
            size = core::cmp::max((*ht).p.min_size, HASH_MIN_SIZE as u16) as usize;
            tbl = bucket_table_alloc(ht, size, rust_rhw_gfp_kernel_nofail);
        }

        (*nelems(ht)).store(0, Ordering::SeqCst);

        st_once(addr_of_mut!((*ht).tbl), tbl as usize); // RCU_INIT_POINTER

        rust_rhw_init_work(ht);

        0
    }
}

/// `rhashtable_free_one()`.
unsafe fn rhashtable_free_one(ht: *mut Rht, obj: usize, free_fn: FreeFn, arg: *mut c_void) {
    // SAFETY: the caller has exclusive access to the table being destroyed.
    unsafe {
        if !(*ht).rhlist {
            free_fn(rht_obj(ht, obj), arg);
            return;
        }

        let mut list = obj as *mut RhlistHead;
        loop {
            let o = list as usize;
            list = ld(addr_of!((*list).next) as *const usize) as *mut RhlistHead;
            free_fn(rht_obj(ht, o), arg);
            if list.is_null() {
                break;
            }
        }
    }
}

/// `rhashtable_free_and_destroy()`.
#[no_mangle]
pub unsafe extern "C" fn rust_rhashtable_free_and_destroy(ht: *mut Rht, free_fn: Option<FreeFn>, arg: *mut c_void) {
    // SAFETY: the caller's contract is the C function's.
    unsafe {
        rust_rhw_cancel_work_sync(ht);

        rust_rhw_mutex_lock(ht);
        let mut tbl = ld(addr_of!((*ht).tbl)) as *mut Tbl;
        loop {
            if let Some(f) = free_fn {
                let mut i: c_uint = 0;
                while i < (*tbl).size {
                    rust_rhw_cond_resched();
                    let mut pos = rht_ptr(rht_bucket(tbl, i));
                    let mut next = if !is_nulls(pos) { ld(next_of(pos)) } else { 0 };
                    while !is_nulls(pos) {
                        rhashtable_free_one(ht, pos, f, arg);
                        pos = next;
                        next = if !is_nulls(pos) { ld(next_of(pos)) } else { 0 };
                    }
                    i += 1;
                }
            }

            let next_tbl = ld(addr_of!((*tbl).future_tbl)) as *mut Tbl;
            rust_rht_bucket_table_free(tbl);
            if next_tbl.is_null() {
                break;
            }
            tbl = next_tbl;
        }
        rust_rhw_mutex_unlock(ht);
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------
// nested tables
// ---------------------------------------------------------------------------------------------------------------------------------

/// `__rht_bucket_nested()`.
#[no_mangle]
pub unsafe extern "C" fn rust___rht_bucket_nested(tbl: *const Tbl, hash: c_uint) -> Bkt {
    // SAFETY: a live table, inside an RCU read section.
    unsafe {
        let tbl = tbl as *mut Tbl;
        let nest = (*tbl).nest;
        let mut index = (hash & ((1u32 << nest) - 1)) as usize;
        let mut size = (*tbl).size >> nest;
        let mut subhash = hash;

        let top = ld(buckets(tbl)) as *mut usize; // nested_table_top()
        let mut ntbl = ld(top.add(index)) as *mut usize;
        subhash >>= nest;

        while !ntbl.is_null() && size > (1u32 << SHIFT) {
            index = (subhash & ((1u32 << SHIFT) - 1)) as usize;
            ntbl = ld(ntbl.add(index)) as *mut usize;
            size >>= SHIFT;
            subhash >>= SHIFT;
        }

        if ntbl.is_null() {
            return null_mut();
        }

        ntbl.add(subhash as usize)
    }
}

/// `rht_bucket_nested_insert()`.
#[no_mangle]
pub unsafe extern "C" fn rust_rht_bucket_nested_insert(ht: *mut Rht, tbl: *mut Tbl, mut hash: c_uint) -> Bkt {
    // SAFETY: a live table.
    unsafe {
        let nest = (*tbl).nest;
        let mut index = (hash & ((1u32 << nest) - 1)) as usize;
        let mut size = (*tbl).size >> nest;

        let top = ld(buckets(tbl)) as *mut usize; // nested_table_top()
        hash >>= nest;
        let mut ntbl = nested_table_alloc(ht, top.add(index), size <= (1u32 << SHIFT));

        while !ntbl.is_null() && size > (1u32 << SHIFT) {
            index = (hash & ((1u32 << SHIFT) - 1)) as usize;
            size >>= SHIFT;
            hash >>= SHIFT;
            ntbl = nested_table_alloc(ht, ntbl.add(index), size <= (1u32 << SHIFT));
        }

        if ntbl.is_null() {
            return null_mut();
        }

        ntbl.add(hash as usize)
    }
}
