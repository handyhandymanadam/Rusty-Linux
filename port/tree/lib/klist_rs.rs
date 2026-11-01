// SPDX-License-Identifier: GPL-2.0-only

//! The klist machinery -- the Rust behind `lib/klist.c`.
//!
//! Ported from `lib/klist.c` (6.18.49), Patrick Mochel's "klists": a list head plus a spinlock, nodes with a reference count and a "dead" bit kept in the low
//! bit of `n_klist`, and iterators that hold a reference on the current node so the list can change under them. In Rust: everything but `klist_init` (it needs
//! `spin_lock_init`'s per-call-site lockdep key) and `klist_remove` (it sleeps: `current`, `set_current_state`, `schedule`). In C (`klist_glue.c`): those two, the
//! exports as thunks (MODVERSIONS fingerprints come from the DWARF of the definition), and one-line wrappers for everything whose behaviour depends on the
//! configuration -- the spinlock calls (`spinlock_t`'s size and lockdep), `list_add`/`list_add_tail`/`list_del` (CONFIG_LIST_HARDENED checks, poisoning), the `kref`
//! calls (refcount saturation warnings), `wake_up_process`, `mb()` and the `WARN_ON` sites.
//!
//! Replaces: lib/klist.c (all but `klist_init` and `klist_remove`)

use core::ffi::{c_int, c_ulong, c_void};
use core::ptr::null_mut;

/// `struct list_head`.
#[repr(C)]
pub struct ListHead {
    next: *mut ListHead,
    prev: *mut ListHead,
}

type NodeFn = Option<unsafe extern "C" fn(*mut c_void)>;

/// `struct klist_waiter` (the definition sits here and in `klist_glue.c`, which `klist_remove()` fills in).
#[allow(dead_code)]
#[repr(C)]
pub struct KlistWaiter {
    list: ListHead,
    node: *mut c_void,
    process: *mut c_void,
    woken: c_int,
}

const KNODE_DEAD: c_ulong = 1;
const KNODE_KLIST_MASK: c_ulong = !KNODE_DEAD;

/// `offsetof(struct klist_node, n_node)` (checked by `klist_glue.c`).
const OFF_N_NODE: usize = 8;

extern "C" {
    static rust_kl_off_list: usize; // offsetof(struct klist, k_list)
    static rust_kl_off_get: usize;
    static rust_kl_off_put: usize;

    fn rust_kl_lock(k: *mut c_void);
    fn rust_kl_unlock(k: *mut c_void);
    fn rust_kl_lock_irqsave(k: *mut c_void, flags: *mut c_ulong);
    fn rust_kl_unlock_irqrestore(k: *mut c_void, flags: c_ulong);
    fn rust_kl_remove_lock();
    fn rust_kl_remove_unlock();
    fn rust_kl_waiters() -> *mut ListHead;

    fn rust_kl_list_add(new: *mut ListHead, head: *mut ListHead);
    fn rust_kl_list_add_tail(new: *mut ListHead, head: *mut ListHead);
    fn rust_kl_list_del(entry: *mut ListHead);
    fn rust_kl_init_list_head(l: *mut ListHead);

    fn rust_kl_kref_init(n: *mut c_void);
    fn rust_kl_kref_get(n: *mut c_void);
    fn rust_kl_kref_get_unless_zero(n: *mut c_void) -> bool;
    fn rust_kl_kref_dec_and_test(n: *mut c_void) -> bool;

    fn rust_kl_wake_up_process(task: *mut c_void);
    fn rust_kl_mb();
    fn rust_kl_warn_dead_at_start(cond: bool);
    fn rust_kl_warn_dead_twice(cond: bool);
    fn rust_kl_warn_release_not_dead(cond: bool);
}

#[inline(always)]
unsafe fn n_klist(n: *mut c_void) -> *mut c_ulong {
    n as *mut c_ulong
}

#[inline(always)]
unsafe fn n_node(n: *mut c_void) -> *mut ListHead {
    unsafe { (n as *mut u8).add(OFF_N_NODE) as *mut ListHead }
}

#[inline(always)]
unsafe fn k_list(k: *mut c_void) -> *mut ListHead {
    unsafe { (k as *mut u8).add(rust_kl_off_list) as *mut ListHead }
}

#[inline(always)]
unsafe fn k_get(k: *mut c_void) -> NodeFn {
    unsafe { *((k as *mut u8).add(rust_kl_off_get) as *mut NodeFn) }
}

#[inline(always)]
unsafe fn k_put(k: *mut c_void) -> NodeFn {
    unsafe { *((k as *mut u8).add(rust_kl_off_put) as *mut NodeFn) }
}

/// `to_klist_node()`: the node a `n_node` belongs to.
#[inline(always)]
unsafe fn to_klist_node(l: *mut ListHead) -> *mut c_void {
    unsafe { (l as *mut u8).sub(OFF_N_NODE) as *mut c_void }
}

/// `knode_klist()`.
#[inline(always)]
unsafe fn knode_klist(n: *mut c_void) -> *mut c_void {
    unsafe { (*n_klist(n) & KNODE_KLIST_MASK) as *mut c_void }
}

/// `knode_dead()`.
#[inline(always)]
unsafe fn knode_dead(n: *mut c_void) -> bool {
    unsafe { *n_klist(n) & KNODE_DEAD != 0 }
}

/// `knode_set_klist()`.
#[inline(always)]
unsafe fn knode_set_klist(n: *mut c_void, k: *mut c_void) {
    unsafe {
        *n_klist(n) = k as c_ulong;
        // no knode deserves to start its life dead
        rust_kl_warn_dead_at_start(knode_dead(n));
    }
}

/// `knode_kill()`.
#[inline(always)]
unsafe fn knode_kill(n: *mut c_void) {
    unsafe {
        // and no knode should die twice ever either, see we're very humane
        rust_kl_warn_dead_twice(knode_dead(n));
        *n_klist(n) |= KNODE_DEAD;
    }
}

/// `klist_node_init()`.
unsafe fn klist_node_init(k: *mut c_void, n: *mut c_void) {
    unsafe {
        rust_kl_init_list_head(n_node(n));
        rust_kl_kref_init(n);
        knode_set_klist(n, k);
        if let Some(get) = k_get(k) {
            get(n);
        }
    }
}

/// `klist_add_head()`.
#[no_mangle]
pub unsafe extern "C" fn rust_klist_add_head(n: *mut c_void, k: *mut c_void) {
    unsafe {
        klist_node_init(k, n);
        rust_kl_lock(k);
        rust_kl_list_add(n_node(n), k_list(k));
        rust_kl_unlock(k);
    }
}

/// `klist_add_tail()`.
#[no_mangle]
pub unsafe extern "C" fn rust_klist_add_tail(n: *mut c_void, k: *mut c_void) {
    unsafe {
        klist_node_init(k, n);
        rust_kl_lock(k);
        rust_kl_list_add_tail(n_node(n), k_list(k));
        rust_kl_unlock(k);
    }
}

/// `klist_add_behind()`.
#[no_mangle]
pub unsafe extern "C" fn rust_klist_add_behind(n: *mut c_void, pos: *mut c_void) {
    unsafe {
        let k = knode_klist(pos);
        klist_node_init(k, n);
        rust_kl_lock(k);
        rust_kl_list_add(n_node(n), n_node(pos));
        rust_kl_unlock(k);
    }
}

/// `klist_add_before()`.
#[no_mangle]
pub unsafe extern "C" fn rust_klist_add_before(n: *mut c_void, pos: *mut c_void) {
    unsafe {
        let k = knode_klist(pos);
        klist_node_init(k, n);
        rust_kl_lock(k);
        rust_kl_list_add_tail(n_node(n), n_node(pos));
        rust_kl_unlock(k);
    }
}

/// `klist_release()`: the last reference went; unlink the node and wake whoever waits in `klist_remove()` for it.
unsafe fn klist_release(n: *mut c_void) {
    unsafe {
        rust_kl_warn_release_not_dead(!knode_dead(n));
        rust_kl_list_del(n_node(n));
        rust_kl_remove_lock();
        let head = rust_kl_waiters();
        let mut pos = (*head).next;
        while pos != head {
            let tmp = (*pos).next;
            let waiter = pos as *mut KlistWaiter;
            if (*waiter).node == n {
                rust_kl_list_del(pos);
                (*waiter).woken = 1;
                rust_kl_mb();
                rust_kl_wake_up_process((*waiter).process);
            }
            pos = tmp;
        }
        rust_kl_remove_unlock();
        knode_set_klist(n, null_mut());
    }
}

/// `klist_dec_and_del()`: `kref_put(&n->n_ref, klist_release)`.
unsafe fn klist_dec_and_del(n: *mut c_void) -> bool {
    unsafe {
        if rust_kl_kref_dec_and_test(n) {
            klist_release(n);
            return true;
        }
        false
    }
}

/// `klist_put()`.
unsafe fn klist_put(n: *mut c_void, kill: bool) {
    unsafe {
        let k = knode_klist(n);
        let mut put = k_put(k);

        rust_kl_lock(k);
        if kill {
            knode_kill(n);
        }
        if !klist_dec_and_del(n) {
            put = None;
        }
        rust_kl_unlock(k);
        if let Some(put) = put {
            put(n);
        }
    }
}

/// `klist_del()`.
#[no_mangle]
pub unsafe extern "C" fn rust_klist_del(n: *mut c_void) {
    unsafe { klist_put(n, true) }
}

/// `klist_node_attached()`.
#[no_mangle]
pub unsafe extern "C" fn rust_klist_node_attached(n: *mut c_void) -> c_int {
    unsafe { (*n_klist(n) != 0) as c_int }
}

/// `klist_iter_init_node()`.
#[no_mangle]
pub unsafe extern "C" fn rust_klist_iter_init_node(k: *mut c_void, i: *mut c_void, n: *mut c_void) {
    unsafe {
        let i_klist = i as *mut *mut c_void;
        let i_cur = (i as *mut u8).add(8) as *mut *mut c_void;
        *i_klist = k;
        *i_cur = null_mut();
        if !n.is_null() && rust_kl_kref_get_unless_zero(n) {
            *i_cur = n;
        }
    }
}

/// `klist_iter_exit()`.
#[no_mangle]
pub unsafe extern "C" fn rust_klist_iter_exit(i: *mut c_void) {
    unsafe {
        let i_cur = (i as *mut u8).add(8) as *mut *mut c_void;
        if !(*i_cur).is_null() {
            klist_put(*i_cur, false);
            *i_cur = null_mut();
        }
    }
}

/// `klist_prev()` (`forward == false`) and `klist_next()` (`forward == true`): they differ only in the direction.
unsafe fn klist_step(i: *mut c_void, forward: bool) -> *mut c_void {
    unsafe {
        let i_klist = *(i as *mut *mut c_void);
        let i_cur = (i as *mut u8).add(8) as *mut *mut c_void;
        let mut put = k_put(i_klist);
        let last = *i_cur;
        let mut flags: c_ulong = 0;
        let mut step: *mut c_void;
        let head = k_list(i_klist);

        rust_kl_lock_irqsave(i_klist, &mut flags);

        if !last.is_null() {
            let l = n_node(last);
            step = to_klist_node(if forward { (*l).next } else { (*l).prev });
            if !klist_dec_and_del(last) {
                put = None;
            }
        } else {
            step = to_klist_node(if forward { (*head).next } else { (*head).prev });
        }

        *i_cur = null_mut();
        while n_node(step) != head {
            if !knode_dead(step) {
                rust_kl_kref_get(step);
                *i_cur = step;
                break;
            }
            let l = n_node(step);
            step = to_klist_node(if forward { (*l).next } else { (*l).prev });
        }

        rust_kl_unlock_irqrestore(i_klist, flags);

        if let Some(put) = put {
            if !last.is_null() {
                put(last);
            }
        }
        *i_cur
    }
}

/// `klist_prev()`.
#[no_mangle]
pub unsafe extern "C" fn rust_klist_prev(i: *mut c_void) -> *mut c_void {
    unsafe { klist_step(i, false) }
}

/// `klist_next()`.
#[no_mangle]
pub unsafe extern "C" fn rust_klist_next(i: *mut c_void) -> *mut c_void {
    unsafe { klist_step(i, true) }
}
