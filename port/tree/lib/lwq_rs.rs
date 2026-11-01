// SPDX-License-Identifier: GPL-2.0-only

//! The consumer side of the light-weight queue -- the Rust behind `lib/lwq.c`.
//!
//! Ported from `lib/lwq.c` (6.18.49), "Light-weight single-linked queue" (NeilBrown). Producers push onto an `llist` (`q->new`) without blocking, in any
//! context. Consumers serialise on `q->lock`; the entries they are working through sit in `q->ready` in dequeue order. When `ready` runs out the whole
//! `new` list is taken (`llist_del_all`) and reversed. In Rust: `__lwq_dequeue` and `lwq_dequeue_all`. In C (`lwq_glue.c`): the exports as thunks
//! (MODVERSIONS fingerprints come from the DWARF of the definition), `spin_lock`/`spin_unlock` wrappers, the `CONFIG_LWQ_TEST` module verbatim, and
//! the offsets of `ready` and `new` (they follow a `spinlock_t` whose size depends on the configuration).
//!
//! # The ordering contract (concurrency bar, item 1)
//! * `lwq_empty()` is an ACQUIRE load of `ready` plus a lockless look at `new.first`; it pairs with the producer's `lwq_enqueue()`.
//! * While the consumer holds the lock and is about to take `new`, it first publishes the placeholder `1` in `ready` with a RELEASE store so that the
//!   queue never appears transiently empty to a concurrent `lwq_empty()` between emptying `new` and filling `ready`.
//! * `llist_del_all` is a fully ordered `xchg(&new.first, NULL)`.
//!
//! Replaces: lib/lwq.c (the two dequeue functions; the exports, the lock calls and the test module stay C)

use core::ffi::c_void;
use core::ptr::{null_mut, read_volatile, write_volatile};
use core::sync::atomic::{AtomicPtr, Ordering};

/// `struct llist_node`.
#[repr(C)]
pub struct LlistNode {
    next: *mut LlistNode,
}

extern "C" {
    static rust_lwq_off_ready: usize; // offsetof(struct lwq, ready)
    static rust_lwq_off_new: usize; // offsetof(struct lwq, new)

    fn rust_lwqw_lock(q: *mut c_void);
    fn rust_lwqw_unlock(q: *mut c_void);
    /// `lib/llist.c`
    fn llist_reverse_order(head: *mut LlistNode) -> *mut LlistNode;
}

#[inline(always)]
unsafe fn ready_of(q: *mut c_void) -> *mut *mut LlistNode {
    unsafe { (q as *mut u8).add(rust_lwq_off_ready) as *mut *mut LlistNode }
}

#[inline(always)]
unsafe fn new_of(q: *mut c_void) -> *mut *mut LlistNode {
    unsafe { (q as *mut u8).add(rust_lwq_off_new) as *mut *mut LlistNode }
}

/// `lwq_empty()`.
#[inline(always)]
unsafe fn lwq_empty(q: *mut c_void) -> bool {
    unsafe { AtomicPtr::from_ptr(ready_of(q)).load(Ordering::Acquire).is_null() && read_volatile(new_of(q)).is_null() }
}

/// `llist_del_all()`.
#[inline(always)]
unsafe fn llist_del_all(q: *mut c_void) -> *mut LlistNode {
    unsafe { AtomicPtr::from_ptr(new_of(q)).swap(null_mut(), Ordering::SeqCst) }
}

/// `__lwq_dequeue()`.
#[no_mangle]
pub unsafe extern "C" fn rust_lwq_dequeue(q: *mut c_void) -> *mut LlistNode {
    unsafe {
        if lwq_empty(q) {
            return null_mut();
        }
        rust_lwqw_lock(q);
        let mut this = read_volatile(ready_of(q));
        if this.is_null() && !read_volatile(new_of(q)).is_null() {
            // ensure queue doesn't appear transiently lwq_empty
            AtomicPtr::from_ptr(ready_of(q)).store(1 as *mut LlistNode, Ordering::Release);
            this = llist_reverse_order(llist_del_all(q));
            if this.is_null() {
                write_volatile(ready_of(q), null_mut());
            }
        }
        if !this.is_null() {
            write_volatile(ready_of(q), (*this).next);
        }
        rust_lwqw_unlock(q);
        this
    }
}

/// `lwq_dequeue_all()`.
#[no_mangle]
pub unsafe extern "C" fn rust_lwq_dequeue_all(q: *mut c_void) -> *mut LlistNode {
    unsafe {
        if lwq_empty(q) {
            return null_mut();
        }

        rust_lwqw_lock(q);
        let mut r = read_volatile(ready_of(q));
        write_volatile(ready_of(q), null_mut());
        let t = llist_del_all(q);
        rust_lwqw_unlock(q);
        let mut ep: *mut *mut LlistNode = &mut r;
        while !(*ep).is_null() {
            ep = &mut (**ep).next;
        }
        *ep = llist_reverse_order(t);
        r
    }
}
