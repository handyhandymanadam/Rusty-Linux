// SPDX-License-Identifier: GPL-2.0-only

//! The notifier-chain core -- the Rust behind `kernel/notifier.c`.
//!
//! Ported from `kernel/notifier.c` (6.18.49): `notifier_chain_register()` (sorted insert by priority, duplicate and unique-priority refusal), `notifier_chain_unregister()`,
//! `notifier_call_chain()` (walk, stop on `NOTIFY_STOP_MASK`, bounded by `nr_to_call`, counted in `nr_calls`) and `notifier_call_chain_robust()` (call up; if a callback stopped
//! the chain, call down over the ones already called). In C (`notifier_glue.c`): every public function (the four chain flavours with their spinlock / rwsem / mutex / SRCU, the
//! die chain), the exports, the callback invocation itself (an indirect call through `nb->notifier_call`, kept in C for CFI and so a NULL callback oopses as before), the
//! tracepoints, the duplicate-registration `WARN` with `%ps`, and the `CONFIG_DEBUG_NOTIFIERS` text check.
//!
//! `struct notifier_block` is `{ notifier_call, next, priority }` and does not depend on the configuration. The chain head is a pointer to `struct notifier_block *`.
//!
//! Replaces: kernel/notifier.c (the chain core)

use core::ffi::{c_int, c_ulong, c_void};
use core::sync::atomic::{AtomicPtr, Ordering};

const EEXIST: c_int = 17;
const EBUSY: c_int = 16;
const ENOENT: c_int = 2;
const NOTIFY_DONE: c_int = 0;
const NOTIFY_STOP_MASK: c_int = 0x8000;

/// Mirrors `struct notifier_block`.
#[repr(C)]
pub struct Nb {
    notifier_call: *const c_void,
    next: AtomicPtr<Nb>,
    priority: c_int,
}

extern "C" {
    fn rust_nt_warn_dup(n: *mut Nb);
    fn rust_nt_trace_register(n: *mut Nb);
    fn rust_nt_trace_unregister(n: *mut Nb);
    /// `trace_notifier_run()` + `nb->notifier_call(nb, val, v)`.
    fn rust_nt_call(nb: *mut Nb, val: c_ulong, v: *mut c_void) -> c_int;
    /// `CONFIG_DEBUG_NOTIFIERS`: false (after a WARN) when the callback is not kernel text; always true otherwise.
    fn rust_nt_callback_ok(nb: *mut Nb) -> bool;
}

#[inline]
unsafe fn slot<'a>(nl: *mut *mut Nb) -> &'a AtomicPtr<Nb> {
    // `*nl` is a `struct notifier_block __rcu *`; AtomicPtr<Nb> has the same layout as a pointer.
    unsafe { &*(nl as *const AtomicPtr<Nb>) }
}

/// Body of `notifier_chain_register()`; callers hold the chain's lock (or are single-threaded early in boot).
#[no_mangle]
pub unsafe extern "C" fn rust_nt_register(mut nl: *mut *mut Nb, n: *mut Nb, unique_priority: bool) -> c_int {
    unsafe {
        loop {
            let cur = slot(nl).load(Ordering::Relaxed);
            if cur.is_null() {
                break;
            }
            if cur == n {
                rust_nt_warn_dup(n);
                return -EEXIST;
            }
            if (*n).priority > (*cur).priority {
                break;
            }
            if (*n).priority == (*cur).priority && unique_priority {
                return -EBUSY;
            }
            nl = (*cur).next.as_ptr();
        }
        (*n).next.store(slot(nl).load(Ordering::Relaxed), Ordering::Relaxed);
        slot(nl).store(n, Ordering::Release); // rcu_assign_pointer()
        rust_nt_trace_register(n);
    }
    0
}

/// Body of `notifier_chain_unregister()`.
#[no_mangle]
pub unsafe extern "C" fn rust_nt_unregister(mut nl: *mut *mut Nb, n: *mut Nb) -> c_int {
    unsafe {
        loop {
            let cur = slot(nl).load(Ordering::Relaxed);
            if cur.is_null() {
                return -ENOENT;
            }
            if cur == n {
                slot(nl).store((*n).next.load(Ordering::Relaxed), Ordering::Release);
                rust_nt_trace_unregister(n);
                return 0;
            }
            nl = (*cur).next.as_ptr();
        }
    }
}

/// Body of `notifier_call_chain()`. `nr_to_call` is -1 for "all"; `nr_calls` may be NULL.
#[no_mangle]
pub unsafe extern "C" fn rust_nt_call_chain(nl: *mut *mut Nb, val: c_ulong, v: *mut c_void, mut nr_to_call: c_int, nr_calls: *mut c_int) -> c_int {
    let mut ret = NOTIFY_DONE;
    unsafe {
        let mut nb = slot(nl).load(Ordering::Relaxed); // rcu_dereference_raw()
        while !nb.is_null() && nr_to_call != 0 {
            let next_nb = (*nb).next.load(Ordering::Relaxed);
            if !rust_nt_callback_ok(nb) {
                nb = next_nb;
                continue;
            }
            ret = rust_nt_call(nb, val, v);
            if !nr_calls.is_null() {
                *nr_calls += 1;
            }
            if ret & NOTIFY_STOP_MASK != 0 {
                break;
            }
            nb = next_nb;
            nr_to_call = nr_to_call.wrapping_sub(1);
        }
    }
    ret
}

/// Body of `notifier_call_chain_robust()`.
#[no_mangle]
pub unsafe extern "C" fn rust_nt_call_chain_robust(nl: *mut *mut Nb, val_up: c_ulong, val_down: c_ulong, v: *mut c_void) -> c_int {
    let mut nr: c_int = 0;
    unsafe {
        let ret = rust_nt_call_chain(nl, val_up, v, -1, &mut nr);
        if ret & NOTIFY_STOP_MASK != 0 {
            rust_nt_call_chain(nl, val_down, v, nr.wrapping_sub(1), core::ptr::null_mut());
        }
        ret
    }
}
