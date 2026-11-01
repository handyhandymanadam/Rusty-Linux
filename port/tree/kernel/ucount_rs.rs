// SPDX-License-Identifier: GPL-2.0-only

//! The counter arithmetic of `kernel/ucount.c` -- the Rust behind it.
//!
//! Ported from `kernel/ucount.c` (6.18.49): the walks up the chain of user namespaces that charge and uncharge per-user counters: `inc_ucount()` (charge each level below its
//! maximum, undo on failure), `dec_ucount()`, `inc_rlimit_ucounts()`, `dec_rlimit_ucounts()`, `inc_rlimit_get_ucounts()` / `dec_rlimit_put_ucounts()` (the rlimit counters that
//! hold a reference on each level while non-zero) and `is_rlimit_overlimit()`. In C (`ucount_glue.c`): the hash table of `struct ucounts` with its lock and RCU lookups
//! (`alloc_ucounts()`, `put_ucounts()`), the sysctl tables, the initcall, thunks for the entry points, offsets of the fields (`struct ucounts` and `struct user_namespace`
//! depend on the configuration), and one wrapper per `WARN_ON_ONCE` site (the once-flag is per site).
//!
//! Atomics: `atomic_long_add_return` / `sub_return` / `try_cmpxchg` / `dec_if_positive` are fully ordered (SeqCst); `atomic_long_read` and `atomic_long_dec` are relaxed.
//!
//! Replaces: kernel/ucount.c (the counter walks)

use core::ffi::{c_int, c_long, c_void};
use core::sync::atomic::{AtomicIsize, Ordering};

type Ucounts = c_void;
type Ns = c_void;

extern "C" {
    static rust_uc_off_ns: usize; // ucounts->ns
    static rust_uc_off_ucount: usize; // ucounts->ucount[]
    static rust_uc_off_rlimit: usize; // ucounts->rlimit[]
    static rust_uc_off_ns_ucounts: usize; // ns->ucounts
    static rust_uc_off_ns_ucount_max: usize; // ns->ucount_max[]
    static rust_uc_off_ns_rlimit_max: usize; // ns->rlimit_max[]
    fn rust_uc_alloc(ns: *mut Ns, uid: u32) -> *mut Ucounts;
    fn rust_uc_put(u: *mut Ucounts);
    fn rust_uc_get(u: *mut Ucounts) -> *mut Ucounts;
    fn rust_uc_warn_dec_ucount();
    fn rust_uc_warn_dec_rlimit();
    fn rust_uc_warn_do_dec();
    fn rust_uc_warn_unwind();
}

#[inline]
unsafe fn ns_of(u: *mut Ucounts) -> *mut Ns {
    unsafe { *((u as *mut u8).add(rust_uc_off_ns) as *const *mut Ns) }
}
#[inline]
unsafe fn parent(u: *mut Ucounts) -> *mut Ucounts {
    // iter->ns->ucounts
    unsafe { *((ns_of(u) as *mut u8).add(rust_uc_off_ns_ucounts) as *const *mut Ucounts) }
}
#[inline]
unsafe fn ucount<'a>(u: *mut Ucounts, t: usize) -> &'a AtomicIsize {
    unsafe { &*((u as *mut u8).add(rust_uc_off_ucount + 8 * t) as *const AtomicIsize) }
}
#[inline]
unsafe fn rlimit<'a>(u: *mut Ucounts, t: usize) -> &'a AtomicIsize {
    unsafe { &*((u as *mut u8).add(rust_uc_off_rlimit + 8 * t) as *const AtomicIsize) }
}
#[inline]
unsafe fn rlimit_max(ns: *mut Ns, t: usize) -> c_long {
    unsafe { (*((ns as *mut u8).add(rust_uc_off_ns_rlimit_max + 8 * t) as *const AtomicIsize)).load(Ordering::Relaxed) as c_long }
}

/// `atomic_long_inc_below()`.
fn inc_below(v: &AtomicIsize, u: isize) -> bool {
    let mut c = v.load(Ordering::Relaxed);
    loop {
        if c >= u {
            return false;
        }
        match v.compare_exchange(c, c + 1, Ordering::SeqCst, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(now) => c = now,
        }
    }
}

/// `atomic_long_dec_if_positive()`: returns the old value minus one (negative: not stored).
fn dec_if_positive(v: &AtomicIsize) -> isize {
    let mut c = v.load(Ordering::Relaxed);
    loop {
        let dec = c.wrapping_sub(1);
        if dec < 0 {
            return dec;
        }
        match v.compare_exchange(c, dec, Ordering::SeqCst, Ordering::Relaxed) {
            Ok(_) => return dec,
            Err(now) => c = now,
        }
    }
}

/// Body of `inc_ucount()`.
#[no_mangle]
pub unsafe extern "C" fn rust_inc_ucount(ns: *mut Ns, uid: u32, ty: c_int) -> *mut Ucounts {
    unsafe {
        let ucounts = rust_uc_alloc(ns, uid);
        let t = ty as usize;
        let mut iter = ucounts;
        while !iter.is_null() {
            let tns = ns_of(iter);
            let max = (*((tns as *mut u8).add(rust_uc_off_ns_ucount_max + 8 * t) as *const AtomicIsize)).load(Ordering::Relaxed);
            if !inc_below(ucount(iter, t), max) {
                // fail: undo the levels already charged
                let bad = iter;
                let mut it = ucounts;
                while it != bad {
                    ucount(it, t).fetch_sub(1, Ordering::Relaxed);
                    it = parent(it);
                }
                rust_uc_put(ucounts);
                return core::ptr::null_mut();
            }
            iter = parent(iter);
        }
        ucounts
    }
}

/// Body of `dec_ucount()`.
#[no_mangle]
pub unsafe extern "C" fn rust_dec_ucount(ucounts: *mut Ucounts, ty: c_int) {
    unsafe {
        let mut iter = ucounts;
        while !iter.is_null() {
            let dec = dec_if_positive(ucount(iter, ty as usize));
            if dec < 0 {
                rust_uc_warn_dec_ucount();
            }
            iter = parent(iter);
        }
        rust_uc_put(ucounts);
    }
}

/// Body of `inc_rlimit_ucounts()`.
#[no_mangle]
pub unsafe extern "C" fn rust_inc_rlimit_ucounts(ucounts: *mut Ucounts, ty: c_int, v: c_long) -> c_long {
    unsafe {
        let t = ty as usize;
        let mut max = c_long::MAX;
        let mut ret: c_long = 0;
        let mut iter = ucounts;
        while !iter.is_null() {
            let new = rlimit(iter, t).fetch_add(v as isize, Ordering::SeqCst).wrapping_add(v as isize) as c_long;
            if new < 0 || new > max {
                ret = c_long::MAX;
            } else if iter == ucounts {
                ret = new;
            }
            max = rlimit_max(ns_of(iter), t);
            iter = parent(iter);
        }
        ret
    }
}

/// Body of `dec_rlimit_ucounts()`.
#[no_mangle]
pub unsafe extern "C" fn rust_dec_rlimit_ucounts(ucounts: *mut Ucounts, ty: c_int, v: c_long) -> bool {
    unsafe {
        let mut new: c_long = -1;
        let mut iter = ucounts;
        while !iter.is_null() {
            let dec = rlimit(iter, ty as usize).fetch_sub(v as isize, Ordering::SeqCst).wrapping_sub(v as isize) as c_long;
            if dec < 0 {
                rust_uc_warn_dec_rlimit();
            }
            if iter == ucounts {
                new = dec;
            }
            iter = parent(iter);
        }
        new == 0
    }
}

unsafe fn do_dec_rlimit_put_ucounts(ucounts: *mut Ucounts, last: *mut Ucounts, ty: usize) {
    unsafe {
        let mut iter = ucounts;
        while iter != last {
            let dec = rlimit(iter, ty).fetch_sub(1, Ordering::SeqCst).wrapping_sub(1);
            if dec < 0 {
                rust_uc_warn_do_dec();
            }
            let next = parent(iter);
            if dec == 0 {
                rust_uc_put(iter);
            }
            iter = next;
        }
    }
}

/// Body of `dec_rlimit_put_ucounts()`.
#[no_mangle]
pub unsafe extern "C" fn rust_dec_rlimit_put_ucounts(ucounts: *mut Ucounts, ty: c_int) {
    unsafe { do_dec_rlimit_put_ucounts(ucounts, core::ptr::null_mut(), ty as usize) }
}

/// Body of `inc_rlimit_get_ucounts()`.
#[no_mangle]
pub unsafe extern "C" fn rust_inc_rlimit_get_ucounts(ucounts: *mut Ucounts, ty: c_int, override_rlimit: bool) -> c_long {
    unsafe {
        let t = ty as usize;
        let mut max = c_long::MAX;
        let mut ret: c_long = 0;
        let mut iter = ucounts;
        while !iter.is_null() {
            let new = rlimit(iter, t).fetch_add(1, Ordering::SeqCst).wrapping_add(1) as c_long;
            let mut unwind = new < 0 || new > max;
            if !unwind {
                if iter == ucounts {
                    ret = new;
                }
                if !override_rlimit {
                    max = rlimit_max(ns_of(iter), t);
                }
                if new == 1 && rust_uc_get(iter).is_null() {
                    unwind = true;
                }
            }
            if unwind {
                let dec = rlimit(iter, t).fetch_sub(1, Ordering::SeqCst).wrapping_sub(1);
                if dec < 0 {
                    rust_uc_warn_unwind();
                }
                do_dec_rlimit_put_ucounts(ucounts, iter, t);
                return 0;
            }
            iter = parent(iter);
        }
        ret
    }
}

/// Body of `is_rlimit_overlimit()`.
#[no_mangle]
pub unsafe extern "C" fn rust_is_rlimit_overlimit(ucounts: *mut Ucounts, ty: c_int, rl: u64) -> bool {
    unsafe {
        let t = ty as usize;
        let mut max: c_long = if rl > c_long::MAX as u64 { c_long::MAX } else { rl as c_long };
        let mut iter = ucounts;
        while !iter.is_null() {
            let val = rlimit(iter, t).load(Ordering::Relaxed) as c_long;
            if val < 0 || val > max {
                return true;
            }
            max = rlimit_max(ns_of(iter), t);
            iter = parent(iter);
        }
        false
    }
}
