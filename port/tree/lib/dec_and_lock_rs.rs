// SPDX-License-Identifier: GPL-2.0-only

//! The `atomic_dec_and_lock` family -- the Rust behind `lib/dec_and_lock.c`.
//!
//! Ported from `lib/dec_and_lock.c` (6.18.49): decrement a counter without taking the lock unless that would drop it to zero; in that case take the lock, decrement, and keep the
//! lock only if the counter really reached zero (return 1), else drop it (return 0). The lock-free step is `atomic_add_unless(v, -1, 1)`, a compare-exchange loop here; the final
//! `atomic_dec_and_test()` is a fully ordered decrement. In C (`dec_and_lock_glue.c`): the four exports as thunks (the MODVERSIONS fingerprint comes from the DWARF of the definition)
//! and one-line wrappers for the locks (`spinlock_t` and `raw_spinlock_t` depend on the configuration: lockdep, PREEMPT_RT, debug).
//!
//! Replaces: lib/dec_and_lock.c

use core::ffi::{c_int, c_ulong, c_void};
use core::sync::atomic::{AtomicI32, Ordering};

extern "C" {
    fn rust_dl_lock(lock: *mut c_void);
    fn rust_dl_unlock(lock: *mut c_void);
    fn rust_dl_lock_irqsave(lock: *mut c_void, flags: *mut c_ulong);
    fn rust_dl_unlock_irqrestore(lock: *mut c_void, flags: c_ulong);
    fn rust_dl_raw_lock(lock: *mut c_void);
    fn rust_dl_raw_unlock(lock: *mut c_void);
    fn rust_dl_raw_lock_irqsave(lock: *mut c_void, flags: *mut c_ulong);
    fn rust_dl_raw_unlock_irqrestore(lock: *mut c_void, flags: c_ulong);
}

/// `atomic_add_unless(atomic, -1, 1)`: subtract 1 from the counter unless that would drop it to 0 (it was 1). True if it subtracted.
#[inline(always)]
unsafe fn dec_unless_one(atomic: *mut c_void) -> bool {
    let a = unsafe { &*(atomic as *const AtomicI32) };
    let mut c = a.load(Ordering::Relaxed);
    loop {
        if c == 1 {
            return false;
        }
        match a.compare_exchange_weak(c, c.wrapping_sub(1), Ordering::SeqCst, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(x) => c = x,
        }
    }
}

/// `atomic_dec_and_test()`: a fully ordered decrement; true if the result is 0.
#[inline(always)]
unsafe fn dec_and_test(atomic: *mut c_void) -> bool {
    let a = unsafe { &*(atomic as *const AtomicI32) };
    a.fetch_sub(1, Ordering::SeqCst).wrapping_sub(1) == 0
}

/// The body of C `_atomic_dec_and_lock()`.
#[no_mangle]
pub unsafe extern "C" fn rust__atomic_dec_and_lock(atomic: *mut c_void, lock: *mut c_void) -> c_int {
    unsafe {
        // Subtract 1 from counter unless that drops it to 0 (ie. it was 1)
        if dec_unless_one(atomic) {
            return 0;
        }

        // Otherwise do it the slow way
        rust_dl_lock(lock);
        if dec_and_test(atomic) {
            return 1;
        }
        rust_dl_unlock(lock);
        0
    }
}

/// The body of C `_atomic_dec_and_lock_irqsave()`.
#[no_mangle]
pub unsafe extern "C" fn rust__atomic_dec_and_lock_irqsave(atomic: *mut c_void, lock: *mut c_void, flags: *mut c_ulong) -> c_int {
    unsafe {
        if dec_unless_one(atomic) {
            return 0;
        }

        rust_dl_lock_irqsave(lock, flags);
        if dec_and_test(atomic) {
            return 1;
        }
        rust_dl_unlock_irqrestore(lock, *flags);
        0
    }
}

/// The body of C `_atomic_dec_and_raw_lock()`.
#[no_mangle]
pub unsafe extern "C" fn rust__atomic_dec_and_raw_lock(atomic: *mut c_void, lock: *mut c_void) -> c_int {
    unsafe {
        if dec_unless_one(atomic) {
            return 0;
        }

        rust_dl_raw_lock(lock);
        if dec_and_test(atomic) {
            return 1;
        }
        rust_dl_raw_unlock(lock);
        0
    }
}

/// The body of C `_atomic_dec_and_raw_lock_irqsave()`.
#[no_mangle]
pub unsafe extern "C" fn rust__atomic_dec_and_raw_lock_irqsave(atomic: *mut c_void, lock: *mut c_void, flags: *mut c_ulong) -> c_int {
    unsafe {
        if dec_unless_one(atomic) {
            return 0;
        }

        rust_dl_raw_lock_irqsave(lock, flags);
        if dec_and_test(atomic) {
            return 1;
        }
        rust_dl_raw_unlock_irqrestore(lock, *flags);
        0
    }
}
