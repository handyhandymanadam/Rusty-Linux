// SPDX-License-Identifier: GPL-2.0

//! The out-of-line refcount functions -- the Rust behind `lib/refcount.c`.
//!
//! Ported from `lib/refcount.c` (6.18.49). `refcount_t` is one 32-bit atomic; the inline fast paths (`refcount_inc`, `refcount_dec_and_test`, ...) live in
//! `include/linux/refcount.h` and call `refcount_warn_saturate()` when an operation leaves the valid range. In Rust: `refcount_warn_saturate`
//! (saturate, then say why), `refcount_dec_if_one` and `refcount_dec_not_one`. In C (`refcount_glue.c`): the exports as thunks (their MODVERSIONS
//! fingerprints come from the DWARF of the definition), the three `dec_and_{mutex_,}lock*` functions (they only take a lock around Rust's
//! `refcount_dec_not_one`) and one `WARN_ONCE` per site (the warning now names the glue file: recorded divergence).
//!
//! # The ordering contract (concurrency bar, item 1)
//! * `refcount_dec_if_one` is a single `cmpxchg(1 -> 0)` with RELEASE ordering (failure: relaxed), like `atomic_try_cmpxchg_release`.
//! * `refcount_dec_not_one` reads the counter once, then loops on a RELEASE `cmpxchg(val -> val - 1)`; a failed cmpxchg reloads the current value
//!   and re-evaluates the saturated / one / underflow cases against it. The saturated value is never changed; 1 is never decremented; 0 is
//!   reported as an underflow and left alone.
//!
//! Replaces: lib/refcount.c (the three non-locking functions; the exports and the lock wrappers stay C)

use core::ffi::c_uint;
use core::sync::atomic::{AtomicI32, Ordering};

/// `REFCOUNT_SATURATED` (`INT_MIN / 2`).
const REFCOUNT_SATURATED: i32 = -1_073_741_824;

// enum refcount_saturation_type
const REFCOUNT_ADD_NOT_ZERO_OVF: c_uint = 0;
const REFCOUNT_ADD_OVF: c_uint = 1;
const REFCOUNT_ADD_UAF: c_uint = 2;
const REFCOUNT_SUB_UAF: c_uint = 3;
const REFCOUNT_DEC_LEAK: c_uint = 4;

extern "C" {
    /// One C `WARN_ONCE` per site: 0..=4 the five named cases, 5 the default arm, 6 the underflow in `refcount_dec_not_one`.
    fn rust_rfw_warn(site: c_uint);
}

/// `refcount_warn_saturate()`.
#[no_mangle]
pub unsafe extern "C" fn rust_refcount_warn_saturate(r: *const AtomicI32, t: c_uint) {
    // SAFETY: `r` is the `atomic_t` inside a `refcount_t` (the caller's contract in C).
    unsafe {
        (*r).store(REFCOUNT_SATURATED, Ordering::Relaxed);

        match t {
            REFCOUNT_ADD_NOT_ZERO_OVF => rust_rfw_warn(0),
            REFCOUNT_ADD_OVF => rust_rfw_warn(1),
            REFCOUNT_ADD_UAF => rust_rfw_warn(2),
            REFCOUNT_SUB_UAF => rust_rfw_warn(3),
            REFCOUNT_DEC_LEAK => rust_rfw_warn(4),
            _ => rust_rfw_warn(5),
        }
    }
}

/// `refcount_dec_if_one()`: the 1 -> 0 transition; `true` if it happened.
#[no_mangle]
pub unsafe extern "C" fn rust_refcount_dec_if_one(r: *const AtomicI32) -> bool {
    // SAFETY: as above.
    unsafe { (*r).compare_exchange(1, 0, Ordering::Release, Ordering::Relaxed).is_ok() }
}

/// `refcount_dec_not_one()`: decrement unless the value is 1 (then `false`); a saturated or underflowing counter is left alone and reports `true`.
#[no_mangle]
pub unsafe extern "C" fn rust_refcount_dec_not_one(r: *const AtomicI32) -> bool {
    // SAFETY: as above.
    unsafe {
        let a = &*r;
        let mut val = a.load(Ordering::Relaxed) as u32;

        loop {
            if val == REFCOUNT_SATURATED as u32 {
                return true;
            }

            if val == 1 {
                return false;
            }

            let new = val.wrapping_sub(1);
            if new > val {
                rust_rfw_warn(6);
                return true;
            }

            match a.compare_exchange(val as i32, new as i32, Ordering::Release, Ordering::Relaxed) {
                Ok(_) => return true,
                Err(cur) => val = cur as u32,
            }
        }
    }
}
