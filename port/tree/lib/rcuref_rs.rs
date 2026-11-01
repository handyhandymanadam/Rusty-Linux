// SPDX-License-Identifier: GPL-2.0-only

//! The slow paths of `rcuref_t` -- the Rust behind `lib/rcuref.c`.
//!
//! Ported from `lib/rcuref.c` (6.18.49), "Scalable reference counting for RCU protected objects" (Thomas Gleixner). The counter is one
//! 32-bit atomic, biased so that 0 means one reference: values up to `RCUREF_MAXREF` are live, `RCUREF_SATURATED` is the middle of the
//! saturation zone, `RCUREF_RELEASED`..`RCUREF_DEAD` the dead zone, and `RCUREF_NOREF` (-1) means the last reference was dropped. The
//! fast paths (`rcuref_get`, `rcuref_put`) are header inlines that do one `atomic_add_negative_relaxed`/`_release` and call these
//! only when the result left the live zone. In C (`rcuref_glue.c`): the two exports as thunks (their MODVERSIONS fingerprints come from
//! the DWARF of the definition) and the two `WARN_ONCE` sites, one wrapper each (the warning now names the glue file -- recorded divergence).
//!
//! # The ordering contract (concurrency bar, item 1)
//! * Reads and plain resets use `READ_ONCE` / `WRITE_ONCE` (relaxed atomics).
//! * The one transition that publishes "this object may be destroyed", NOREF -> DEAD, is a `cmpxchg` with RELEASE ordering, and on success
//!   an ACQUIRE fence follows (`smp_acquire__after_ctrl_dep()`): everything the other (non-last) droppers did to the object before their
//!   `put` is visible to the winner that frees it. A failed `cmpxchg` (a racing `get` revived it, or another `put` already marked it dead)
//!   is not an error and does not retry; that caller must not free.
//!
//! Replaces: lib/rcuref.c (the algorithms; the exports and the `WARN_ONCE` sites stay C)

use core::sync::atomic::{fence, AtomicU32, Ordering};

const RCUREF_MAXREF: u32 = 0x7FFF_FFFF;
const RCUREF_SATURATED: u32 = 0xA000_0000;
const RCUREF_RELEASED: u32 = 0xC000_0000;
const RCUREF_DEAD: u32 = 0xE000_0000;
const RCUREF_NOREF: u32 = 0xFFFF_FFFF;

extern "C" {
    fn rust_rcw_warn_saturated(cond: bool) -> bool;
    fn rust_rcw_warn_imbalanced(cond: bool) -> bool;
}

/// `rcuref_get_slowpath()`: the increment already happened; `false` = the reference was dead and the caller got nothing.
#[no_mangle]
pub unsafe extern "C" fn rust_rcuref_get_slowpath(refcnt: *const AtomicU32) -> bool {
    // SAFETY: `refcnt` is the `atomic_t` inside a live `rcuref_t` (the caller's contract in C).
    unsafe {
        let r = &*refcnt;
        let cnt = r.load(Ordering::Relaxed);

        // If the reference count was already marked dead, undo the increment so it stays in the middle of the dead zone and return fail.
        if cnt >= RCUREF_RELEASED {
            r.store(RCUREF_DEAD, Ordering::Relaxed);
            return false;
        }

        // If it was saturated, warn and mark it so. In case the increment was already on a saturated value restore the saturation marker.
        // This keeps it in the middle of the saturation zone and prevents the reference count from overflowing. This leaks the object
        // memory, but prevents the obvious reference count overflow damage.
        if rust_rcw_warn_saturated(cnt > RCUREF_MAXREF) {
            r.store(RCUREF_SATURATED, Ordering::Relaxed);
        }
        true
    }
}

/// `rcuref_put_slowpath()`: `cnt` is the value the decrement produced; `true` = the caller dropped the last reference and may free.
#[no_mangle]
pub unsafe extern "C" fn rust_rcuref_put_slowpath(refcnt: *const AtomicU32, cnt: u32) -> bool {
    // SAFETY: as above.
    unsafe {
        let r = &*refcnt;

        // Did this drop the last reference?
        if cnt == RCUREF_NOREF {
            // Carefully try to set the reference count to RCUREF_DEAD. This can fail if a concurrent get() operation has elevated it again
            // or the corresponding put() even marked it dead already. Both are valid situations and do not require a retry. If this fails
            // the caller is not allowed to deconstruct the object.
            if r.compare_exchange(cnt, RCUREF_DEAD, Ordering::Release, Ordering::Relaxed).is_err() {
                return false;
            }

            // The caller can safely schedule the object for deconstruction. Provide acquire ordering.
            fence(Ordering::Acquire); // smp_acquire__after_ctrl_dep()
            return true;
        }

        // If the reference count was already in the dead zone, then this put() operation is imbalanced. Warn, put the reference count back
        // to DEAD and tell the caller to not deconstruct the object.
        if rust_rcw_warn_imbalanced(cnt >= RCUREF_RELEASED) {
            r.store(RCUREF_DEAD, Ordering::Relaxed);
            return false;
        }

        // This is a put() operation on a saturated refcount. Restore the mean saturation value and tell the caller to not deconstruct the
        // object.
        if cnt > RCUREF_MAXREF {
            r.store(RCUREF_SATURATED, Ordering::Relaxed);
        }
        false
    }
}
