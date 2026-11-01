// SPDX-License-Identifier: GPL-2.0

//! `bust_spinlocks()` -- the Rust behind `lib/bust_spinlocks.c`.
//!
//! Replaces: lib/bust_spinlocks.c
//!
//! # `oops_in_progress` stays a plain, racy `int`
//!
//! It is `extern int oops_in_progress` in `include/linux/printk.h`, read
//! and written non-atomically from several other C files
//! (`kernel/panic.c`, `kernel/smp.c`) that are not part of this port. Making
//! the Rust side's accesses atomic would not make the variable safe -- the
//! other readers still do plain loads -- and would just make this file's
//! behavior inconsistent with theirs. It is a best-effort diagnostic counter
//! for a system already crashing, not a synchronization primitive, and the
//! C treats it that way; this keeps doing the same.

use core::ffi::c_int;

extern "C" {
    static mut oops_in_progress: c_int;
    fn console_unblank();
    fn wake_up_klogd();
}

/// `bust_spinlocks(yes)`: clear whatever would keep oops/die/BUG/panic
/// output from reaching the user.
///
/// # Safety
/// Must run in the same single-threaded-at-this-point context the C
/// function assumed: during an oops/panic path, where concurrent access to
/// `oops_in_progress` is a pre-existing, accepted race, not one this port
/// introduces.
#[no_mangle]
pub unsafe extern "C" fn bust_spinlocks(yes: c_int) {
    if yes != 0 {
        // SAFETY: forwarding the C's own non-atomic increment. Not `+=`:
        // `oops_in_progress` is a plain `extern int` other C files also
        // touch non-atomically, so nothing here bounds it to a small
        // value the way a single well-behaved caller would -- signed
        // overflow is UB in the C too, this just gives it defined
        // (wrapped) behavior instead of a new Rust-only panic on a
        // counter that in practice never gets close.
        unsafe { oops_in_progress = oops_in_progress.wrapping_add(1) };
    } else {
        // SAFETY: console_unblank() takes no arguments and returns nothing.
        unsafe { console_unblank() };
        // SAFETY: forwarding the C's own non-atomic decrement, same
        // reasoning as the increment above.
        unsafe { oops_in_progress = oops_in_progress.wrapping_sub(1) };
        // SAFETY: reading back the value just written, same context.
        if unsafe { oops_in_progress } == 0 {
            // SAFETY: wake_up_klogd() takes no arguments and returns nothing.
            unsafe { wake_up_klogd() };
        }
    }
}
