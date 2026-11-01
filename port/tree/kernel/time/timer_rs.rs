// SPDX-License-Identifier: GPL-2.0

//! The timer-wheel and jiffies-rounding arithmetic of `kernel/time/timer.c` -- the Rust behind it.
//!
//! Ported from `kernel/time/timer.c` (6.18.49): `calc_index()` and `calc_wheel_index()` (which wheel level and bucket an expiry lands in, with the round-up that keeps a timer from
//! firing early, the forced expiry of obscenely large timeouts and the handling of an expiry in the past), and the rounding core of `round_jiffies_common()` (skew by 3 jiffies per
//! CPU, round to a whole second, down only within the first quarter second and unless forced up). In C (`timer_glue.c`): everything else -- the timer bases and their lists, the
//! softirq, NO_HZ, the migration hierarchy, the exports -- and the final `time_is_after_jiffies()` test of `round_jiffies_common()`, which reads `jiffies`.
//!
//! `HZ` and `LVL_DEPTH` (9 for HZ above 100, else 8) are compile-time constants in C; the glue passes them and checks them against the headers. Arithmetic is the C's: unsigned long
//! operations wrap. A `cpu` of 0 or more is what the callers pass (`raw_smp_processor_id()`).
//!
//! Replaces: kernel/time/timer.c (the wheel index and rounding arithmetic)

use core::ffi::{c_int, c_long, c_uint, c_ulong};

const LVL_CLK_SHIFT: u32 = 3;
const LVL_BITS: u32 = 6;
const LVL_SIZE: c_ulong = 1 << LVL_BITS;
const LVL_MASK: c_ulong = LVL_SIZE - 1;

/// `LVL_SHIFT(n)`.
#[inline(always)]
fn lvl_shift(n: u32) -> u32 {
    n * LVL_CLK_SHIFT
}

/// `LVL_START(n)`: the first delta that is for level `n`.
#[inline(always)]
fn lvl_start(n: u32) -> c_ulong {
    (LVL_SIZE - 1) << ((n - 1) * LVL_CLK_SHIFT)
}

/// `calc_index()`: round `expires` up with the level's granularity so a timer cannot fire early; returns the bucket index and stores the bucket's expiry.
#[inline(always)]
fn calc_index(expires: c_ulong, lvl: u32, bucket_expiry: &mut c_ulong) -> c_uint {
    let e = (expires >> lvl_shift(lvl)).wrapping_add(1);
    *bucket_expiry = e << lvl_shift(lvl);
    ((lvl as c_ulong) * LVL_SIZE).wrapping_add(e & LVL_MASK) as c_uint
}

/// `calc_wheel_index()` for C; `lvl_depth` is `LVL_DEPTH`.
///
/// # Safety
/// `bucket_expiry` must be valid for writes.
#[no_mangle]
pub unsafe extern "C" fn rust_timer_calc_wheel_index(expires: c_ulong, clk: c_ulong, bucket_expiry: *mut c_ulong, lvl_depth: c_uint) -> c_uint {
    // SAFETY: the caller passes a valid pointer to the bucket expiry.
    let be = unsafe { &mut *bucket_expiry };
    let delta = expires.wrapping_sub(clk);

    for n in 1..8 {
        if delta < lvl_start(n) {
            return calc_index(expires, n - 1, be);
        }
    }
    if lvl_depth > 8 && delta < lvl_start(8) {
        calc_index(expires, 7, be)
    } else if (delta as c_long) < 0 {
        *be = clk;
        (clk & LVL_MASK) as c_uint
    } else {
        // Force expire obscene large timeouts to expire at the capacity limit of the wheel.
        let cutoff = lvl_start(lvl_depth);
        let mut expires = expires;
        if delta >= cutoff {
            let max = cutoff.wrapping_sub(1 << lvl_shift(lvl_depth - 1));
            expires = clk.wrapping_add(max);
        }
        calc_index(expires, lvl_depth - 1, be)
    }
}

/// The rounding of `round_jiffies_common()` up to the final `time_is_after_jiffies()` test: skew by 3 jiffies per CPU, round to a whole second (down if within the first quarter
/// second and not `force_up`), remove the skew again. `hz` is `HZ`.
#[no_mangle]
pub extern "C" fn rust_timer_round_jiffies(j: c_ulong, cpu: c_int, force_up: bool, hz: c_int) -> c_ulong {
    let skew = (cpu.wrapping_mul(3) as c_long) as c_ulong;

    // skew each extra cpu with an extra 3 jiffies so not all fire at once
    let mut j = j.wrapping_add(skew);
    let rem: c_int = (j % (hz as c_ulong)) as c_int;

    // just after a whole second (late timer irq, ...) round down, not up, unless forced up: 1/4 second as the cutoff
    if rem < hz / 4 && !force_up {
        j = j.wrapping_sub(rem as c_ulong);
    } else {
        j = j.wrapping_sub(rem as c_ulong).wrapping_add(hz as c_ulong);
    }

    // remove the skew again
    j.wrapping_sub(skew)
}
