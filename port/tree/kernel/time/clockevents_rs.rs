// SPDX-License-Identifier: GPL-2.0

//! The conversion arithmetic of `kernel/time/clockevents.c` -- the Rust behind it.
//!
//! Ported from `kernel/time/clockevents.c` (6.18.49): `cev_delta2ns()` (ticks to nanoseconds with its overflow and rounding rules), the ticks conversion `(delta * mult) >> shift`
//! that programs a device (three sites), the clamp of a delta to the device limits in `clockevents_program_event()`, the min-delta growth of `clockevents_increase_min_delta()`
//! and the seconds-before-wrap limit of `clockevents_config()`. Each is a pure function of numbers; the device structure, the state tests, the callbacks, the lists and the sysfs
//! interface stay C (`clockevents_glue.c`), which passes the fields it needs, so no layout of `struct clock_event_device` is assumed.
//!
//! Arithmetic is the C's: unsigned operations wrap, a shift count of 64 or more is masked to 6 bits (undefined in C). A division by zero (`freq == 0`, `mult == 0`) is an oops in C
//! and a Rust panic (abort) here; the C glue replaces a zero `mult` by 1 first (with its `WARN_ON`), as upstream, and `clockevents_config()` is never called with a zero frequency.
//!
//! Replaces: kernel/time/clockevents.c (the conversion arithmetic)

use core::ffi::c_ulong;

/// `cev_delta2ns()` after the zero-mult fix-up: `latch` device ticks as nanoseconds, bounded; `ismax` selects the upper-limit rounding rule. `mult` is not zero.
#[no_mangle]
pub extern "C" fn rust_ce_delta2ns(latch: c_ulong, mult: u32, shift: u32, ismax: bool) -> u64 {
    let latch = latch as u64;
    let mut clc: u64 = latch.wrapping_shl(shift);
    let rnd: u64 = (mult as u64) - 1;

    // Upper bound sanity check: if the backwards conversion is not equal latch, the shift overflowed.
    if clc.wrapping_shr(shift) != latch {
        clc = u64::MAX;
    }

    // Round up so the backwards conversion is right; for the upper limit with mult > (1 << shift) the add is omitted (it could exceed the device's boundary), and it is omitted
    // when it would overflow.
    if (u64::MAX - clc > rnd) && (!ismax || (mult as u64) <= 1u64.wrapping_shl(shift)) {
        clc += rnd;
    }

    clc /= mult as u64;

    // Deltas less than 1 usec are pointless noise.
    if clc > 1000 {
        clc
    } else {
        1000
    }
}

/// `(unsigned long long)delta * mult >> shift`: the device ticks for a delta in nanoseconds.
#[no_mangle]
pub extern "C" fn rust_ce_ns2ticks(delta: i64, mult: u32, shift: u32) -> u64 {
    (delta as u64).wrapping_mul(mult as u64).wrapping_shr(shift)
}

/// `delta = min(delta, max_delta_ns); delta = max(delta, min_delta_ns)` with the limits cast to `int64_t`.
#[no_mangle]
pub extern "C" fn rust_ce_clamp_delta(delta: i64, min_delta_ns: u64, max_delta_ns: u64) -> i64 {
    let d = delta.min(max_delta_ns as i64);
    d.max(min_delta_ns as i64)
}

/// The new `min_delta_ns` after a reprogramming failure: at least 5 us, else 1.5 times, never above `limit`.
#[no_mangle]
pub extern "C" fn rust_ce_bump_min_delta(min_delta_ns: u64, limit: u64) -> u64 {
    let n = if min_delta_ns < 5000 { 5000 } else { min_delta_ns.wrapping_add(min_delta_ns >> 1) };
    if n > limit {
        limit
    } else {
        n
    }
}

/// The seconds a device can sleep, for `clockevents_calc_mult_shift()`: `max_delta_ticks / freq`, at least 1, and 600 at most for devices with more than 32 bits of ticks.
#[no_mangle]
pub extern "C" fn rust_ce_config_sec(max_delta_ticks: c_ulong, freq: u32) -> u64 {
    let ticks = max_delta_ticks as u64;
    let mut sec = ticks / (freq as u64);
    if sec == 0 {
        sec = 1;
    } else if sec > 600 && ticks > u32::MAX as u64 {
        sec = 600;
    }
    sec
}
