// SPDX-License-Identifier: GPL-2.0+

//! The clock-conversion arithmetic of `kernel/time/clocksource.c` -- the Rust behind it.
//!
//! Ported from `kernel/time/clocksource.c` (6.18.49): `clocks_calc_mult_shift()` (the mult/shift pair for a frequency ratio), `clocks_calc_max_nsecs()` (the longest interval a
//! mult/shift pair converts without overflow), `clocksource_max_adjustment()`, `clocksource_update_max_deferment()` and the arithmetic of
//! `__clocksource_update_freq_scale()` (seconds before wrap, uncertainty margin, mult halving while an 11 % adjustment would overflow). In C (`clocksource_glue.c`): everything
//! else -- the registration list, the watchdog, the selection logic, sysfs -- the exports as thunks, and the two `WARN`s and the `pr_info()` of `__clocksource_update_freq_scale()`.
//! The update function works on a copy of the clocksource fields it touches ([`CsMath`]), so no layout of `struct clocksource` is assumed.
//!
//! Arithmetic is the C's: 64-bit and 32-bit unsigned operations wrap, a shift count of 64 or more is masked to 6 bits (what the x86 shift instruction does; undefined in C).
//! A division by zero (`from == 0`, `mult + maxadj == 0`, `scale == 0` with a frequency, `scale * freq == 0`) is an oops in C and a Rust panic (abort) here; no caller passes them.
//!
//! Replaces: kernel/time/clocksource.c (the conversion arithmetic)

const NSEC_PER_SEC: i64 = 1_000_000_000;

/// `clocksource_cyc2ns()`: `((u64)cycles * mult) >> shift`.
#[inline(always)]
fn cyc2ns(cycles: u64, mult: u32, shift: u32) -> u64 {
    cycles.wrapping_mul(mult as u64).wrapping_shr(shift)
}

/// `clocksource_max_adjustment()`: 11 % of `mult`, as the kernel won't correct more than that.
#[inline(always)]
fn max_adjustment(mult: u32) -> u32 {
    ((mult as u64) * 11 / 100) as u32
}

/// `clocks_calc_mult_shift()`.
fn calc_mult_shift(from: u32, to: u32, maxsec: u32) -> (u32, u32) {
    // the shift factor which is limiting the conversion range
    let mut tmp: u64 = ((maxsec as u64) * (from as u64)) >> 32;
    let mut sftacc: u32 = 32;
    while tmp != 0 {
        tmp >>= 1;
        sftacc -= 1;
    }

    // the shift/mult pair which has the best accuracy and fits the maxsec conversion range
    let mut sft: u32 = 32;
    tmp = 0;
    while sft > 0 {
        tmp = (to as u64) << sft;
        tmp = tmp.wrapping_add((from / 2) as u64);
        tmp /= from as u64;
        if (tmp >> sftacc) == 0 {
            break;
        }
        sft -= 1;
    }
    (tmp as u32, sft)
}

/// `clocks_calc_max_nsecs()`: returns the maximum nanoseconds (half the true limit) and the maximum cycles.
fn calc_max_nsecs(mult: u32, shift: u32, maxadj: u32, mask: u64) -> (u64, u64) {
    // the maximum number of cycles that can be passed to cyc2ns() without overflowing a 64-bit result
    let mut max_cycles: u64 = u64::MAX / (mult.wrapping_add(maxadj) as u64);

    // the minimum of that and the mask; the maxadj is subtracted so a large negative adjustment cannot make us sleep too long
    if mask < max_cycles {
        max_cycles = mask;
    }
    let max_nsecs = cyc2ns(max_cycles, mult.wrapping_sub(maxadj), shift);

    // 50 % of the actual maximum, so bad values can be detected
    (max_nsecs >> 1, max_cycles)
}

/// `clocks_calc_mult_shift()` for C: stores the pair through `mult` and `shift`.
///
/// # Safety
/// `mult` and `shift` must be valid for writes.
#[no_mangle]
pub unsafe extern "C" fn rust_clocks_calc_mult_shift(mult: *mut u32, shift: *mut u32, from: u32, to: u32, maxsec: u32) {
    let (m, s) = calc_mult_shift(from, to, maxsec);
    // SAFETY: the caller passes valid pointers (C `clocks_calc_mult_shift()`'s contract).
    unsafe {
        *mult = m;
        *shift = s;
    }
}

/// `clocks_calc_max_nsecs()` for C; `max_cyc` may be NULL.
///
/// # Safety
/// `max_cyc` must be NULL or valid for writes.
#[no_mangle]
pub unsafe extern "C" fn rust_clocks_calc_max_nsecs(mult: u32, shift: u32, maxadj: u32, mask: u64, max_cyc: *mut u64) -> u64 {
    let (nsecs, cycles) = calc_max_nsecs(mult, shift, maxadj, mask);
    if !max_cyc.is_null() {
        // SAFETY: non-NULL and valid for writes by the caller's contract.
        unsafe { *max_cyc = cycles };
    }
    nsecs
}

/// The fields of `struct clocksource` that `__clocksource_update_freq_scale()` reads and writes; the glue copies them in and out.
#[repr(C)]
pub struct CsMath {
    /// `cs->mask`
    mask: u64,
    /// `cs->max_idle_ns`
    max_idle_ns: u64,
    /// `cs->max_cycles`
    max_cycles: u64,
    /// `cs->max_raw_delta`
    max_raw_delta: u64,
    /// `cs->mult`
    mult: u32,
    /// `cs->shift`
    shift: u32,
    /// `cs->maxadj`
    maxadj: u32,
    /// `cs->uncertainty_margin`
    uncertainty_margin: u32,
}

/// The arithmetic of `__clocksource_update_freq_scale()`. `max_skew` is `WATCHDOG_MAX_SKEW` and `threshold` `WATCHDOG_THRESHOLD`, both in nanoseconds (`long`).
///
/// # Safety
/// `m` must point to a valid [`CsMath`].
#[no_mangle]
pub unsafe extern "C" fn rust_cs_update_freq_scale(m: *mut CsMath, scale: u32, freq: u32, max_skew: i64, threshold: i64) {
    // SAFETY: the caller passes a valid, exclusive structure.
    let m = unsafe { &mut *m };

    // Default clocksources self-define their mult/shift; the others specify a freq value.
    if freq != 0 {
        // The maximum number of seconds we can run before wrapping around. For a mask over 32 bits the sleep is limited to 10 minutes for a good conversion precision.
        let mut sec: u64 = m.mask;
        sec /= freq as u64;
        sec /= scale as u64;
        if sec == 0 {
            sec = 1;
        } else if sec > 600 && m.mask > u32::MAX as u64 {
            sec = 600;
        }

        let to = (NSEC_PER_SEC / (scale as i64)) as u32;
        let (mult, shift) = calc_mult_shift(freq, to, sec.wrapping_mul(scale as u64) as u32);
        m.mult = mult;
        m.shift = shift;
    }

    // The uncertainty margin if not specified: the clock period bounded below at 2 * WATCHDOG_MAX_SKEW, or the watchdog threshold when scale or freq is zero.
    if scale != 0 && freq != 0 && m.uncertainty_margin == 0 {
        m.uncertainty_margin = (NSEC_PER_SEC / (scale.wrapping_mul(freq) as i64)) as u32;
        if (m.uncertainty_margin as i64) < max_skew.wrapping_mul(2) {
            m.uncertainty_margin = max_skew.wrapping_mul(2) as u32;
        }
    } else if m.uncertainty_margin == 0 {
        m.uncertainty_margin = threshold as u32;
    }

    // Clocksources with large 'mult' values must not overflow when adjusted.
    m.maxadj = max_adjustment(m.mult);
    while freq != 0 && (m.mult.wrapping_add(m.maxadj) < m.mult || m.mult.wrapping_sub(m.maxadj) > m.mult) {
        m.mult >>= 1;
        m.shift = m.shift.wrapping_sub(1);
        m.maxadj = max_adjustment(m.mult);
    }

    // clocksource_update_max_deferment()
    let (nsecs, cycles) = calc_max_nsecs(m.mult, m.shift, m.maxadj, m.mask);
    m.max_idle_ns = nsecs;
    m.max_cycles = cycles;

    // Threshold for detecting negative motion in clocksource_delta(): 0.875 of the counter width, so overly long idle sleeps do not trigger it.
    m.max_raw_delta = (m.mask >> 1).wrapping_add(m.mask >> 2).wrapping_add(m.mask >> 3);
}
