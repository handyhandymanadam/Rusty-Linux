// SPDX-License-Identifier: GPL-2.0

//! Load-average fixed-point arithmetic -- the Rust behind part of `kernel/sched/loadavg.c`.
//!
//! Ported from `kernel/sched/loadavg.c` (6.18.49, Ingo Molnar and others): `fixed_power_int()`, `x^n` in fixed point by repeated squaring, and `calc_load_n()`, the load average after
//! `n` missed 5-second intervals (`a_n = a_0 e^n + a (1 - e^n)`), which uses the header's `calc_load()` step with the decay factor raised to the n-th power. `calc_load()` itself is a
//! header inline used by C too, so its three lines are written out here. In C (`loadavg.c`, the glue at the original path, included by `build_utility.c`): everything that reads the
//! runqueues, the NO_HZ bookkeeping and `calc_global_load()`.
//!
//! Replaces: kernel/sched/loadavg.c (fixed_power_int, calc_load_n)

/// `FSHIFT`: bits of precision of the load average.
const FSHIFT: u32 = 11;
/// `FIXED_1`: 1.0 in fixed point.
const FIXED_1: u64 = 1 << FSHIFT;

/// `fixed_power_int()`: `x^n` with `frac_bits` fractional bits, rounding at each step.
fn fixed_power_int(mut x: u64, frac_bits: u32, mut n: u32) -> u64 {
    let mut result: u64 = 1 << frac_bits;

    if n != 0 {
        loop {
            if n & 1 != 0 {
                result = result.wrapping_mul(x);
                result = result.wrapping_add(1 << (frac_bits - 1));
                result >>= frac_bits;
            }
            n >>= 1;
            if n == 0 {
                break;
            }
            x = x.wrapping_mul(x);
            x = x.wrapping_add(1 << (frac_bits - 1));
            x >>= frac_bits;
        }
    }

    result
}

/// `calc_load()` of `<linux/sched/loadavg.h>`: one step of the exponential average.
fn calc_load(load: u64, exp: u64, active: u64) -> u64 {
    let mut newload = load.wrapping_mul(exp).wrapping_add(active.wrapping_mul(FIXED_1.wrapping_sub(exp)));
    if active >= load {
        newload = newload.wrapping_add(FIXED_1 - 1);
    }

    newload / FIXED_1
}

/// `calc_load_n()`: the load average after `n` intervals of constant `active` load.
#[no_mangle]
pub extern "C" fn calc_load_n(load: u64, exp: u64, active: u64, n: u32) -> u64 {
    calc_load(load, fixed_power_int(exp, FSHIFT, n), active)
}
