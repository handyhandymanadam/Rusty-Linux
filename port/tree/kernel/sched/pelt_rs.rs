// SPDX-License-Identifier: GPL-2.0

//! Per-entity load tracking (PELT) arithmetic -- the Rust behind part of `kernel/sched/pelt.c`.
//!
//! Ported from `kernel/sched/pelt.c` (6.18.49, Paul Turner, Ben Segall, Peter Zijlstra): the geometric decay of the load / runnable / utilization sums (`decay_load`), the
//! contribution of whole periods (`__accumulate_pelt_segments`), the accumulation over a time delta (`accumulate_sum`), the update of a `struct sched_avg`'s sums
//! (`___update_load_sum`) and the averages derived from them (`___update_load_avg`). In C (`pelt.c`, installed as the glue; upstream's file is `pelt_norust.c`): everything that
//! knows `struct sched_entity`, `struct cfs_rq` or `struct rq` -- the `__update_load_avg_*` and `update_*_load_avg` entry points, tracepoints, the IRQ and hardware-pressure
//! averages -- calling these through `___update_load_sum()` / `___update_load_avg()` wrappers that pass in the decay table.
//!
//! Replaces: kernel/sched/pelt.c (decay_load, __accumulate_pelt_segments, accumulate_sum, ___update_load_sum, ___update_load_avg)

use core::ffi::c_int;

/// `LOAD_AVG_PERIOD`: the half-life, in periods.
const LOAD_AVG_PERIOD: u64 = 32;
/// `LOAD_AVG_MAX`: the maximum value of a sum (`1024 * sum of y^n`).
const LOAD_AVG_MAX: u64 = 47742;
/// `PELT_MIN_DIVIDER`.
const PELT_MIN_DIVIDER: u32 = (LOAD_AVG_MAX - 1024) as u32;
/// `SCHED_CAPACITY_SHIFT`.
const SCHED_CAPACITY_SHIFT: u32 = 10;

/// `struct sched_avg` (offsets checked by the C side).
#[repr(C)]
pub struct SchedAvg {
    last_update_time: u64,
    load_sum: u64,
    runnable_sum: u64,
    util_sum: u32,
    period_contrib: u32,
    load_avg: u64,
    runnable_avg: u64,
    util_avg: u64,
    util_est: u32,
}

/// `decay_load()`: `val * y^n` with `y^32 = 1/2`, from the table `inv` of `y^n` for `n < 32` scaled by 2^32.
fn decay_load(val: u64, n: u64, inv: &[u32; 32]) -> u64 {
    let mut val = val;

    if n > LOAD_AVG_PERIOD * 63 {
        return 0;
    }

    // after bounds checking we can collapse to 32-bit
    let mut local_n = n as u32;

    // As y^PERIOD = 1/2, we can combine y^n = 1/2^(n/PERIOD) * y^(n%PERIOD) with a look-up table which covers y^n (n<PERIOD) to achieve constant time decay_load.
    if local_n >= LOAD_AVG_PERIOD as u32 {
        val >>= local_n / LOAD_AVG_PERIOD as u32;
        local_n %= LOAD_AVG_PERIOD as u32;
    }

    ((val as u128 * inv[local_n as usize] as u128) >> 32) as u64
}

/// `__accumulate_pelt_segments()`.
fn accumulate_pelt_segments(periods: u64, d1: u32, d3: u32, inv: &[u32; 32]) -> u32 {
    let c3 = d3; // y^0 == 1

    // c1 = d1 y^p
    let c1 = decay_load(d1 as u64, periods, inv) as u32;

    //            p-1
    // c2 = 1024 \Sum y^n
    //            n=1
    //
    //              inf        inf
    //    = 1024 ( \Sum y^n - \Sum y^n - y^0 )
    //              n=0        n=p
    let c2 = LOAD_AVG_MAX.wrapping_sub(decay_load(LOAD_AVG_MAX, periods, inv)).wrapping_sub(1024) as u32;

    c1.wrapping_add(c2).wrapping_add(c3)
}

/// `accumulate_sum()`: returns the number of period boundaries crossed.
fn accumulate_sum(mut delta: u64, sa: &mut SchedAvg, load: u64, runnable: u64, running: c_int, inv: &[u32; 32]) -> u64 {
    let mut contrib = delta as u32; // p == 0 -> delta < 1024

    delta += sa.period_contrib as u64;
    let periods = delta / 1024; // A period is 1024us (~1ms)

    // Step 1: decay old *_sum if we crossed period boundaries.
    if periods != 0 {
        sa.load_sum = decay_load(sa.load_sum, periods, inv);
        sa.runnable_sum = decay_load(sa.runnable_sum, periods, inv);
        sa.util_sum = decay_load(sa.util_sum as u64, periods, inv) as u32;

        // Step 2
        delta %= 1024;
        if load != 0 {
            // This relies on the `if (!load) runnable = running = 0;` clause from ___update_load_sum(); this results in the below usage of @contrib to disappear entirely,
            // so no point in calculating it.
            contrib = accumulate_pelt_segments(periods, 1024 - sa.period_contrib, delta as u32, inv);
        }
    }
    sa.period_contrib = delta as u32;

    if load != 0 {
        sa.load_sum = sa.load_sum.wrapping_add(load.wrapping_mul(contrib as u64));
    }
    if runnable != 0 {
        sa.runnable_sum = sa.runnable_sum.wrapping_add(runnable.wrapping_mul(contrib as u64) << SCHED_CAPACITY_SHIFT);
    }
    if running != 0 {
        sa.util_sum = sa.util_sum.wrapping_add(contrib << SCHED_CAPACITY_SHIFT);
    }

    periods
}

/// `___update_load_sum()`: bring the sums of `sa` up to `now`; 1 if the averages need recomputing (a period boundary was crossed), else 0.
#[no_mangle]
pub unsafe extern "C" fn rust_pelt_update_load_sum(now: u64, sa: *mut SchedAvg, load: u64, runnable: u64, running: c_int, inv: *const u32) -> c_int {
    unsafe {
        let sa = &mut *sa;
        let inv = &*(inv as *const [u32; 32]);
        let mut load_runnable = runnable;
        let mut load_running = running;

        let mut delta = now.wrapping_sub(sa.last_update_time);
        // This should only happen when time goes backwards, which it unfortunately does during sched clock init when we swap over to TSC.
        if (delta as i64) < 0 {
            sa.last_update_time = now;
            return 0;
        }

        // Use 1024ns as the unit of measurement since it's a reasonable approximation of 1us and fast to compute.
        delta >>= 10;
        if delta == 0 {
            return 0;
        }

        sa.last_update_time = sa.last_update_time.wrapping_add(delta << 10);

        // running is a subset of runnable (weight) so running can't be set if runnable is clear. But there are some corner cases where the current se has been already
        // dequeued but cfs_rq->curr still points to it. This means that weight will be 0 but not running for a sched_entity but also for a cfs_rq if the latter becomes idle.
        if load == 0 {
            load_runnable = 0;
            load_running = 0;
        }

        // Now we know we crossed measurement unit boundaries. The *_avg accrues by two steps: Step 1: accumulate *_sum since last_update_time. If we haven't crossed
        // period boundaries, finish.
        if accumulate_sum(delta, sa, load, load_runnable, load_running, inv) == 0 {
            return 0;
        }

        1
    }
}

/// `___update_load_avg()`: Step 2, update the averages from the sums.
#[no_mangle]
pub unsafe extern "C" fn rust_pelt_update_load_avg(sa: *mut SchedAvg, load: u64) {
    unsafe {
        let sa = &mut *sa;
        let divider = PELT_MIN_DIVIDER.wrapping_add(sa.period_contrib) as u64;

        sa.load_avg = load.wrapping_mul(sa.load_sum) / divider;
        sa.runnable_avg = sa.runnable_sum / divider;
        sa.util_avg = sa.util_sum as u64 / divider;
    }
}
