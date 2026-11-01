// SPDX-License-Identifier: GPL-2.0

//! Tick-based CPU time correction -- the Rust behind part of `kernel/sched/cputime.c`.
//!
//! Ported from `cputime_adjust()` of `kernel/sched/cputime.c` (6.18.49, Frederic Weisbecker and others): tick sampling gives random user / system splits, so they are scaled against the
//! exactly accounted runtime, keeping `stime + utime == rtime` and never letting either go backwards. The C function (`cputime.c`, the glue at the original path) takes and drops
//! `prev->lock` and calls `rust_cputime_adjust()` with the sampled split, the runtime and pointers to the previous split. The scaling uses the kernel's own
//! `mul_u64_u64_div_u64()`, reached through a wrapper.
//!
//! Replaces: kernel/sched/cputime.c (the body of cputime_adjust)

extern "C" {
    /// `mul_u64_u64_div_u64(a, b, c)`
    fn rust_cp_mul_u64_u64_div_u64(a: u64, b: u64, c: u64) -> u64;
}

/// The part of `cputime_adjust()` between taking and dropping `prev->lock`: update `*prev_stime` / `*prev_utime` from the sampled `curr_stime` / `curr_utime` and the runtime `rtime`.
#[no_mangle]
#[allow(unused_assignments)] // upstream assigns utime on the early paths and recomputes it below
pub unsafe extern "C" fn rust_cputime_adjust(curr_stime: u64, curr_utime: u64, rtime: u64, prev_stime: *mut u64, prev_utime: *mut u64) {
    unsafe {
        // This is possible under two circumstances: rtime isn't monotonic after all (a bug); we got reordered by the lock. In both cases this acts as a filter such that the
        // rest of the code can assume it is monotonic regardless of anything else.
        if (*prev_stime).wrapping_add(*prev_utime) >= rtime {
            return;
        }

        let mut stime = curr_stime;
        let mut utime = curr_utime;

        'update: {
            // If either stime or utime are 0, assume all runtime is userspace. Once a task gets some ticks, the monotonicity code at 'update:' will ensure things converge to
            // the observed ratio.
            if stime == 0 {
                utime = rtime;
                break 'update;
            }

            if utime == 0 {
                stime = rtime;
                break 'update;
            }

            stime = rust_cp_mul_u64_u64_div_u64(stime, rtime, stime.wrapping_add(utime));
            // Because mul_u64_u64_div_u64() can approximate on some achitectures; enforce the constraint that: a*b/(b+c) <= a.
            if stime > rtime {
                stime = rtime;
            }
        }

        // Make sure stime doesn't go backwards; this preserves monotonicity for utime because rtime is monotonic.
        //
        //  utime_i+1 = rtime_i+1 - stime_i
        //            = rtime_i+1 - (rtime_i - utime_i)
        //            = (rtime_i+1 - rtime_i) + utime_i
        //            >= utime_i
        if stime < *prev_stime {
            stime = *prev_stime;
        }
        utime = rtime.wrapping_sub(stime);

        // Make sure utime doesn't go backwards; this still preserves monotonicity for stime, analogous argument to above.
        if utime < *prev_utime {
            utime = *prev_utime;
            stime = rtime.wrapping_sub(utime);
        }

        *prev_stime = stime;
        *prev_utime = utime;
    }
}
