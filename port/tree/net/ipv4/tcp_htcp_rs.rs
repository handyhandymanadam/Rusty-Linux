// SPDX-License-Identifier: GPL-2.0-only

//! The H-TCP congestion-control arithmetic -- the Rust behind part of `net/ipv4/tcp_htcp.c`.
//!
//! Ported from `net/ipv4/tcp_htcp.c` (6.18.49, Baruch Even): the RTT and achieved-throughput measurement of `measure_achieved_throughput` (with `measure_rtt`), the adaptive back-off
//! factor `htcp_beta_update`, the time-since-congestion additive-increase factor `htcp_alpha_update`, `htcp_param_update`, the window increase of `htcp_cong_avoid` and the reduction
//! of `htcp_recalc_ssthresh`. In C (`tcp_htcp_glue.c`): everything that touches the socket, init / state / undo, the module parameters and the registration, with the pieces above as thin
//! wrappers passing in the clock (`jiffies`, `tcp_jiffies32`), `HZ`, the converted times and the tunables. Arithmetic is 32-bit unsigned with wrapping as in C; `beta` is a `u8` that
//! receives a truncated 32-bit quotient before it is compared, as in C. A zero divisor is a Rust panic where C takes a divide error.
//!
//! Replaces: net/ipv4/tcp_htcp.c (measure_rtt, measure_achieved_throughput, htcp_beta_update, htcp_alpha_update, htcp_param_update, the increase of htcp_cong_avoid, the arithmetic of htcp_recalc_ssthresh)

/// `struct htcp` (the glue checks the offsets).
#[repr(C)]
pub struct Htcp {
    alpha: u32,
    beta: u8,
    modeswitch: u8,
    pkts_acked: u16,
    packetcount: u32,
    min_rtt: u32,
    max_rtt: u32,
    last_cong: u32,
    undo_last_cong: u32,
    undo_max_rtt: u32,
    undo_old_max_b: u32,
    min_b: u32,
    max_b: u32,
    old_max_b: u32,
    bi: u32,
    lasttime: u32,
}

const ALPHA_BASE: u32 = 1 << 7;
const BETA_MIN: u8 = 1 << 6;
const BETA_MAX: u8 = 102;

const TCP_CA_OPEN: u8 = 0;

/// `htcp_cong_time()`: the (truncated) time since the last congestion event.
fn cong_time(ca: &Htcp, jiffies: u32) -> u32 {
    jiffies.wrapping_sub(ca.last_cong)
}

/// `measure_rtt()`: keep the minimum RTT and, in the Open state, the maximum.
fn measure_rtt(ca: &mut Htcp, srtt: u32, ca_state: u8, ms20: u32) {
    // keep track of minimum RTT seen so far, minRTT is zero at first
    if ca.min_rtt > srtt || ca.min_rtt == 0 {
        ca.min_rtt = srtt;
    }

    // max RTT
    if ca_state == TCP_CA_OPEN {
        if ca.max_rtt < ca.min_rtt {
            ca.max_rtt = ca.min_rtt;
        }
        // `maxRTT + msecs_to_jiffies(20)` is an unsigned long sum: no 32-bit wrap
        if ca.max_rtt < srtt && (srtt as u64) <= ca.max_rtt as u64 + ms20 as u64 {
            ca.max_rtt = srtt;
        }
    }
}

/// `measure_achieved_throughput()`: `rtt_jiffies` is `usecs_to_jiffies(rtt_us)` when `has_rtt` (the sample had a positive RTT).
#[no_mangle]
pub unsafe extern "C" fn rust_htcp_throughput(
    ca: *mut Htcp,
    pkts_acked: u32,
    has_rtt: i32,
    rtt_jiffies: u32,
    ca_state: u8,
    now: u32,
    jiffies: u32,
    cwnd: u32,
    hz: u32,
    ms20: u32,
    use_bandwidth_switch: i32,
) {
    // SAFETY: the glue passes the connection's `struct htcp`.
    let ca = unsafe { &mut *ca };

    if ca_state == TCP_CA_OPEN {
        ca.pkts_acked = pkts_acked as u16;
    }

    if has_rtt != 0 {
        measure_rtt(ca, rtt_jiffies, ca_state, ms20);
    }

    if use_bandwidth_switch == 0 {
        return;
    }

    // achieved throughput calculations: only in the Open and Disorder states
    if ((1u32 << (ca_state & 31)) & 0b11) == 0 {
        ca.packetcount = 0;
        ca.lasttime = now;
        return;
    }

    ca.packetcount = ca.packetcount.wrapping_add(pkts_acked);

    let alpha_pkts = if ca.alpha >> 7 != 0 { ca.alpha >> 7 } else { 1 };
    if ca.packetcount >= cwnd.wrapping_sub(alpha_pkts) && now.wrapping_sub(ca.lasttime) >= ca.min_rtt && ca.min_rtt > 0 {
        let cur_bi = ca.packetcount.wrapping_mul(hz) / now.wrapping_sub(ca.lasttime);

        if cong_time(ca, jiffies) / ca.min_rtt <= 3 {
            // just after backoff
            ca.min_b = cur_bi;
            ca.max_b = cur_bi;
            ca.bi = cur_bi;
        } else {
            ca.bi = ca.bi.wrapping_mul(3).wrapping_add(cur_bi) / 4;
            if ca.bi > ca.max_b {
                ca.max_b = ca.bi;
            }
            if ca.min_b > ca.max_b {
                ca.min_b = ca.max_b;
            }
        }
        ca.packetcount = 0;
        ca.lasttime = now;
    }
}

/// `htcp_beta_update()`.
fn beta_update(ca: &mut Htcp, min_rtt: u32, max_rtt: u32, use_bandwidth_switch: i32, ms10: u32) {
    if use_bandwidth_switch != 0 {
        let max_b = ca.max_b;
        let old_max_b = ca.old_max_b;

        ca.old_max_b = ca.max_b;
        // !between(5 * maxB, 4 * old_maxB, 6 * old_maxB)
        let (s1, s2, s3) = (max_b.wrapping_mul(5), old_max_b.wrapping_mul(4), old_max_b.wrapping_mul(6));
        if s3.wrapping_sub(s2) < s1.wrapping_sub(s2) {
            ca.beta = BETA_MIN;
            ca.modeswitch = 0;
            return;
        }
    }

    if ca.modeswitch != 0 && min_rtt > ms10 && max_rtt != 0 {
        ca.beta = ((min_rtt << 7) / max_rtt) as u8;
        if ca.beta < BETA_MIN {
            ca.beta = BETA_MIN;
        } else if ca.beta > BETA_MAX {
            ca.beta = BETA_MAX;
        }
    } else {
        ca.beta = BETA_MIN;
        ca.modeswitch = 1;
    }
}

/// `htcp_alpha_update()`.
fn alpha_update(ca: &mut Htcp, jiffies: u32, hz: u32, use_rtt_scaling: i32) {
    let min_rtt = ca.min_rtt;
    let mut factor: u32 = 1;
    let mut diff = cong_time(ca, jiffies);

    if diff > hz {
        diff -= hz;
        factor = 1u32.wrapping_add(diff.wrapping_mul(10).wrapping_add((diff / 2).wrapping_mul(diff / 2) / hz) / hz);
    }

    if use_rtt_scaling != 0 && min_rtt != 0 {
        let mut scale = (hz << 3) / min_rtt.wrapping_mul(10);

        // clamping ratio to interval [0.5,10]<<3
        scale = scale.clamp(1 << 2, 10 << 3);
        factor = (factor << 3) / scale;
        if factor == 0 {
            factor = 1;
        }
    }

    ca.alpha = factor.wrapping_mul(2).wrapping_mul((128i32 - ca.beta as i32) as u32);
    if ca.alpha == 0 {
        ca.alpha = ALPHA_BASE;
    }
}

/// `htcp_alpha_update()` for the glue.
#[no_mangle]
pub unsafe extern "C" fn rust_htcp_alpha_update(ca: *mut Htcp, jiffies: u32, hz: u32, use_rtt_scaling: i32) {
    // SAFETY: the glue passes the connection's `struct htcp`.
    let ca = unsafe { &mut *ca };
    alpha_update(ca, jiffies, hz, use_rtt_scaling);
}

/// `htcp_param_update()`: called at a congestion event; recompute beta and alpha and let the maximum RTT fade slowly.
#[no_mangle]
pub unsafe extern "C" fn rust_htcp_param_update(ca: *mut Htcp, use_bandwidth_switch: i32, use_rtt_scaling: i32, jiffies: u32, hz: u32, ms10: u32) {
    // SAFETY: the glue passes the connection's `struct htcp`.
    let ca = unsafe { &mut *ca };
    let min_rtt = ca.min_rtt;
    let max_rtt = ca.max_rtt;

    beta_update(ca, min_rtt, max_rtt, use_bandwidth_switch, ms10);
    alpha_update(ca, jiffies, hz, use_rtt_scaling);

    // add slowly fading memory for maxRTT to accommodate routing changes
    if min_rtt > 0 && max_rtt > min_rtt {
        ca.max_rtt = min_rtt.wrapping_add((max_rtt - min_rtt).wrapping_mul(95) / 100);
    }
}

/// The reduction of `htcp_recalc_ssthresh()` (after `htcp_param_update`): `cwnd * beta / 128`, floor 2.
#[no_mangle]
pub unsafe extern "C" fn rust_htcp_ssthresh(ca: *const Htcp, cwnd: u32) -> u32 {
    // SAFETY: the glue passes the connection's `struct htcp`.
    let ca = unsafe { &*ca };
    (cwnd.wrapping_mul(ca.beta as u32) >> 7).max(2)
}

/// The increase outside slow start in `htcp_cong_avoid()`. Returns 1 when `*cwnd` was raised by one; sets `*cnt` and recomputes alpha when the counter reached the threshold.
#[no_mangle]
pub unsafe extern "C" fn rust_htcp_ai(ca: *mut Htcp, cwnd: *mut u32, cnt: *mut u32, clamp: u32, jiffies: u32, hz: u32, use_rtt_scaling: i32) -> i32 {
    // SAFETY: the glue passes the connection's `struct htcp` and the window and counter of its `struct tcp_sock`.
    let (ca, cwnd, cnt) = unsafe { (&mut *ca, &mut *cwnd, &mut *cnt) };
    let mut changed = 0;

    // In dangerous area, increase slowly. In theory this is tp->snd_cwnd += alpha / tp->snd_cwnd
    if (cnt.wrapping_mul(ca.alpha) >> 7) >= *cwnd {
        if *cwnd < clamp {
            *cwnd = cwnd.wrapping_add(1);
            changed = 1;
        }
        *cnt = 0;
        alpha_update(ca, jiffies, hz, use_rtt_scaling);
    } else {
        *cnt = cnt.wrapping_add(ca.pkts_acked as u32);
    }

    ca.pkts_acked = 1;
    changed
}
