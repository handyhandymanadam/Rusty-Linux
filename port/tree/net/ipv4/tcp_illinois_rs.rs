// SPDX-License-Identifier: GPL-2.0-only

//! The TCP Illinois congestion-control arithmetic -- the Rust behind part of `net/ipv4/tcp_illinois.c`.
//!
//! Ported from `net/ipv4/tcp_illinois.c` (6.18.49, Stephen Hemminger, Shao Liu): RTT measurement per ACK (`tcp_illinois_acked`), the delay-driven additive-increase factor `alpha()`
//! and multiplicative-decrease factor `beta()`, their once-per-RTT recomputation (`update_params`), the window increase of `tcp_illinois_cong_avoid` and the window reduction of
//! `tcp_illinois_ssthresh`. In C (`tcp_illinois_glue.c`): everything that touches the socket, the module parameters, `tcp_illinois_info` and the registration, with the pieces above as
//! thin wrappers. Arithmetic is 32-bit unsigned with wrapping, as in C; a zero divisor (which C reaches as a divide error) is a Rust panic.
//!
//! Replaces: net/ipv4/tcp_illinois.c (tcp_illinois_acked, max_delay, avg_delay, alpha, beta, update_params, the increase of tcp_illinois_cong_avoid, tcp_illinois_ssthresh)

/// `struct illinois` (the glue checks the offsets).
#[repr(C)]
pub struct Illinois {
    sum_rtt: u64,
    cnt_rtt: u16,
    base_rtt: u32,
    max_rtt: u32,
    end_seq: u32,
    alpha: u32,
    beta: u32,
    acked: u16,
    rtt_above: u8,
    rtt_low: u8,
}

const ALPHA_SHIFT: u32 = 7;
const ALPHA_SCALE: u32 = 1 << ALPHA_SHIFT;
const ALPHA_MIN: u32 = (3 * ALPHA_SCALE) / 10;
const ALPHA_MAX: u32 = 10 * ALPHA_SCALE;
const ALPHA_BASE: u32 = ALPHA_SCALE;
const RTT_MAX: u32 = u32::MAX / ALPHA_MAX;

const BETA_SHIFT: u32 = 6;
const BETA_SCALE: u32 = 1 << BETA_SHIFT;
const BETA_MIN: u32 = BETA_SCALE / 8;
const BETA_MAX: u32 = BETA_SCALE / 2;
const BETA_BASE: u32 = BETA_MAX;

/// `tcp_illinois_acked()`: remember how many packets this ACK covered and fold the RTT sample (if any) into the minimum, maximum and sum.
#[no_mangle]
pub unsafe extern "C" fn rust_ill_acked(ca: *mut Illinois, pkts_acked: u32, rtt_us: i32) {
    // SAFETY: the glue passes the connection's `struct illinois`.
    let ca = unsafe { &mut *ca };

    ca.acked = pkts_acked as u16;

    // dup ack, no rtt sample
    if rtt_us < 0 {
        return;
    }
    let mut rtt = rtt_us as u32;

    // ignore bogus values, this prevents wraparound in alpha math
    if rtt > RTT_MAX {
        rtt = RTT_MAX;
    }

    // keep track of minimum RTT seen so far
    if ca.base_rtt > rtt {
        ca.base_rtt = rtt;
    }

    // and max
    if ca.max_rtt < rtt {
        ca.max_rtt = rtt;
    }

    ca.cnt_rtt = ca.cnt_rtt.wrapping_add(1);
    ca.sum_rtt = ca.sum_rtt.wrapping_add(rtt as u64);
}

/// Maximum queuing delay.
fn max_delay(ca: &Illinois) -> u32 {
    ca.max_rtt.wrapping_sub(ca.base_rtt)
}

/// Average queuing delay.
fn avg_delay(ca: &Illinois) -> u32 {
    let t = ca.sum_rtt / ca.cnt_rtt as u64;
    t.wrapping_sub(ca.base_rtt as u64) as u32
}

/// `alpha()`: the additive-increase factor. A small window or low delay gives the maximum; high delay shrinks it towards ALPHA_MIN.
fn alpha(ca: &mut Illinois, da: u32, mut dm: u32, theta: i32) -> u32 {
    let d1 = dm / 100; // Low threshold

    if da <= d1 {
        // If never got out of low delay zone, then use max
        if ca.rtt_above == 0 {
            return ALPHA_MAX;
        }

        // Wait for 5 good RTT's before allowing alpha to go alpha max. This prevents one good RTT from causing sudden window increase.
        ca.rtt_low = ca.rtt_low.wrapping_add(1);
        if (ca.rtt_low as i32) < theta {
            return ca.alpha;
        }

        ca.rtt_low = 0;
        ca.rtt_above = 0;
        return ALPHA_MAX;
    }

    ca.rtt_above = 1;

    dm = dm.wrapping_sub(d1);
    let da = da.wrapping_sub(d1);
    dm.wrapping_mul(ALPHA_MAX) / dm.wrapping_add(da.wrapping_mul(ALPHA_MAX - ALPHA_MIN) / ALPHA_MIN)
}

/// `beta()`: the multiplicative-decrease factor. Delay under 10% of the maximum gives 1/8, over 80% gives 1/2, linear in between.
fn beta(da: u32, dm: u32) -> u32 {
    let d2 = dm / 10;
    if da <= d2 {
        return BETA_MIN;
    }

    let d3 = dm.wrapping_mul(8) / 10;
    if da >= d3 || d3 <= d2 {
        return BETA_MAX;
    }

    BETA_MIN.wrapping_mul(d3).wrapping_sub(BETA_MAX.wrapping_mul(d2)).wrapping_add((BETA_MAX - BETA_MIN).wrapping_mul(da)) / (d3 - d2)
}

/// `update_params()`: recompute alpha and beta once per RTT (small windows use the Reno values), then `rtt_reset()` with `snd_nxt`.
#[no_mangle]
pub unsafe extern "C" fn rust_ill_update_params(ca: *mut Illinois, cwnd: u32, snd_nxt: u32, win_thresh: i32, theta: i32) {
    // SAFETY: the glue passes the connection's `struct illinois`.
    let ca = unsafe { &mut *ca };

    if cwnd < win_thresh as u32 {
        ca.alpha = ALPHA_BASE;
        ca.beta = BETA_BASE;
    } else if ca.cnt_rtt > 0 {
        let dm = max_delay(ca);
        let da = avg_delay(ca);

        ca.alpha = alpha(ca, da, dm, theta);
        ca.beta = beta(da, dm);
    }

    ca.end_seq = snd_nxt;
    ca.cnt_rtt = 0;
    ca.sum_rtt = 0;
}

/// The increase outside slow start in `tcp_illinois_cong_avoid()`: count the packets acknowledged and, once alpha / cwnd of them have accumulated, raise the window. Returns 1 when
/// `*cwnd` was changed (`*cnt` is then zero).
#[no_mangle]
pub unsafe extern "C" fn rust_ill_ai(ca: *mut Illinois, cwnd: *mut u32, cnt: *mut u32, clamp: u32) -> i32 {
    // SAFETY: the glue passes the connection's `struct illinois` and the window and counter of its `struct tcp_sock`.
    let (ca, cwnd, cnt) = unsafe { (&mut *ca, &mut *cwnd, &mut *cnt) };

    // snd_cwnd_cnt is # of packets since last cwnd increment
    *cnt = cnt.wrapping_add(ca.acked as u32);
    ca.acked = 1;

    // This is close approximation of: tp->snd_cwnd += alpha/tp->snd_cwnd
    let delta = cnt.wrapping_mul(ca.alpha) >> ALPHA_SHIFT;
    if delta >= *cwnd {
        *cwnd = cwnd.wrapping_add(delta / *cwnd).min(clamp);
        *cnt = 0;
        return 1;
    }
    0
}

/// `tcp_illinois_ssthresh()`: multiplicative decrease by beta / 64, floor 2.
#[no_mangle]
pub unsafe extern "C" fn rust_ill_ssthresh(ca: *const Illinois, cwnd: u32) -> u32 {
    // SAFETY: the glue passes the connection's `struct illinois`.
    let ca = unsafe { &*ca };
    let decr = cwnd.wrapping_mul(ca.beta) >> BETA_SHIFT;
    cwnd.wrapping_sub(decr).max(2)
}
