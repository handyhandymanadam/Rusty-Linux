// SPDX-License-Identifier: GPL-2.0-only

//! The BIC congestion-control arithmetic -- the Rust behind part of `net/ipv4/tcp_bic.c`.
//!
//! Ported from `net/ipv4/tcp_bic.c` (6.18.49, Stephen Hemminger): `bictcp_update()` (how many ACKs raise the congestion window by one: binary search below the last maximum, slow start
//! and linear increase above it), the window reduction of `bictcp_recalc_ssthresh()` and the delayed-ACK ratio of `bictcp_acked()`. In C (`tcp_bic_glue.c`): everything that touches the
//! socket, the module parameters and the registration, and the three arithmetic pieces as thin wrappers passing in the tunables. All arithmetic is 32-bit unsigned with wrapping, as the
//! C mixes `int` parameters with `u32` operands (the parameters are converted to unsigned).
//!
//! Replaces: net/ipv4/tcp_bic.c (bictcp_update, the arithmetic of bictcp_recalc_ssthresh and bictcp_acked)

/// `struct bictcp` (the glue checks the offsets).
#[repr(C)]
pub struct Bictcp {
    cnt: u32,
    last_max_cwnd: u32,
    last_cwnd: u32,
    last_time: u32,
    epoch_start: u32,
    delayed_ack: u32,
}

const BICTCP_BETA_SCALE: u32 = 1024;
const BICTCP_B: u32 = 4;
const ACK_RATIO_SHIFT: u32 = 4;

/// `bictcp_update()`: set `ca->cnt` for window `cwnd` at jiffy `now`.
#[no_mangle]
pub unsafe extern "C" fn rust_bic_update(ca: *mut Bictcp, cwnd: u32, now: u32, hz: u32, low_window: i32, max_increment: i32, smooth_part: i32) {
    // SAFETY: the glue passes the connection's `struct bictcp`.
    let ca = unsafe { &mut *ca };
    let low_window = low_window as u32;
    let max_inc = max_increment as u32;
    let smooth = smooth_part as u32;

    if ca.last_cwnd == cwnd && (now.wrapping_sub(ca.last_time) as i32) <= (hz / 32) as i32 {
        return;
    }

    ca.last_cwnd = cwnd;
    ca.last_time = now;

    if ca.epoch_start == 0 {
        // record the beginning of an epoch
        ca.epoch_start = now;
    }

    // start off normal
    if cwnd <= low_window {
        ca.cnt = cwnd;
        return;
    }

    // binary increase
    if cwnd < ca.last_max_cwnd {
        let dist = (ca.last_max_cwnd - cwnd) / BICTCP_B;

        if dist > max_inc {
            // linear increase
            ca.cnt = cwnd / max_inc;
        } else if dist <= 1 {
            // binary search increase
            ca.cnt = cwnd.wrapping_mul(smooth) / BICTCP_B;
        } else {
            // binary search increase
            ca.cnt = cwnd / dist;
        }
    } else {
        // slow start AMD linear increase
        if cwnd < ca.last_max_cwnd.wrapping_add(BICTCP_B) {
            // slow start
            ca.cnt = cwnd.wrapping_mul(smooth) / BICTCP_B;
        } else if cwnd < ca.last_max_cwnd.wrapping_add((max_increment.wrapping_mul((BICTCP_B - 1) as i32)) as u32) {
            // slow start
            ca.cnt = cwnd.wrapping_mul(BICTCP_B - 1) / cwnd.wrapping_sub(ca.last_max_cwnd);
        } else {
            // linear increase
            ca.cnt = cwnd / max_inc;
        }
    }

    // if in slow start or link utilization is very low
    if ca.last_max_cwnd == 0 && ca.cnt > 20 {
        // increase cwnd 5% per RTT
        ca.cnt = 20;
    }

    ca.cnt = (ca.cnt << ACK_RATIO_SHIFT) / ca.delayed_ack;
    if ca.cnt == 0 {
        // cannot be zero
        ca.cnt = 1;
    }
}

/// `bictcp_recalc_ssthresh()`: end the epoch, remember the window the reduction came from (lowered by fast convergence) and return the new slow-start threshold.
#[no_mangle]
pub unsafe extern "C" fn rust_bic_ssthresh(ca: *mut Bictcp, cwnd: u32, fast_convergence: i32, beta: i32, low_window: i32) -> u32 {
    // SAFETY: the glue passes the connection's `struct bictcp`.
    let ca = unsafe { &mut *ca };
    let beta = beta as u32;

    ca.epoch_start = 0; // end of epoch

    // Wmax and fast convergence
    if cwnd < ca.last_max_cwnd && fast_convergence != 0 {
        ca.last_max_cwnd = cwnd.wrapping_mul(BICTCP_BETA_SCALE.wrapping_add(beta)) / (2 * BICTCP_BETA_SCALE);
    } else {
        ca.last_max_cwnd = cwnd;
    }

    if cwnd <= low_window as u32 {
        (cwnd >> 1).max(2)
    } else {
        (cwnd.wrapping_mul(beta) / BICTCP_BETA_SCALE).max(2)
    }
}

/// `bictcp_acked()` in the open state: the sliding-window delayed-ACK ratio, `ratio = (15 * ratio + sample) / 16`.
#[no_mangle]
pub unsafe extern "C" fn rust_bic_acked(ca: *mut Bictcp, pkts_acked: u32) {
    // SAFETY: the glue passes the connection's `struct bictcp`.
    let ca = unsafe { &mut *ca };
    ca.delayed_ack = ca.delayed_ack.wrapping_add(pkts_acked.wrapping_sub(ca.delayed_ack >> ACK_RATIO_SHIFT));
}
