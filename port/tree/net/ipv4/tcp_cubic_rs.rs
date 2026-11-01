// SPDX-License-Identifier: GPL-2.0-only

//! The CUBIC congestion-control arithmetic -- the Rust behind part of `net/ipv4/tcp_cubic.c`.
//!
//! Ported from `net/ipv4/tcp_cubic.c` (6.18.49, Sangtae Ha et al.): the table-driven cube root with its Newton-Raphson step (`cubic_root`), and `bictcp_update()`, which recomputes
//! how many ACKs should raise the congestion window by one (`ca->cnt`) from the cubic function of the time since the last window reduction, with the TCP-friendly lower bound.
//! In C (`tcp_cubic_glue.c`): everything that touches the socket (`cubictcp_init`, `cubictcp_cong_avoid`, `cubictcp_recalc_ssthresh`, HyStart, the statistics counters), the module
//! parameters, the registration, and the two arithmetic functions as thin wrappers passing in what the Rust needs (the jiffies clock, `HZ`, the delay converted to jiffies and the
//! tunables).
//!
//! Replaces: net/ipv4/tcp_cubic.c (cubic_root, bictcp_update)

/// `struct bictcp` up to `tcp_cwnd` (the rest is HyStart state; the glue checks the offsets).
#[repr(C)]
pub struct Bictcp {
    cnt: u32,
    last_max_cwnd: u32,
    last_cwnd: u32,
    last_time: u32,
    bic_origin_point: u32,
    bic_k: u32,
    delay_min: u32,
    epoch_start: u32,
    ack_cnt: u32,
    tcp_cwnd: u32,
}

const BICTCP_HZ: u32 = 10;

/// `cubic_root()`: the cube root of `a`, from a table of the 6 high bits and one Newton-Raphson step.
#[no_mangle]
pub extern "C" fn rust_cubic_root(a: u64) -> u32 {
    // cbrt(x) MSB values for x MSB values in [0..63]. Precomputed then refined by hand - Willy Tarreau.
    // For x in [0..63], v = cbrt(x << 18) - 1, cbrt(x) = (v[x] + 10) >> 6
    const V: [u8; 64] = [
        0, 54, 54, 54, 118, 118, 118, 118, 123, 129, 134, 138, 143, 147, 151, 156, 157, 161, 164, 168, 170, 173, 176, 179, 181, 185, 187, 190, 192, 194, 197, 199, 200, 202, 204, 206, 209,
        211, 213, 215, 217, 219, 221, 222, 224, 225, 227, 229, 231, 232, 234, 236, 237, 239, 240, 242, 244, 245, 246, 248, 250, 251, 252, 254,
    ];

    // fls64(a)
    let mut b: u32 = 64 - a.leading_zeros();
    if b < 7 {
        // a in [0..63]
        return (V[a as u32 as usize] as u32 + 35) >> 6;
    }

    b = ((b * 84) >> 8) - 1;
    let shift = a >> (b * 3);

    let mut x: u32 = ((V[shift as usize] as u32 + 10) << b) >> 6;

    // Newton-Raphson iteration
    //                         2
    // x    = ( 2 * x  +  a / x  ) / 3
    //  k+1          k         k
    x = 2u32.wrapping_mul(x).wrapping_add((a / (x as u64).wrapping_mul(x.wrapping_sub(1) as u64)) as u32);
    (x.wrapping_mul(341)) >> 10
}

/// `bictcp_update()`: set `ca->cnt`, the number of ACKs needed to grow the window by one packet, for window `cwnd` and `acked` newly acknowledged packets at jiffy `now`.
/// `delay_jiffies` is `usecs_to_jiffies(ca->delay_min)`.
#[no_mangle]
pub unsafe extern "C" fn rust_bictcp_update(
    ca: *mut Bictcp,
    cwnd: u32,
    acked: u32,
    now: u32,
    hz: u32,
    delay_jiffies: u64,
    tcp_friendliness: i32,
    cube_rtt_scale: u32,
    beta_scale: u32,
    cube_factor: u64,
) {
    unsafe {
        let ca = &mut *ca;

        ca.ack_cnt = ca.ack_cnt.wrapping_add(acked); // count the number of ACKed packets

        if ca.last_cwnd == cwnd && (now.wrapping_sub(ca.last_time) as i32) <= (hz / 32) as i32 {
            return;
        }

        // The CUBIC function can update ca->cnt at most once per jiffy. On all cwnd reduction events, ca->epoch_start is set to 0, which will force a recalculation of ca->cnt.
        if !(ca.epoch_start != 0 && now == ca.last_time) {
            ca.last_cwnd = cwnd;
            ca.last_time = now;

            if ca.epoch_start == 0 {
                ca.epoch_start = now; // record beginning
                ca.ack_cnt = acked; // start counting
                ca.tcp_cwnd = cwnd; // syn with cubic

                if ca.last_max_cwnd <= cwnd {
                    ca.bic_k = 0;
                    ca.bic_origin_point = cwnd;
                } else {
                    // Compute new K based on (wmax-cwnd) * (srtt>>3 / HZ) / c * 2^(3*bictcp_HZ)
                    ca.bic_k = rust_cubic_root(cube_factor.wrapping_mul(ca.last_max_cwnd.wrapping_sub(cwnd) as u64));
                    ca.bic_origin_point = ca.last_max_cwnd;
                }
            }

            // cubic function - calc: c * time^3 / rtt, while considering overflow in calculation of time^3 (so time^3 is done by using 64 bit) and without the support of
            // division of 64bit numbers (so all divisions are done by using 32 bit) also NOTE the unit of those veriables: time = (t - K) / 2^bictcp_HZ, c = bic_scale >> 10,
            // rtt = (srtt >> 3) / HZ. The following code does not have overflow problems, if the cwnd < 1 million packets.
            let mut t: u64 = (now.wrapping_sub(ca.epoch_start) as i32) as i64 as u64;
            t = t.wrapping_add(delay_jiffies);

            // change the unit from HZ to bictcp_HZ
            t <<= BICTCP_HZ;
            t /= hz as u64;

            let offs: u64 = if t < ca.bic_k as u64 { ca.bic_k as u64 - t } else { t - ca.bic_k as u64 }; // t - K

            // c/rtt * (t-K)^3
            let delta = ((cube_rtt_scale as u64).wrapping_mul(offs).wrapping_mul(offs).wrapping_mul(offs) >> (10 + 3 * BICTCP_HZ)) as u32;
            let bic_target = if t < ca.bic_k as u64 {
                ca.bic_origin_point.wrapping_sub(delta) // below origin
            } else {
                ca.bic_origin_point.wrapping_add(delta) // above origin
            };

            // cubic function - calc bictcp_cnt
            if bic_target > cwnd {
                ca.cnt = cwnd / (bic_target - cwnd);
            } else {
                ca.cnt = 100u32.wrapping_mul(cwnd); // very small increment
            }

            // The initial growth of cubic function may be too conservative when the available bandwidth is still unknown.
            if ca.last_max_cwnd == 0 && ca.cnt > 20 {
                ca.cnt = 20; // increase cwnd 5% per RTT
            }
        }

        // tcp_friendliness: TCP Friendly
        if tcp_friendliness != 0 {
            let scale = beta_scale;

            let mut delta = cwnd.wrapping_mul(scale) >> 3;
            while ca.ack_cnt > delta {
                // update tcp cwnd
                ca.ack_cnt -= delta;
                ca.tcp_cwnd = ca.tcp_cwnd.wrapping_add(1);
            }

            if ca.tcp_cwnd > cwnd {
                // if bic is slower than tcp
                delta = ca.tcp_cwnd - cwnd;
                let max_cnt = cwnd / delta;
                if ca.cnt > max_cnt {
                    ca.cnt = max_cnt;
                }
            }
        }

        // The maximum rate of cwnd increase CUBIC allows is 1 packet per 2 packets ACKed, meaning cwnd grows at 1.5x per RTT.
        ca.cnt = ca.cnt.max(2);
    }
}
