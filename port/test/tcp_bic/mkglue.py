#!/usr/bin/env python3
"""mkglue.py PRISTINE.c OUT.c -- tcp_bic_glue.c = upstream net/ipv4/tcp_bic.c with bictcp_update(), the arithmetic of bictcp_recalc_ssthresh() and the delayed-ACK update of bictcp_acked() replaced by calls into tcp_bic_rs.rs."""
import sys
s = open(sys.argv[1]).read()
wr = r'''/* RUST-WRAPPERS BEGIN: the arithmetic is in tcp_bic_rs.rs. */
void rust_bic_update(struct bictcp *ca, u32 cwnd, u32 now, u32 hz, int low_window, int max_increment, int smooth_part);
u32 rust_bic_ssthresh(struct bictcp *ca, u32 cwnd, int fast_convergence, int beta, int low_window);
void rust_bic_acked(struct bictcp *ca, u32 pkts_acked);

/* tcp_bic_rs.rs hard-codes these offsets of struct bictcp. */
static_assert(offsetof(struct bictcp, cnt) == 0 && offsetof(struct bictcp, last_max_cwnd) == 4 && offsetof(struct bictcp, last_cwnd) == 8 && offsetof(struct bictcp, last_time) == 12 &&
	      offsetof(struct bictcp, epoch_start) == 16 && offsetof(struct bictcp, delayed_ack) == 20);
static_assert(BICTCP_BETA_SCALE == 1024 && BICTCP_B == 4 && ACK_RATIO_SHIFT == 4);

static inline void bictcp_update(struct bictcp *ca, u32 cwnd)
{
	rust_bic_update(ca, cwnd, tcp_jiffies32, HZ, low_window, max_increment, smooth_part);
}
/* RUST-WRAPPERS END */

'''
a = s.index("/*\n * Compute congestion window to use.\n */"); b = s.index("static void bictcp_cong_avoid(")
s = s[:a] + wr + s[b:]
a = s.index("\tca->epoch_start = 0;\t/* end of epoch */"); b = s.index("static void bictcp_state(")
s = s[:a] + "\treturn rust_bic_ssthresh(ca, tcp_snd_cwnd(tp), fast_convergence, beta, low_window);\n}\n\n" + s[b:]
old = "\t\tca->delayed_ack += sample->pkts_acked -\n\t\t\t(ca->delayed_ack >> ACK_RATIO_SHIFT);\n"
assert old in s
s = s.replace(old, "\t\trust_bic_acked(ca, sample->pkts_acked);\n")
note = "// SPDX-License-Identifier: GPL-2.0-only\n/*\n * RUST PORT (net/ipv4/tcp_bic.c, 6.18.49): bictcp_update(), the window arithmetic of bictcp_recalc_ssthresh() and the delayed-ACK ratio of bictcp_acked() are in\n * tcp_bic_rs.rs. Everything that touches the socket, the module parameters and the registration are upstream's. Upstream's whole file is installed as tcp_bic_norust.c for CONFIG_RUST=n.\n */\n"
s = s.replace("// SPDX-License-Identifier: GPL-2.0-only\n", note, 1)
open(sys.argv[2], "w").write(s)
