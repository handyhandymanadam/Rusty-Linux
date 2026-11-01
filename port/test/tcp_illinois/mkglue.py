#!/usr/bin/env python3
"""mkglue.py PRISTINE.c OUT.c -- tcp_illinois_glue.c = upstream net/ipv4/tcp_illinois.c with the RTT sampling, alpha / beta, update_params, the window increase and ssthresh replaced by calls into tcp_illinois_rs.rs."""
import sys
s = open(sys.argv[1]).read()
wr = r'''/* RUST-WRAPPERS BEGIN: the arithmetic is in tcp_illinois_rs.rs. */
void rust_ill_acked(struct illinois *ca, u32 pkts_acked, s32 rtt_us);
void rust_ill_update_params(struct illinois *ca, u32 cwnd, u32 snd_nxt, int win_thresh, int theta);
int rust_ill_ai(struct illinois *ca, u32 *cwnd, u32 *cnt, u32 clamp);
u32 rust_ill_ssthresh(const struct illinois *ca, u32 cwnd);

/* tcp_illinois_rs.rs hard-codes these offsets of struct illinois. */
static_assert(sizeof(struct illinois) == 40 && offsetof(struct illinois, sum_rtt) == 0 && offsetof(struct illinois, cnt_rtt) == 8 && offsetof(struct illinois, base_rtt) == 12 &&
	      offsetof(struct illinois, max_rtt) == 16 && offsetof(struct illinois, end_seq) == 20 && offsetof(struct illinois, alpha) == 24 && offsetof(struct illinois, beta) == 28 &&
	      offsetof(struct illinois, acked) == 32 && offsetof(struct illinois, rtt_above) == 34 && offsetof(struct illinois, rtt_low) == 35);
static_assert(ALPHA_SHIFT == 7 && ALPHA_MIN == 38 && ALPHA_MAX == 1280 && ALPHA_BASE == 128 && BETA_SHIFT == 6 && BETA_MIN == 8 && BETA_MAX == 32 && BETA_BASE == 32 && RTT_MAX == 3355443);

/* Measure RTT for each ack. */
static void tcp_illinois_acked(struct sock *sk, const struct ack_sample *sample)
{
	rust_ill_acked(inet_csk_ca(sk), sample->pkts_acked, sample->rtt_us);
}

/* Update alpha and beta values once per RTT */
static void update_params(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	rust_ill_update_params(inet_csk_ca(sk), tcp_snd_cwnd(tp), tp->snd_nxt, win_thresh, theta);
}
/* RUST-WRAPPERS END */

'''
# acked .. through update_params
a = s.index("/* Measure RTT for each ack. */"); b = s.index("/*\n * In case of loss, reset to default values")
s = s[:a] + wr + s[b:]
a = s.index("\t\tu32 delta;\n"); b = s.index("static u32 tcp_illinois_ssthresh(")
new = "\t\tu32 cwnd = tcp_snd_cwnd(tp);\n\n\t\tif (rust_ill_ai(ca, &cwnd, &tp->snd_cwnd_cnt, tp->snd_cwnd_clamp))\n\t\t\ttcp_snd_cwnd_set(tp, cwnd);\n\t}\n}\n\n"
s = s[:a] + new + s[b:]
a = s.index("\tu32 decr;\n"); b = s.index("/* Extract info for Tcp socket info")
s = s[:a] + "\n\treturn rust_ill_ssthresh(ca, tcp_snd_cwnd(tp));\n}\n\n" + s[b:]
note = "// SPDX-License-Identifier: GPL-2.0-only\n/*\n * RUST PORT (net/ipv4/tcp_illinois.c, 6.18.49): the RTT sampling, alpha() / beta(), update_params(), the window increase and the reduction are in tcp_illinois_rs.rs. Everything that\n * touches the socket, the module parameters, tcp_illinois_info() and the registration are upstream's. Upstream's whole file is installed as tcp_illinois_norust.c for CONFIG_RUST=n.\n */\n"
s = s.replace("// SPDX-License-Identifier: GPL-2.0-only\n", note, 1)
open(sys.argv[2], "w").write(s)
