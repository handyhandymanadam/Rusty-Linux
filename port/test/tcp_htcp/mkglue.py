#!/usr/bin/env python3
"""mkglue.py PRISTINE.c OUT.c -- tcp_htcp_glue.c = upstream net/ipv4/tcp_htcp.c with the measurements, beta / alpha / parameter updates, the window increase and the ssthresh arithmetic replaced by calls into tcp_htcp_rs.rs."""
import sys
s = open(sys.argv[1]).read()
wr = r'''/* RUST-WRAPPERS BEGIN: the arithmetic is in tcp_htcp_rs.rs. */
void rust_htcp_throughput(struct htcp *ca, u32 pkts_acked, int has_rtt, u32 rtt_jiffies, u8 ca_state, u32 now, u32 jiffies32, u32 cwnd, u32 hz, u32 ms20, int use_bandwidth_switch);
void rust_htcp_alpha_update(struct htcp *ca, u32 jiffies32, u32 hz, int use_rtt_scaling);
void rust_htcp_param_update(struct htcp *ca, int use_bandwidth_switch, int use_rtt_scaling, u32 jiffies32, u32 hz, u32 ms10);
u32 rust_htcp_ssthresh(const struct htcp *ca, u32 cwnd);
int rust_htcp_ai(struct htcp *ca, u32 *cwnd, u32 *cnt, u32 clamp, u32 jiffies32, u32 hz, int use_rtt_scaling);

/* tcp_htcp_rs.rs hard-codes these offsets of struct htcp. */
static_assert(sizeof(struct htcp) == 56 && offsetof(struct htcp, alpha) == 0 && offsetof(struct htcp, beta) == 4 && offsetof(struct htcp, modeswitch) == 5 && offsetof(struct htcp, pkts_acked) == 6 &&
	      offsetof(struct htcp, packetcount) == 8 && offsetof(struct htcp, minRTT) == 12 && offsetof(struct htcp, maxRTT) == 16 && offsetof(struct htcp, last_cong) == 20 &&
	      offsetof(struct htcp, undo_last_cong) == 24 && offsetof(struct htcp, undo_maxRTT) == 28 && offsetof(struct htcp, undo_old_maxB) == 32 && offsetof(struct htcp, minB) == 36 &&
	      offsetof(struct htcp, maxB) == 40 && offsetof(struct htcp, old_maxB) == 44 && offsetof(struct htcp, Bi) == 48 && offsetof(struct htcp, lasttime) == 52);
static_assert(ALPHA_BASE == 128 && BETA_MIN == 64 && BETA_MAX == 102 && TCP_CA_Open == 0 && TCPF_CA_Open == 1 && TCPF_CA_Disorder == 2);

static void measure_achieved_throughput(struct sock *sk, const struct ack_sample *sample)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	const struct tcp_sock *tp = tcp_sk(sk);
	int has_rtt = sample->rtt_us > 0;

	rust_htcp_throughput(inet_csk_ca(sk), sample->pkts_acked, has_rtt, has_rtt ? usecs_to_jiffies(sample->rtt_us) : 0, icsk->icsk_ca_state, tcp_jiffies32, (u32)jiffies,
			     tcp_snd_cwnd(tp), HZ, msecs_to_jiffies(20), use_bandwidth_switch);
}

static inline void htcp_alpha_update(struct htcp *ca)
{
	rust_htcp_alpha_update(ca, (u32)jiffies, HZ, use_rtt_scaling);
}

static void htcp_param_update(struct sock *sk)
{
	rust_htcp_param_update(inet_csk_ca(sk), use_bandwidth_switch, use_rtt_scaling, (u32)jiffies, HZ, msecs_to_jiffies(10));
}
/* RUST-WRAPPERS END */

'''
a = s.index("static inline void measure_rtt("); b = s.index("static u32 htcp_recalc_ssthresh(")
s = s[:a] + wr + s[b:]
a = s.index("\tconst struct htcp *ca = inet_csk_ca(sk);\n\n\thtcp_param_update(sk);"); b = s.index("static void htcp_cong_avoid(")
s = s[:a] + "\tconst struct htcp *ca = inet_csk_ca(sk);\n\n\thtcp_param_update(sk);\n\treturn rust_htcp_ssthresh(ca, tcp_snd_cwnd(tp));\n}\n\n" + s[b:]
a = s.index("\t\t/* In dangerous area, increase slowly."); b = s.index("static void htcp_init(")
s = s[:a] + "\t\tu32 cwnd = tcp_snd_cwnd(tp);\n\n\t\tif (rust_htcp_ai(ca, &cwnd, &tp->snd_cwnd_cnt, tp->snd_cwnd_clamp, (u32)jiffies, HZ, use_rtt_scaling))\n\t\t\ttcp_snd_cwnd_set(tp, cwnd);\n\t}\n}\n\n" + s[b:]
note = "// SPDX-License-Identifier: GPL-2.0-only\n/*\n * RUST PORT (net/ipv4/tcp_htcp.c, 6.18.49): the RTT and throughput measurement, the beta / alpha / parameter updates, the window increase and the ssthresh arithmetic are in\n * tcp_htcp_rs.rs. Everything that touches the socket, init / state / undo, the module parameters and the registration are upstream's. Upstream's whole file is installed as\n * tcp_htcp_norust.c for CONFIG_RUST=n.\n */\n"
s = s.replace("// SPDX-License-Identifier: GPL-2.0-only\n", note, 1)
open(sys.argv[2], "w").write(s)
