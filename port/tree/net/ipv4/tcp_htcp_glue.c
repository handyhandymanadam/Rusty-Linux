// SPDX-License-Identifier: GPL-2.0-only
/*
 * RUST PORT (net/ipv4/tcp_htcp.c, 6.18.49): the RTT and throughput measurement, the beta / alpha / parameter updates, the window increase and the ssthresh arithmetic are in
 * tcp_htcp_rs.rs. Everything that touches the socket, init / state / undo, the module parameters and the registration are upstream's. Upstream's whole file is installed as
 * tcp_htcp_norust.c for CONFIG_RUST=n.
 */
/*
 * H-TCP congestion control. The algorithm is detailed in:
 * R.N.Shorten, D.J.Leith:
 *   "H-TCP: TCP for high-speed and long-distance networks"
 *   Proc. PFLDnet, Argonne, 2004.
 * https://www.hamilton.ie/net/htcp3.pdf
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <net/tcp.h>

#define ALPHA_BASE	(1<<7)	/* 1.0 with shift << 7 */
#define BETA_MIN	(1<<6)	/* 0.5 with shift << 7 */
#define BETA_MAX	102	/* 0.8 with shift << 7 */

static int use_rtt_scaling __read_mostly = 1;
module_param(use_rtt_scaling, int, 0644);
MODULE_PARM_DESC(use_rtt_scaling, "turn on/off RTT scaling");

static int use_bandwidth_switch __read_mostly = 1;
module_param(use_bandwidth_switch, int, 0644);
MODULE_PARM_DESC(use_bandwidth_switch, "turn on/off bandwidth switcher");

struct htcp {
	u32	alpha;		/* Fixed point arith, << 7 */
	u8	beta;           /* Fixed point arith, << 7 */
	u8	modeswitch;	/* Delay modeswitch
				   until we had at least one congestion event */
	u16	pkts_acked;
	u32	packetcount;
	u32	minRTT;
	u32	maxRTT;
	u32	last_cong;	/* Time since last congestion event end */
	u32	undo_last_cong;

	u32	undo_maxRTT;
	u32	undo_old_maxB;

	/* Bandwidth estimation */
	u32	minB;
	u32	maxB;
	u32	old_maxB;
	u32	Bi;
	u32	lasttime;
};

static inline u32 htcp_cong_time(const struct htcp *ca)
{
	return jiffies - ca->last_cong;
}

static inline u32 htcp_ccount(const struct htcp *ca)
{
	return htcp_cong_time(ca) / ca->minRTT;
}

static inline void htcp_reset(struct htcp *ca)
{
	ca->undo_last_cong = ca->last_cong;
	ca->undo_maxRTT = ca->maxRTT;
	ca->undo_old_maxB = ca->old_maxB;

	ca->last_cong = jiffies;
}

static u32 htcp_cwnd_undo(struct sock *sk)
{
	struct htcp *ca = inet_csk_ca(sk);

	if (ca->undo_last_cong) {
		ca->last_cong = ca->undo_last_cong;
		ca->maxRTT = ca->undo_maxRTT;
		ca->old_maxB = ca->undo_old_maxB;
		ca->undo_last_cong = 0;
	}

	return tcp_reno_undo_cwnd(sk);
}

/* RUST-WRAPPERS BEGIN: the arithmetic is in tcp_htcp_rs.rs. */
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

static u32 htcp_recalc_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct htcp *ca = inet_csk_ca(sk);

	htcp_param_update(sk);
	return rust_htcp_ssthresh(ca, tcp_snd_cwnd(tp));
}

static void htcp_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct htcp *ca = inet_csk_ca(sk);

	if (!tcp_is_cwnd_limited(sk))
		return;

	if (tcp_in_slow_start(tp))
		tcp_slow_start(tp, acked);
	else {
		u32 cwnd = tcp_snd_cwnd(tp);

		if (rust_htcp_ai(ca, &cwnd, &tp->snd_cwnd_cnt, tp->snd_cwnd_clamp, (u32)jiffies, HZ, use_rtt_scaling))
			tcp_snd_cwnd_set(tp, cwnd);
	}
}

static void htcp_init(struct sock *sk)
{
	struct htcp *ca = inet_csk_ca(sk);

	memset(ca, 0, sizeof(struct htcp));
	ca->alpha = ALPHA_BASE;
	ca->beta = BETA_MIN;
	ca->pkts_acked = 1;
	ca->last_cong = jiffies;
}

static void htcp_state(struct sock *sk, u8 new_state)
{
	switch (new_state) {
	case TCP_CA_Open:
		{
			struct htcp *ca = inet_csk_ca(sk);

			if (ca->undo_last_cong) {
				ca->last_cong = jiffies;
				ca->undo_last_cong = 0;
			}
		}
		break;
	case TCP_CA_CWR:
	case TCP_CA_Recovery:
	case TCP_CA_Loss:
		htcp_reset(inet_csk_ca(sk));
		break;
	}
}

static struct tcp_congestion_ops htcp __read_mostly = {
	.init		= htcp_init,
	.ssthresh	= htcp_recalc_ssthresh,
	.cong_avoid	= htcp_cong_avoid,
	.set_state	= htcp_state,
	.undo_cwnd	= htcp_cwnd_undo,
	.pkts_acked	= measure_achieved_throughput,
	.owner		= THIS_MODULE,
	.name		= "htcp",
};

static int __init htcp_register(void)
{
	BUILD_BUG_ON(sizeof(struct htcp) > ICSK_CA_PRIV_SIZE);
	BUILD_BUG_ON(BETA_MIN >= BETA_MAX);
	return tcp_register_congestion_control(&htcp);
}

static void __exit htcp_unregister(void)
{
	tcp_unregister_congestion_control(&htcp);
}

module_init(htcp_register);
module_exit(htcp_unregister);

MODULE_AUTHOR("Baruch Even");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("H-TCP");
