// SPDX-License-Identifier: GPL-2.0-only
/*
 * RUST PORT (net/ipv4/tcp_illinois.c, 6.18.49): the RTT sampling, alpha() / beta(), update_params(), the window increase and the reduction are in tcp_illinois_rs.rs. Everything that
 * touches the socket, the module parameters, tcp_illinois_info() and the registration are upstream's. Upstream's whole file is installed as tcp_illinois_norust.c for CONFIG_RUST=n.
 */
/*
 * TCP Illinois congestion control.
 * Home page:
 *	http://www.ews.uiuc.edu/~shaoliu/tcpillinois/index.html
 *
 * The algorithm is described in:
 * "TCP-Illinois: A Loss and Delay-Based Congestion Control Algorithm
 *  for High-Speed Networks"
 * http://tamerbasar.csl.illinois.edu/LiuBasarSrikantPerfEvalArtJun2008.pdf
 *
 * Implemented from description in paper and ns-2 simulation.
 * Copyright (C) 2007 Stephen Hemminger <shemminger@linux-foundation.org>
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/inet_diag.h>
#include <asm/div64.h>
#include <net/tcp.h>

#define ALPHA_SHIFT	7
#define ALPHA_SCALE	(1u<<ALPHA_SHIFT)
#define ALPHA_MIN	((3*ALPHA_SCALE)/10)	/* ~0.3 */
#define ALPHA_MAX	(10*ALPHA_SCALE)	/* 10.0 */
#define ALPHA_BASE	ALPHA_SCALE		/* 1.0 */
#define RTT_MAX		(U32_MAX / ALPHA_MAX)	/* 3.3 secs */

#define BETA_SHIFT	6
#define BETA_SCALE	(1u<<BETA_SHIFT)
#define BETA_MIN	(BETA_SCALE/8)		/* 0.125 */
#define BETA_MAX	(BETA_SCALE/2)		/* 0.5 */
#define BETA_BASE	BETA_MAX

static int win_thresh __read_mostly = 15;
module_param(win_thresh, int, 0);
MODULE_PARM_DESC(win_thresh, "Window threshold for starting adaptive sizing");

static int theta __read_mostly = 5;
module_param(theta, int, 0);
MODULE_PARM_DESC(theta, "# of fast RTT's before full growth");

/* TCP Illinois Parameters */
struct illinois {
	u64	sum_rtt;	/* sum of rtt's measured within last rtt */
	u16	cnt_rtt;	/* # of rtts measured within last rtt */
	u32	base_rtt;	/* min of all rtt in usec */
	u32	max_rtt;	/* max of all rtt in usec */
	u32	end_seq;	/* right edge of current RTT */
	u32	alpha;		/* Additive increase */
	u32	beta;		/* Muliplicative decrease */
	u16	acked;		/* # packets acked by current ACK */
	u8	rtt_above;	/* average rtt has gone above threshold */
	u8	rtt_low;	/* # of rtts measurements below threshold */
};

static void rtt_reset(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct illinois *ca = inet_csk_ca(sk);

	ca->end_seq = tp->snd_nxt;
	ca->cnt_rtt = 0;
	ca->sum_rtt = 0;

	/* TODO: age max_rtt? */
}

static void tcp_illinois_init(struct sock *sk)
{
	struct illinois *ca = inet_csk_ca(sk);

	ca->alpha = ALPHA_MAX;
	ca->beta = BETA_BASE;
	ca->base_rtt = 0x7fffffff;
	ca->max_rtt = 0;

	ca->acked = 0;
	ca->rtt_low = 0;
	ca->rtt_above = 0;

	rtt_reset(sk);
}

/* RUST-WRAPPERS BEGIN: the arithmetic is in tcp_illinois_rs.rs. */
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

/*
 * In case of loss, reset to default values
 */
static void tcp_illinois_state(struct sock *sk, u8 new_state)
{
	struct illinois *ca = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {
		ca->alpha = ALPHA_BASE;
		ca->beta = BETA_BASE;
		ca->rtt_low = 0;
		ca->rtt_above = 0;
		rtt_reset(sk);
	}
}

/*
 * Increase window in response to successful acknowledgment.
 */
static void tcp_illinois_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct illinois *ca = inet_csk_ca(sk);

	if (after(ack, ca->end_seq))
		update_params(sk);

	/* RFC2861 only increase cwnd if fully utilized */
	if (!tcp_is_cwnd_limited(sk))
		return;

	/* In slow start */
	if (tcp_in_slow_start(tp))
		tcp_slow_start(tp, acked);

	else {
		u32 cwnd = tcp_snd_cwnd(tp);

		if (rust_ill_ai(ca, &cwnd, &tp->snd_cwnd_cnt, tp->snd_cwnd_clamp))
			tcp_snd_cwnd_set(tp, cwnd);
	}
}

static u32 tcp_illinois_ssthresh(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct illinois *ca = inet_csk_ca(sk);

	return rust_ill_ssthresh(ca, tcp_snd_cwnd(tp));
}

/* Extract info for Tcp socket info provided via netlink. */
static size_t tcp_illinois_info(struct sock *sk, u32 ext, int *attr,
				union tcp_cc_info *info)
{
	const struct illinois *ca = inet_csk_ca(sk);

	if (ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		info->vegas.tcpv_enabled = 1;
		info->vegas.tcpv_rttcnt = ca->cnt_rtt;
		info->vegas.tcpv_minrtt = ca->base_rtt;
		info->vegas.tcpv_rtt = 0;

		if (info->vegas.tcpv_rttcnt > 0) {
			u64 t = ca->sum_rtt;

			do_div(t, info->vegas.tcpv_rttcnt);
			info->vegas.tcpv_rtt = t;
		}
		*attr = INET_DIAG_VEGASINFO;
		return sizeof(struct tcpvegas_info);
	}
	return 0;
}

static struct tcp_congestion_ops tcp_illinois __read_mostly = {
	.init		= tcp_illinois_init,
	.ssthresh	= tcp_illinois_ssthresh,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.cong_avoid	= tcp_illinois_cong_avoid,
	.set_state	= tcp_illinois_state,
	.get_info	= tcp_illinois_info,
	.pkts_acked	= tcp_illinois_acked,

	.owner		= THIS_MODULE,
	.name		= "illinois",
};

static int __init tcp_illinois_register(void)
{
	BUILD_BUG_ON(sizeof(struct illinois) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&tcp_illinois);
}

static void __exit tcp_illinois_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_illinois);
}

module_init(tcp_illinois_register);
module_exit(tcp_illinois_unregister);

MODULE_AUTHOR("Stephen Hemminger, Shao Liu");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP Illinois");
MODULE_VERSION("1.0");
