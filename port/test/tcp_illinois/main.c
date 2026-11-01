/* tcp_illinois differential: the pristine RTT sampling, alpha() / beta(), update_params(), window increase and ssthresh (ARM_REF) against tcp_illinois_rs.rs through the glue (ARM_RS), on a
 * stand-in socket. Random connections: RTT samples (negative, zero, around RTT_MAX, huge, runs of equal ones so the delay stays low and then rises), ACKs of 0-70000 packets, round
 * ends (update_params) at windows below and above win_thresh, delay profiles that put the average delay below 1% / 10% of the maximum, between 10% and 80%, above 80%, the five-good-RTT
 * wait (theta from -3 to 20), window increases in and out of slow start with clamps at, below and above the window, losses and ssthresh.   usage: t SHARD (env EB_N, EB_PROVE) */
#include "refshim.h"
int cwnd_limited;
#include SRCFILE
static unsigned long long rs_;
static unsigned long long rnd64(void) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return (rs_ >> 11) ^ (rs_ << 53); }
static unsigned rnd(unsigned n) { return n ? (unsigned)(rnd64() % n) : 0; }
static void dump(const struct sock *sk)
{
	const struct illinois *c = &sk->ca;
	printf("sum=%llu cnt=%u base=%u max=%u end=%u alpha=%u beta=%u acked=%u above=%u low=%u | nxt=%u cwnd=%u ccnt=%u clamp=%u ssth=%u", (unsigned long long)c->sum_rtt, c->cnt_rtt, c->base_rtt, c->max_rtt, c->end_seq,
	       c->alpha, c->beta, c->acked, c->rtt_above, c->rtt_low, sk->tp.snd_nxt, sk->tp.snd_cwnd, sk->tp.snd_cwnd_cnt, sk->tp.snd_cwnd_clamp, sk->tp.snd_ssthresh);
}
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0, prove = getenv("EB_PROVE") != NULL; long n = getenv("EB_N") ? atol(getenv("EB_N")) : 20000, it, pc = 0;
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (it = 0; it < n; it++) {
		struct sock sk; int step, steps = 20 + rnd(80); u32 profile = rnd(5), baseline = 1000 + rnd(200000);
		memset(&sk, 0, sizeof sk);
		win_thresh = rnd(4) ? 15 : (int)rnd(40) - 2; theta = rnd(3) ? 5 : (int)rnd(24) - 3;
		sk.tp.snd_nxt = rnd64(); sk.tp.snd_cwnd = 1 + rnd(rnd(3) ? 60 : 5000); sk.tp.snd_ssthresh = rnd(3) ? 2 + rnd(100) : 0x7fffffff; sk.tp.snd_cwnd_clamp = rnd(5) ? 0xffff : 1 + rnd(200);
		/* tcp_illinois_init */
		sk.ca.alpha = ALPHA_MAX; sk.ca.beta = BETA_BASE; sk.ca.base_rtt = 0x7fffffff; sk.ca.max_rtt = 0; sk.ca.acked = 0; sk.ca.rtt_low = 0; sk.ca.rtt_above = 0; rtt_reset(&sk);
		for (step = 0; step < steps; step++) {
			int op = rnd(20);
			cwnd_limited = rnd(6) != 0;
			if (op < 10) {
				struct ack_sample sm; u32 r;
				sm.pkts_acked = rnd(8) == 0 ? rnd(70000) : rnd(4);
				switch (rnd(8)) {
				case 0: sm.rtt_us = -1 - (int)rnd(5); break;
				case 1: sm.rtt_us = 3355443 - 2 + rnd(5); break;
				case 2: sm.rtt_us = (int)(0x7fffffffu - rnd(4)); break;
				case 3: sm.rtt_us = 0; break;
				default:
					switch (profile) {
					case 0: sm.rtt_us = baseline + rnd(rnd(2) ? 3 : baseline / 50 + 1); break;			/* nearly constant: delay below the low threshold */
					case 1: sm.rtt_us = baseline + rnd(baseline); break;					/* spread over a full baseline */
					case 2: sm.rtt_us = baseline + rnd(baseline * 3 / 2 + 1); break;
					case 3: sm.rtt_us = rnd(5) ? baseline : baseline * (2 + rnd(30)); break;			/* occasional spikes */
					default: sm.rtt_us = 1 + rnd(1000000); break;
					}
				}
				tcp_illinois_acked(&sk, &sm);
				printf("%ld.%d ack pk=%u rtt=%d -> ", it, step, sm.pkts_acked, sm.rtt_us); dump(&sk); printf("\n");
				(void)r;
			} else if (op < 15) {
				u32 ack = sk.ca.end_seq + (rnd(3) == 0 ? 0 : rnd(4) == 0 ? (u32)-1 - rnd(3) : 1 + rnd(1000));
				u32 acked = rnd(6) == 0 ? rnd(100000) : rnd(5);
				if (rnd(4) == 0) sk.tp.snd_cwnd = 1 + rnd(rnd(2) ? 30 : 3000);
				if (rnd(6) == 0) sk.tp.snd_cwnd_cnt = rnd(rnd(2) ? 100 : 100000);
				if (rnd(10) == 0) sk.tp.snd_nxt += rnd(100000);
				if (rnd(10) == 0) sk.tp.snd_ssthresh = rnd(2) ? sk.tp.snd_cwnd + 1 : rnd(200);
				tcp_illinois_cong_avoid(&sk, ack, acked);
				printf("%ld.%d avoid ack=%u acked=%u lim=%d win_thresh=%d theta=%d -> ", it, step, ack, acked, cwnd_limited, win_thresh, theta); dump(&sk); printf("\n");
			} else if (op < 17) {
				u32 r;
				if (rnd(3) == 0) sk.ca.beta = rnd(70);
				r = tcp_illinois_ssthresh(&sk); if (prove && pc++ == 3) r++;
				printf("%ld.%d ssthresh cwnd=%u beta=%u -> %u\n", it, step, sk.tp.snd_cwnd, sk.ca.beta, r);
				if (rnd(2)) sk.tp.snd_cwnd = r;
			} else if (op < 19) {
				tcp_illinois_state(&sk, rnd(2) ? TCP_CA_Loss : 0);
				printf("%ld.%d state -> ", it, step); dump(&sk); printf("\n");
			} else {
				if (rnd(2)) sk.ca.sum_rtt = rnd64() >> rnd(60);	/* garbage sums: the averages must still agree */
				if (rnd(2)) sk.ca.cnt_rtt = rnd(70000);
				if (rnd(3) == 0) sk.ca.max_rtt = rnd(1000000);
			}
		}
	}
	return 0;
}
