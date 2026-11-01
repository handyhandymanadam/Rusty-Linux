/* tcp_htcp differential: the pristine H-TCP measurements, beta / alpha / parameter updates, window increase, ssthresh, init, state and undo (ARM_REF) against tcp_htcp_rs.rs through the glue (ARM_RS),
 * on a stand-in socket. Random connections at HZ 100, 250, 300 and 1000 with jiffies near the 32-bit wrap: ACK samples (RTT absent, tiny, around the 20 ms and 10 ms limits, huge; all
 * congestion states; 0-70000 packets), long and short times since congestion (so the quadratic alpha factor, the RTT scaling clamps and the ccount <= 3 branch all occur), the bandwidth
 * switch and RTT scaling on and off, window increases in and out of slow start, congestion events (ssthresh), state changes and undo.   usage: t SHARD (env EB_N, EB_PROVE) */
#include "refshim.h"
unsigned int hz_g; unsigned long jiffies; int cwnd_limited;
static int use_rtt_scaling_x;
#include SRCFILE
static unsigned long long rs_;
static unsigned long long rnd64(void) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return (rs_ >> 11) ^ (rs_ << 53); }
static unsigned rnd(unsigned n) { return n ? (unsigned)(rnd64() % n) : 0; }
static void dump(const struct sock *sk)
{
	const struct htcp *c = &sk->ca;
	printf("alpha=%u beta=%u mode=%u pk=%u cnt=%u min=%u max=%u lcong=%u ulcong=%u umax=%u uomaxB=%u minB=%u maxB=%u omaxB=%u Bi=%u lt=%u | st=%u cwnd=%u ccnt=%u clamp=%u ssth=%u", c->alpha, c->beta, c->modeswitch, c->pkts_acked,
	       c->packetcount, c->minRTT, c->maxRTT, c->last_cong, c->undo_last_cong, c->undo_maxRTT, c->undo_old_maxB, c->minB, c->maxB, c->old_maxB, c->Bi, c->lasttime, sk->icsk.icsk_ca_state, sk->tp.snd_cwnd,
	       sk->tp.snd_cwnd_cnt, sk->tp.snd_cwnd_clamp, sk->tp.snd_ssthresh);
}
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0, prove = getenv("EB_PROVE") != NULL; long n = getenv("EB_N") ? atol(getenv("EB_N")) : 20000, it, pc = 0;
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (it = 0; it < n; it++) {
		static const unsigned hzs[] = { 100, 250, 300, 1000 }; struct sock sk; int step, steps = 20 + rnd(100); u32 baseus = 1000 + rnd(rnd(2) ? 60000 : 400000);
		hz_g = hzs[rnd(4)]; use_rtt_scaling = rnd(4) != 0; use_bandwidth_switch = rnd(4) != 0;
		jiffies = rnd(3) == 0 ? 0xfffff000ul + rnd(0x2000) : (rnd(3) == 0 ? 0x1ffffff00ul + rnd(500) : rnd64() >> rnd(40));
		memset(&sk, 0, sizeof sk);
		sk.tp.snd_cwnd = 1 + rnd(rnd(3) ? 80 : 6000); sk.tp.snd_ssthresh = rnd(3) ? 2 + rnd(200) : 0x7fffffff; sk.tp.snd_cwnd_clamp = rnd(5) ? 0xffff : 1 + rnd(300);
		htcp_init(&sk);
		for (step = 0; step < steps; step++) {
			int op = rnd(20);
			cwnd_limited = rnd(6) != 0;
			jiffies += rnd(4) == 0 ? 0 : rnd(rnd(5) == 0 ? 8 * hz_g : hz_g / 4 + 2);
			if (op < 9) {
				struct ack_sample sm;
				sm.pkts_acked = rnd(8) == 0 ? rnd(70000) : rnd(5);
				switch (rnd(8)) {
				case 0: sm.rtt_us = rnd(2) ? 0 : -1 - (int)rnd(3); break;
				case 1: sm.rtt_us = 10000 + rnd(2) * 10000 - 2 + rnd(5) * 1000; break;
				case 2: sm.rtt_us = (int)(0x7fffffffu - rnd(4)); break;
				default: sm.rtt_us = baseus + rnd(rnd(2) ? 3000 : baseus / 2 + 1); break;
				}
				sk.icsk.icsk_ca_state = rnd(3) ? TCP_CA_Open : rnd(5);
				if (rnd(12) == 0) sk.ca.minB = sk.ca.maxB + 1 + rnd(1000);	/* a state no sequence of ACKs reaches: minB above maxB */
				if (rnd(25) == 0) sk.ca.beta = 128;		/* alpha = 2 * factor * 0 -> the ALPHA_BASE fallback */
				measure_achieved_throughput(&sk, &sm);
				printf("%ld.%d ack hz=%u pk=%u rtt=%d j=%lu bw=%d rs=%d -> ", it, step, hz_g, sm.pkts_acked, sm.rtt_us, jiffies, use_bandwidth_switch, use_rtt_scaling); dump(&sk); printf("\n");
				if (rnd(6) == 0) sk.tp.snd_cwnd = 1 + rnd(rnd(2) ? 100 : 6000);
			} else if (op < 14) {
				u32 acked = rnd(6) == 0 ? rnd(100000) : rnd(5);
				if (rnd(6) == 0) sk.tp.snd_cwnd_cnt = rnd(rnd(2) ? 100 : 100000);
				if (rnd(10) == 0) sk.tp.snd_ssthresh = rnd(2) ? sk.tp.snd_cwnd + 1 : rnd(200);
				if (rnd(5) == 0) jiffies += rnd(20 * hz_g);
				htcp_cong_avoid(&sk, 0, acked);
				printf("%ld.%d avoid acked=%u lim=%d j=%lu -> ", it, step, acked, cwnd_limited, jiffies); dump(&sk); printf("\n");
			} else if (op < 16) {
				u32 r;
				if (rnd(3) == 0) sk.ca.maxB = rnd64() >> rnd(32);
				if (rnd(3) == 0) sk.ca.old_maxB = sk.ca.maxB + (rnd(2) ? rnd(sk.ca.maxB / 4 + 1) : -rnd(sk.ca.maxB / 5 + 1));
				if (rnd(3) == 0) sk.ca.modeswitch = rnd(2);
				if (rnd(4) == 0) sk.ca.maxRTT = sk.ca.minRTT + rnd(300);
				r = htcp_recalc_ssthresh(&sk); if (prove && pc++ == 3) r++;
				printf("%ld.%d ssthresh cwnd=%u j=%lu -> %u ", it, step, sk.tp.snd_cwnd, jiffies, r); dump(&sk); printf("\n");
				if (rnd(2)) sk.tp.snd_cwnd = r;
			} else if (op < 19) {
				u8 st = rnd(5);
				htcp_state(&sk, st);
				printf("%ld.%d state %u -> ", it, step, st); dump(&sk); printf("\n");
			} else {
				u32 r = htcp_cwnd_undo(&sk);
				printf("%ld.%d undo -> %u ", it, step, r); dump(&sk); printf("\n");
			}
		}
	}
	return 0;
}
