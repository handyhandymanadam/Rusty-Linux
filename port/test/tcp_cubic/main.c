/* tcp_cubic differential: the pristine cubic_root() and bictcp_update() (ARM_REF) against tcp_cubic_rs.rs through the glue's wrappers (ARM_RS). cubic_root on values of every bit width and every
 * 6-bit pattern near the table edges; bictcp_update over simulated congestion-avoidance runs: windows from 8 to millions of packets, ACK batches, jiffies advancing in uneven steps (so the
 * once-per-jiffy and 1/32 s shortcuts happen), window reductions (epoch reset, last_max_cwnd set or zero), idle shifts, the standard parameter set and others, HZ of 100, 250, 300 and 1000,
 * friendliness on and off.   usage: t SHARD (env EB_N, EB_PROVE) */
#include "refshim.h"
unsigned int hz_g; u32 tj, cube_rtt_scale, beta_scale; u64 cube_factor; int tcp_friendliness;
#include SRCFILE
static unsigned long long rs_;
static unsigned long long rnd64(void) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return (rs_ >> 11) ^ (rs_ << 53); }
static unsigned rnd(unsigned n) { return n ? (unsigned)(rnd64() % n) : 0; }
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0, prove = getenv("EB_PROVE") != NULL; long n = getenv("EB_N") ? atol(getenv("EB_N")) : 4000, it, pc = 0; int i;
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (it = 0; it < n * 40; it++) {
		u64 a; unsigned w = 1 + rnd(64);
		a = rnd64() >> (64 - w); if (rnd(4) == 0) a = (u64)1 << rnd(64); if (rnd(6) == 0) a += rnd(5) - 2;
		{ u32 r = cubic_root(a); if (prove && pc++ == 3) r++; printf("root %llu -> %u\n", (unsigned long long)a, r); }
	}
	for (it = 0; it < n; it++) {
		static const unsigned hzs[] = { 100, 250, 300, 1000 }; int beta = rnd(3) ? 717 : 100 + rnd(900), bic_scale = rnd(3) ? 41 : 1 + rnd(200); struct bictcp ca; int step, steps = 20 + rnd(60); u32 cwnd = 8 + rnd(rnd(4) ? 400 : 3000000);
		hz_g = hzs[rnd(4)]; tcp_friendliness = rnd(5) != 0;
		beta_scale = 8 * (1024 + beta) / 3 / (1024 - beta); cube_rtt_scale = bic_scale * 10; cube_factor = 1ull << (10 + 3 * BICTCP_HZ); cube_factor /= bic_scale * 10;
		memset(&ca, 0, sizeof ca); tj = rnd(4) == 0 ? 0xffffff00u + rnd(200) : (u32)rnd64() >> rnd(32);
		if (rnd(2)) { ca.last_max_cwnd = rnd(2) ? cwnd + rnd(cwnd) : rnd(cwnd + 1); }
		ca.delay_min = rnd(3) ? 0 : 1000 + rnd(200000);
		for (step = 0; step < steps; step++) {
			u32 acked = 1 + rnd(rnd(3) ? 8 : 100);
			tj += rnd(4) == 0 ? 0 : rnd(hz_g / 5 + 2);
			if (rnd(50) == 0) tj -= 1 + rnd(hz_g / 10 + 2);		/* a clock that went backwards: only the signed comparisons notice */
			if (rnd(60) == 0 && ca.epoch_start) ca.epoch_start = tj + 1 + rnd(100);	/* an epoch that has not started yet */
			if (rnd(40) == 0) { ca.epoch_start = 0; ca.last_max_cwnd = rnd(2) ? cwnd : cwnd - cwnd / 5 * 2; }
			if (rnd(60) == 0) { u32 d = rnd(hz_g * 3); ca.epoch_start += d; if (ca.epoch_start - tj < 0x80000000u && ca.epoch_start != tj) ca.epoch_start = tj; }
			if (rnd(30) == 0) ca.delay_min = rnd(3) ? ca.delay_min : 500 + rnd(500000);
			if (cwnd < 8) cwnd = 8;
			bictcp_update(&ca, cwnd, acked);
			printf("%ld.%d hz=%u cwnd=%u acked=%u tj=%u -> cnt=%u lmax=%u lcwnd=%u ltime=%u origin=%u K=%u dmin=%u epoch=%u ack=%u tcpcwnd=%u\n", it, step, hz_g, cwnd, acked, tj, ca.cnt, ca.last_max_cwnd,
			       ca.last_cwnd, ca.last_time, ca.bic_origin_point, ca.bic_K, ca.delay_min, ca.epoch_start, ca.ack_cnt, ca.tcp_cwnd);
			cwnd += (ca.cnt ? acked / ca.cnt : 0) + rnd(3); if (rnd(8) == 0) cwnd += rnd(cwnd / 4 + 1); if (cwnd > 20000000) cwnd = 20000000;
		}
	}
	return 0;
}
