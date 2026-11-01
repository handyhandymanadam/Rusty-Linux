/* tcp_bic differential: the pristine bictcp_update(), the window arithmetic of bictcp_recalc_ssthresh() and the delayed-ACK update of bictcp_acked() (ARM_REF) against tcp_bic_rs.rs through the
 * glue's wrappers (ARM_RS). Simulated congestion-avoidance runs: windows from 1 to millions of packets (below and above low_window), last maxima around the window (inside the binary
 * search range, within B, within max_increment * 3, far above, zero), jiffies advancing in uneven steps, a clock that goes backwards, window reductions with fast convergence on and off,
 * delayed-ACK samples, and parameter sets from the defaults to extremes (including negative values, which C converts to unsigned).   usage: t SHARD (env EB_N, EB_PROVE) */
#include "refshim.h"
unsigned int hz_g; u32 tj;
#include SRCFILE
static unsigned long long rs_;
static unsigned long long rnd64(void) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return (rs_ >> 11) ^ (rs_ << 53); }
static unsigned rnd(unsigned n) { return n ? (unsigned)(rnd64() % n) : 0; }
static void dump(const struct bictcp *ca) { printf("cnt=%u lmax=%u lcwnd=%u ltime=%u epoch=%u da=%u", ca->cnt, ca->last_max_cwnd, ca->last_cwnd, ca->last_time, ca->epoch_start, ca->delayed_ack); }
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0, prove = getenv("EB_PROVE") != NULL; long n = getenv("EB_N") ? atol(getenv("EB_N")) : 20000, it, pc = 0;
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (it = 0; it < n; it++) {
		static const unsigned hzs[] = { 100, 250, 300, 1000 }; struct bictcp ca; int step, steps = 10 + rnd(60); u32 cwnd = 1 + rnd(rnd(4) ? 400 : 3000000);
		hz_g = hzs[rnd(4)];
		fast_convergence = rnd(4) != 0; low_window = rnd(5) ? 14 : (rnd(6) == 0 ? -1 - (int)rnd(10) : rnd(100)); beta = rnd(4) ? 819 : (rnd(8) == 0 ? -(int)rnd(2000) : (int)rnd(2000));
		max_increment = rnd(4) ? 16 : 1 + rnd(200); smooth_part = rnd(4) ? 20 : (rnd(8) == 0 ? -(int)rnd(40) : (int)rnd(100));
		if (rnd(40) == 0) max_increment = 0x70000000 + rnd(0x8000000);	/* max_increment * 3 overflows int */
		memset(&ca, 0, sizeof ca); ca.delayed_ack = 2 << ACK_RATIO_SHIFT; tj = rnd(4) == 0 ? 0xffffff00u + rnd(200) : (u32)rnd64() >> rnd(32);
		if (rnd(2)) ca.last_max_cwnd = rnd(3) == 0 ? rnd(cwnd + 1) : cwnd + rnd(rnd(2) ? 8 : cwnd + 1);
		if (rnd(3) == 0) ca.last_max_cwnd = cwnd + (rnd(2) ? 3 : 4) * (u32)(max_increment > 0 ? max_increment : 1) + rnd(3) - 1;
		for (step = 0; step < steps; step++) {
			int op = rnd(10);
			if (cwnd < 1) cwnd = 1;
			if (op < 6) {
				tj += rnd(4) == 0 ? 0 : rnd(hz_g / 5 + 2);
				if (rnd(50) == 0) tj -= 1 + rnd(hz_g / 10 + 2);
				if (rnd(40) == 0) ca.last_max_cwnd = cwnd + rnd(4) * rnd(40);
				bic_update(&ca, cwnd);
				printf("%ld.%d upd hz=%u cwnd=%u tj=%u low=%d maxinc=%d smooth=%d -> ", it, step, hz_g, cwnd, tj, low_window, max_increment, smooth_part); dump(&ca); printf("\n");
				cwnd += (ca.cnt ? 1 + rnd(8) / ca.cnt : 0) + rnd(3); if (rnd(8) == 0) cwnd += rnd(cwnd / 4 + 1); if (cwnd > 20000000) cwnd = 20000000;
			} else if (op < 8) {
				u32 r = bic_ssthresh(&ca, cwnd); if (prove && pc++ == 3) r++;
				printf("%ld.%d ssthresh cwnd=%u fc=%d beta=%d low=%d -> %u ", it, step, cwnd, fast_convergence, beta, low_window, r); dump(&ca); printf("\n");
				cwnd = r > 1 ? r : 2;
			} else {
				u32 pk = rnd(4) == 0 ? rnd(100) : 1 + rnd(3);
				bic_acked(&ca, pk);
				printf("%ld.%d acked pk=%u -> ", it, step, pk); dump(&ca); printf("\n");
				if (rnd(30) == 0) ca.delayed_ack = rnd(3) ? rnd(40) + 1 : rnd64();
			}
		}
	}
	return 0;
}
