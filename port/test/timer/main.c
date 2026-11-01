/* timer differential: the pristine round_jiffies_common, calc_index and calc_wheel_index (ARM_REF: ref.c extracted from the pristine file) against timer_rs.rs plus the wrappers of
 * timer_glue.c (ARM_RS: ref.c extracted from the glue). HZ is a compile-time define (100, 250, 300, 1000: the build, as in the kernel; LVL_DEPTH follows). Random and edge arguments:
 * round_jiffies_common over every cpu, force_up, values around whole seconds, the quarter-second cut-off, jiffies wrap-around and an expiry already past; calc_wheel_index over deltas at
 * every level boundary +-1, negative deltas, the wheel cut-off and its neighbours, and wrapping clocks. Prints every result and the bucket expiry.   usage: t SHARD (env TW_N, TW_PROVE) */
#include "refshim.h"
unsigned long jiffies;
#include SRCFILE
static unsigned long long rs_;
static unsigned long long rnd64(void) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return rs_ >> 11 ^ (rs_ << 53); }
static unsigned rnd(unsigned n) { return n ? (unsigned)(rnd64() % n) : 0; }
static unsigned long edge(void)
{
	switch (rnd(8)) {
	case 0: return 0; case 1: return ~0UL - rnd(5); case 2: return (unsigned long)rnd64(); case 3: return (unsigned long)(rnd64() >> rnd(60)); case 4: return 1UL << rnd(64);
	case 5: return (1UL << (1 + rnd(63))) - 1 + rnd(3) - 1; case 6: return (unsigned long)HZ * rnd(100000) + rnd(3) - 1; default: return (unsigned long)(HZ / 4) + (unsigned long)HZ * rnd(1000) + rnd(3) - 1;
	}
}
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0; long n = getenv("TW_N") ? atol(getenv("TW_N")) : 400000; int prove = getenv("TW_PROVE") != NULL; long i; static int pc;
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (i = 0; i < n; i++) {
		if (rnd(2)) {
			unsigned long j = edge(), r; int cpu = rnd(3) ? rnd(8) : rnd(512); bool up = rnd(2); if (rnd(8) == 0) cpu = -(int)rnd(1000);
			jiffies = rnd(4) ? j - (unsigned long)rnd(3 * HZ) + (rnd(2) ? 0UL : (unsigned long)HZ) : edge();
			if (rnd(4) == 0) jiffies = j - rnd(5);
			r = round_jiffies_common(j, cpu, up); if (prove && pc++ == 3) r++;
			printf("%ld R j=%lu cpu=%d up=%d jf=%lu -> %lu\n", i, j, cpu, up, jiffies, r);
		} else {
			unsigned long clk = edge(), delta, expires, be = 0xdeadbeef, ex; int idx; int lv = 1 + rnd(9);
			switch (rnd(5)) {
			case 0: delta = ((63UL) << ((lv - 1) * 3)) + rnd(5) - 2; break;
			case 1: delta = (unsigned long)rnd64() >> rnd(64); break;
			case 2: delta = (63UL << (8 * 3)) + rnd(5) - 2 - (rnd(2) ? (1UL << 24) : 0); break;
			case 3: delta = -(unsigned long)(rnd64() >> rnd(64)); break;
			default: delta = rnd(100000); break;
			}
			expires = clk + delta; ex = expires;
			idx = calc_wheel_index(expires, clk, &be); if (prove && pc++ == 3) be++;
			printf("%ld W clk=%lu exp=%lu -> %d %lu\n", i, clk, ex, idx, be);
		}
	}
	return 0;
}
