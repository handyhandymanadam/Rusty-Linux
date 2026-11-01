/* PELT differential: the pristine decay / accumulate / ___update_load_sum / ___update_load_avg (ARM_REF) against pelt_rs.rs through the glue's wrappers (ARM_RS). Random sched_avg states (sums
 * up to their maxima, period remainders 0..1023), update sequences with time steps from below one unit (1024 ns) to hundreds of periods (past the 63-half-life cutoff), loads of 0, 1, 1024 and
 * large, runnable and running flags in every combination, a clock that steps backwards, 32-bit sums at their limits.   usage: t SHARD (env EB_N, EB_PROVE) */
#include "refshim.h"
#include SRCFILE
static unsigned long long rs_;
static unsigned long long rnd64(void) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return (rs_ >> 11) ^ (rs_ << 53); }
static unsigned rnd(unsigned n) { return n ? (unsigned)(rnd64() % n) : 0; }
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0, prove = getenv("EB_PROVE") != NULL; long n = getenv("EB_N") ? atol(getenv("EB_N")) : 30000, it, pc = 0; int step;
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (it = 0; it < n; it++) {
		struct sched_avg sa; u64 now; int steps = 3 + rnd(25);
		memset(&sa, 0, sizeof sa);
		now = rnd(4) == 0 ? rnd64() >> rnd(20) : (u64)rnd(1u << 30) << 10;
		sa.last_update_time = rnd(8) == 0 ? now - rnd(100000) : now;
		if (rnd(2)) { sa.load_sum = rnd64() % ((u64)LOAD_AVG_MAX << 20); sa.runnable_sum = rnd64() % ((u64)LOAD_AVG_MAX << 20); sa.util_sum = (u32)(rnd64() % ((u64)LOAD_AVG_MAX << 10)); sa.period_contrib = rnd(1024); }
		if (rnd(10) == 0) { sa.util_sum = ~0u - rnd(5); sa.load_sum = ~0ULL - rnd(5); sa.runnable_sum = ~0ULL - rnd(5); sa.period_contrib = 1023; }
		for (step = 0; step < steps; step++) {
			static const unsigned long loads[] = { 0, 1, 2, 15, 1024, 88761, 1 << 20 };
			unsigned long load = rnd(5) ? loads[rnd(7)] : rnd64() >> rnd(60), runnable = rnd(3) ? loads[rnd(7)] : rnd64() >> rnd(60); int running = rnd(2), r;
			u64 dt = rnd(6) == 0 ? rnd(1024) : rnd(4) == 0 ? (u64)rnd(300) << 10 << 10 : rnd(8) == 0 ? (u64)rnd(3000) << 20 : (u64)rnd(4000) << 10;
			now += dt; if (rnd(40) == 0) now -= rnd(1 << 20) + 1;
			r = ___update_load_sum(now, &sa, load, runnable, running); if (prove && pc++ == 3) r ^= 1;
			printf("%ld.%d load=%lu run=%lu running=%d now=%llu -> %d last=%llu lsum=%llu rsum=%llu usum=%u contrib=%u", it, step, load, runnable, running, (unsigned long long)now, r,
			       (unsigned long long)sa.last_update_time, (unsigned long long)sa.load_sum, (unsigned long long)sa.runnable_sum, sa.util_sum, sa.period_contrib);
			if (r) { ___update_load_avg(&sa, rnd(2) ? 1 : (rnd(2) ? load : 1024)); printf(" avg=%lu/%lu/%lu", sa.load_avg, sa.runnable_avg, sa.util_avg); }
			printf("\n");
		}
	}
	return 0;
}
