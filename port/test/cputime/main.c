/* cputime_adjust differential: the pristine tick-based cputime_adjust() (ARM_REF) against cputime_rs.rs through the glue (ARM_RS). Sequences of samples with a growing runtime and random
 * user / system splits (including zeros, huge values near 2^63, a runtime that goes backwards, equal to or below the previous sum), checking after every call the split returned and the
 * stored previous split.   usage: t SHARD (env EB_N, EB_PROVE) */
#include "refshim.h"
#include SRCFILE
static unsigned long long rs_;
static unsigned long long rnd64(void) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return (rs_ >> 11) ^ (rs_ << 53); }
static unsigned rnd(unsigned n) { return n ? (unsigned)(rnd64() % n) : 0; }
static u64 big(void) { int k = rnd(6); return k == 0 ? 0 : k == 1 ? rnd(10) : k == 2 ? rnd(1000000) : k == 3 ? rnd64() >> rnd(64) : k == 4 ? ((u64)1 << 62) + rnd(1000) : rnd64() >> 1; }
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0, prove = getenv("EB_PROVE") != NULL; long n = getenv("EB_N") ? atol(getenv("EB_N")) : 30000, it, pc = 0; int step;
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (it = 0; it < n; it++) {
		struct prev_cputime prev = { 0, 0, 0 }; u64 rtime = rnd(3) ? 0 : big() >> 2; int steps = 2 + rnd(20);
		if (rnd(2)) { prev.stime = big() >> 3; prev.utime = big() >> 3; }
		for (step = 0; step < steps; step++) {
			struct task_cputime cur; u64 ut = 7, st = 9;
			rtime += rnd(3) ? big() >> 4 : 0; if (rnd(12) == 0) rtime -= rnd(1000);
			cur.sum_exec_runtime = rtime; cur.stime = rnd(5) == 0 ? 0 : rnd(3) ? big() >> 2 : big(); cur.utime = rnd(5) == 0 ? 0 : rnd(3) ? big() >> 2 : big();
			if (rnd(6) == 0) { cur.stime = rnd(100); cur.utime = rnd(100); }
			cputime_adjust(&cur, &prev, &ut, &st); if (prove && pc++ == 3) ut++;
			printf("%ld.%d rtime=%llu cur=%llu/%llu -> ut=%llu st=%llu prev=%llu/%llu lock=%d\n", it, step, (unsigned long long)rtime, (unsigned long long)cur.utime, (unsigned long long)cur.stime,
			       (unsigned long long)ut, (unsigned long long)st, (unsigned long long)prev.utime, (unsigned long long)prev.stime, prev.lock);
		}
	}
	return 0;
}
