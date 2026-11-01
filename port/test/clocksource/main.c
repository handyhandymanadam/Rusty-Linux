/* clocksource differential: the pristine conversion functions (ARM_REF: ref.c extracted from the pristine file) against clocksource_rs.rs plus the thunks and the
 * __clocksource_update_freq_scale glue (ARM_RS: ref.c extracted from clocksource_glue.c). Random and edge-valued arguments to clocks_calc_mult_shift, clocks_calc_max_nsecs (NULL
 * and non-NULL max_cyc) and __clocksource_update_freq_scale (frequency 0 and not, every scale, preset margins, WATCHDOG_MAX_SKEW values by shard, masks from 1 to 64 bits, large
 * mult values that force the halving loop). Prints every result, every clocksource field, the pr_info lines and the WARN count.   usage: t SHARD (env CS_N, CS_PROVE) */
#include "refshim.h"
long max_skew_usec = 125; int warns;
#include SRCFILE
static unsigned long long rs_;
static unsigned long long rnd64(void) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return rs_ >> 11; }
static unsigned rnd(unsigned n) { return n ? (unsigned)(rnd64() % n) : 0; }
static u32 rnd32(void) { return (u32)(rnd64() ^ (rnd64() << 21)); }
static u32 edge32(void)
{
	static const u32 e[] = { 1, 2, 3, 100, 1000, 32768, 1000000, 3579545, 24000000, 100000000, 1000000000, 2400000000u, 4294967295u, 4294967294u, 2147483648u, 2147483647u, 11, 12 };
	switch (rnd(4)) { case 0: return e[rnd(sizeof e / sizeof e[0])]; case 1: return rnd32(); case 2: return 1 + rnd(1u << (1 + rnd(31))); default: return (u32)(rnd64() >> (rnd(32))) | 1; }
}
static u64 mask64(void)
{
	switch (rnd(6)) { case 0: return ~0ULL; case 1: return (1ULL << (1 + rnd(63))) - 1; case 2: return 0xffffffffULL; case 3: return (1ULL << 48) - 1; case 4: return rnd64(); default: return (1ULL << (8 + rnd(56))) - 1; }
}
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0; long n = getenv("CS_N") ? atol(getenv("CS_N")) : 200000; int prove = getenv("CS_PROVE") != NULL; long i;
	static const long skews[] = { 125, 62, 1, 5000, 3000000 };
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1); max_skew_usec = skews[shard % 5];
	for (i = 0; i < n; i++) {
		int k = rnd(4);
		if (k == 0) {
			u32 mult = 0xdeadbeef, shift = 0xfeedface, from = edge32(), to = edge32(), maxsec = rnd(5) ? edge32() % 5000 : edge32(); if (rnd(8) == 0) maxsec = rnd(4) ? 0 : maxsec;
			clocks_calc_mult_shift(&mult, &shift, from, to, maxsec);
			{ static int pm; if (prove && pm++ == 3) mult++; }
			printf("%ld M %u %u %u -> %u %u\n", i, from, to, maxsec, mult, shift);
		} else if (k == 1) {
			u32 mult = edge32(), shift = rnd(64), maxadj = rnd(3) ? (u32)((u64)mult * 11 / 100) : (rnd(2) ? edge32() : 0); u64 mask = mask64(), mc = 0x1234, r; int nonnull = rnd(4) != 0;
			if (rnd(6) == 0) shift = rnd(34);
			if ((u32)(mult + maxadj) == 0) maxadj++;
			if ((u32)(mult + maxadj) == 0) continue;
			r = clocks_calc_max_nsecs(mult, shift, maxadj, mask, nonnull ? &mc : NULL);
			printf("%ld N %u %u %u %llx %d -> %llx %llx\n", i, mult, shift, maxadj, (unsigned long long)mask, nonnull, (unsigned long long)r, (unsigned long long)mc);
		} else {
			struct clocksource cs; u32 scale, freq; static const u32 scales[] = { 1, 1000, 1, 1, 1000000, 3, 7, 1 };
			cs.name = "tclk"; cs.mask = mask64(); cs.mult = rnd(2) ? 0 : edge32(); cs.shift = rnd(2) ? 0 : rnd(40); cs.maxadj = rnd32(); cs.max_idle_ns = rnd64(); cs.max_cycles = rnd64(); cs.max_raw_delta = rnd64();
			cs.uncertainty_margin = rnd(4) ? 0 : (rnd(2) ? rnd32() : rnd(2000000)); freq = rnd(6) == 0 ? 0 : edge32(); scale = rnd(8) == 0 ? 0 : scales[rnd(8)];
			if (k == 3) {   /* targeted: seconds-before-wrap at its thresholds, the margin around 2 * WATCHDOG_MAX_SKEW, a big frequency with a small mask */
				int mode = rnd(3); scale = scales[rnd(8)]; cs.uncertainty_margin = 0;
				if (mode == 0) {
					static const unsigned sect[] = { 0, 1, 2, 3, 599, 600, 601, 602, 1199, 1200 }; u64 fs; freq = edge32(); fs = (u64)freq * scale; cs.mask = (u64)sect[rnd(10)] * fs + rnd64() % fs;
					if (rnd(2) && cs.mask <= 0xffffffffULL) cs.mask += 0x100000000ULL;
				} else if (mode == 1) {
					long target = 2 * max_skew_usec * 1000 + (long)rnd(7) - 3; if (target < 1) target = 1; freq = (u32)((1000000000L / target) / scale); if (freq == 0) freq = 1;
					if (rnd(2)) freq += rnd(3) - 1; if (freq == 0) freq = 1;
				} else {
					freq = 2147483648u + rnd(2147483647u); cs.mask = rnd64() % ((u64)freq * scale + 1);
				}
			}
			if (freq != 0 && scale == 0) scale = 1;
			if (scale != 0 && freq != 0 && (u32)(scale * freq) == 0) scale = 1;
			if (freq != 0 && (cs.mask == 0)) cs.mask = 1;
			if (freq == 0 && cs.mult == 0) cs.mult = 1 + rnd(5);
			warns = 0;
			__clocksource_update_freq_scale(&cs, scale, freq);
			{ static int pu; if (prove && pu++ == 3) cs.maxadj++; }
			printf("%ld U s=%u f=%u skew=%ld -> mult=%u shift=%u maxadj=%u um=%u idle=%llu cyc=%llx raw=%llx mask=%llx warns=%d\n", i, scale, freq, max_skew_usec, cs.mult, cs.shift, cs.maxadj, cs.uncertainty_margin,
			       (unsigned long long)cs.max_idle_ns, (unsigned long long)cs.max_cycles, (unsigned long long)cs.max_raw_delta, (unsigned long long)cs.mask, warns);
		}
	}
	return 0;
}
