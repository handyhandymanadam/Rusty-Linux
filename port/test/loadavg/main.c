/* loadavg differential: the pristine fixed_power_int() / calc_load_n() (ARM_REF) against loadavg_rs.rs (ARM_RS). The three real decay factors and random ones, powers 0..70 and large, loads and active
 * counts from 0 to well past what the kernel stores, plus the full 64-bit range.   usage: t SHARD (env EB_N, EB_PROVE) */
#include "refshim.h"
#include SRCFILE
static unsigned long long rs_;
static unsigned long long rnd64(void) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return (rs_ >> 11) ^ (rs_ << 53); }
static unsigned rnd(unsigned n) { return n ? (unsigned)(rnd64() % n) : 0; }
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0, prove = getenv("EB_PROVE") != NULL; long n = getenv("EB_N") ? atol(getenv("EB_N")) : 400000, it, pc = 0;
	static const unsigned long exps[] = { 1884, 2014, 2037, 0, 1, 2047, 2048 };
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (it = 0; it < n; it++) {
		unsigned long exp = rnd(4) ? exps[rnd(7)] : rnd(3) ? rnd(2049) : (unsigned long)rnd64() >> rnd(60), load = rnd(3) ? rnd(40 * 2048) : rnd(5) ? (unsigned long)rnd64() >> rnd(64) : 0, active = rnd(3) ? rnd(40 * 2048) : (unsigned long)rnd64() >> rnd(64);
		unsigned int nn = rnd(3) ? rnd(75) : rnd(4) ? rnd(1000000) : (unsigned)rnd64(); unsigned long r;
		r = calc_load_n(load, exp, active, nn); if (prove && pc++ == 3) r++;
		printf("%ld exp=%lu load=%lu active=%lu n=%u -> %lu\n", it, exp, load, active, nn, r);
	}
	return 0;
}
