/* SPDX-License-Identifier: GPL-2.0 */
/* Differential for the kernel/time/time.c conversions at ONE CONFIG_HZ (the binary is built per HZ): pristine C (c_*), using
 * the REAL jiffies.h macros and the REAL generated timeconst.h for that HZ, against time_rs.rs. Edge values + random 64-bit
 * inputs for all 17 functions; struct results compared whole. usage: main SHARD ; TIME_PROVE_CAN_FAIL=1 breaks the Rust arm. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
typedef int64_t time64_t;
struct timespec64 { time64_t tv_sec; long tv_nsec; };
struct kot { long tv_sec; long tv_usec; };
#define F1(r, n, a) r c_##n(a), n(a);
unsigned c_jiffies_to_msecs(unsigned long), jiffies_to_msecs(unsigned long);
unsigned c_jiffies_to_usecs(unsigned long), jiffies_to_usecs(unsigned long);
time64_t c_mktime64(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned), mktime64(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
struct kot c_ns_to_kernel_old_timeval(int64_t), ns_to_kernel_old_timeval(int64_t);
void c_set_normalized_timespec64(struct timespec64 *, time64_t, int64_t), set_normalized_timespec64(struct timespec64 *, time64_t, int64_t);
struct timespec64 c_ns_to_timespec64(int64_t), ns_to_timespec64(int64_t);
unsigned long c___msecs_to_jiffies(unsigned), __msecs_to_jiffies(unsigned);
unsigned long c___usecs_to_jiffies(unsigned), __usecs_to_jiffies(unsigned);
unsigned long c_timespec64_to_jiffies(const struct timespec64 *), timespec64_to_jiffies(const struct timespec64 *);
void c_jiffies_to_timespec64(unsigned long, struct timespec64 *), jiffies_to_timespec64(unsigned long, struct timespec64 *);
long c_jiffies_to_clock_t(unsigned long), jiffies_to_clock_t(unsigned long);
unsigned long c_clock_t_to_jiffies(unsigned long), clock_t_to_jiffies(unsigned long);
uint64_t c_jiffies64_to_nsecs(uint64_t), jiffies64_to_nsecs(uint64_t);
uint64_t c_jiffies64_to_msecs(uint64_t), jiffies64_to_msecs(uint64_t);
uint64_t c_nsecs_to_jiffies64(uint64_t), nsecs_to_jiffies64(uint64_t);
unsigned long c_nsecs_to_jiffies(uint64_t), nsecs_to_jiffies(uint64_t);
struct timespec64 c_timespec64_add_safe(struct timespec64, struct timespec64), timespec64_add_safe(struct timespec64, struct timespec64);

static int poison; static unsigned long long fails, checks;
#define FAIL(...) do { if (fails++ < 10) fprintf(stderr, __VA_ARGS__); } while (0)
static uint64_t rs;
static uint64_t rnd(void) { uint64_t z = (rs += 0x9e3779b97f4a7c15ULL); z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL; z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL; return z ^ (z >> 31); }
static uint64_t pick(void)      /* edge-heavy 64-bit value */
{
	static const uint64_t e[] = { 0, 1, 2, 9, 10, 99, 100, 249, 250, 251, 299, 300, 301, 999, 1000, 1001, 4294967295ULL, 4294967296ULL, 0x7fffffffULL, 0x80000000ULL,
		0x3fffffffffffffffULL, 0x4000000000000000ULL, 0x7ffffffffffffffeULL, 0x7fffffffffffffffULL, 0x8000000000000000ULL, ~0ULL, ~0ULL - 1, 1000000000ULL, 999999999ULL, 1000000001ULL };
	switch (rnd() % 6) {
	case 0: return e[rnd() % (sizeof e / sizeof *e)];
	case 1: return rnd() % 2000;
	case 2: return rnd() % 4000000000ULL;
	case 3: return rnd() >> (rnd() % 64);
	case 4: return e[rnd() % (sizeof e / sizeof *e)] + (rnd() % 5) - 2;
	default: return rnd();
	}
}
#define CMP(what, x, y, ...) do { checks++; if ((x) != (y)) FAIL("MISMATCH " what " " __VA_ARGS__ " c=%lld rs=%lld\n", (long long)(x), (long long)(y)); } while (0)
static void cmpts(const char *w, struct timespec64 a, struct timespec64 b) { checks++; if (a.tv_sec != b.tv_sec || a.tv_nsec != b.tv_nsec) FAIL("MISMATCH %s c=%lld.%ld rs=%lld.%ld\n", w, (long long)a.tv_sec, a.tv_nsec, (long long)b.tv_sec, b.tv_nsec); }
int main(int argc, char **argv)
{
	unsigned shard = argc > 1 ? atoi(argv[1]) : 0;
	long long n = getenv("TIME_N") ? atoll(getenv("TIME_N")) : 20000000LL;
	poison = getenv("TIME_PROVE_CAN_FAIL") != 0;
	rs = 0x1234567ULL * (shard + 1);
	for (long long it = 0; it < n; it++) {
		uint64_t v = pick(), w = pick();
		unsigned long x = v;
		unsigned u = (unsigned)pick();
		long long vv = (long long)v;
		unsigned a = c_jiffies_to_msecs(x), b = jiffies_to_msecs(x);
		if (poison && v == 7) b++;
		CMP("jiffies_to_msecs", a, b, "");
		CMP("jiffies_to_usecs", c_jiffies_to_usecs(x), jiffies_to_usecs(x));
		unsigned yr = (unsigned)(rnd() % 10000), mo = (unsigned)(rnd() % 16), dy = (unsigned)(rnd() % 40), hr = (unsigned)(rnd() % 30), mi = (unsigned)(rnd() % 70), se = (unsigned)(rnd() % 70);
		if (rnd() % 20 == 0) { yr = (unsigned)pick(); mo = (unsigned)pick(); dy = (unsigned)pick(); hr = (unsigned)pick(); mi = (unsigned)pick(); se = (unsigned)pick(); }
		CMP("mktime64", c_mktime64(yr, mo, dy, hr, mi, se), mktime64(yr, mo, dy, hr, mi, se));
		struct kot k1 = c_ns_to_kernel_old_timeval(vv), k2 = ns_to_kernel_old_timeval(vv);
		checks++; if (k1.tv_sec != k2.tv_sec || k1.tv_usec != k2.tv_usec) FAIL("MISMATCH ns_to_kernel_old_timeval %lld\n", vv);
		cmpts("ns_to_timespec64", c_ns_to_timespec64(vv), ns_to_timespec64(vv));
		struct timespec64 t1, t2;
		int64_t nn = (int64_t)(rnd() % 8 == 0 ? pick() : (rnd() % 20000000000ULL) - 10000000000LL);
		c_set_normalized_timespec64(&t1, vv, nn % 100000000000000LL); set_normalized_timespec64(&t2, vv, nn % 100000000000000LL);
		cmpts("set_normalized_timespec64", t1, t2);
		CMP("__msecs_to_jiffies", c___msecs_to_jiffies(u), __msecs_to_jiffies(u));
		CMP("__usecs_to_jiffies", c___usecs_to_jiffies(u), __usecs_to_jiffies(u));
		struct timespec64 in = { (time64_t)v, (long)(rnd() % 4 ? rnd() % 1000000000UL : pick()) };
		CMP("timespec64_to_jiffies", c_timespec64_to_jiffies(&in), timespec64_to_jiffies(&in), "");
		c_jiffies_to_timespec64(x, &t1); jiffies_to_timespec64(x, &t2); cmpts("jiffies_to_timespec64", t1, t2);
		CMP("jiffies_to_clock_t", c_jiffies_to_clock_t(x), jiffies_to_clock_t(x));
		CMP("clock_t_to_jiffies", c_clock_t_to_jiffies(x), clock_t_to_jiffies(x));
		CMP("jiffies64_to_nsecs", c_jiffies64_to_nsecs(v), jiffies64_to_nsecs(v));
		CMP("jiffies64_to_msecs", c_jiffies64_to_msecs(v), jiffies64_to_msecs(v));
		CMP("nsecs_to_jiffies64", c_nsecs_to_jiffies64(v), nsecs_to_jiffies64(v));
		CMP("nsecs_to_jiffies", c_nsecs_to_jiffies(w), nsecs_to_jiffies(w));
		struct timespec64 l = { (time64_t)v, (long)(rnd() % 1500000000UL) }, r = { (time64_t)w, (long)(rnd() % 1500000000UL) };
		cmpts("timespec64_add_safe", c_timespec64_add_safe(l, r), timespec64_add_safe(l, r));
	}
	printf("shard %u: %llu checks, %llu failures\n", shard, checks, fails);
	return fails != 0;
}
