/* SPDX-License-Identifier: GPL-2.0 */
/* Differential for kernel/time/timeconv.c: pristine C (c_time64_to_tm) vs timeconv_rs.rs, whole struct tm compared
 * (padding poisoned identically). Exhaustive: every day -80M..+80M (~+-220,000 years) x 4 times-of-day x 5 offsets;
 * random: 2^64 values of totalsecs x full-range int offsets, and values around every year/month boundary.
 * usage: main SHARD NSHARDS ; TIMECONV_PROVE_CAN_FAIL=1 breaks the Rust arm. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
struct tm { int tm_sec, tm_min, tm_hour, tm_mday, tm_mon; long tm_year; int tm_wday, tm_yday; };
void c_time64_to_tm(int64_t, int, struct tm *);
void time64_to_tm(int64_t, int, struct tm *);
static unsigned long long fails, checks; static int poison;
#define FAIL(...) do { if (fails++ < 10) fprintf(stderr, __VA_ARGS__); } while (0)
static uint64_t rs;
static uint64_t rnd(void) { uint64_t z = (rs += 0x9e3779b97f4a7c15ULL); z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL; z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL; return z ^ (z >> 31); }
static void t(int64_t secs, int off)
{
	struct tm a, b;
	memset(&a, 0xA5, sizeof a); memset(&b, 0xA5, sizeof b);
	c_time64_to_tm(secs, off, &a); time64_to_tm(secs, off, &b);
	if (poison && secs == 86400 * 365) b.tm_mday++;
	checks++;
	if (memcmp(&a, &b, sizeof a))
		FAIL("MISMATCH secs=%lld off=%d c=%ld-%d-%d %d:%d:%d wd%d yd%d rs=%ld-%d-%d %d:%d:%d wd%d yd%d\n", (long long)secs, off,
		     a.tm_year, a.tm_mon, a.tm_mday, a.tm_hour, a.tm_min, a.tm_sec, a.tm_wday, a.tm_yday,
		     b.tm_year, b.tm_mon, b.tm_mday, b.tm_hour, b.tm_min, b.tm_sec, b.tm_wday, b.tm_yday);
}
int main(int argc, char **argv)
{
	unsigned shard = argc > 1 ? atoi(argv[1]) : 0, nsh = argc > 2 ? atoi(argv[2]) : 1;
	poison = getenv("TIMECONV_PROVE_CAN_FAIL") != 0;
	long long nrand = getenv("TIMECONV_NRAND") ? atoll(getenv("TIMECONV_NRAND")) : 200000000LL;
	long long lim = getenv("TIMECONV_DAYS") ? atoll(getenv("TIMECONV_DAYS")) : 80000000LL;
	static const int offs[] = { 0, 1, -1, 86399, -86399 };
	static const int64_t tod[] = { 0, 1, 43200, 86399 };
	for (long long d = -lim + shard; d <= lim; d += nsh)
		for (int i = 0; i < 4; i++) for (int j = 0; j < 5; j++) t(d * 86400 + tod[i], offs[j]);
	rs = 0x1234567ULL * (shard + 1);
	for (long long i = 0; i < nrand; i++) {
		int64_t s = (int64_t)rnd();
		int off = (int)rnd();
		switch (rnd() % 4) {
		case 0: break;
		case 1: s = (int64_t)(rnd() % (1ULL << 40)) - (1LL << 39); break;
		case 2: s = ((int64_t)(rnd() % 40000) - 20000) * 86400 * 366 + (int64_t)(rnd() % 3) * 86400 * 28; off = (int)(rnd() % 400000) - 200000; break;
		default: s = (rnd() & 1) ? INT64_MAX - (int64_t)(rnd() % 100000) : INT64_MIN + (int64_t)(rnd() % 100000); break;
		}
		t(s, off);
	}
	printf("shard %u/%u: %llu checks, %llu failures\n", shard, nsh, checks, fails);
	return fails != 0;
}
