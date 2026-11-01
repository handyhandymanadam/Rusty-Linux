/* SPDX-License-Identifier: GPL-2.0 */
/* Differential for kernel/time/timecounter.c: pristine C (c_*) vs timecounter_rs.rs. The cycle counter is a global the
 * test sets before every call to either arm. Whole struct timecounter compared after every call, plus return values.
 * usage: main SHARD ; TC_PROVE_CAN_FAIL=1 breaks the Rust arm. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
typedef uint64_t u64; typedef uint32_t u32; typedef int64_t s64;
struct cyclecounter { u64 (*read)(struct cyclecounter *cc); u64 mask; u32 mult; u32 shift; };
struct timecounter { struct cyclecounter *cc; u64 cycle_last; u64 nsec; u64 mask; u64 frac; };
void c_timecounter_init(struct timecounter *, struct cyclecounter *, u64);
u64 c_timecounter_read(struct timecounter *);
u64 c_timecounter_cyc2time(const struct timecounter *, u64);
void timecounter_init(struct timecounter *, struct cyclecounter *, u64);
u64 timecounter_read(struct timecounter *);
u64 timecounter_cyc2time(const struct timecounter *, u64);

static u64 cur; static int poison; static unsigned long long fails, checks;
#define FAIL(...) do { if (fails++ < 10) fprintf(stderr, __VA_ARGS__); } while (0)
static u64 rd(struct cyclecounter *cc) { (void)cc; return cur; }
static uint64_t rs;
static uint64_t rnd(void) { uint64_t z = (rs += 0x9e3779b97f4a7c15ULL); z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL; z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL; return z ^ (z >> 31); }
static u64 maskof(void) { switch (rnd() % 4) { case 0: return ~0ULL; case 1: return (1ULL << (rnd() % 63)) - 1; case 2: return (1ULL << 48) - 1; default: return rnd() | 1; } }
#define CHK(what, x, y) do { checks++; if ((x) != (y)) FAIL("MISMATCH %s: c=%llx rs=%llx\n", what, (unsigned long long)(x), (unsigned long long)(y)); } while (0)
int main(int argc, char **argv)
{
	unsigned shard = argc > 1 ? atoi(argv[1]) : 0;
	long long n = getenv("TC_N") ? atoll(getenv("TC_N")) : 5000000LL;
	poison = getenv("TC_PROVE_CAN_FAIL") != 0;
	rs = 0x1234567ULL * (shard + 1);
	for (long long it = 0; it < n; it++) {
		struct cyclecounter ca = { rd, maskof(), (u32)rnd(), (u32)(rnd() % 64) }, cb;
		if (rnd() % 3 == 0) ca.mult = rnd() % 5000;
		cb = ca;
		struct timecounter a, b;
		memset(&a, 0xA5, sizeof a); memset(&b, 0xA5, sizeof b);
		u64 start = rnd(), v = rnd();
		cur = v; c_timecounter_init(&a, &ca, start);
		cur = v; timecounter_init(&b, &cb, start);
		a.cc = b.cc = 0;               /* pointers differ by design: compare the rest */
		a.cc = &ca; b.cc = &cb;
		if (memcmp(&a.cycle_last, &b.cycle_last, sizeof a - sizeof a.cc)) FAIL("init MISMATCH\n");
		checks++;
		for (int k = 0; k < 8; k++) {
			switch (rnd() % 3) {
			case 0: v += (rnd() % 2) ? rnd() % 100000 : rnd(); break;
			case 1: v -= rnd() % 1000; break;
			default: v = rnd(); break;
			}
			if (rnd() % 2) {
				cur = v; u64 ra = c_timecounter_read(&a);
				cur = v; u64 rb = timecounter_read(&b);
				if (poison && k == 3) rb++;
				CHK("read", ra, rb);
			} else {
				u64 t = (rnd() % 2) ? v + rnd() % 1000 : rnd();
				u64 ra = c_timecounter_cyc2time(&a, t), rb = timecounter_cyc2time(&b, t);
				CHK("cyc2time", ra, rb);
			}
			if (memcmp(&a.cycle_last, &b.cycle_last, sizeof a - sizeof a.cc)) FAIL("state MISMATCH after step %d\n", k);
			checks++;
		}
	}
	printf("shard %u: %llu checks, %llu failures\n", shard, checks, fails);
	return fails != 0;
}
