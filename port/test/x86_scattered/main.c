/* SPDX-License-Identifier: GPL-2.0 */
/* Differential for arch/x86/kernel/cpu/scattered.c: pristine C (c_init_scattered_cpuid_features) vs scattered_rs.rs, both against a
 * fake CPUID the harness answers (random per leaf/sub-leaf, with random maximum levels so the "level valid" test is exercised on
 * both sides). The cpuinfo_x86 is a 48-byte header + 24 capability words; every byte after the call is compared. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
struct ci { unsigned char hdr[48]; uint32_t cap[24 + 2]; };
void c_init_scattered_cpuid_features(struct ci *), init_scattered_cpuid_features(struct ci *);
static uint64_t rs, seed;
static uint64_t mix(uint64_t z) { z += 0x9e3779b97f4a7c15ULL; z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL; z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL; return z ^ (z >> 31); }
static uint64_t rnd(void) { return mix(rs += 0x9e3779b97f4a7c15ULL); }
static int mode;
void test_cpuid(uint32_t op, uint32_t count, uint32_t *o)
{
	uint32_t base = op & 0xffff0000;
	if (op == base) {                     /* the max-level query: leaf 0 of each range */
		static const uint32_t pick[] = { 0, 1, 5, 6, 7, 0xf, 0x10, 0x12, 0x13, 0x20, 0x7fffffff };
		uint32_t m = mix(seed ^ base) % 4 == 0 ? 0 : (uint32_t)(mix(seed * 3 + base) % 0x30);
		if (mode == 1) m = 0x30;
		o[0] = base + m + (mix(seed + base) % 7 == 0 ? 0xffff : 0); (void)pick;
		o[1] = (uint32_t)mix(seed + op + 1); o[2] = (uint32_t)mix(seed + op + 2); o[3] = (uint32_t)mix(seed + op + 3);
		return;
	}
	for (int i = 0; i < 4; i++) o[i] = (uint32_t)mix(seed ^ ((uint64_t)op << 20) ^ ((uint64_t)count << 8) ^ i);
	if (mode == 1) for (int i = 0; i < 4; i++) o[i] = ~0u;
	if (mode == 2) for (int i = 0; i < 4; i++) o[i] = 0;
}
int main(int argc, char **argv)
{
	unsigned shard = argc > 1 ? atoi(argv[1]) : 0;
	long long n = getenv("SC_N") ? atoll(getenv("SC_N")) : 2000000LL;
	int poison = getenv("SC_PROVE_CAN_FAIL") != 0;
	unsigned long long fails = 0, checks = 0;
	rs = 0x1234567ULL * (shard + 1);
	for (long long it = 0; it < n; it++) {
		seed = rnd(); mode = it % 5 == 0 ? 1 : it % 7 == 0 ? 2 : 0;
		struct ci a, b;
		for (int i = 0; i < (int)sizeof a; i++) ((unsigned char *)&a)[i] = ((unsigned char *)&b)[i] = rnd();
		if (it % 3 == 0) memset(a.cap, 0, sizeof a.cap), memset(b.cap, 0, sizeof b.cap);
		c_init_scattered_cpuid_features(&a); init_scattered_cpuid_features(&b);
		if (poison && it == 3) b.cap[2] ^= 1;
		checks++;
		if (memcmp(&a, &b, sizeof a)) { if (fails++ < 10) fprintf(stderr, "MISMATCH seed=%llx mode=%d\n", (unsigned long long)seed, mode); }
	}
	printf("shard %u: %llu checks, %llu failures\n", shard, checks, fails);
	return fails != 0;
}
