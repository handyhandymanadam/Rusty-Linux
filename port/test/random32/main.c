/* SPDX-License-Identifier: GPL-2.0 */
/* Differential for lib/random32.c (prandom_u32_state, prandom_bytes_state): pristine C (c_*) vs random32_rs.rs.
 * Random states (incl. all-zero and all-ones), runs of 1..20 steps, byte fills of 0..40 bytes at every alignment into
 * canary-padded buffers; every output, the final state and every buffer byte compared. usage: main SHARD */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
struct rnd_state { uint32_t s1, s2, s3, s4; };
uint32_t c_prandom_u32_state(struct rnd_state *), prandom_u32_state(struct rnd_state *);
void c_prandom_bytes_state(struct rnd_state *, void *, size_t), prandom_bytes_state(struct rnd_state *, void *, size_t);
static int poison; static unsigned long long fails, checks;
#define FAIL(...) do { if (fails++ < 10) fprintf(stderr, __VA_ARGS__); } while (0)
static uint64_t rs;
static uint64_t rnd(void) { uint64_t z = (rs += 0x9e3779b97f4a7c15ULL); z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL; z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL; return z ^ (z >> 31); }
int main(int argc, char **argv)
{
	unsigned shard = argc > 1 ? atoi(argv[1]) : 0;
	long long n = getenv("R32_N") ? atoll(getenv("R32_N")) : 20000000LL;
	poison = getenv("R32_PROVE_CAN_FAIL") != 0;
	rs = 0x1234567ULL * (shard + 1);
	for (long long it = 0; it < n; it++) {
		struct rnd_state a, b;
		switch (rnd() % 8) { case 0: memset(&a, 0, sizeof a); break; case 1: memset(&a, 0xff, sizeof a); break; default: a.s1 = rnd(); a.s2 = rnd(); a.s3 = rnd(); a.s4 = rnd(); }
		b = a;
		int steps = 1 + rnd() % 20;
		for (int i = 0; i < steps; i++) {
			uint32_t x = c_prandom_u32_state(&a), y = prandom_u32_state(&b);
			if (poison && it == 7 && i == 3) y ^= 1;
			checks++; if (x != y) FAIL("u32 MISMATCH step %d c=%08x rs=%08x\n", i, x, y);
		}
		checks++; if (memcmp(&a, &b, sizeof a)) FAIL("state MISMATCH\n");
		unsigned char ba[64 + 8], bb[64 + 8];
		memset(ba, 0xA5, sizeof ba); memset(bb, 0xA5, sizeof bb);
		size_t off = rnd() % 8, len = rnd() % 41;
		c_prandom_bytes_state(&a, ba + off, len); prandom_bytes_state(&b, bb + off, len);
		checks++; if (memcmp(ba, bb, sizeof ba) || memcmp(&a, &b, sizeof a)) FAIL("bytes MISMATCH off=%zu len=%zu\n", off, len);
	}
	printf("shard %u: %llu checks, %llu failures\n", shard, checks, fails);
	return fails != 0;
}
