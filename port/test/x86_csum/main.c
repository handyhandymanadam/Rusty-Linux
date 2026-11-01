/* SPDX-License-Identifier: GPL-2.0 */
/* Differential for arch/x86/lib/csum-partial_64.c: csum_partial and
 * ip_compute_csum, pristine C (renamed c_*) against the Rust (csum_partial_rs.rs),
 * and both against an INDEPENDENT RFC 1071 implementation written from the RFC's
 * description (16-bit little-endian words, wide accumulator, fold) sharing no
 * expression with either arm.
 *
 * Comparisons:
 *   csum_partial   C == Rust   BIT-IDENTICAL on the raw 32-bit value (the C's carry order is
 *                              part of the contract: a caller can store the raw value);
 *                  Rust == RFC 1071 as ones' complement numbers (value mod 65535: 0 and 0xffff
 *                              are both "zero"; the RFC does not say which one a sum produces).
 *   ip_compute_csum C == Rust bit-identical; == ~RFC 1071 as ones' complement numbers.
 *
 * Memory: every buffer is placed either flush against a PROT_NONE page (end) so one byte read
 * past the end is a SIGSEGV for the Rust arm (the C arm's 8-byte tail load is the shim's
 * page-crossing-safe load_unaligned_zeropad), or at alignment 0..63 inside the arena.
 *
 * usage: main sweep SHARD NSHARDS | main bench      CSUM_PROVE_CAN_FAIL=1 poisons one Rust result
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/mman.h>

typedef uint32_t u32; typedef uint16_t u16; typedef uint8_t u8; typedef uint64_t u64;
u32 c_csum_partial(const void *, int, u32);
u16 c_ip_compute_csum(const void *, int);
u32 csum_partial(const void *, int, u32);
u16 ip_compute_csum(const void *, int);

/* independent oracle: RFC 1071 section 4.1 style, 16-bit LE words, wide accumulator, fold. */
static u32 rfc1071(const u8 *p, int len, u32 init)
{
	u64 acc = (u64)(init & 0xffff) + (init >> 16);
	int i;
	for (i = 0; i + 1 < len; i += 2)
		acc += (u64)p[i] | ((u64)p[i + 1] << 8);
	if (len & 1)
		acc += p[len - 1];
	while (acc >> 16)
		acc = (acc & 0xffff) + (acc >> 16);
	return (u32)acc;           /* 0..0xffff */
}
static u32 fold16(u32 x) { x = (x & 0xffff) + (x >> 16); x = (x & 0xffff) + (x >> 16); return x; }
static int same_ones(u32 a, u32 b) { return a % 65535 == b % 65535; }   /* 0 == 0xffff */

#define ARENA_PAGES 24
#define DATA_MAX ((ARENA_PAGES - 2) * 4096)
unsigned long shim_guard_page;
static u8 *arena_lo, *arena_hi;     /* usable [lo, hi) */
static u8 *src;
static u64 rs;
static u64 rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }

static void arena_init(void)
{
	u8 *m = mmap(0, (size_t)ARENA_PAGES * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (m == MAP_FAILED) { perror("mmap"); exit(2); }
	mprotect(m, 4096, PROT_NONE);
	mprotect(m + (ARENA_PAGES - 1) * 4096, 4096, PROT_NONE);
	arena_lo = m + 4096; arena_hi = m + (ARENA_PAGES - 1) * 4096; shim_guard_page = (unsigned long)arena_hi;
	src = malloc(DATA_MAX + 64);
}
static void fill(int pat)
{
	size_t i;
	switch (pat) {
	case 0: for (i = 0; i < DATA_MAX + 64; i++) src[i] = (u8)rnd(); break;
	case 1: memset(src, 0xff, DATA_MAX + 64); break;
	case 2: memset(src, 0, DATA_MAX + 64); break;
	default: for (i = 0; i < DATA_MAX + 64; i++) src[i] = (rnd() % 10) ? 0xff : (u8)rnd(); break;
	}
}
static u32 pick_sum(void)
{
	static const u32 s[] = { 0, 0xffffffffu, 0xffff0000u, 0x0000ffffu, 0x80000000u, 1 };
	u64 r = rnd();
	return (r & 8) ? (u32)(r >> 8) : s[(r >> 4) % 6];
}

static unsigned long long n_cmp, fails, poison_done;
static int poison;
static void check(const u8 *buf, int len, u32 init, const char *where, int al)
{
	u32 c = c_csum_partial(buf, len, init), r = csum_partial(buf, len, init);
	u16 ci = c_ip_compute_csum(buf, len), ri = ip_compute_csum(buf, len);
	u32 o = rfc1071(buf, len, init), o0 = rfc1071(buf, len, 0);
	if (poison && !poison_done && len == 100) { r ^= 0x10000; poison_done = 1; }
	n_cmp += 2;
	if (poison && poison_done && (c != r)) { printf("poisoned Rust result detected\n"); exit(1); }
	if (c != r || ci != ri || !same_ones(fold16(r), o) || !same_ones((u16)~ri, o0)) {
		if (fails++ < 10)
			fprintf(stderr, "MISMATCH %s len=%d al=%d init=%#x: csum c=%#x r=%#x rfc=%#x | ip c=%#x r=%#x rfc0=%#x\n",
				where, len, al, init, c, r, o, ci, ri, o0);
	}
}

static void sweep(unsigned shard, unsigned nsh)
{
	int len, al, seed;
	for (seed = 0; seed < 32; seed++) {
		rs = 0x9e3779b97f4a7c15ULL * (seed + 1) + shard;
		fill(seed & 3);
		for (len = (int)shard; len <= 4096; len += (int)nsh) {
			/* flush against the trailing guard page */
			u8 *e = arena_hi - len;
			memcpy(e, src + (rnd() % 64), len);
			check(e, len, pick_sum(), "flush-end", (int)((uintptr_t)e & 63));
			/* every alignment 0..63 from the arena start */
			for (al = 0; al < 64; al++) {
				u8 *b = arena_lo + al;
				memcpy(b, src + (rnd() % 64), len);
				check(b, len, pick_sum(), "aligned", al);
			}
		}
		/* random long buffers, random alignment, lengths up to DATA_MAX-64, both layouts */
		{
			int k;
			for (k = 0; k < 3000; k++) {
				int l = (int)(rnd() % (DATA_MAX - 64)), a = (int)(rnd() % 64);
				u8 *b = (rnd() & 1) ? arena_hi - l : arena_lo + a;
				memcpy(b, src, l);
				check(b, l, pick_sum(), "random", (int)((uintptr_t)b & 63));
			}
		}
	}
	/* NULL with len 0 (the contract allows it) */
	n_cmp += 1;
	if (c_csum_partial(0, 0, 0x1234) != csum_partial(0, 0, 0x1234) || csum_partial(0, 0, 0xdeadbeef) != 0xdeadbeefu) {
		fails++; fprintf(stderr, "MISMATCH NULL,0\n");
	}
	printf("shard %u/%u: %llu comparisons (csum_partial + ip_compute_csum, each vs C and vs RFC 1071), %llu failure(s)\n",
	       shard, nsh, n_cmp, fails);
}

static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec * 1e-9; }
static void bench(void)
{
	static const int L[] = { 20, 40, 64, 128, 1500, 9000, 65536 };
	int i, k;
	volatile u32 sink = 0;
	arena_init(); rs = 12345; fill(0);
	memcpy(arena_lo, src, DATA_MAX);
	for (i = 0; i < 7; i++) {
		long it = 400000000L / (L[i] + 64);
		double t0 = now(), t1, t2;
		for (k = 0; k < it; k++) sink += c_csum_partial(arena_lo + (k & 7), L[i], sink);
		t1 = now();
		for (k = 0; k < it; k++) sink += csum_partial(arena_lo + (k & 7), L[i], sink);
		t2 = now();
		printf("len %6d: C %7.2f ns  Rust %7.2f ns  (Rust/C %.2f)\n", L[i], (t1 - t0) / it * 1e9, (t2 - t1) / it * 1e9, (t2 - t1) / (t1 - t0));
	}
}

int main(int argc, char **argv)
{
	poison = getenv("CSUM_PROVE_CAN_FAIL") != NULL;
	if (argc > 1 && !strcmp(argv[1], "bench")) { bench(); return 0; }
	arena_init();
	sweep(argc > 2 ? (unsigned)atoi(argv[2]) : 0, argc > 3 ? (unsigned)atoi(argv[3]) : 1);
	return fails ? 1 : 0;
}
