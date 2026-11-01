/* SPDX-License-Identifier: GPL-2.0 */
/* Differential for the two logic blocks of crypto/cmac.c: the pristine C statements (c_derive_subkeys, c_finup_xor,
 * sliced out of the unmodified file by extract.py) against cmac_rs_derive_subkeys / cmac_rs_finup_xor, and both against
 * an INDEPENDENT oracle written from NIST SP 800-38B (subkey generation: K1 = L<<1 ^ (msb(L)?Rb:0), K2 likewise from K1,
 * Rb = 0x87 (b=128) / 0x1B (b=64), byte-wise; last block: len == b -> M ^ K1, else (M || 1 || 0..) ^ K2; result =
 * prev ^ M_last).  Buffers are placed in a page flush against a PROT_NONE page at the END, and (second pass) flush at the
 * START after one, so a byte read or written outside the contract sizes is a SIGSEGV.
 * Subkeys: bs in {8,16} (+ bs 4, 12, 32 where nothing may change): 6M random L plus the edge values.
 * Finup: bs in {8,16} x every len 0..bs x random prev/src/consts; Rust only: len > bs (clamped, must not fault).
 * usage: main [shard nshards]   CMAC_PROVE_CAN_FAIL=1 poisons one Rust result. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
typedef uint8_t u8;
void c_derive_subkeys(u8 *, unsigned int);
void c_finup_xor(u8 *, const u8 *, unsigned int, const u8 *, unsigned int);
void cmac_rs_derive_subkeys(u8 *, unsigned int);
void cmac_rs_finup_xor(u8 *, const u8 *, unsigned int, const u8 *, unsigned int);

static uint64_t rs = 88172645463325252ULL;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
static unsigned long long n, fails; static int poison;
static u8 *pageA, *pageB, *pageC;      /* three one-page regions each surrounded by PROT_NONE pages */

static u8 *region(long pg, int idx)
{
	u8 *m = mmap(0, 3 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	(void)idx;
	mprotect(m, pg, PROT_NONE); mprotect(m + 2 * pg, pg, PROT_NONE);
	return m + pg;
}

/* NIST SP 800-38B, written from the spec, byte-wise */
static void o_dbl(const u8 *in, u8 *out, int b, u8 rb)
{
	int top = in[0] >> 7;
	for (int i = 0; i < b; i++) out[i] = (u8)(in[i] << 1) | (i + 1 < b ? in[i + 1] >> 7 : 0);
	if (top) out[b - 1] ^= rb;
}
static void o_subkeys(const u8 *L, u8 *k, int b)
{
	u8 rb = b == 16 ? 0x87 : 0x1b;
	o_dbl(L, k, b, rb);
	o_dbl(k, k + b, b, rb);
}
static void o_finup(u8 *prev, const u8 *src, int len, const u8 *k, int b)
{
	u8 m[16];
	memset(m, 0, sizeof m);
	memcpy(m, src, len);
	if (len != b) m[len] = 0x80;
	const u8 *kk = len == b ? k : k + b;
	for (int i = 0; i < b; i++) prev[i] ^= m[i] ^ kk[i];
}

static void bad(const char *what, unsigned bs, unsigned len)
{
	if (fails++ < 10) fprintf(stderr, "MISMATCH %s bs=%u len=%u\n", what, bs, len);
}

static void subkeys_once(u8 *at, unsigned bs, const u8 *L, int placement)
{
	u8 c1[64], c2[64], o[64], base[64];
	(void)placement;
	memset(base, 0xA7, 64); memcpy(base, L, bs);
	memcpy(at, base, 2 * bs); c_derive_subkeys(at, bs); memcpy(c1, at, 2 * bs);
	memcpy(at, base, 2 * bs); cmac_rs_derive_subkeys(at, bs); memcpy(c2, at, 2 * bs);
	if (poison && bs == 16 && L[0] == 0x80) c2[5] ^= 1;
	n++;
	if (bs == 8 || bs == 16) { memcpy(o, L, bs); o_subkeys(L, o, bs); }
	else memcpy(o, base, 2 * bs);            /* other block sizes: nothing may change (C has no default) */
	if (memcmp(c1, c2, 2 * bs) || memcmp(c2, o, 2 * bs)) { bad("subkeys", bs, 0); if (poison) { puts("poisoned Rust result detected"); exit(1); } }
}

int main(int argc, char **argv)
{
	unsigned shard = argc > 2 ? atoi(argv[1]) : 0, nsh = argc > 2 ? atoi(argv[2]) : 1;
	long pg = 4096; poison = getenv("CMAC_PROVE_CAN_FAIL") != NULL;
	pageA = region(pg, 0); pageB = region(pg, 1); pageC = region(pg, 2);
	rs += shard * 0x9e3779b97f4a7c15ULL;
	static const unsigned bss[] = { 8, 16, 4, 12, 32 };
	/* ---- subkeys ---- */
	for (int placement = 0; placement < 2; placement++) {
		for (int bi = 0; bi < 5; bi++) {
			unsigned bs = bss[bi];
			u8 *at = placement ? pageA : pageA + pg - 2 * bs;     /* flush end / flush start */
			u8 L[32];
			/* edge values */
			for (int e = 0; e < 8; e++) {
				for (unsigned i = 0; i < bs; i++) L[i] = e == 0 ? 0 : e == 1 ? 0xff : e == 2 ? (i ? 0 : 0x80) : e == 3 ? (i ? 0xff : 0x7f) : e == 4 ? (i == bs - 1 ? 1 : 0) : e == 5 ? 0x80 : e == 6 ? (i == bs - 1 ? 0x80 : 0) : 0x55;
				subkeys_once(at, bs, L, placement);
			}
			for (long it = shard; it < 1500000; it += nsh) {
				for (unsigned i = 0; i < bs; i++) L[i] = (u8)rnd();
				if (it & 1) L[0] = (u8)((L[0] & 0x7f) | ((it & 2) ? 0x80 : 0));    /* both values of the top bit */
				subkeys_once(at, bs, L, placement);
			}
		}
	}
	/* ---- finup ---- */
	for (int placement = 0; placement < 2; placement++) {
		for (int bi = 0; bi < 2; bi++) {
			unsigned bs = bss[bi];
			for (unsigned len = 0; len <= bs; len++) {
				for (long it = shard; it < 400000; it += nsh) {
					u8 *prev = placement ? pageA : pageA + pg - bs;
					u8 *src = placement ? pageB : pageB + pg - len;
					u8 *k = placement ? pageC : pageC + pg - 2 * bs;
					u8 p0[16], s0[16], k0[32], pc[16], pr[16], po[16];
					for (unsigned i = 0; i < bs; i++) p0[i] = (u8)rnd();
					for (unsigned i = 0; i < len; i++) s0[i] = (u8)rnd();
					for (unsigned i = 0; i < 2 * bs; i++) k0[i] = (u8)rnd();
					memcpy(src, s0, len); memcpy(k, k0, 2 * bs);
					memcpy(prev, p0, bs); c_finup_xor(prev, src, len, k, bs); memcpy(pc, prev, bs);
					memcpy(prev, p0, bs); cmac_rs_finup_xor(prev, src, len, k, bs); memcpy(pr, prev, bs);
					memcpy(po, p0, bs); o_finup(po, s0, len, k0, bs);
					n++;
					if (memcmp(pc, pr, bs) || memcmp(pr, po, bs)) bad("finup", bs, len);
				}
			}
			/* out of contract, Rust only: len > bs is clamped to bs; must not touch memory outside prev[bs], src[bs], k[2bs] */
			for (unsigned len = bs + 1; len <= bs + 5; len++) {
				u8 *prev = placement ? pageA : pageA + pg - bs, *src = placement ? pageB : pageB + pg - bs, *k = placement ? pageC : pageC + pg - 2 * bs;
				memset(prev, 1, bs); memset(src, 2, bs); memset(k, 3, 2 * bs);
				cmac_rs_finup_xor(prev, src, len, k, bs);
				n++;
			}
		}
	}
	printf("shard %u/%u: %llu comparisons (subkeys + finup: C vs Rust vs NIST SP 800-38B oracle, flush against PROT_NONE both ends), %llu failure(s)\n", shard, nsh, n, fails);
	return fails ? 1 : 0;
}
