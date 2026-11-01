/* SPDX-License-Identifier: GPL-2.0 */
/* Differential for the logic of crypto/ecb.c: the pristine crypto_ecb_crypt() (c_ecb_crypt, sliced out of the
 * unmodified file by extract.py) against ecb_rs_crypt(), and both against an INDEPENDENT model of ECB written from the
 * definition (output block j = E(input block j), whole blocks only; remainder = n - blocks*bsize; the -EINVAL rule).
 * The cipher is a deterministic toy block cipher (toy_block over g_bs bytes) used identically by all arms; it also
 * checks that it is only ever handed whole in-bounds blocks (the buffers sit flush against a PROT_NONE page, at the
 * END in the first pass and at the START in the second, so a byte touched outside [0,n) is a SIGSEGV; bytes around
 * the processed range are canaries).
 * usage: main SHARD NSHARDS        ECB_PROVE_CAN_FAIL=1 poisons one Rust result. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/mman.h>
typedef uint8_t u8;
struct crypto_tfm; struct crypto_cipher;
typedef void (*enc_t)(struct crypto_tfm *, u8 *, const u8 *);
int c_ecb_crypt(struct crypto_cipher *, const u8 *, u8 *, unsigned, bool, enc_t);
int ecb_rs_crypt(unsigned, void *, void *, const u8 *, u8 *, unsigned, bool);
/* the same layout as kshim.h's struct crypto_cipher */
struct tfm_s { int unused; };
struct cipher_s { struct tfm_s tfm; unsigned int bsize; };

static unsigned g_bs = 16;
static unsigned long long calls_c, calls_r;
static int g_cc;
static u8 g_key[32] = { 7, 77, 177, 17, 3, 33, 133, 233, 5, 55, 155, 255, 9, 99, 199, 29, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 121, 98, 219, 61 };
static void toy_block(u8 *dst, const u8 *src)
{
	u8 t[32];
	uint32_t h = 2166136261u;
	for (unsigned i = 0; i < g_bs; i++) h = (h ^ src[i] ^ g_key[i]) * 16777619u;
	for (unsigned i = 0; i < g_bs; i++) { h = (h ^ (src[i] + i)) * 16777619u; t[i] = (u8)(h >> 11) ^ g_key[i]; }
	for (unsigned i = 0; i < g_bs; i++) dst[i] = t[i];
}
static void enc_cb(struct crypto_tfm *t, u8 *dst, const u8 *src) { (void)t; g_cc++; toy_block(dst, src); }

static uint64_t rs = 88172645463325252ULL;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
static unsigned long long n_cmp, fails; static int poison, poisoned;
#define PG 4096
static u8 *region(void)
{
	u8 *m = mmap(0, 3 * PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	mprotect(m, PG, PROT_NONE); mprotect(m + 2 * PG, PG, PROT_NONE);
	return m + PG;
}
static u8 *rg[8];
static u8 *place(int r, int len, int mode, int off)
{
	if (len + off > PG) off = 0;
	return mode == 0 ? rg[r] + PG - len - off : rg[r] + off;
}
static void bad(const char *what, unsigned bs, unsigned n, int inpl, int fin)
{
	if (fails++ < 10) fprintf(stderr, "MISMATCH %s bs=%u n=%u inplace=%d final=%d\n", what, bs, n, inpl, fin);
}

static void scenario(unsigned bs, unsigned n, int inplace, int fin, int mode, int a_src, int a_dst)
{
	u8 in[1024], want[1024];
	u8 *srcC, *dstC, *srcR, *dstR;
	unsigned i, nfull = n / bs * bs;
	int rc, rr, want_r;
	struct cipher_s ci = { { 0 }, bs };
	g_bs = bs;
	for (i = 0; i < n; i++) in[i] = (u8)rnd();
	/* model: block by block */
	for (i = 0; i + bs <= n; i += bs) toy_block(want + i, in + i);
	want_r = (n - nfull) && fin ? -22 : (int)(n - nfull);
	if (inplace) { srcC = dstC = place(0, n, mode, a_dst); srcR = dstR = place(2, n, mode, a_dst); }
	else { srcC = place(0, n, mode, a_src); dstC = place(1, n, mode, a_dst); srcR = place(2, n, mode, a_src); dstR = place(3, n, mode, a_dst); }
	memcpy(srcC, in, n); memcpy(srcR, in, n);
	if (!inplace) { memset(dstC, 0xA5, n); memset(dstR, 0xA5, n); }
	g_cc = 0; rc = c_ecb_crypt((struct crypto_cipher *)&ci, srcC, dstC, n, fin, enc_cb); calls_c = g_cc;
	g_cc = 0; rr = ecb_rs_crypt(bs, &ci.tfm, (void *)enc_cb, srcR, dstR, n, fin); calls_r = g_cc;
	if (poison && !poisoned && n == 33) { rr++; poisoned = 1; }
	n_cmp += 6;
	if (rc != rr) bad("return C vs Rust", bs, n, inplace, fin);
	if (rr != want_r) bad("return Rust vs model", bs, n, inplace, fin);
	if (calls_c != calls_r || calls_r != nfull / bs) bad("cipher call count", bs, n, inplace, fin);
	if (memcmp(dstC, dstR, n)) bad("data C vs Rust", bs, n, inplace, fin);
	if (memcmp(dstR, want, nfull)) bad("data Rust vs model", bs, n, inplace, fin);
	/* the unprocessed tail is untouched: separate = still 0xA5, in place = still the input */
	if (!inplace) { for (i = nfull; i < n; i++) if (dstR[i] != 0xA5) { bad("tail written", bs, n, inplace, fin); break; } }
	else if (memcmp(dstR + nfull, in + nfull, n - nfull)) bad("tail written (in place)", bs, n, inplace, fin);
	if (!inplace && memcmp(srcR, in, n)) bad("source modified", bs, n, inplace, fin);
}

static void out_of_contract(void)
{
	/* Rust only: bsize 0 calls the cipher never and touches nothing (zero-length buffers: any access faults) */
	u8 *z = place(0, 0, 0, 0);
	g_cc = 0;
	for (unsigned n = 0; n < 40; n++)
		for (int fin = 0; fin < 2; fin++) {
			int r = ecb_rs_crypt(0, 0, (void *)enc_cb, z, z, n, fin);
			n_cmp++;
			if (r != ((n && fin) ? -22 : (int)n) || g_cc) bad("bsize 0 is not a no-op", 0, n, 0, fin);
		}
}

int main(int argc, char **argv)
{
	unsigned shard = argc > 1 ? atoi(argv[1]) : 0, nsh = argc > 2 ? atoi(argv[2]) : 1;
	static const unsigned bss[] = { 1, 2, 4, 8, 16, 24, 32 };
	poison = getenv("ECB_PROVE_CAN_FAIL") != NULL;
	for (int i = 0; i < 8; i++) rg[i] = region();
	rs += shard * 0x9e3779b97f4a7c15ULL;
	for (int mode = 0; mode < 2; mode++)
		for (int b = 0; b < 7; b++) {
			unsigned bs = bss[b], top = 12 * bs + bs - 1;
			if (top > 400) top = 400;
			for (unsigned n = shard; n <= top; n += nsh)               /* 0 .. 13*bs-1: loop, remainders */
				for (int inplace = 0; inplace < 2; inplace++)
					for (int fin = 0; fin < 2; fin++)
						for (int a = 0; a < 8; a++)
							scenario(bs, n, inplace, fin, mode, a, (a * 3 + 1) & 7);
		}
	for (long k = 0; k < 300000 / (long)nsh; k++) {
		unsigned bs = bss[rnd() % 7], n = rnd() % 500;
		scenario(bs, n, rnd() & 1, rnd() & 1, rnd() & 1, rnd() % 8, rnd() % 8);
	}
	out_of_contract();
	printf("shard %u/%u: %llu comparisons, %llu failure(s)\n", shard, nsh, n_cmp, fails);
	return fails ? 1 : 0;
}
