/* SPDX-License-Identifier: GPL-2.0 */
/* Differential for the logic of crypto/cbc.c: the four pristine chaining loops (c_cbc_*, sliced out of the unmodified file
 * by extract.py) against cbc_rs_encrypt_segment / _encrypt_inplace / _decrypt_segment / _decrypt_inplace, and both
 * against an INDEPENDENT model of CBC written from the definition (c_0 = E(p_0 ^ IV), c_j = E(p_j ^ c_{j-1}); p_0 =
 * D(c_0) ^ IV, p_j = D(c_j) ^ c_{j-1}; the IV afterwards = the last ciphertext block; the remainder bytes untouched).
 * The cipher is a deterministic INVERTIBLE toy block cipher over g_bs bytes (two sequential passes with state, so every
 * output byte depends on earlier input bytes, and D(E(x)) == x is checked at start-up); the shim also checks every
 * cipher call is exactly one block, with a NULL IV, and the source and destination are the same block or disjoint.
 * Every buffer sits flush against a PROT_NONE page at its END (first pass) or START (second pass), so a byte touched
 * outside the contract sizes is a SIGSEGV; bytes past the processed range are canaries.
 * usage: main SHARD NSHARDS        CBC_PROVE_CAN_FAIL=1 poisons one Rust result. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
typedef uint8_t u8;
typedef void (*cipher_t)(void *, const u8 *, u8 *, unsigned);
struct tfm_s { unsigned int bsize; };

int c_cbc_encrypt_segment(struct tfm_s *, const u8 *, u8 *, unsigned, u8 *);
int c_cbc_encrypt_inplace(struct tfm_s *, u8 *, unsigned, u8 *);
int c_cbc_decrypt_segment(struct tfm_s *, const u8 *, u8 *, unsigned, u8 *);
int c_cbc_decrypt_inplace(struct tfm_s *, u8 *, unsigned, u8 *);
unsigned cbc_rs_encrypt_segment(void *, cipher_t, unsigned, const u8 *, u8 *, unsigned, u8 *);
unsigned cbc_rs_encrypt_inplace(void *, cipher_t, unsigned, u8 *, unsigned, u8 *);
unsigned cbc_rs_decrypt_segment(void *, cipher_t, unsigned, const u8 *, u8 *, unsigned, u8 *);
unsigned cbc_rs_decrypt_inplace(void *, cipher_t, unsigned, u8 *, unsigned, u8 *);

static unsigned g_bs = 16;
static unsigned long long g_calls;
static u8 g_key[16] = { 7, 77, 177, 17, 3, 33, 133, 233, 5, 55, 155, 255, 9, 99, 199, 29 };
static unsigned long long n_cmp, fails; static int poison, poisoned;

static void toy_E(u8 *dst, const u8 *src)
{
	u8 t[16]; unsigned i; u8 acc, x;
	memcpy(t, src, g_bs);
	acc = g_key[0];
	for (i = 0; i < g_bs; i++) { x = t[i]; t[i] = (u8)((x + (u8)(acc * 7 + g_key[i & 15])) ^ g_key[(i + 3) & 15]); acc = (u8)(acc * 31 + x + 1); }
	acc = g_key[5];
	for (i = g_bs; i-- > 0;) { x = t[i]; t[i] = (u8)((x ^ (u8)(acc + g_key[(i + 7) & 15])) + 3 * i + 1); acc = (u8)((acc * 17) ^ x); }
	memcpy(dst, t, g_bs);
}
static void toy_D(u8 *dst, const u8 *src)
{
	u8 t[16]; unsigned i; u8 acc, x, y;
	memcpy(t, src, g_bs);
	acc = g_key[5];
	for (i = g_bs; i-- > 0;) { y = t[i]; x = (u8)((u8)(y - (3 * i + 1)) ^ (u8)(acc + g_key[(i + 7) & 15])); t[i] = x; acc = (u8)((acc * 17) ^ x); }
	acc = g_key[0];
	for (i = 0; i < g_bs; i++) { y = t[i]; x = (u8)((y ^ g_key[(i + 3) & 15]) - (u8)(acc * 7 + g_key[i & 15])); t[i] = x; acc = (u8)(acc * 31 + x + 1); }
	memcpy(dst, t, g_bs);
}
int toy_cipher_call(int enc, const u8 *src, u8 *dst, unsigned len, u8 *iv)
{
	if (len != g_bs || iv != NULL) { fprintf(stderr, "BAD CIPHER CALL len=%u bs=%u iv=%p\n", len, g_bs, (void *)iv); abort(); }
	if (src != dst && ((src < dst && src + len > dst) || (dst < src && dst + len > src))) { fprintf(stderr, "PARTIAL OVERLAP in cipher call\n"); abort(); }
	g_calls++;
	if (enc) toy_E(dst, src); else toy_D(dst, src);
	return 0;
}
static void cb_enc(void *t, const u8 *s, u8 *d, unsigned len) { (void)t; toy_cipher_call(1, s, d, len, NULL); }
static void cb_dec(void *t, const u8 *s, u8 *d, unsigned len) { (void)t; toy_cipher_call(0, s, d, len, NULL); }

static uint64_t rs = 88172645463325252ULL;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
#define PG 4096
static u8 *region(void)
{
	u8 *m = mmap(0, 3 * PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	mprotect(m, PG, PROT_NONE); mprotect(m + 2 * PG, PG, PROT_NONE);
	return m + PG;
}
static u8 *rg[10];
static u8 *place(int r, int len, int mode, int off)
{
	if (len + off > PG) off = 0;
	return mode == 0 ? rg[r] + PG - len - off : rg[r] + off;
}
static void bad(const char *what, unsigned bs, unsigned n, int dec, int inpl)
{
	if (fails++ < 10) fprintf(stderr, "MISMATCH %s bs=%u n=%u decrypt=%d inplace=%d\n", what, bs, n, dec, inpl);
}

/* the model: from the definition */
static void model(int dec, unsigned bs, unsigned n, const u8 *in, const u8 *iv0, u8 *out, u8 *iv_end)
{
	u8 prev[16], t[16];
	unsigned off;
	memcpy(prev, iv0, bs);
	for (off = 0; off + bs <= n; off += bs) {
		if (!dec) {
			for (unsigned i = 0; i < bs; i++) t[i] = in[off + i] ^ prev[i];
			toy_E(out + off, t);
			memcpy(prev, out + off, bs);
		} else {
			toy_D(t, in + off);
			for (unsigned i = 0; i < bs; i++) out[off + i] = t[i] ^ prev[i];
			memcpy(prev, in + off, bs);
		}
	}
	memcpy(iv_end, prev, bs);
}

static void scenario(unsigned bs, unsigned n, int dec, int inplace, int mode, int a_src, int a_dst)
{
	u8 in[512], want[512], iv0[16], want_iv[16];
	u8 *srcC, *dstC, *srcR, *dstR, *ivC, *ivR;
	unsigned i, nfull = n / bs * bs, rc, rr;
	unsigned long long calls_c, calls_r;
	struct tfm_s tfm = { bs };
	g_bs = bs;
	for (i = 0; i < n; i++) in[i] = (u8)rnd();
	for (i = 0; i < bs; i++) iv0[i] = (u8)rnd();
	if (rnd() % 7 == 0) memset(iv0, 0, bs);
	model(dec, bs, n, in, iv0, want, want_iv);
	if (inplace) { srcC = dstC = place(0, n, mode, a_dst); srcR = dstR = place(2, n, mode, a_dst); }
	else { srcC = place(0, n, mode, a_src); dstC = place(1, n, mode, a_dst); srcR = place(2, n, mode, a_src); dstR = place(3, n, mode, a_dst); }
	ivC = place(4, bs, mode, 0); ivR = place(5, bs, mode, 0);
	memcpy(srcC, in, n); memcpy(srcR, in, n); memcpy(ivC, iv0, bs); memcpy(ivR, iv0, bs);
	if (!inplace) { memset(dstC, 0xA5, n); memset(dstR, 0xA5, n); }
	g_calls = 0;
	if (!dec) rc = inplace ? c_cbc_encrypt_inplace(&tfm, dstC, n, ivC) : c_cbc_encrypt_segment(&tfm, srcC, dstC, n, ivC);
	else      rc = inplace ? c_cbc_decrypt_inplace(&tfm, dstC, n, ivC) : c_cbc_decrypt_segment(&tfm, srcC, dstC, n, ivC);
	calls_c = g_calls; g_calls = 0;
	if (!dec) rr = inplace ? cbc_rs_encrypt_inplace(&tfm, cb_enc, bs, dstR, n, ivR) : cbc_rs_encrypt_segment(&tfm, cb_enc, bs, srcR, dstR, n, ivR);
	else      rr = inplace ? cbc_rs_decrypt_inplace(&tfm, cb_dec, bs, dstR, n, ivR) : cbc_rs_decrypt_segment(&tfm, cb_dec, bs, srcR, dstR, n, ivR);
	calls_r = g_calls;
	if (poison && !poisoned && n == 33) { rr++; poisoned = 1; }
	n_cmp += 8;
	if (rc != rr || rr != n - nfull) bad("remainder", bs, n, dec, inplace);
	if (calls_c != calls_r || calls_r != nfull / bs) bad("cipher call count", bs, n, dec, inplace);
	if (memcmp(dstC, dstR, n)) bad("data C vs Rust", bs, n, dec, inplace);
	if (memcmp(dstR, want, nfull)) bad("data Rust vs model", bs, n, dec, inplace);
	if (memcmp(ivC, ivR, bs)) bad("iv C vs Rust", bs, n, dec, inplace);
	if (memcmp(ivR, want_iv, bs)) bad("iv Rust vs model", bs, n, dec, inplace);
	if (!inplace) { for (i = nfull; i < n; i++) if (dstR[i] != 0xA5) { bad("tail written", bs, n, dec, inplace); break; } }
	else if (memcmp(dstR + nfull, in + nfull, n - nfull)) bad("tail written (in place)", bs, n, dec, inplace);
	if (!inplace && memcmp(srcR, in, n)) bad("source modified", bs, n, dec, inplace);
}

static void out_of_contract(void)
{
	/* Rust only: bsize 0 or > 16 touches nothing and returns nbytes (zero-length buffers: any access faults) */
	u8 *z = place(0, 0, 0, 0);
	static const unsigned bads[] = { 0, 17, 24, 32, 64, 4096 };
	g_calls = 0;
	for (unsigned b = 0; b < sizeof bads / sizeof *bads; b++)
		for (unsigned n = 0; n < 70; n++) {
			unsigned r[4];
			r[0] = cbc_rs_encrypt_segment(0, cb_enc, bads[b], z, z, n, z);
			r[1] = cbc_rs_encrypt_inplace(0, cb_enc, bads[b], z, n, z);
			r[2] = cbc_rs_decrypt_segment(0, cb_dec, bads[b], z, z, n, z);
			r[3] = cbc_rs_decrypt_inplace(0, cb_dec, bads[b], z, n, z);
			n_cmp += 4;
			for (int k = 0; k < 4; k++) if (r[k] != n) bad("out-of-contract block size is not a no-op", bads[b], n, k >> 1, k & 1);
		}
	if (g_calls) bad("out-of-contract block size called the cipher", 0, 0, 0, 0);
}

int main(int argc, char **argv)
{
	unsigned shard = argc > 1 ? atoi(argv[1]) : 0, nsh = argc > 2 ? atoi(argv[2]) : 1;
	static const unsigned bss[] = { 1, 2, 4, 8, 16 };
	poison = getenv("CBC_PROVE_CAN_FAIL") != NULL;
	for (int i = 0; i < 10; i++) rg[i] = region();
	rs += shard * 0x9e3779b97f4a7c15ULL;
	/* the toy cipher must be a bijection, or the model and the decrypt arms mean nothing */
	for (int b = 0; b < 5; b++) {
		u8 x[16], y[16], z[16];
		g_bs = bss[b];
		for (int k = 0; k < 2000; k++) { for (unsigned i = 0; i < g_bs; i++) x[i] = (u8)rnd(); toy_E(y, x); toy_D(z, y); if (memcmp(x, z, g_bs)) { fprintf(stderr, "toy cipher not invertible\n"); return 2; } }
	}
	for (int mode = 0; mode < 2; mode++)
		for (int b = 0; b < 5; b++) {
			unsigned bs = bss[b], top = 12 * bs + bs - 1;
			if (top > 300) top = 300;
			for (unsigned n = shard; n <= top; n += nsh)
				for (int dec = 0; dec < 2; dec++)
					for (int inplace = 0; inplace < 2; inplace++)
						for (int a = 0; a < 8; a++)
							scenario(bs, n, dec, inplace, mode, a, (a * 3 + 1) & 7);
		}
	for (long k = 0; k < 300000 / (long)nsh; k++) {
		unsigned bs = bss[rnd() % 5], n = rnd() % 400;
		scenario(bs, n, rnd() & 1, rnd() & 1, rnd() & 1, rnd() % 8, rnd() % 8);
	}
	out_of_contract();
	printf("shard %u/%u: %llu comparisons, %llu failure(s)\n", shard, nsh, n_cmp, fails);
	return fails ? 1 : 0;
}
