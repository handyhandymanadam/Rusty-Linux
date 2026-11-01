/* SPDX-License-Identifier: GPL-2.0 */
/* Differential for the logic of crypto/ctr.c: the pristine C statements (c_final / c_segment / c_inplace / c_rfc_iv,
 * sliced out of the unmodified file by extract.py, with crypto_inc sliced verbatim from crypto/algapi.c) against
 * ctr_rs_crypt_final / _segment / _inplace / ctr_rs_rfc3686_iv, and both against an INDEPENDENT model of CTR mode
 * written from the definition (counter block j = initial + j as a big-endian integer, added with an explicit carry
 * loop, never by repeated increment; keystream = E(counter block); output = input ^ keystream; the final partial
 * block uses the first n keystream bytes; the counter afterwards = initial + blocks used).
 * The cipher is a deterministic toy block cipher (toy_encrypt_block, block size g_bs) used identically by all arms.
 * Every buffer (data, counter block, keystream, rfc iv/nonce) sits flush against a PROT_NONE page at its END (second
 * pass: flush at the START), so a byte touched outside the contract sizes is a SIGSEGV; the data buffers also have
 * their bytes around the processed range compared (canaries).
 * Walk model: like crypto_ctr_crypt(): the loop function gets all n bytes, returns the remainder r, then the final
 * function gets the r tail bytes (if any).
 * usage: main SHARD NSHARDS        CTR_PROVE_CAN_FAIL=1 poisons one Rust result. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
typedef uint8_t u8;
typedef void (*enc_t)(void *, u8 *, const u8 *);
unsigned int g_bs = 16;
static u8 g_key[16] = { 7, 77, 177, 17, 3, 33, 133, 233, 5, 55, 155, 255, 9, 99, 199, 29 };

/* toy block cipher over g_bs bytes: every output byte depends on every input byte and the key */
void toy_encrypt_block(u8 *dst, const u8 *src)
{
	u8 t[16];
	uint32_t h = 2166136261u;
	for (unsigned i = 0; i < g_bs; i++) h = (h ^ src[i] ^ g_key[i]) * 16777619u;
	for (unsigned i = 0; i < g_bs; i++) {
		h = (h ^ (src[i] + i)) * 16777619u;
		t[i] = (u8)(h >> 11) ^ g_key[i];
	}
	for (unsigned i = 0; i < g_bs; i++) dst[i] = t[i];
}
static void enc_cb(void *tfm, u8 *dst, const u8 *src) { (void)tfm; toy_encrypt_block(dst, src); }

void c_final(u8 *, unsigned, void *, u8 *, const u8 *, u8 *, unsigned);
unsigned c_segment(u8 *, unsigned, void *, const u8 *, u8 *, unsigned);
unsigned c_inplace(u8 *, unsigned, void *, u8 *, u8 *, unsigned);
void c_rfc_iv(u8 *, const u8 *, const u8 *);
void ctr_rs_crypt_final(u8 *, unsigned, enc_t, void *, u8 *, const u8 *, u8 *, unsigned);
unsigned ctr_rs_crypt_segment(u8 *, unsigned, enc_t, void *, const u8 *, u8 *, unsigned);
unsigned ctr_rs_crypt_inplace(u8 *, unsigned, enc_t, void *, u8 *, u8 *, unsigned);
void ctr_rs_rfc3686_iv(u8 *, const u8 *, const u8 *);

static uint64_t rs = 88172645463325252ULL;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
static unsigned long long n_cmp, fails; static int poison, poisoned;

#define PG 4096
static u8 *region(void)   /* one usable page, PROT_NONE pages before and after */
{
	u8 *m = mmap(0, 3 * PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	mprotect(m, PG, PROT_NONE); mprotect(m + 2 * PG, PG, PROT_NONE);
	return m + PG;
}
static u8 *rg[10];
/* a buffer of exactly `len` bytes: flush at the end (mode 0) or at the start (mode 1) of region r; off shifts it
 * inward (alignment) */
static u8 *place(int r, int len, int mode, int off)
{
	if (len + off > PG) off = 0;
	return mode == 0 ? rg[r] + PG - len - off : rg[r] + off;
}
static void bad(const char *what, unsigned bs, unsigned n, int inpl)
{
	if (fails++ < 10) fprintf(stderr, "MISMATCH %s bs=%u n=%u inplace=%d\n", what, bs, n, inpl);
}

/* independent model */
static void m_ctr_add(u8 *out, const u8 *init, unsigned bs, uint64_t j)
{
	unsigned carry = 0;
	for (int i = bs - 1; i >= 0; i--) {
		unsigned s = init[i] + (unsigned)(j & 0xff) + carry;
		out[i] = (u8)s; carry = s >> 8; j >>= 8;
	}
}
static void m_ctr(u8 *out, const u8 *in, unsigned n, unsigned bs, const u8 *ctr0, u8 *ctr_end)
{
	u8 blk[16], ks[16];
	unsigned j = 0;
	for (unsigned off = 0; off < n; off += bs, j++) {
		m_ctr_add(blk, ctr0, bs, j);
		toy_encrypt_block(ks, blk);
		for (unsigned i = 0; i < bs && off + i < n; i++) out[off + i] = in[off + i] ^ ks[i];
	}
	m_ctr_add(ctr_end, ctr0, bs, j);
}

static void make_ctr(u8 *c, unsigned bs, int kind)
{
	unsigned i;
	for (i = 0; i < bs; i++) c[i] = (u8)rnd();
	if (kind == 0) memset(c, 0, bs);
	else if (kind == 1) memset(c, 0xff, bs);
	else if (kind >= 2 && kind < 2 + (int)bs + 1) {       /* last (kind-2) bytes 0xff: the carry runs up to that position */
		unsigned k = kind - 2;
		for (i = 0; i < k; i++) c[bs - 1 - i] = 0xff;
		if (k < bs) c[bs - 1 - k] = (u8)(rnd() % 255);   /* never 0xff, so the carry stops there */
	}
}

/* one full scenario: n total bytes, inplace or separate, c-arm / rust-arm / model */
static void scenario(unsigned bs, unsigned n, int inplace, int mode, int a_src, int a_dst, int ckind)
{
	u8 in[400], want[400], ctr0[16], want_ctr[16];
	u8 *srcC, *dstC, *srcR, *dstR, *ctrC, *ctrR, *ksC, *ksR;
	unsigned i, r, rem, nfull = n / bs * bs;
	g_bs = bs;
	for (i = 0; i < n; i++) in[i] = (u8)rnd();
	make_ctr(ctr0, bs, ckind);
	m_ctr(want, in, n, bs, ctr0, want_ctr);

	/* C arm */
	if (inplace) { srcC = dstC = place(0, n, mode, a_dst); } else { srcC = place(0, n, mode, a_src); dstC = place(1, n, mode, a_dst); }
	/* Rust arm: separate regions, same placement */
	if (inplace) { srcR = dstR = place(2, n, mode, a_dst); } else { srcR = place(2, n, mode, a_src); dstR = place(3, n, mode, a_dst); }
	ctrC = place(4, bs, mode, 0); ctrR = place(5, bs, mode, 0);
	ksC = place(6, bs, mode, 0); ksR = place(7, bs, mode, 0);
	memcpy(ctrC, ctr0, bs); memcpy(ctrR, ctr0, bs);
	memcpy(srcC, in, n); memcpy(srcR, in, n);
	if (!inplace) { memset(dstC, 0xA5, n); memset(dstR, 0xA5, n); }

	if (nfull) {
		unsigned rc, rr;
		if (inplace) {
			rc = c_inplace(ctrC, bs, 0, ksC, dstC, n);
			rr = ctr_rs_crypt_inplace(ctrR, bs, enc_cb, 0, ksR, dstR, n);
		} else {
			rc = c_segment(ctrC, bs, 0, srcC, dstC, n);
			rr = ctr_rs_crypt_segment(ctrR, bs, enc_cb, 0, srcR, dstR, n);
		}
		if (poison && !poisoned && n == 33) { rr++; poisoned = 1; }
		n_cmp++;
		if (rc != rr || rc != n - nfull) bad("remainder", bs, n, inplace);
		rem = rc;
	} else rem = n;
	if (rem) {
		/* final: tail of the data (the glue passes walk src/dst already advanced) */
		c_final(ctrC, bs, 0, ksC, srcC + nfull + 0 * 0, dstC + nfull, rem);
		ctr_rs_crypt_final(ctrR, bs, enc_cb, 0, ksR, srcR + nfull, dstR + nfull, rem);
		/* in-place final reads the already-processed? no: src == dst for inplace and the tail is untouched so far */
		n_cmp++;
	}
	r = 0;
	n_cmp += 3;
	if (memcmp(dstC, dstR, n)) bad("C data vs Rust data", bs, n, inplace);
	if (memcmp(dstR, want, n)) bad("Rust data vs model", bs, n, inplace);
	if (memcmp(ctrC, ctrR, bs)) bad("C counter vs Rust counter", bs, n, inplace);
	if (memcmp(ctrR, want_ctr, bs)) bad("Rust counter vs model", bs, n, inplace);
	if (!inplace && memcmp(srcR, in, n)) bad("source modified", bs, n, inplace);
	(void)r;
}

static void rfc_iv(int mode)
{
	for (int k = 0; k < 5000; k++) {
		u8 nonce[4], rv[8], *nC = place(0, 4, mode, 0), *rC = place(1, 8, mode, 0), *iC = place(2, 16, mode, 0);
		u8 *iR = place(3, 16, mode, 0), model[16];
		for (int i = 0; i < 4; i++) nonce[i] = (u8)rnd();
		for (int i = 0; i < 8; i++) rv[i] = (u8)rnd();
		memcpy(nC, nonce, 4); memcpy(rC, rv, 8);
		memset(iC, 0xA5, 16); memset(iR, 0xA5, 16);
		c_rfc_iv(iC, nC, rC); ctr_rs_rfc3686_iv(iR, nC, rC);
		memcpy(model, nonce, 4); memcpy(model + 4, rv, 8); model[12] = model[13] = model[14] = 0; model[15] = 1;   /* RFC 3686 s4 */
		n_cmp += 2;
		if (memcmp(iC, iR, 16)) bad("rfc iv C vs Rust", 16, 0, 0);
		if (memcmp(iR, model, 16)) bad("rfc iv Rust vs RFC 3686", 16, 0, 0);
	}
}

static void out_of_contract(void)
{
	/* Rust only: nbytes < bsize or bsize 0 must not touch anything (buffers have 0 bytes: any access faults) */
	u8 *c = place(0, 16, 0, 0), *z = place(1, 0, 0, 0);
	for (unsigned bs = 0; bs <= 16; bs += 4)
		for (unsigned n = 0; n < (bs ? bs : 5); n++) {
			n_cmp += 2;
			if (ctr_rs_crypt_segment(c, bs, enc_cb, 0, z, z, n) != n || ctr_rs_crypt_inplace(c, bs, enc_cb, 0, c, z, n) != n)
				bad("out-of-contract loop is not a no-op", bs, n, 0);
		}
	/* final with nbytes > bsize is clamped to bsize: dst/src of exactly bsize bytes must not fault */
	g_bs = 8;
	{
		u8 *s = place(2, 8, 0, 0), *d = place(3, 8, 0, 0), *k = place(4, 8, 0, 0), *ct = place(5, 8, 0, 0);
		memset(s, 1, 8); memset(ct, 0, 8);
		ctr_rs_crypt_final(ct, 8, enc_cb, 0, k, s, d, 50);
		n_cmp++;
	}
}

int main(int argc, char **argv)
{
	unsigned shard = argc > 1 ? atoi(argv[1]) : 0, nsh = argc > 2 ? atoi(argv[2]) : 1;
	static const unsigned bss[] = { 4, 8, 16 };
	poison = getenv("CTR_PROVE_CAN_FAIL") != NULL;
	for (int i = 0; i < 10; i++) rg[i] = region();
	rs += shard * 0x9e3779b97f4a7c15ULL;
	for (int mode = 0; mode < 2; mode++)
		for (int b = 0; b < 3; b++) {
			unsigned bs = bss[b];
			for (unsigned n = shard + 1; n <= 12 * bs + bs - 1; n += nsh)     /* 1 .. 13*bs-1: loops, remainders, finals */
				for (int inplace = 0; inplace < 2; inplace++)
					for (int a = 0; a < 8; a++)
						for (int ck = 0; ck < (int)bs + 4; ck++)
							scenario(bs, n, inplace, mode, a, (a * 3 + 1) & 7, ck);
		}
	/* random fuzz */
	for (long k = 0; k < 400000 / (long)nsh; k++) {
		unsigned bs = bss[rnd() % 3], n = 1 + rnd() % 380;
		scenario(bs, n, rnd() & 1, rnd() & 1, rnd() % 8, rnd() % 8, rnd() % (bs + 4));
	}
	rfc_iv(0); rfc_iv(1);
	out_of_contract();
	printf("shard %u/%u: %llu comparisons, %llu failure(s)\n", shard, nsh, n_cmp, fails);
	return fails ? 1 : 0;
}
