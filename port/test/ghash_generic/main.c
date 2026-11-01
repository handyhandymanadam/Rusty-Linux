/* SPDX-License-Identifier: GPL-2.0 */
/* Differential for crypto/ghash-generic.c: pristine C callbacks (ref.c) vs
 * ghash_rs.rs, both over the REAL lib/crypto/gf128mul.c, plus a pure-Python
 * NIST SP 800-38D GHASH (vectors.py) as a third, independent oracle. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
typedef uint8_t u8; typedef uint64_t u64;
struct gf128mul_4k { u64 t[256][2]; };
void c_init(u8 *); int c_setkey(struct gf128mul_4k **, const u8 *, unsigned);
unsigned c_update(u8 *, const struct gf128mul_4k *, const u8 *, unsigned);
void c_finup(u8 *, const struct gf128mul_4k *, const u8 *, unsigned, u8 *); void c_exit(struct gf128mul_4k **);
void crypto_ghash_rs_init(u8 *); int crypto_ghash_rs_setkey(struct gf128mul_4k **, const u8 *, unsigned);
unsigned crypto_ghash_rs_update(u8 *, const struct gf128mul_4k *, const u8 *, unsigned);
void crypto_ghash_rs_finup(u8 *, const struct gf128mul_4k *, const u8 *, unsigned, u8 *); void crypto_ghash_rs_exit(struct gf128mul_4k **);
extern int shim_fail_alloc; int shim_frees(void);

static uint64_t rs = 88172645463325252ULL;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
static void fill(void *p, size_t n) { u8 *b = p; while (n--) *b++ = (u8)rnd(); }
static unsigned long long checks, fails;
#define FAIL(...) do { if (fails++ < 10) fprintf(stderr, __VA_ARGS__); } while (0)
static int poison(void) { return getenv("GHASH_PROVE_CAN_FAIL") != NULL; }
static int hexval(int c) { return c <= '9' ? c - '0' : c - 'a' + 10; }

struct impl {
	void (*init)(u8 *); int (*setkey)(struct gf128mul_4k **, const u8 *, unsigned);
	unsigned (*update)(u8 *, const struct gf128mul_4k *, const u8 *, unsigned);
	void (*finup)(u8 *, const struct gf128mul_4k *, const u8 *, unsigned, u8 *); void (*exit)(struct gf128mul_4k **);
};
static const struct impl IC = { c_init, c_setkey, c_update, c_finup, c_exit };
static const struct impl IR = { crypto_ghash_rs_init, crypto_ghash_rs_setkey, crypto_ghash_rs_update, crypto_ghash_rs_finup, crypto_ghash_rs_exit };

/* shash-layer emulation (BLOCK_ONLY): buffer, update whole blocks, finup the rest */
static void digest(const struct impl *I, const u8 *key, const u8 *msg, size_t len, const unsigned *chunks, int nch, u8 *out)
{
	struct gf128mul_4k *g = NULL; u8 buf[16] __attribute__((aligned(16))); u8 *pend = malloc(len + 64); size_t plen = 0, pos = 0; int c = 0;
	if (I->setkey(&g, key, 16)) FAIL("setkey failed\n");
	I->init(buf);
	while (pos < len) {
		size_t n = nch > 0 ? chunks[c++ % nch] : len; if (n > len - pos) n = len - pos;
		memcpy(pend + plen, msg + pos, n); plen += n; pos += n;
		if (plen >= 16) { unsigned rem = I->update(buf, g, pend, (unsigned)plen);
			if (rem >= 16 || rem > plen) { FAIL("update returned %u\n", rem); rem = 0; }
			memmove(pend, pend + plen - rem, rem); plen = rem; }
	}
	I->finup(buf, g, pend, (unsigned)plen, out);
	I->exit(&g); free(pend);
}

static void vectors(const char *path)
{
	FILE *f = fopen(path, "r"); static char line[8000]; size_t n = 0;
	if (!f) { fprintf(stderr, "no vectors file\n"); exit(2); }
	while (fgets(line, sizeof line, f)) {
		char *hk = strtok(line, " "), *hm = strtok(NULL, " "), *hd = strtok(NULL, " \n");
		size_t ml = strcmp(hm, "-") ? strlen(hm) / 2 : 0, i; u8 key[16], want[16], oc[16], orr[16], *m = malloc(ml + 1); unsigned ch[4];
		for (i = 0; i < 16; i++) { key[i] = (u8)(hexval(hk[2 * i]) * 16 + hexval(hk[2 * i + 1])); want[i] = (u8)(hexval(hd[2 * i]) * 16 + hexval(hd[2 * i + 1])); }
		for (i = 0; i < ml; i++) m[i] = (u8)(hexval(hm[2 * i]) * 16 + hexval(hm[2 * i + 1]));
		for (int k = 0; k < 4; k++) {
			int nch = k == 0 ? 0 : 1 + (int)(rnd() % 4);
			for (int j = 0; j < 4; j++) ch[j] = k == 1 ? 1 + rnd() % 3 : 1 + rnd() % 40;
			digest(&IC, key, m, ml, ch, nch, oc); digest(&IR, key, m, ml, ch, nch, orr);
			if (poison()) orr[0]++;
			checks += 2;
			if (memcmp(oc, want, 16)) FAIL("C != NIST reference: len %zu\n", ml);
			if (memcmp(orr, want, 16)) FAIL("Rust != NIST reference: len %zu\n", ml);
		}
		free(m); n++;
	}
	fclose(f);
	printf("ghash_generic: %zu reference vectors x 4 chunkings\n", n);
}

static void direct(unsigned long long n)
{
	static u8 raw[1100];
	for (unsigned long long it = 0; it < n; it++) {
		struct gf128mul_4k *g1 = NULL, *g2 = NULL; u8 key[16]; u8 b1[16] __attribute__((aligned(16))), b2[16] __attribute__((aligned(16)));
		u8 o1[32], o2[32]; unsigned off = rnd() & 7, len = 16 + (unsigned)(rnd() % 300), r1, r2; int f = shim_frees();
		fill(key, 16); fill(raw, sizeof raw); fill(b1, 16); memcpy(b2, b1, 16);
		if ((it & 31) == 0) memset(key, (it & 32) ? 0xff : 0, 16);
		if (c_setkey(&g1, key, 16) || crypto_ghash_rs_setkey(&g2, key, 16)) { FAIL("setkey failed\n"); return; }
		checks++;
		if (memcmp(g1, g2, sizeof *g1)) FAIL("key tables differ\n");
		r1 = c_update(b1, g1, raw + off, len); r2 = crypto_ghash_rs_update(b2, g2, raw + off, len);
		checks++;
		if (r1 != r2 || memcmp(b1, b2, 16)) FAIL("update differs len=%u\n", len);
		len = (unsigned)(rnd() % 16); if ((it & 3) == 0) len = (it & 4) ? 0 : 15;
		memset(o1, 0xA5, sizeof o1); memset(o2, 0xA5, sizeof o2);
		c_finup(b1, g1, len ? raw + off : NULL, len, o1 + 3); crypto_ghash_rs_finup(b2, g2, len ? raw + off : NULL, len, o2 + 3);
		if (poison()) o2[3]++;
		checks++;
		if (memcmp(b1, b2, 16) || memcmp(o1, o2, sizeof o1)) FAIL("finup differs len=%u\n", len);
		/* setkey protocol: wrong lengths, replacement frees the old table, allocation failure */
		{
			struct gf128mul_4k *h1 = g1, *h2 = g2; unsigned kl = (it & 1) ? (unsigned)(rnd() % 40) : 16; int s1, s2, fa = shim_frees();
			if (kl == 16) kl = 17;                            /* wrong length: untouched, not freed */
			s1 = c_setkey(&h1, key, kl); s2 = crypto_ghash_rs_setkey(&h2, key, kl);
			checks++;
			if (s1 != s2 || s1 != -22 || h1 != g1 || h2 != g2 || shim_frees() != fa) FAIL("wrong-length setkey differs\n");
			shim_fail_alloc = 1; fa = shim_frees();
			s1 = c_setkey(&h1, key, 16); int fr1 = shim_frees() - fa; fa = shim_frees();
			s2 = crypto_ghash_rs_setkey(&h2, key, 16); int fr2 = shim_frees() - fa;
			shim_fail_alloc = 0;
			checks++;
			if (s1 != s2 || s1 != -12 || h1 != NULL || h2 != NULL || fr1 != fr2 || fr1 != 1) FAIL("ENOMEM setkey differs: %d %d frees %d %d\n", s1, s2, fr1, fr2);
			g1 = NULL; g2 = NULL;     /* both tables were freed by the failing setkey */
		}
		/* exit: null -> no free; table -> one free */
		{
			struct gf128mul_4k *e1 = NULL, *e2 = NULL; int fa = shim_frees();
			c_exit(&e1); crypto_ghash_rs_exit(&e2); checks++;
			if (shim_frees() != fa) FAIL("exit(NULL) freed\n");
			c_setkey(&e1, key, 16); crypto_ghash_rs_setkey(&e2, key, 16); fa = shim_frees();
			c_exit(&e1); crypto_ghash_rs_exit(&e2); checks++;
			if (shim_frees() != fa + 2) FAIL("exit(table) frees %d != 2\n", shim_frees() - fa);
		}
		(void)f;
	}
	/* init */
	{ u8 a[16], b[16]; memset(b, 0xee, 16); c_init(a); crypto_ghash_rs_init(b); checks++; if (memcmp(a, b, 16)) FAIL("init differs\n"); }
}


/* ---- the multiply the Rust calls: lib/crypto/gf128mul.c (C, not ported) vs the
 * NIST SP 800-38D Algorithm 1 bit-by-bit multiply. Both sides are bilinear over
 * GF(2) (the table has t[j+k] = t[j]^t[k], t[0] = 0, and its entries are x-multiples
 * of H), so agreement on all 128 x 128 pairs of basis vectors is agreement on all
 * 2^256 (H, a): a proof, not a sample. Additivity is also spot-checked. ---- */
typedef unsigned __int128 u128;
static u128 be(const u8 *p) { u128 v = 0; for (int i = 0; i < 16; i++) v = (v << 8) | p[i]; return v; }
static void tobe(u128 v, u8 *p) { for (int i = 15; i >= 0; i--) { p[i] = (u8)v; v >>= 8; } }
static u128 nist_mul(u128 x, u128 y)
{
	u128 z = 0, v = y, R = (u128)(getenv("GHASH_PROVE_BASIS_CAN_FAIL") ? 0xe0 : 0xe1) << 120;
	for (int i = 0; i < 128; i++) { if ((x >> (127 - i)) & 1) z ^= v; v = (v & 1) ? (v >> 1) ^ R : v >> 1; }
	return z;
}
void gf128mul_4k_lle(void *a, const struct gf128mul_4k *t);
static void basis(void)
{
	u128 pairs = 0, bad = 0;
	for (int i = 0; i < 128; i++) {
		u8 hk[16]; struct gf128mul_4k *g = NULL;
		tobe((u128)1 << i, hk);
		if (c_setkey(&g, hk, 16)) { FAIL("basis setkey\n"); return; }
		for (int j = 0; j < 128; j++) {
			u8 a[16] __attribute__((aligned(16))); tobe((u128)1 << j, a);
			gf128mul_4k_lle(a, g);
			pairs++; if (be(a) != nist_mul((u128)1 << j, (u128)1 << i)) bad++;
		}
		c_exit(&g);
	}
	checks += (unsigned long long)pairs;
	if (bad) FAIL("gf128mul_4k_lle != NIST multiply on %llu of %llu basis pairs\n", (unsigned long long)bad, (unsigned long long)pairs);
	/* additivity of the real C multiply: (a^b)*H == a*H ^ b*H, and H linear: table(H1^H2) */
	for (int it = 0; it < 20000; it++) {
		u8 h1[16], h2[16], hx[16], a[16] __attribute__((aligned(16))), b[16] __attribute__((aligned(16))), c[16] __attribute__((aligned(16)));
		struct gf128mul_4k *g1 = NULL, *g2 = NULL, *gx = NULL;
		fill(h1, 16); fill(h2, 16); fill(a, 16); fill(b, 16);
		for (int k = 0; k < 16; k++) { hx[k] = h1[k] ^ h2[k]; c[k] = a[k] ^ b[k]; }
		c_setkey(&g1, h1, 16); c_setkey(&g2, h2, 16); c_setkey(&gx, hx, 16);
		u8 a1[16] __attribute__((aligned(16))), a2[16] __attribute__((aligned(16))), b1[16] __attribute__((aligned(16))), ax[16] __attribute__((aligned(16)));
		memcpy(a1, a, 16); memcpy(a2, a, 16); memcpy(b1, b, 16); memcpy(ax, a, 16);
		gf128mul_4k_lle(a1, g1); gf128mul_4k_lle(a2, g2); gf128mul_4k_lle(b1, g1); gf128mul_4k_lle(ax, gx);
		gf128mul_4k_lle(c, g1);
		checks += 2;
		for (int k = 0; k < 16; k++) { if (c[k] != (u8)(a1[k] ^ b1[k])) { FAIL("not additive in a\n"); break; } }
		for (int k = 0; k < 16; k++) { if (ax[k] != (u8)(a1[k] ^ a2[k])) { FAIL("not additive in H\n"); break; } }
		c_exit(&g1); c_exit(&g2); c_exit(&gx);
	}
	printf("ghash_generic: gf128mul_4k_lle == NIST multiply on all %llu basis pairs (=> all inputs, by bilinearity)\n", (unsigned long long)pairs);
}

int main(int argc, char **argv)
{
	unsigned long long n = argc > 2 ? strtoull(argv[2], 0, 0) : 100000;
	if (argc > 1 && strcmp(argv[1], "-")) vectors(argv[1]);
	basis();
	direct(n);
	printf("ghash_generic: %llu comparisons, %llu failure(s)\n", checks, fails);
	return fails ? 1 : 0;
}
