/* SPDX-License-Identifier: GPL-2.0 */
/* Differential for crypto/sha3_generic.c: pristine C (ref.c) vs sha3_rs.rs,
 * plus hashlib's digests as a third, independent oracle. See run.sh. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef uint8_t u8; typedef uint64_t u64;
void c_init_st(u64 *);
unsigned int c_update_st(u64 *, const u8 *, unsigned int, unsigned int);
void c_finup_st(u64 *, const u8 *, unsigned int, u8 *, unsigned int, unsigned int);
void crypto_sha3_rs_init(u64 *);
unsigned int crypto_sha3_rs_update(u64 *, const u8 *, unsigned int, unsigned int);
void crypto_sha3_rs_finup(u64 *, const u8 *, unsigned int, u8 *, unsigned int, unsigned int);

static uint64_t rs = 88172645463325252ULL;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
static void fill(void *p, size_t n) { u8 *b = p; while (n--) *b++ = (u8)rnd(); }
static unsigned long long checks, fails;
#define FAIL(...) do { if (fails++ < 10) fprintf(stderr, __VA_ARGS__); } while (0)
static int poison(void) { return getenv("SHA3_PROVE_CAN_FAIL") != NULL; }

static const struct { const char *name; unsigned ds, rsiz; } algs[4] = {
	{ "sha3_224", 28, 144 }, { "sha3_256", 32, 136 }, { "sha3_384", 48, 104 }, { "sha3_512", 64, 72 },
};

/* ---- shash-layer emulation (BLOCK_ONLY): buffer, call update on whole blocks,
 * keep the returned remainder, finup the last < rsiz bytes ---- */
struct impl {
	void (*init)(u64 *);
	unsigned (*update)(u64 *, const u8 *, unsigned, unsigned);
	void (*finup)(u64 *, const u8 *, unsigned, u8 *, unsigned, unsigned);
};
static void c_init_w(u64 *s) { c_init_st(s); }
static const struct impl IC = { c_init_w, c_update_st, c_finup_st };
static const struct impl IR = { crypto_sha3_rs_init, crypto_sha3_rs_update, crypto_sha3_rs_finup };

static void digest_chunked(const struct impl *I, int a, const u8 *msg, size_t len, size_t *chunks, int nch,
			   u8 *out, u64 *st_out)
{
	u64 st[25]; u8 *pend = malloc(len + 400); size_t plen = 0, pos = 0; int c = 0;
	unsigned rsiz = algs[a].rsiz;

	I->init(st);
	while (pos < len) {
		size_t n = (nch > 0) ? chunks[c++ % nch] : len;
		if (n > len - pos) n = len - pos;
		memcpy(pend + plen, msg + pos, n); plen += n; pos += n;
		if (plen >= rsiz) {
			unsigned rem = I->update(st, pend, (unsigned)plen, rsiz);
			if (rem >= rsiz || rem > plen) { FAIL("update returned %u (plen %zu)\n", rem, plen); rem = 0; }
			memmove(pend, pend + plen - rem, rem); plen = rem;
		}
	}
	I->finup(st, pend, (unsigned)plen, out, algs[a].ds, rsiz);
	if (st_out) memcpy(st_out, st, 200);
	free(pend);
}

static int hexval(int c) { return c <= '9' ? c - '0' : c - 'a' + 10; }

static void vectors(const char *path)
{
	FILE *f = fopen(path, "r"); static char line[20000]; size_t n = 0;
	if (!f) { fprintf(stderr, "no vectors file\n"); exit(2); }
	while (fgets(line, sizeof line, f)) {
		char *alg = strtok(line, " "), *hm = strtok(NULL, " "), *hd = strtok(NULL, " \n");
		size_t ml = strcmp(hm, "-") ? strlen(hm) / 2 : 0, i; u8 *m = malloc(ml + 1), want[64], oc[64], orr[64]; u64 sc[25], sr[25];
		int a; size_t ch[5];
		for (a = 0; a < 4; a++) if (!strcmp(alg, algs[a].name)) break;
		if (a == 4) { FAIL("unknown alg %s\n", alg); continue; }
		for (i = 0; i < ml; i++) m[i] = (u8)(hexval(hm[2 * i]) * 16 + hexval(hm[2 * i + 1]));
		for (i = 0; i < algs[a].ds; i++) want[i] = (u8)(hexval(hd[2 * i]) * 16 + hexval(hd[2 * i + 1]));
		for (int k = 0; k < 5; k++) {
			int nch = k == 0 ? 0 : 1 + (int)(rnd() % 4);
			for (int j = 0; j < 4; j++) ch[j] = k == 1 ? 1 + rnd() % 3 : 1 + rnd() % 400;
			memset(oc, 0xA5, 64); memset(orr, 0x5A, 64);
			digest_chunked(&IC, a, m, ml, ch, nch, oc, sc);
			digest_chunked(&IR, a, m, ml, ch, nch, orr, sr);
			if (poison()) orr[0]++;
			checks += 3;
			if (memcmp(oc, want, algs[a].ds)) FAIL("C != hashlib: %s len %zu\n", alg, ml);
			if (memcmp(orr, want, algs[a].ds)) FAIL("Rust != hashlib: %s len %zu\n", alg, ml);
			if (memcmp(sc, sr, 200)) FAIL("final state differs: %s len %zu\n", alg, ml);
		}
		free(m); n++;
	}
	fclose(f);
	printf("sha3_generic: %zu hashlib vectors x 5 chunkings\n", n);
}

/* ---- direct differential on random state/data ---- */
static void direct(unsigned long long n)
{
	static u8 buf[2400 + 64];
	for (unsigned long long it = 0; it < n; it++) {
		int a = (int)(rnd() & 3); unsigned rsiz = algs[a].rsiz, ds = algs[a].ds;
		u64 s1[25], s2[25], sref[25]; unsigned off = (unsigned)(rnd() & 7);
		unsigned len = rsiz + (unsigned)(rnd() % (rsiz * 12));
		unsigned r1, r2;
		u8 o1[80], o2[80];

		fill(buf, sizeof buf); fill(s1, 200); memcpy(s2, s1, 200); memcpy(sref, s1, 200);
		if ((it & 15) == 0) { memset(s1, 0, 200); memcpy(s2, s1, 200); }
		if ((it & 31) == 1) { memset(buf, 0xff, sizeof buf); }
		r1 = c_update_st(s1, buf + off, len, rsiz);
		r2 = crypto_sha3_rs_update(s2, buf + off, len, rsiz);
		checks++;
		if (r1 != r2 || memcmp(s1, s2, 200)) FAIL("update differs a=%d len=%u\n", a, len);
		if (len == rsiz && (it & 7) == 0) {   /* the pure permutation, via a zero block */
			u8 z[144] = { 0 }; u64 p1[25], p2[25];
			fill(p1, 200); memcpy(p2, p1, 200);
			c_update_st(p1, z, rsiz, rsiz); crypto_sha3_rs_update(p2, z, rsiz, rsiz);
			checks++; if (memcmp(p1, p2, 200)) FAIL("permutation differs\n");
		}
		/* finup: len < rsiz, including 0 and rsiz-1; src may be NULL when len == 0 */
		len = (unsigned)(rnd() % rsiz); if ((it & 3) == 0) len = (it & 4) ? 0 : rsiz - 1;
		memcpy(s1, sref, 200); memcpy(s2, sref, 200);
		memset(o1, 0xA5, sizeof o1); memset(o2, 0xA5, sizeof o2);
		c_finup_st(s1, len ? buf + off : NULL, len, o1 + 3, ds, rsiz);
		crypto_sha3_rs_finup(s2, len ? buf + off : NULL, len, o2 + 3, ds, rsiz);
		if (poison()) o2[3]++;
		checks++;
		if (memcmp(s1, s2, 200) || memcmp(o1, o2, sizeof o1)) FAIL("finup differs a=%d len=%u\n", a, len);
	}
	/* init */
	{ u64 s1[25], s2[25]; memset(s2, 0xee, 200); c_init_st(s1); crypto_sha3_rs_init(s2); checks++;
	  if (memcmp(s1, s2, 200)) FAIL("init differs\n");
	  for (int i = 0; i < 25; i++) { if (s2[i]) FAIL("init not zero\n"); } }
}

int main(int argc, char **argv)
{
	unsigned long long n = argc > 2 ? strtoull(argv[2], 0, 0) : 300000;
	if (argc > 1 && strcmp(argv[1], "-")) vectors(argv[1]);
	direct(n);
	printf("sha3_generic: %llu comparisons, %llu failure(s)\n", checks, fails);
	return fails ? 1 : 0;
}
