/* SPDX-License-Identifier: GPL-2.0 */
/* Differential for lib/crypto/gf128mul.c -> gf128mul_glue.c + gf128mul_rs.rs.
 *   subject  : gf128mul_glue.c + gf128mul_rs.rs  (public names)
 *   oracle A : the PRISTINE upstream gf128mul.c, every public name renamed ref_*
 *   oracle B : independent bit-by-bit references below (NIST SP 800-38D Alg. 1
 *              for lle; carry-less multiply mod x^128+x^7+x^2+x+1 for bbe/ble)
 * Every multiply API is also checked on ALL 128 x 128 basis pairs: each API is
 * GF(2)-bilinear (see logs/proofs/gf128mul.py), so basis agreement is agreement
 * on all 2^256 operand pairs for the model-level statement. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <crypto/gf128mul.h>

#define REFP(x) ref_##x
void ref_gf128mul_x8_ble(le128 *, const le128 *);
void ref_gf128mul_lle(be128 *, const be128 *);
struct gf128mul_64k *ref_gf128mul_init_64k_bbe(const be128 *);
void ref_gf128mul_free_64k(struct gf128mul_64k *);
void ref_gf128mul_64k_bbe(be128 *, const struct gf128mul_64k *);
struct gf128mul_4k *ref_gf128mul_init_4k_lle(const be128 *);
void ref_gf128mul_4k_lle(be128 *, const struct gf128mul_4k *);

/* ---- shim: allocation accounting and failure injection ---- */
int shim_fail_at;                         /* 0 = never; k = the k-th kzalloc since reset fails */
static int allocs, kfrees, nlive, doublefree;
static const void *live[64];
static void acct_reset(void) { allocs = kfrees = doublefree = 0; }   /* live set is kept */
void *shim_kzalloc(size_t n)
{
	void *p; allocs++;
	if (shim_fail_at && allocs == shim_fail_at) return NULL;
	if (nlive >= 64) { fprintf(stderr, "live allocation set overflow: objects are leaking\n"); exit(1); }
	p = calloc(1, n); live[nlive++] = p; return p;
}
void kfree_sensitive(const void *p)
{
	int i; kfrees++;
	if (!p) return;
	for (i = 0; i < nlive; i++) if (live[i] == p) { live[i] = live[--nlive]; memset((void *)p, 0, 8); free((void *)p); return; }
	doublefree++;
}

static uint64_t rs = 88172645463325252ULL;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
typedef unsigned __int128 u128;
static unsigned long long checks, fails;
static unsigned long long per[16];
#define FAIL(...) do { if (fails++ < 10) fprintf(stderr, __VA_ARGS__); } while (0)
static int poison;          /* GF128_PROVE_CAN_FAIL: corrupt the subject's output */
static int basis_poison;    /* GF128_PROVE_BASIS_CAN_FAIL: wrong reduction in oracle B */

static u128 rnd128(void)
{
	u128 v = ((u128)rnd() << 64) | rnd();
	switch (rnd() % 16) {                 /* edge values */
	case 0: return 0;
	case 1: return ~(u128)0;
	case 2: return (u128)1 << (rnd() % 128);
	case 3: return ~((u128)1 << (rnd() % 128));
	case 4: return (u128)(rnd() & 0xff) << (8 * (rnd() % 16));
	}
	return v;
}
/* memory image <-> integer. be: byte 0 is the most significant. le: byte 0 is the least. */
static u128 be_int(const void *p) { const uint8_t *b = p; u128 v = 0; for (int i = 0; i < 16; i++) v = (v << 8) | b[i]; return v; }
static u128 le_int(const void *p) { const uint8_t *b = p; u128 v = 0; for (int i = 15; i >= 0; i--) v = (v << 8) | b[i]; return v; }
static void be_mem(u128 v, void *p) { uint8_t *b = p; for (int i = 15; i >= 0; i--) { b[i] = (uint8_t)v; v >>= 8; } }
static void le_mem(u128 v, void *p) { uint8_t *b = p; for (int i = 0; i < 16; i++) { b[i] = (uint8_t)v; v >>= 8; } }

/* ---- oracle B ---- */
/* NIST SP 800-38D Algorithm 1: bit 0 of the block is the MSB of the first byte. */
static u128 nist_mul(u128 x, u128 y)
{
	u128 z = 0, v = y, R = (u128)(basis_poison ? 0xe0 : 0xe1) << 120;
	for (int i = 0; i < 128; i++) { if ((x >> (127 - i)) & 1) z ^= v; v = (v & 1) ? (v >> 1) ^ R : v >> 1; }
	return z;
}
/* integer bit i = coefficient of x^i; reduce by x^128 = x^7+x^2+x+1 */
static u128 pmul(u128 x, u128 y)
{
	u128 z = 0;
	for (int i = 127; i >= 0; i--) {
		int top = (int)(z >> 127); z <<= 1; if (top) z ^= (basis_poison ? 0x86 : 0x87);
		if ((x >> i) & 1) z ^= y;
	}
	return z;
}
static u128 pmul_x8(u128 v) { return pmul(v, (u128)1 << 8); }

/* ---- comparisons ---- */
static void note(int api, unsigned long long n) { per[api] += n; checks += n; }
enum { A_LLE, A_4K, A_64K, A_X8, A_T4, A_T64, A_ALLOC, A_N };
static const char *const names[] = { "gf128mul_lle", "4k_lle mult", "64k_bbe mult", "x8_ble", "4k table", "64k tables", "alloc/free", 0 };

static void one_lle(u128 a, u128 b)
{
	be128 s, r, bb; u128 want = nist_mul(a, b), gs, gr;
	be_mem(a, &s); be_mem(a, &r); be_mem(b, &bb);
	gf128mul_lle(&s, &bb); ref_gf128mul_lle(&r, &bb);
	if (poison) ((uint8_t *)&s)[3] ^= 1;
	gs = be_int(&s); gr = be_int(&r);
	note(A_LLE, 1);
	if (gs != gr || gs != want) FAIL("lle: subject/A/B differ for a=%016llx%016llx b=%016llx%016llx\n", (unsigned long long)(a >> 64), (unsigned long long)a, (unsigned long long)(b >> 64), (unsigned long long)b);
}
static void one_x8(u128 x)
{
	le128 s, r, in; u128 want = pmul_x8(x), gs, gr;
	le_mem(x, &in);
	gf128mul_x8_ble(&s, &in); ref_gf128mul_x8_ble(&r, &in);
	if (poison) ((uint8_t *)&s)[9] ^= 1;
	gs = le_int(&s); gr = le_int(&r);
	note(A_X8, 1);
	if (gs != gr || gs != want) FAIL("x8_ble differs for x=%016llx%016llx\n", (unsigned long long)(x >> 64), (unsigned long long)x);
	{ /* in place (r == x) */
		le128 ip = in, ip2 = in; gf128mul_x8_ble(&ip, &ip); ref_gf128mul_x8_ble(&ip2, &ip2);
		note(A_X8, 1);
		if (memcmp(&ip, &ip2, 16) || le_int(&ip) != want) FAIL("x8_ble in place differs\n");
	}
}

static int check_t4(const struct gf128mul_4k *s, const struct gf128mul_4k *r, u128 g)
{
	int bad = 0;
	note(A_T4, 1);
	if (memcmp(s, r, sizeof *s)) { FAIL("4k table differs from upstream\n"); bad = 1; }
	for (int v = 0; v < 256; v++) { be128 w; be_mem(nist_mul((u128)v << 120, g), &w); if (memcmp(&s->t[v], &w, 16)) { FAIL("4k table[%d] != NIST g*v\n", v); bad = 1; break; } }
	return bad;
}
static int check_t64(const struct gf128mul_64k *s, const struct gf128mul_64k *r, u128 g)
{
	int bad = 0;
	note(A_T64, 16);
	for (int i = 0; i < 16; i++) {
		if (memcmp(s->t[i], r->t[i], sizeof *s->t[i])) { FAIL("64k table %d differs from upstream\n", i); bad = 1; }
		for (int v = 0; v < 256; v++) { be128 w; be_mem(pmul(g, (u128)v << (8 * i)), &w); if (memcmp(&s->t[i]->t[v], &w, 16)) { FAIL("64k table[%d][%d] != g*x^(8i)*v\n", i, v); bad = 1; break; } }
	}
	return bad;
}
/* init a 4k table with both, compare, multiply `na` operands */
static void run_4k(u128 g, const u128 *as, int na)
{
	be128 gb; struct gf128mul_4k *s, *r;
	be_mem(g, &gb); acct_reset(); s = gf128mul_init_4k_lle(&gb); r = ref_gf128mul_init_4k_lle(&gb);
	if (!s || !r) { FAIL("4k init NULL\n"); return; }
	if (check_t4(s, r, g)) { gf128mul_free_4k(s); gf128mul_free_4k(r); return; }
	for (int k = 0; k < na; k++) {
		be128 a1, a2; u128 want = nist_mul(as[k], g);
		be_mem(as[k], &a1); a2 = a1;
		gf128mul_4k_lle(&a1, s); ref_gf128mul_4k_lle(&a2, r);
		if (poison) ((uint8_t *)&a1)[0] ^= 0x80;
		note(A_4K, 1);
		if (memcmp(&a1, &a2, 16) || be_int(&a1) != want) FAIL("4k_lle mult differs\n");
	}
	gf128mul_free_4k(s); gf128mul_free_4k(r);
}
static void run_64k(u128 g, const u128 *as, int na)
{
	be128 gb; struct gf128mul_64k *s, *r;
	be_mem(g, &gb); s = gf128mul_init_64k_bbe(&gb); r = ref_gf128mul_init_64k_bbe(&gb);
	if (!s || !r) { FAIL("64k init NULL\n"); return; }
	if (!check_t64(s, r, g)) for (int k = 0; k < na; k++) {
		be128 a1, a2; u128 want = pmul(as[k], g);
		be_mem(as[k], &a1); a2 = a1;
		gf128mul_64k_bbe(&a1, s); ref_gf128mul_64k_bbe(&a2, r);
		if (poison) ((uint8_t *)&a1)[15] ^= 1;
		note(A_64K, 1);
		if (memcmp(&a1, &a2, 16) || be_int(&a1) != want) FAIL("64k_bbe mult differs\n");
	}
	gf128mul_free_64k(s); ref_gf128mul_free_64k(r);
}

static void basis(void)
{
	u128 as[128];
	for (int j = 0; j < 128; j++) as[j] = (u128)1 << j;
	for (int i = 0; i < 128; i++) {
		u128 g = (u128)1 << i;
		for (int j = 0; j < 128; j++) one_lle(as[j], g);
		run_4k(g, as, 128);
		run_64k(g, as, 128);
	}
	for (int j = 0; j < 128; j++) one_x8(as[j]);
	printf("gf128mul: all 128x128 basis pairs through lle, 4k_lle, 64k_bbe; 128 x8_ble basis vectors\n");
}

/* every reduction-table entry, reached through each user of it */
static void sweep(void)
{
	for (int v = 0; v < 256; v++) {
		/* TABLE_BE via x8_ble: top byte v */
		for (int rep = 0; rep < 4; rep++) one_x8(((u128)v << 120) | (rep ? (rnd128() >> 8) : 0));
		/* xda_le via lle (x8_lle_ti) and via 4k (x8_lle): operand byte 15 = v, multiplier/selector 0x80 in byte 15 */
		u128 g = (rnd128() & ~(u128)0xff) | (u128)v;
		u128 sel = 0x80;
		one_lle(g, sel);
		run_4k(g, &sel, 1);
		/* TABLE_BE via the 64k fill: t[0][128] = g*x^7 has top byte v when g = v << 113 */
		u128 as[2] = { rnd128(), 1 };
		run_64k((u128)v << 113, as, 2);
	}
	printf("gf128mul: all 256 values of both reduction tables reached on each user (x8_ble, lle ti, 4k x8_lle, 64k fill)\n");
}

static void randoms(unsigned long long n)
{
	for (unsigned long long it = 0; it < n; it++) {
		one_lle(rnd128(), rnd128());
		one_x8(rnd128());
		if (it % 4 == 0) { u128 as[8]; for (int k = 0; k < 8; k++) as[k] = rnd128(); run_4k(rnd128(), as, 8); }
		if (it % 16 == 0) { u128 as[8]; for (int k = 0; k < 8; k++) as[k] = rnd128(); run_64k(rnd128(), as, 8); }
	}
}

static void allocfail(void)
{
	be128 g; be_mem(rnd128(), &g);
	for (int k = 1; k <= 18; k++) {            /* 17 kzalloc in init_64k: k=18 never fails */
		struct gf128mul_64k *s, *r; int n0 = nlive, as_, ak, al, ad, rs_, rk, rl, rd;
		shim_fail_at = k; acct_reset(); s = gf128mul_init_64k_bbe(&g);
		as_ = allocs; ak = kfrees; al = nlive - n0; ad = doublefree;
		shim_fail_at = k; acct_reset(); r = ref_gf128mul_init_64k_bbe(&g);
		rs_ = allocs; rk = kfrees; rl = nlive - n0 - al; rd = doublefree;
		shim_fail_at = 0;
		note(A_ALLOC, 1);
		if ((s == NULL) != (r == NULL) || (s == NULL) != (k <= 17)) FAIL("init_64k k=%d: NULL-ness subject %d ref %d\n", k, s == NULL, r == NULL);
		if (as_ != rs_ || ak != rk || al != rl || ad != rd || ad) FAIL("init_64k k=%d: allocs %d/%d kfree calls %d/%d live %d/%d dbl %d/%d\n", k, as_, rs_, ak, rk, al, rl, ad, rd);
		/* k=1: t itself failed, upstream returns NULL without calling free_64k; k=2..17: free_64k = 17 kfree calls */
		if (k <= 17 && (al != 0 || ak != (k == 1 ? 0 : 17))) FAIL("init_64k k=%d: failure path left %d live, %d kfree calls (want 0, %d)\n", k, al, ak, k == 1 ? 0 : 17);
		if (k == 18 && al != 17) FAIL("init_64k success: %d live (want 17)\n", al);
		if (s) { acct_reset(); gf128mul_free_64k(s); note(A_ALLOC, 1);
			if (kfrees != 17 || doublefree) FAIL("free_64k: %d kfree calls (want 17), doublefree %d\n", kfrees, doublefree); }
		if (r) { acct_reset(); ref_gf128mul_free_64k(r); }
		if (nlive != n0) FAIL("init_64k k=%d: %d objects leaked\n", k, nlive - n0);
	}
	{ /* init_4k_lle: one kzalloc */
		struct gf128mul_4k *s, *r; int n0 = nlive;
		shim_fail_at = 1; acct_reset(); s = gf128mul_init_4k_lle(&g); int sa = allocs, sl = nlive - n0;
		shim_fail_at = 1; acct_reset(); r = ref_gf128mul_init_4k_lle(&g); int ra = allocs, rl = nlive - n0;
		shim_fail_at = 0; note(A_ALLOC, 1);
		if (s || r || sa != ra || sl || rl) FAIL("init_4k k=1: not NULL / accounting\n");
		acct_reset(); s = gf128mul_init_4k_lle(&g); r = ref_gf128mul_init_4k_lle(&g); note(A_ALLOC, 1);
		if (!s || !r || nlive != n0 + 2) FAIL("init_4k success accounting\n");
		gf128mul_free_4k(s); gf128mul_free_4k(r); if (nlive != n0 || doublefree) FAIL("4k free accounting\n");
	}
	printf("gf128mul: allocation failure injected at each of the 17 kzallocs of init_64k_bbe (+ none) and the 1 of init_4k_lle; free_64k = 17 kfree calls\n");
}

int main(int argc, char **argv)
{
	unsigned long long n = argc > 1 ? strtoull(argv[1], 0, 0) : 100000;
	poison = getenv("GF128_PROVE_CAN_FAIL") != NULL;
	basis_poison = getenv("GF128_PROVE_BASIS_CAN_FAIL") != NULL;
	basis(); sweep(); randoms(n); allocfail();
	for (int i = 0; names[i]; i++) printf("gf128mul:   %-14s %llu comparisons\n", names[i], per[i]);
	printf("gf128mul: %llu comparisons, %llu failure(s)\n", checks, fails);
	return fails ? 1 : 0;
}
