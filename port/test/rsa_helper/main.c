/* SPDX-License-Identifier: GPL-2.0 */
/* Differential for the logic of crypto/rsa_helper.c: the eight pristine rsa_get_* functions (c_rsa_get_*, sliced out of the
 * unmodified file by extract.py) against the Rust rsa_get_*, and both against an independent statement of the rules
 * (spec_ok below). Built twice: FIPS=0 (CONFIG_CRYPTO_FIPS unset: fips_enabled is the constant 0, as in both kernel
 * configs) and FIPS=1 (the cfg arm: fips_enabled is a variable, run with 0 and 1, and the pr_err text is captured from both
 * sides and compared byte for byte, including the KERN_ERR prefix).
 * Compared per call: the return value, the whole 128-byte struct rsa_key afterwards, and the printk calls. `value` buffers
 * sit flush against a PROT_NONE page (END in the first pass, START in the second): the FIPS arm reads leading bytes and a
 * read outside [0, vlen) is a SIGSEGV. Context structs are exact-size buffers with a guard page too.
 * usage: main [--poison]            --poison perturbs one Rust result to prove the harness can fail. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/mman.h>
typedef uint8_t u8;
struct rsa_key { const u8 *n, *e, *d, *p, *q, *dp, *dq, *qinv; size_t n_sz, e_sz, d_sz, p_sz, q_sz, dp_sz, dq_sz, qinv_sz; };
typedef int (*fn_t)(void *, size_t, unsigned char, const void *, size_t);
#define F(x) int c_rsa_get_##x(void *, size_t, unsigned char, const void *, size_t); int rsa_get_##x(void *, size_t, unsigned char, const void *, size_t);
F(n) F(e) F(d) F(p) F(q) F(dp) F(dq) F(qinv)
static const char *names[8] = { "n", "e", "d", "p", "q", "dp", "dq", "qinv" };
static fn_t cf[8] = { c_rsa_get_n, c_rsa_get_e, c_rsa_get_d, c_rsa_get_p, c_rsa_get_q, c_rsa_get_dp, c_rsa_get_dq, c_rsa_get_qinv };
static fn_t rf[8] = { rsa_get_n, rsa_get_e, rsa_get_d, rsa_get_p, rsa_get_q, rsa_get_dp, rsa_get_dq, rsa_get_qinv };

int fips_enabled;                       /* used by the FIPS=1 builds only */
static char pbuf[512]; static int pn;
int _printk(const char *fmt, ...) { pn++; snprintf(pbuf, sizeof pbuf, "%s", fmt); return 0; }   /* the format only: no arguments are used */

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
static u8 *rg[6];
static u8 *place(int r, int len, int mode) { return mode == 0 ? rg[r] + PG - len : rg[r]; }
static void bad(const char *what, int fn, size_t n_sz, size_t vlen, int fips)
{
	if (fails++ < 10) fprintf(stderr, "MISMATCH %s fn=%s n_sz=%zu vlen=%zu fips=%d\n", what, names[fn], n_sz, vlen, fips);
}
/* the rules, stated once more here from the header comment of the Rust file / the C text */
static int spec_ok(int fn, const u8 *value, size_t n_sz, size_t vlen, int fips)
{
	if (!value || !vlen) return 0;
	if (fn == 0) {
		if (fips) { size_t z = 0; while (z < vlen && value[z] == 0) z++; if (vlen - z < 256) return 0; }
		return 1;
	}
	if (fn == 1 || fn == 2) return n_sz != 0 && vlen <= n_sz;
	return vlen <= n_sz;
}
static size_t *field_sz(struct rsa_key *k, int fn) { size_t *p[8] = { &k->n_sz, &k->e_sz, &k->d_sz, &k->p_sz, &k->q_sz, &k->dp_sz, &k->dq_sz, &k->qinv_sz }; return p[fn]; }
static const u8 **field_ptr(struct rsa_key *k, int fn) { const u8 **p[8] = { &k->n, &k->e, &k->d, &k->p, &k->q, &k->dp, &k->dq, &k->qinv }; return p[fn]; }

static void one(int fn, size_t n_sz, size_t vlen, int zeros, int null_value, int fips, int mode)
{
	u8 *vC = place(0, vlen, mode);
	struct rsa_key *kc = (struct rsa_key *)place(1, sizeof(struct rsa_key), mode), *kr = (struct rsa_key *)place(2, sizeof(struct rsa_key), mode), pre;
	const u8 *value = null_value ? NULL : vC;
	int rc, rr, ok, pn_c, pn_r; char msg_c[512];
	size_t i;
	for (i = 0; i < vlen; i++) vC[i] = (u8)rnd() | 1;
	for (i = 0; i < vlen && i < (size_t)zeros; i++) vC[i] = 0;
	for (i = 0; i < sizeof pre; i++) ((u8 *)&pre)[i] = (u8)rnd();
	pre.n_sz = n_sz;                         /* context as the decoder leaves it: other fields arbitrary, n_sz as set */
	memcpy(kc, &pre, sizeof pre); memcpy(kr, &pre, sizeof pre);
	fips_enabled = fips;
	pn = 0; rc = cf[fn](kc, 3, 2, value, vlen); pn_c = pn; strcpy(msg_c, pbuf);
	pn = 0; rr = rf[fn](kr, 3, 2, value, vlen); pn_r = pn;
	if (poison && !poisoned && fn == 2 && vlen == 5) { rr = 0; poisoned = 1; kr->e_sz ^= 1; }
	ok = spec_ok(fn, value, n_sz, vlen, fips);
	n_cmp += 6;
	if (rc != rr) bad("return C vs Rust", fn, n_sz, vlen, fips);
	if (rr != (ok ? 0 : -EINVAL)) bad("return Rust vs spec", fn, n_sz, vlen, fips);
	if (memcmp(kc, kr, sizeof pre)) bad("struct rsa_key C vs Rust", fn, n_sz, vlen, fips);
	if (pn_c != pn_r || (pn_c && strcmp(msg_c, pbuf))) bad("printk C vs Rust", fn, n_sz, vlen, fips);
	/* spec: on success the field and its size are stored (n also sets n_sz = vlen), nothing else changes; on failure nothing */
	{
		struct rsa_key want = pre;
		if (ok) { *field_ptr(&want, fn) = value; *field_sz(&want, fn) = vlen; }
		if (memcmp(&want, kr, sizeof want)) bad("struct rsa_key Rust vs spec", fn, n_sz, vlen, fips);
	}
	if (fn == 0 && fips && !ok && value && vlen && pn_r != 1) bad("FIPS error not printed once", fn, n_sz, vlen, fips);
	if (!(fn == 0 && fips && !ok && value && vlen) && pn_r) bad("unexpected printk", fn, n_sz, vlen, fips);
	if (pn_r && strcmp(pbuf, "\001" "3RSA: key size not allowed in FIPS mode\n")) bad("printk text", fn, n_sz, vlen, fips);
}

int main(int argc, char **argv)
{
	int nfips =
#ifdef FIPS
		2;
#else
		1;
#endif
	poison = argc > 1 && !strcmp(argv[1], "--poison");
	for (int i = 0; i < 6; i++) rg[i] = region();
	for (int fips = 0; fips < nfips; fips++)
		for (int mode = 0; mode < 2; mode++)
			for (int fn = 0; fn < 8; fn++) {
				/* every (n_sz, vlen) in 0..300 x 0..300 sampled densely around the boundaries 0, 1, 255, 256, 257 */
				for (size_t n_sz = 0; n_sz <= 300; n_sz += (n_sz < 4 || (n_sz > 250 && n_sz < 262)) ? 1 : 7)
					for (size_t vlen = 0; vlen <= 300; vlen++)
						for (int z = 0; z < 3; z++)
							one(fn, n_sz, vlen, z == 0 ? 0 : z == 1 ? 1 : (int)(rnd() % 40), 0, fips, mode);
				for (size_t n_sz = 0; n_sz < 4; n_sz++) for (size_t vlen = 0; vlen < 4; vlen++) one(fn, n_sz, vlen, 0, 1, fips, mode);   /* NULL value */
			}
	/* FIPS: leading zeros around the 256-byte threshold, exhaustively */
	for (int fips = 0; fips < nfips; fips++)
		for (size_t vlen = 250; vlen <= 300; vlen++)
			for (int z = 0; z <= (int)vlen; z += 1) one(0, 0, vlen, z, 0, fips, (int)(rnd() & 1));
	/* random contexts */
	for (long k = 0; k < 400000; k++)
		one((int)(rnd() % 8), rnd() % 600, rnd() % 600, (int)(rnd() % 300), (rnd() % 50) == 0, nfips == 2 ? (int)(rnd() & 1) : 0, (int)(rnd() & 1));
	printf("rsa_helper (FIPS build=%d): %llu comparisons, %llu failure(s)\n", nfips == 2, n_cmp, fails);
	return fails ? 1 : 0;
}
