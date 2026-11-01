/* SPDX-License-Identifier: GPL-2.0 */
/* Differential for crypto/rsa.c: the UNMODIFIED pristine file compiled as a userspace TU (c_arm.c) against rsa_glue.c +
 * rsa_rs.rs (r_arm.c + the Rust staticlib), through their akcipher_alg tables, over the GMP mock MPI layer (mpi_mock.c) that
 * injects failures at every MPI creation and every MPI operation and records a trace of every call with its operand values.
 * Compared per scenario between the arms: return value, the destination bytes with canaries, the trace hash (same calls, same
 * order, same operands), the call count, the number of live MPIs afterwards (a leak or a double free shows), and the key
 * state (which of the 8 MPIs are set, with what values). Independent oracle (GMP, never the code under test): c = m^e mod n,
 * m = c^d mod n (plain, not CRT), the payload range 1 < x < n - 1, -EOVERFLOW when the result does not fit, the key-size rule.
 * Built with FIPS unset (as both kernel configs) and with FIPS (the cfg arm, fips_enabled run as 0 and 1).
 * usage: main [--poison] */
#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include "shim.h"

struct akcipher_alg *c_alg(void);
struct akcipher_alg *r_alg(void);
extern long g_create_seq, g_fail_create_at, g_op_seq, g_fail_op_at, g_live, g_calls;
extern uint64_t g_trace;
extern int g_parse_ret, g_sign_neg;
mpz_ptr mock_z(MPI a);
struct parse_in { struct rsa_key k; };
static unsigned long long n_cmp, fails;
static int poison, poisoned;
static gmp_randstate_t rst;
static void bad(const char *what, const char *ctx) { if (fails++ < 12) fprintf(stderr, "MISMATCH %s [%s]\n", what, ctx); }

/* ---- keys */
struct tkey {
	int bits; mpz_t n, e, d, p, q, dp, dq, qinv;
	u8 *f[8]; size_t sz[8]; struct parse_in pin; mpz_ptr v[8];
};
static void put_be(struct tkey *k, int i, mpz_t v, int zpad)
{
	size_t cnt, len = mpz_sgn(v) ? (mpz_sizeinbase(v, 2) + 7) / 8 : 1;
	u8 *b = calloc(1, len + zpad + 1);
	if (mpz_sgn(v)) mpz_export(b + zpad, &cnt, 1, 1, 0, 0, v);
	k->f[i] = b; k->sz[i] = len + zpad;
}
static void mkkey(struct tkey *k, int bits, unsigned long e, int zpad, int consistent)
{
	mpz_t phi, t, p1, q1; int tries = 0;
	mpz_inits(k->n, k->e, k->d, k->p, k->q, k->dp, k->dq, k->qinv, phi, t, p1, q1, NULL);
	k->bits = bits;
	do {
		mpz_urandomb(k->p, rst, bits / 2); mpz_setbit(k->p, bits / 2 - 1); mpz_setbit(k->p, bits / 2 - 2); mpz_nextprime(k->p, k->p);
		mpz_urandomb(k->q, rst, bits - bits / 2); mpz_setbit(k->q, bits - bits / 2 - 1); mpz_setbit(k->q, bits - bits / 2 - 2); mpz_nextprime(k->q, k->q);
		mpz_mul(k->n, k->p, k->q);
		mpz_sub_ui(p1, k->p, 1); mpz_sub_ui(q1, k->q, 1); mpz_mul(phi, p1, q1);
		mpz_set_ui(k->e, e); mpz_gcd(t, k->e, phi);
		if (++tries > 50) { fprintf(stderr, "key generation failed\n"); exit(2); }
	} while (mpz_cmp_ui(t, 1) != 0 || (int)mpz_sizeinbase(k->n, 2) != bits || mpz_cmp(k->p, k->q) == 0);
	(void)consistent;
	mpz_invert(k->d, k->e, phi);
	mpz_mod(k->dp, k->d, p1); mpz_mod(k->dq, k->d, q1); mpz_invert(k->qinv, k->q, k->p);
	put_be(k, 0, k->n, zpad); put_be(k, 1, k->e, zpad ? zpad - 1 : 0); put_be(k, 2, k->d, zpad);
	put_be(k, 3, k->p, zpad); put_be(k, 4, k->q, zpad); put_be(k, 5, k->dp, zpad ? 1 : 0); put_be(k, 6, k->dq, 0); put_be(k, 7, k->qinv, zpad);
	k->pin.k.n = k->f[0]; k->pin.k.e = k->f[1]; k->pin.k.d = k->f[2]; k->pin.k.p = k->f[3]; k->pin.k.q = k->f[4];
	k->pin.k.dp = k->f[5]; k->pin.k.dq = k->f[6]; k->pin.k.qinv = k->f[7];
	k->pin.k.n_sz = k->sz[0]; k->pin.k.e_sz = k->sz[1]; k->pin.k.d_sz = k->sz[2]; k->pin.k.p_sz = k->sz[3]; k->pin.k.q_sz = k->sz[4];
	k->pin.k.dp_sz = k->sz[5]; k->pin.k.dq_sz = k->sz[6]; k->pin.k.qinv_sz = k->sz[7];
	mpz_clears(phi, t, p1, q1, NULL);
}
static void setexp(struct tkey *k, mpz_t e)   /* an arbitrary exponent field (key not RSA-consistent: for the load rules only) */
{
	free(k->f[1]); put_be(k, 1, e, 0); k->pin.k.e = k->f[1]; k->pin.k.e_sz = k->sz[1]; mpz_set(k->e, e);
}

/* ---- one arm's transform: a context of 8 MPI pointers */
struct arm { struct akcipher_alg *alg; struct crypto_akcipher tfm; };
static void arm_init(struct arm *a, struct akcipher_alg *alg) { a->alg = alg; memset(&a->tfm, 0, sizeof a->tfm); a->tfm.base.ctx = calloc(8, sizeof(MPI)); }
static void arm_free(struct arm *a) { a->alg->exit(&a->tfm); free(a->tfm.base.ctx); }
static void arm_nofault(void) { g_fail_create_at = g_fail_op_at = -1; g_parse_ret = 0; }
static void arm_reset(void) { g_create_seq = g_op_seq = g_calls = 0; g_trace = 1469598103934665603ULL; }

struct snap { long ret; uint64_t trace; long live, calls, creates, ops; char key[8 * 1200]; u8 dst[1100]; size_t dstn; };
static void snap_key(struct arm *a, struct snap *s)
{
	MPI *c = a->tfm.base.ctx; char *p = s->key; *p = 0;
	for (int i = 0; i < 8; i++) {
		if (!c[i]) { p += sprintf(p, "-;"); continue; }
		p += gmp_sprintf(p, "%Zx;", mock_z(c[i]));
	}
}
static int snap_eq(const struct snap *x, const struct snap *y)
{
	return x->ret == y->ret && x->trace == y->trace && x->live == y->live && x->calls == y->calls && !strcmp(x->key, y->key)
		&& x->dstn == y->dstn && !memcmp(x->dst, y->dst, x->dstn);
}

/* set a key; `old` first loads a good key (so the old key is freed); faults armed only for the measured call */
static void do_set(struct akcipher_alg *alg, int pub, struct tkey *k, struct tkey *oldk, long fc, long fo, int pret, struct snap *s)
{
	struct arm a; long base;
	arm_init(&a, alg); arm_nofault(); arm_reset();
	if (oldk) { if (pub) alg->set_pub_key(&a.tfm, &oldk->pin, 77); else alg->set_priv_key(&a.tfm, &oldk->pin, 77); }
	base = g_live; arm_reset(); g_fail_create_at = fc; g_fail_op_at = fo; g_parse_ret = pret;
	s->ret = pub ? alg->set_pub_key(&a.tfm, &k->pin, 99) : alg->set_priv_key(&a.tfm, &k->pin, 99);
	s->trace = g_trace; s->calls = g_calls; s->creates = g_create_seq; s->ops = g_op_seq; s->live = g_live - base;
	snap_key(&a, s); s->dstn = 0; arm_nofault();
	/* max_size, when the modulus is there */
	{ MPI *c = a.tfm.base.ctx; if (c[0]) s->live = s->live * 1000 + alg->max_size(&a.tfm); }
	arm_free(&a);
	if (g_live != 0) bad("MPIs still live after the transform exit (leak)", alg == c_alg() ? "C arm" : "Rust arm");
	(void)base;
}

/* run an operation: key loaded first (pub or priv), then the request with faults armed */
static void do_op(struct akcipher_alg *alg, int enc, int load_pub, int load_none, struct tkey *k, const u8 *src, unsigned slen, unsigned dlen,
		  long fc, long fo, struct snap *s)
{
	struct arm a; struct akcipher_request req; struct scatterlist sg_s, sg_d; long base;
	u8 *sb = malloc(slen + 1), *db = malloc(dlen + 16);
	arm_init(&a, alg); arm_nofault(); arm_reset();
	if (!load_none || load_none == 2) { if (load_pub) alg->set_pub_key(&a.tfm, &k->pin, 99); else alg->set_priv_key(&a.tfm, &k->pin, 99); }
	if (load_none == 2) { MPI *c = a.tfm.base.ctx; mpi_free(c[1]); c[1] = NULL; }    /* a partial key: n set, e gone */
	base = g_live; arm_reset(); g_fail_create_at = fc; g_fail_op_at = fo;
	memcpy(sb, src, slen); memset(db, 0xA5, dlen + 16);
	sg_s.buf = sb; sg_s.len = slen; sg_d.buf = db; sg_d.len = dlen;
	req.tfm = &a.tfm; req.src = &sg_s; req.dst = &sg_d; req.src_len = slen; req.dst_len = dlen;
	s->ret = enc ? alg->encrypt(&req) : alg->decrypt(&req);
	s->trace = g_trace; s->calls = g_calls; s->creates = g_create_seq; s->ops = g_op_seq; s->live = g_live - base;
	arm_nofault(); snap_key(&a, s);
	s->dstn = dlen + 16 > sizeof s->dst ? sizeof s->dst : dlen + 16; memcpy(s->dst, db, s->dstn);
	if (memcmp(sb, src, slen)) s->ret = -123456;   /* the source must not be modified */
	arm_free(&a); free(sb); free(db);
}

static void sweep_set(struct tkey *k, struct tkey *oldk, int pub, const char *what)
{
	struct snap a, b; char ctx[160]; long nc, no;
	do_set(c_alg(), pub, k, oldk, -1, -1, 0, &a); do_set(r_alg(), pub, k, oldk, -1, -1, 0, &b);
	n_cmp++; snprintf(ctx, sizeof ctx, "%s pub=%d nominal bits=%d", what, pub, k->bits);
	if (poison && !poisoned && b.ret == 0) { b.ret = 1; poisoned = 1; }
	if (!snap_eq(&a, &b)) bad("set_key nominal C vs Rust", ctx);
	nc = a.creates; no = a.ops;
	for (long f = 0; f <= nc; f++) {
		do_set(c_alg(), pub, k, oldk, f, -1, 0, &a); do_set(r_alg(), pub, k, oldk, f, -1, 0, &b); n_cmp++;
		snprintf(ctx, sizeof ctx, "%s pub=%d create-fault %ld", what, pub, f);
		if (!snap_eq(&a, &b)) bad("set_key create fault C vs Rust", ctx);
	}
	for (long f = 0; f <= no; f++) {
		do_set(c_alg(), pub, k, oldk, -1, f, 0, &a); do_set(r_alg(), pub, k, oldk, -1, f, 0, &b); n_cmp++;
		snprintf(ctx, sizeof ctx, "%s pub=%d op-fault %ld", what, pub, f);
		if (!snap_eq(&a, &b)) bad("set_key op fault C vs Rust", ctx);
	}
	for (int pr = -1; pr >= -2; pr--) {
		do_set(c_alg(), pub, k, oldk, -1, -1, pr * 11, &a); do_set(r_alg(), pub, k, oldk, -1, -1, pr * 11, &b); n_cmp++;
		snprintf(ctx, sizeof ctx, "%s pub=%d parse error %d", what, pub, pr * 11);
		if (!snap_eq(&a, &b)) bad("set_key parse error C vs Rust", ctx);
		if (a.ret != pr * 11) bad("parse error not returned", ctx);
	}
}
static int size_ok(int bits_by_limbs, int fips)
{
	switch (bits_by_limbs) { case 512: case 1024: case 1536: return !fips; case 2048: case 3072: case 4096: return 1; }
	return 0;
}
static int bytes_of(mpz_t v) { return mpz_sgn(v) ? (int)((mpz_sizeinbase(v, 2) + 7) / 8) : 0; }

static void sweep_op(struct tkey *k, int enc, int load_pub, int load_none, mpz_t x, int xbytes_extra, unsigned dlen_delta, const char *what)
{
	size_t kbytes = bytes_of(k->n), slen = kbytes + xbytes_extra; u8 *src = calloc(1, slen + 8); struct snap a, b; char ctx[200];
	unsigned dlen; long nc, no; size_t cnt;
	if (bytes_of(x) > (int)slen) { free(src); return; }
	if (mpz_sgn(x)) mpz_export(src + (slen - bytes_of(x)), &cnt, 1, 1, 0, 0, x);
	dlen = (unsigned)kbytes + dlen_delta;
	do_op(c_alg(), enc, load_pub, load_none, k, src, slen, dlen, -1, -1, &a); do_op(r_alg(), enc, load_pub, load_none, k, src, slen, dlen, -1, -1, &b);
	n_cmp++; snprintf(ctx, sizeof ctx, "%s enc=%d pub=%d none=%d slen=%zu dlen=%u bits=%d", what, enc, load_pub, load_none, slen, dlen, k->bits);
	if (poison && !poisoned && b.ret == 0) { b.ret = 5; poisoned = 1; if (snap_eq(&a, &b)) bad("poison not seen", ctx); }
	if (!snap_eq(&a, &b)) bad("op nominal C vs Rust", ctx);
	nc = a.creates; no = a.ops;
	/* the independent oracle, on the no-fault run */
	{
		mpz_t r, nm1; int expect; mpz_inits(r, nm1, NULL); mpz_sub_ui(nm1, k->n, 1);
		if (load_none == 1 || load_none == 2) expect = -EINVAL;
		else if (!enc && load_pub) expect = -EINVAL;                 /* no d in a public key */
		else if (mpz_cmp_ui(x, 1) <= 0 || mpz_cmp(x, nm1) >= 0) expect = -EINVAL;
		else {
			mpz_powm(r, x, enc ? k->e : k->d, k->n);                    /* plain powm, NOT the CRT */
			expect = (unsigned)(mpz_size(r) * 8) > dlen ? -EOVERFLOW : 0;      /* mpi_write_to_sgl: nbytes < mpi_get_size(a) = nlimbs * 8 */
			if (expect == 0) {
				u8 *want = calloc(1, dlen + 1); size_t c2;
				if (mpz_sgn(r)) mpz_export(want + (dlen - bytes_of(r)), &c2, 1, 1, 0, 0, r);
				if (memcmp(a.dst, want, dlen)) bad("result differs from the GMP oracle", ctx);
				for (unsigned i = dlen; i < a.dstn; i++) if (a.dst[i] != 0xA5) bad("canary overwritten", ctx);
				free(want);
			}
		}
		n_cmp++;
		if (a.ret != expect) { char m[64]; snprintf(m, sizeof m, "return %ld, oracle %d", a.ret, expect); bad(m, ctx); }
		mpz_clears(r, nm1, NULL);
	}
	for (long f = 0; f <= nc; f++) {
		do_op(c_alg(), enc, load_pub, load_none, k, src, slen, dlen, f, -1, &a); do_op(r_alg(), enc, load_pub, load_none, k, src, slen, dlen, f, -1, &b); n_cmp++;
		snprintf(ctx, sizeof ctx, "%s enc=%d create-fault %ld", what, enc, f);
		if (!snap_eq(&a, &b)) bad("op create fault C vs Rust", ctx);
		if (a.live != 0) bad("leak after a create fault (C)", ctx);
	}
	for (long f = 0; f <= no; f++) {
		do_op(c_alg(), enc, load_pub, load_none, k, src, slen, dlen, -1, f, &a); do_op(r_alg(), enc, load_pub, load_none, k, src, slen, dlen, -1, f, &b); n_cmp++;
		snprintf(ctx, sizeof ctx, "%s enc=%d op-fault %ld", what, enc, f);
		if (!snap_eq(&a, &b)) bad("op fault C vs Rust", ctx);
		if (a.live != 0) bad("leak after an op fault (C)", ctx);
	}
	free(src);
}

int main(int argc, char **argv)
{
	static const int accepted[] = { 512, 1024, 1536, 2048, 3072, 4096 };
	static const int rejected[] = { 700, 1088, 1100, 1200, 2112, 3000 };
	int nfips =
#ifdef FIPS
		2;
#else
		1;
#endif
	poison = argc > 1 && !strcmp(argv[1], "--poison");
	gmp_randinit_mt(rst); gmp_randseed_ui(rst, 20261005);
	for (int fips = 0; fips < nfips; fips++) {
#ifdef FIPS
		extern int fips_enabled; fips_enabled = fips;
#endif
		/* ---- key loading: sizes, exponents, old key present or not */
		for (unsigned i = 0; i < sizeof accepted / sizeof *accepted + sizeof rejected / sizeof *rejected; i++) {
			int bits = i < sizeof accepted / sizeof *accepted ? accepted[i] : rejected[i - sizeof accepted / sizeof *accepted];
			struct tkey k, old; mkkey(&k, bits, 65537, i % 3, 1); mkkey(&old, 1024, 65537, 0, 1);
			for (int pub = 0; pub < 2; pub++) {
				sweep_set(&k, NULL, pub, "fresh"); sweep_set(&k, &old, pub, "replacing");
				/* the rule: the key loads iff the limb-rounded modulus size is accepted */
				{ struct snap s; int limbs_bits = (int)((mpz_size(k.n) * 64)); do_set(c_alg(), pub, &k, NULL, -1, -1, 0, &s); n_cmp++;
				  if ((s.ret == 0) != size_ok(limbs_bits, fips) || (s.ret && s.ret != -EINVAL)) bad("key size rule", "set"); }
			}
		}
		{ /* exponents under FIPS: odd, 2^16 < e < 2^256 */
			struct tkey k; mkkey(&k, 2048, 65537, 0, 1);
			static const char *es[] = { "3", "10001", "10003", "65538", "10000", "10001", "1000000000000000000000000000000000000000000000000000000000000001",
				"10000000000000000000000000000000000000000000000000000000000000001", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
				"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "2" };
			for (unsigned i = 0; i < sizeof es / sizeof *es; i++) {
				mpz_t e; mpz_init_set_str(e, es[i], 16); setexp(&k, e);
				for (int pub = 0; pub < 2; pub++) sweep_set(&k, NULL, pub, "exponent");
				{ struct snap s; do_set(c_alg(), 1, &k, NULL, -1, -1, 0, &s); n_cmp++;
				  int ok_e = !fips || (mpz_tstbit(e, 0) && mpz_cmp_ui(e, 65536) > 0 && mpz_sizeinbase(e, 2) <= 256);
				  if ((s.ret == 0) != ok_e) { char m[100]; snprintf(m, sizeof m, "exponent rule (fips %d, e=%s, ret %ld)", fips, es[i], s.ret); bad(m, "set"); } }
				mpz_clear(e);
			}
		}
		/* ---- operations on consistent keys */
		for (int kb = 0; kb < 3; kb++) {
			int bits = kb == 0 ? 512 : kb == 1 ? 1024 : 2048;
			struct tkey k;
			if (fips && bits < 2048) continue;       /* the load rule rejects them under FIPS (covered above) */
			mkkey(&k, bits, 65537, kb, 1);
			{
				mpz_t x, nm1, t; mpz_inits(x, nm1, t, NULL); mpz_sub_ui(nm1, k.n, 1);
				static const int specials = 9;
				for (int enc = 0; enc < 2; enc++)
					for (int sp = 0; sp < specials + 4; sp++) {
						switch (sp) {
						case 0: mpz_set_ui(x, 0); break;
						case 1: mpz_set_ui(x, 1); break;
						case 2: mpz_set_ui(x, 2); break;
						case 3: mpz_sub_ui(x, k.n, 2); break;
						case 4: mpz_set(x, nm1); break;
						case 5: mpz_set(x, k.n); break;
						case 6: mpz_add_ui(x, k.n, 1); break;
						case 7: mpz_set_ui(x, 3); break;
						case 8: mpz_sub_ui(x, k.n, 3); break;
						default: mpz_urandomm(x, rst, nm1); if (mpz_cmp_ui(x, 1) <= 0) mpz_set_ui(x, 5); break;
						}
						for (int extra = 0; extra < 3; extra++)
							for (int dd = -2; dd <= 1; dd++) {
								if (dd == 1 && sp > 4 && extra) continue;
								sweep_op(&k, enc, enc ? 1 : 0, 0, x, extra, (unsigned)dd, "op");
							}
					}
				/* no key / wrong key state */
				mpz_set_ui(x, 2);
				for (int enc = 0; enc < 2; enc++) { sweep_op(&k, enc, 1, 1, x, 0, 0, "no key"); }
				sweep_op(&k, 0, 1, 0, x, 0, 0, "decrypt with a public key");
				sweep_op(&k, 1, 0, 0, x, 0, 0, "encrypt with a private key (has e)");
				sweep_op(&k, 1, 1, 2, x, 0, 0, "encrypt with n set and e missing");
				/* a negative result from the MPI layer is -EBADMSG (never happens for these inputs; forced in the mock) */
				for (int enc = 0; enc < 2; enc++) {
					struct snap a, b; u8 *src = calloc(1, bytes_of(k.n)); size_t cnt; char ctx[100]; mpz_t t; mpz_init(t);
					mpz_export(src + (bytes_of(k.n) - 1), &cnt, 1, 1, 0, 0, x);
					g_sign_neg = 1;
					do_op(c_alg(), enc, enc, 0, &k, src, bytes_of(k.n), bytes_of(k.n), -1, -1, &a); do_op(r_alg(), enc, enc, 0, &k, src, bytes_of(k.n), bytes_of(k.n), -1, -1, &b);
					g_sign_neg = 0; n_cmp += 2; snprintf(ctx, sizeof ctx, "forced negative result enc=%d", enc);
					if (!snap_eq(&a, &b)) bad("negative result C vs Rust", ctx);
					if (a.ret != -EBADMSG) bad("negative result is not -EBADMSG", ctx);
					free(src); mpz_clear(t);
				}
				mpz_clears(x, nm1, t, NULL);
			}
		}
	}
	/* random keys, payloads and sizes on top of the fixed scenarios */
	for (int fips = 0; fips < nfips; fips++) {
#ifdef FIPS
		extern int fips_enabled; fips_enabled = fips;
#endif
		for (int it = 0; it < 40; it++) {
			static const int bs[] = { 512, 1024, 1536, 2048 };
			int bits = bs[gmp_urandomm_ui(rst, 4)], enc = (int)gmp_urandomm_ui(rst, 2); struct tkey k; mpz_t x; unsigned long es[] = { 3, 65537, 17, 257 };
			if (fips && bits < 2048) bits = 2048;
			mkkey(&k, bits, fips ? 65537 : es[gmp_urandomm_ui(rst, 4)], (int)gmp_urandomm_ui(rst, 4), 1);   /* FIPS rejects e <= 2^16 at key load */
			mpz_init(x); mpz_urandomb(x, rst, bits - (int)gmp_urandomm_ui(rst, 12)); if (mpz_cmp(x, k.n) >= 0) mpz_mod(x, x, k.n);
			if (mpz_cmp_ui(x, 1) <= 0) mpz_set_ui(x, 7);
			sweep_op(&k, enc, enc, 0, x, (int)gmp_urandomm_ui(rst, 3), (unsigned)((int)gmp_urandomm_ui(rst, 4) - 2), "random");
			mpz_clear(x);
		}
	}
	printf("rsa (FIPS build=%d): %llu comparisons, %llu failure(s)\n", nfips == 2, n_cmp, fails);
	return fails ? 1 : 0;
}
