/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * port/test/mpi-mul-pow/drv.c -- differential for lib/crypto/mpi/mpi-mul.c
 * -> mpi_mul_rs.rs (mpi_mul, mpi_mulm) and lib/crypto/mpi/mpi-pow.c ->
 * mpi_pow_rs.rs (mpi_powm).
 *
 * mpi_alloc/mpi_resize/mpi_free/mpi_tdiv_r (mpiutil_rs.rs, mpi_div_rs.rs),
 * mpihelp_mul/mpihelp_mul_karatsuba_case/mpihelp_release_karatsuba_ctx/
 * mpih_sqr_n_basecase/mpih_sqr_n (mpih_mul_rs.rs), mpihelp_lshift/
 * mpihelp_rshift (generic_mpih_rs.rs), mpihelp_divrem (mpih_div_rs.rs) are
 * shared dependencies, already ported and verified by their own harnesses,
 * linked into both arms unchanged -- not under test here.
 *
 * Independent oracle: OpenSSL's BIGNUM (BN_mul/BN_mod_mul/BN_mod_exp) --
 * a completely separate, independently-implemented bignum library, not
 * derived from or related to GMP/libgcrypt's MPI at all. Values move
 * between MPI's sign-magnitude little-endian limb array and a BIGNUM via
 * BN_lebin2bn()/BN_set_negative(), which is exact on this little-endian
 * machine (a native unsigned long array's raw bytes already are the
 * number's little-endian byte representation).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <openssl/bn.h>

#define MAXLIMBS 80

typedef unsigned long mpi_limb_t;
struct gcry_mpi {
	int alloced;
	int nlimbs;
	int nbits;
	int sign;
	unsigned flags;
	mpi_limb_t *d;
};
typedef struct gcry_mpi *MPI;

/* ---- Shared dependencies: ONE implementation, linked into both arms ---- */
MPI mpi_alloc(unsigned nlimbs);
void mpi_free(MPI a);
int mpi_resize(MPI a, unsigned nlimbs);
int mpi_tdiv_r(MPI rem, MPI num, MPI den);

/* ---- C arm (renamed via -D, see run.sh) ---- */
int c_mpi_mul(MPI w, MPI u, MPI v);
int c_mpi_mulm(MPI w, MPI u, MPI v, MPI m);
int c_mpi_powm(MPI res, MPI base, MPI exp, MPI mod);

/* ---- Rust arm (kept at the real names) ---- */
int mpi_mul(MPI w, MPI u, MPI v);
int mpi_mulm(MPI w, MPI u, MPI v, MPI m);
int mpi_powm(MPI res, MPI base, MPI exp, MPI mod);

static unsigned long cases, mism;
static int poison;
static BN_CTX *bnctx;

static void bad(const char *what)
{
	if (mism < 20)
		printf("MISMATCH %s\n", what);
	mism++;
}

/* xorshift32, not a textbook LCG: an LCG with an odd multiplier and odd
 * increment (as used elsewhere in this project's harnesses) has a
 * DETERMINISTIC low bit -- it alternates 0/1/0/1... every call regardless
 * of state, a well-known LCG weakness. That silently zeroed out this
 * harness's coverage of odd/even exponent parity in the random sweep
 * (every call site that builds a value from consecutive rnd() calls ends
 * up with a fixed low-bit relationship between them). Found while
 * chasing why the random sweep never reproduced the hand-picked
 * negative-base/even-exponent case above. xorshift's low bit is not
 * degenerate this way.
 */
static uint32_t rnd_state = 0xFEEDFACE;
static uint32_t rnd(void)
{
	rnd_state ^= rnd_state << 13;
	rnd_state ^= rnd_state >> 17;
	rnd_state ^= rnd_state << 5;
	return rnd_state;
}

static MPI mk_mpi(int nlimbs, int sign, const mpi_limb_t *limbs)
{
	MPI m = mpi_alloc(nlimbs > 0 ? (unsigned)nlimbs : 1);
	int i;
	for (i = 0; i < nlimbs; i++)
		m->d[i] = limbs[i];
	m->nlimbs = nlimbs;
	m->sign = sign;
	return m;
}

static void fill_random_mpi(mpi_limb_t *a, int n)
{
	int i;
	for (i = 0; i < n; i++)
		a[i] = ((uint64_t)rnd() << 32) | rnd();
	while (n > 1 && a[n - 1] == 0)
		n--;
}

static int mpi_eq(MPI a, MPI b)
{
	if (a->nlimbs != b->nlimbs)
		return 0;
	if (a->nlimbs != 0 && a->sign != b->sign)
		return 0;
	return memcmp(a->d, b->d, (size_t)a->nlimbs * sizeof(mpi_limb_t)) == 0;
}

static BIGNUM *mpi_to_bn(MPI m)
{
	BIGNUM *b;
	if (m->nlimbs == 0) {
		b = BN_new();
		BN_zero(b);
		return b;
	}
	b = BN_lebin2bn((const unsigned char *)m->d,
			 (int)(m->nlimbs * sizeof(mpi_limb_t)), NULL);
	if (m->sign)
		BN_set_negative(b, 1);
	return b;
}

/* Compare MPI m against BIGNUM b, mathematically (sign included; a zero
 * MPI's sign is don't-care, matching every other harness's mpi_eq()). */
static int mpi_eq_bn(MPI m, const BIGNUM *b)
{
	BIGNUM *mb = mpi_to_bn(m);
	int eq = (BN_cmp(mb, b) == 0);
	BN_free(mb);
	return eq;
}

static void run_mul(int usize, int usign, const mpi_limb_t *up,
		     int vsize, int vsign, const mpi_limb_t *vp)
{
	MPI u1 = mk_mpi(usize, usign, up), v1 = mk_mpi(vsize, vsign, vp);
	MPI u2 = mk_mpi(usize, usign, up), v2 = mk_mpi(vsize, vsign, vp);
	MPI wc = mpi_alloc((unsigned)(usize + vsize + 2));
	MPI wr = mpi_alloc((unsigned)(usize + vsize + 2));
	int rc, rr;
	BIGNUM *bu, *bv, *expect;

	rc = c_mpi_mul(wc, u1, v1);
	rr = mpi_mul(wr, u2, v2);
	cases++;
	if (rc != rr)
		bad("mpi_mul: return code differs");
	cases++;
	if (!mpi_eq(wc, wr))
		bad("mpi_mul: arms disagree");

	bu = mpi_to_bn(u1);
	bv = mpi_to_bn(v1);
	expect = BN_new();
	BN_mul(expect, bu, bv, bnctx);
	cases++;
	if (rc == 0 && (!mpi_eq_bn(wc, expect) || !mpi_eq_bn(wr, expect)))
		bad("mpi_mul: disagrees with the independent BIGNUM reference");
	BN_free(bu); BN_free(bv); BN_free(expect);

	if (poison) {
		MPI wr2 = mpi_alloc((unsigned)(usize + vsize + 2));
		mpi_mul(wr2, u2, v2);
		if (wr2->nlimbs > 0) {
			wr2->d[0] ^= 1;
			cases++;
			/* Deliberately corrupted -- must now disagree. */
			if (!mpi_eq(wc, wr2))
				bad("mpi_mul: poisoned run (expected)");
		}
		mpi_free(wr2);
	}

	mpi_free(u1); mpi_free(v1); mpi_free(u2); mpi_free(v2);
	mpi_free(wc); mpi_free(wr);
}

/* Aliasing: w may be identical to u and/or v. */
static void run_mul_alias(int usize, int usign, const mpi_limb_t *up,
			   int vsize, int vsign, const mpi_limb_t *vp)
{
	/* w == u */
	{
		MPI wc = mk_mpi(usize, usign, up), vc = mk_mpi(vsize, vsign, vp);
		MPI wr = mk_mpi(usize, usign, up), vr = mk_mpi(vsize, vsign, vp);
		int rc = c_mpi_mul(wc, wc, vc);
		int rr = mpi_mul(wr, wr, vr);
		cases++;
		if (rc != rr || !mpi_eq(wc, wr))
			bad("mpi_mul: w==u aliasing, arms disagree");
		mpi_free(wc); mpi_free(vc); mpi_free(wr); mpi_free(vr);
	}
	/* w == v */
	{
		MPI wc = mk_mpi(vsize, vsign, vp), uc = mk_mpi(usize, usign, up);
		MPI wr = mk_mpi(vsize, vsign, vp), ur = mk_mpi(usize, usign, up);
		int rc = c_mpi_mul(wc, uc, wc);
		int rr = mpi_mul(wr, ur, wr);
		cases++;
		if (rc != rr || !mpi_eq(wc, wr))
			bad("mpi_mul: w==v aliasing, arms disagree");
		mpi_free(wc); mpi_free(uc); mpi_free(wr); mpi_free(ur);
	}
	/* w == u == v */
	{
		MPI wc = mk_mpi(usize, usign, up);
		MPI wr = mk_mpi(usize, usign, up);
		int rc = c_mpi_mul(wc, wc, wc);
		int rr = mpi_mul(wr, wr, wr);
		cases++;
		if (rc != rr || !mpi_eq(wc, wr))
			bad("mpi_mul: w==u==v aliasing, arms disagree");
		mpi_free(wc); mpi_free(wr);
	}
}

/* mpi_mulm: non-negative operands only, so truncated (mpi_tdiv_r) and
 * Euclidean (BN_mod_mul) remainders coincide -- see this harness's own
 * header comment on why that keeps the oracle comparison simple. */
static void run_mulm(int usize, const mpi_limb_t *up,
		      int vsize, const mpi_limb_t *vp,
		      int msize, const mpi_limb_t *mp)
{
	MPI u1 = mk_mpi(usize, 0, up), v1 = mk_mpi(vsize, 0, vp), m1 = mk_mpi(msize, 0, mp);
	MPI u2 = mk_mpi(usize, 0, up), v2 = mk_mpi(vsize, 0, vp), m2 = mk_mpi(msize, 0, mp);
	MPI wc = mpi_alloc((unsigned)(usize + vsize + 2));
	MPI wr = mpi_alloc((unsigned)(usize + vsize + 2));
	int rc, rr;
	BIGNUM *bu, *bv, *bm, *expect;

	rc = c_mpi_mulm(wc, u1, v1, m1);
	rr = mpi_mulm(wr, u2, v2, m2);
	cases++;
	if (rc != rr)
		bad("mpi_mulm: return code differs");
	cases++;
	if (!mpi_eq(wc, wr))
		bad("mpi_mulm: arms disagree");

	bu = mpi_to_bn(u1); bv = mpi_to_bn(v1); bm = mpi_to_bn(m1);
	expect = BN_new();
	BN_mod_mul(expect, bu, bv, bm, bnctx);
	cases++;
	if (rc == 0 && (!mpi_eq_bn(wc, expect) || !mpi_eq_bn(wr, expect)))
		bad("mpi_mulm: disagrees with the independent BIGNUM reference");
	BN_free(bu); BN_free(bv); BN_free(bm); BN_free(expect);

	mpi_free(u1); mpi_free(v1); mpi_free(m1);
	mpi_free(u2); mpi_free(v2); mpi_free(m2);
	mpi_free(wc); mpi_free(wr);
}

static void run_powm(int bsize, int bsign, const mpi_limb_t *bp,
		      int esize, const mpi_limb_t *ep,
		      int msize, const mpi_limb_t *mp)
{
	MPI base1 = mk_mpi(bsize, bsign, bp), exp1 = mk_mpi(esize, 0, ep), mod1 = mk_mpi(msize, 0, mp);
	MPI base2 = mk_mpi(bsize, bsign, bp), exp2 = mk_mpi(esize, 0, ep), mod2 = mk_mpi(msize, 0, mp);
	MPI resc = mpi_alloc((unsigned)(2 * msize + 2));
	MPI resr = mpi_alloc((unsigned)(2 * msize + 2));
	int rc, rr;
	BIGNUM *bb, *be, *bm, *expect;

	rc = c_mpi_powm(resc, base1, exp1, mod1);
	rr = mpi_powm(resr, base2, exp2, mod2);
	cases++;
	if (rc != rr)
		bad("mpi_powm: return code differs");
	cases++;
	if (!mpi_eq(resc, resr))
		bad("mpi_powm: arms disagree");

	/*
	 * mpi_powm()'s own sign handling: rsign starts as bsign and is
	 * corrected to a canonical (Euclidean, non-negative-when-mod-is-
	 * positive) representative ONLY when negative_result is true, i.e.
	 * only when the exponent is odd (`ep[0] & 1`). For a negative base
	 * with an EVEN exponent, the C leaves rsign == bsign uncorrected --
	 * found by this harness (Guard 12 shape: both arms agreed with each
	 * other and disagreed with the oracle, so the oracle's assumption
	 * was the thing that was wrong, not the port). Both arms reproduce
	 * this faithfully; skip the oracle assertion for that one shape
	 * rather than assert an "expected" value the real C does not
	 * produce -- BN_mod_exp always returns the canonical reduction.
	 */
	if (rc == 0 && !(bsign && !(ep[0] & 1))) {
		bb = mpi_to_bn(base1); be = mpi_to_bn(exp1); bm = mpi_to_bn(mod1);
		expect = BN_new();
		BN_mod_exp(expect, bb, be, bm, bnctx);
		cases++;
		if (!mpi_eq_bn(resc, expect) || !mpi_eq_bn(resr, expect)) {
			int i2;
			bad("mpi_powm: disagrees with the independent BIGNUM reference");
			if (mism <= 20) {
				char *bs = BN_bn2hex(bb), *es = BN_bn2hex(be), *ms = BN_bn2hex(bm), *xs = BN_bn2hex(expect);
				printf("  base=%s(sign=%d) exp=%s mod=%s bignum_expect=%s\n", bs, bsign, es, ms, xs);
				printf("  resc(nlimbs=%d,sign=%d):", resc->nlimbs, resc->sign);
				for (i2 = 0; i2 < resc->nlimbs; i2++) printf(" %016lx", resc->d[i2]);
				printf("\n");
				OPENSSL_free(bs); OPENSSL_free(es); OPENSSL_free(ms); OPENSSL_free(xs);
			}
		}
		BN_free(bb); BN_free(be); BN_free(bm); BN_free(expect);
	}

	if (poison && rc == 0) {
		MPI resr2 = mpi_alloc((unsigned)(2 * msize + 2));
		mpi_powm(resr2, base2, exp2, mod2);
		if (resr2->nlimbs > 0) {
			resr2->d[0] ^= 1;
			cases++;
			/* Deliberately corrupted -- must now disagree. */
			if (!mpi_eq(resc, resr2))
				bad("mpi_powm: poisoned run (expected)");
		}
		mpi_free(resr2);
	}

	mpi_free(base1); mpi_free(exp1); mpi_free(mod1);
	mpi_free(base2); mpi_free(exp2); mpi_free(mod2);
	mpi_free(resc); mpi_free(resr);
}

int main(void)
{
	unsigned n;
	mpi_limb_t up[MAXLIMBS], vp[MAXLIMBS], mp[MAXLIMBS], ep[MAXLIMBS];

	if (getenv("MPIMULPOW_PROVE_CAN_FAIL"))
		poison = 1;
	bnctx = BN_CTX_new();

	/* mpi_mul: hand-picked. */
	{
		mpi_limb_t seven[1] = { 7 }, five[1] = { 5 };
		run_mul(1, 0, seven, 1, 0, five);
		run_mul(1, 1, seven, 1, 0, five);
		run_mul(1, 0, seven, 1, 1, five);
		run_mul(1, 1, seven, 1, 1, five);
	}
	{
		/* usize < vsize: the swap-U-and-V path. */
		mpi_limb_t small[1] = { 3 };
		mpi_limb_t big[2] = { 0x123456789ULL, 7 };
		run_mul(1, 0, small, 2, 0, big);
	}
	{
		mpi_limb_t zero[1] = { 0 };
		mpi_limb_t five[1] = { 5 };
		run_mul(0, 0, zero, 1, 0, five); /* u == 0 */
		run_mul(1, 0, five, 0, 0, zero); /* v == 0 */
	}
	{
		fill_random_mpi(up, 3);
		fill_random_mpi(vp, 2);
		run_mul_alias(3, 0, up, 2, 0, vp);
	}

	/* mpi_mulm: hand-picked. */
	{
		mpi_limb_t seven[1] = { 7 }, five[1] = { 5 }, three[1] = { 3 };
		run_mulm(1, seven, 1, five, 1, three);
	}

	/* mpi_powm: hand-picked, covering the special branches. */
	{
		mpi_limb_t three[1] = { 3 }, five[1] = { 5 }, seven[1] = { 7 };
		run_powm(1, 0, three, 1, five, 1, seven); /* 3^5 mod 7 */
	}
	{
		/* Exponent zero. */
		mpi_limb_t base[1] = { 9 }, zero[1] = { 0 }, seven[1] = { 7 };
		run_powm(1, 0, base, 0, zero, 1, seven);
	}
	{
		/* Negative base, odd exponent -- negative_result path. */
		mpi_limb_t base[1] = { 3 }, exp[1] = { 5 }, mod[1] = { 7 };
		run_powm(1, 1, base, 1, exp, 1, mod); /* (-3)^5 mod 7 */
	}
	{
		/* Negative base, even exponent -- negative_result stays false. */
		mpi_limb_t base[1] = { 3 }, exp[1] = { 4 }, mod[1] = { 7 };
		run_powm(1, 1, base, 1, exp, 1, mod);
	}
	{
		/* base > mod: the "reduce the base first" path. */
		mpi_limb_t base[1] = { 20 }, exp[1] = { 3 }, mod[1] = { 7 };
		run_powm(1, 0, base, 1, exp, 1, mod);
	}
	{
		/* Modulus already normalized (top bit set): mod_shift_cnt == 0. */
		mpi_limb_t base[1] = { 5 }, exp[1] = { 3 };
		mpi_limb_t mod[1] = { (mpi_limb_t)1 << 63 | 1 };
		run_powm(1, 0, base, 1, exp, 1, mod);
	}
	{
		/* Large modulus/base/exponent: forces real Karatsuba recursion
		 * inside mpih_sqr_n / mpihelp_mul_karatsuba_case (msize/bsize
		 * >= KARATSUBA_THRESHOLD == 16). */
		fill_random_mpi(mp, 20);
		mp[19] |= (mpi_limb_t)1 << 63; /* keep it sizeable */
		fill_random_mpi(up, 20);
		fill_random_mpi(ep, 3);
		run_powm(20, 0, up, 3, ep, 20, mp);
	}

	/* Random sweep. */
	for (n = 0; n < 800; n++) {
		int usize = 1 + (int)(rnd() % 6);
		int vsize = 1 + (int)(rnd() % 6);
		int usign = (int)(rnd() & 1);
		int vsign = (int)(rnd() & 1);

		fill_random_mpi(up, usize);
		fill_random_mpi(vp, vsize);
		run_mul(usize, usign, up, vsize, vsign, vp);
	}
	for (n = 0; n < 300; n++) {
		int usize = 1 + (int)(rnd() % 4);
		int vsize = 1 + (int)(rnd() % 4);
		int msize = 1 + (int)(rnd() % 4);

		fill_random_mpi(up, usize);
		fill_random_mpi(vp, vsize);
		fill_random_mpi(mp, msize);
		if (mp[msize - 1] == 0)
			mp[msize - 1] = 1;
		run_mulm(usize, up, vsize, vp, msize, mp);
	}
	for (n = 0; n < 300; n++) {
		int bsize = 1 + (int)(rnd() % 4);
		int esize = 1 + (int)(rnd() % 3);
		int msize = 1 + (int)(rnd() % 4);
		int bsign = (int)(rnd() & 1);

		fill_random_mpi(up, bsize);
		fill_random_mpi(ep, esize);
		fill_random_mpi(mp, msize);
		if (mp[msize - 1] == 0)
			mp[msize - 1] = 1;
		run_powm(bsize, bsign, up, esize, ep, msize, mp);
	}

	if (mism) {
		fprintf(stderr, "%lu/%lu cases MISMATCHED\n", mism, cases);
		return 1;
	}
	printf("%lu cases, 0 mismatches\n", cases);
	return 0;
}
