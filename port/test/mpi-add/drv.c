/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * port/test/mpi-add/drv.c -- differential for lib/crypto/mpi/mpi-add.c ->
 * mpi_add_rs.rs (mpi_add, mpi_sub, mpi_addm, mpi_subm) and
 * lib/crypto/mpi/mpi-sub-ui.c -> mpi_sub_ui_rs.rs (mpi_sub_ui).
 *
 * mpi_alloc/mpi_free/mpi_resize/mpi_copy/mpi_mod/mpi_normalize are shared
 * dependencies (mpiutil_rs.rs, already ported and verified; mpi_mod/
 * mpi_normalize still pristine C) -- one build of each, linked into both
 * arms, not under test here. What's compared is mpi_add()/mpi_sub()/
 * mpi_addm()/mpi_subm()/mpi_sub_ui()'s own logic, fed multi-limb random
 * operands of varying sign and relative size.
 *
 * A from-scratch bignum reference (not the C arm) checks the actual
 * arithmetic independently -- see ref_add()/ref_sub() -- for the same
 * reason md5's harness checked against RFC vectors: a cross-differential
 * alone cannot see both arms being wrong identically.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>

/* rust_mpi_* -- stand in for the retained thunk's real kmalloc wrappers,
 * same reasoning as port/test/mpiutil/drv.c. */
void *rust_mpi_kmalloc(size_t len) { return malloc(len); }
void *rust_mpi_kcalloc(size_t n, size_t size) { return calloc(n, size); }
void rust_mpi_kfree(void *p) { free(p); }
void rust_mpi_kfree_sensitive(void *p) { free(p); }

/* _printk(): mpi_free()'s invalid-flags path calls this directly; not
 * exercised by anything in this harness (every MPI here has flags == 0),
 * but must resolve at link time. */
int _printk(const char *fmt, ...)
{
	va_list ap;
	int ret;
	va_start(ap, fmt);
	ret = vprintf(fmt, ap);
	va_end(ap);
	return ret;
}

#define NLIMBS 6 /* room for every operand and result in this harness */

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
MPI mpi_copy(MPI a);

/* mpi_mod()/mpi_normalize() are still pristine C in the real tree
 * (mpi-mod.c/mpi-bit.c), not under test here and not what mpi_addm()/
 * mpi_subm()/mpi_sub_ui() are being checked for -- linking their real
 * bodies would pull in mpih-div.c/mpih-mul.c/mpi-mul.c/mpi-bit.c's whole
 * dependency chain for a function whose own correctness this differential
 * does not check. A small real (not stubbed-out) implementation, correct
 * for the single/double-limb values this harness ever uses, is enough to
 * exercise the ?: tail-call SHAPE in mpi_addm()/mpi_subm() -- does it call
 * mpi_mod() at all, with the right arguments, only when add/sub succeeded. */
void mpi_normalize(MPI a)
{
	while (a->nlimbs > 0 && a->d[a->nlimbs - 1] == 0)
		a->nlimbs--;
}

int mpi_mod(MPI rem, MPI dividend, MPI divisor)
{
	/* Repeated subtraction: correct for any input, and this harness
	 * only ever divides by single-digit-sized moduli, so it terminates
	 * quickly. dividend and divisor must both be non-negative here,
	 * which is all mpi_addm()/mpi_subm() ever pass in this harness. */
	MPI r = mpi_copy(dividend);
	MPI d = divisor;

	while (r->nlimbs > d->nlimbs
	       || (r->nlimbs == d->nlimbs
		   && memcmp(r->d, d->d, (size_t)r->nlimbs * sizeof(mpi_limb_t)) >= 0)) {
		int i;
		unsigned long borrow = 0;

		for (i = 0; i < r->nlimbs; i++) {
			unsigned long di = (i < d->nlimbs ? d->d[i] : 0) + borrow;
			unsigned long ri = r->d[i];
			unsigned long new_borrow = (di < borrow) || (ri < di);
			r->d[i] = ri - di;
			borrow = new_borrow;
		}
		mpi_normalize(r);
	}

	rem->nlimbs = r->nlimbs;
	rem->sign = 0;
	memcpy(rem->d, r->d, (size_t)r->nlimbs * sizeof(mpi_limb_t));
	mpi_free(r);
	return 0;
}

/* ---- C arm (renamed via -D, see run.sh) ---- */
int c_mpi_add(MPI w, MPI u, MPI v);
int c_mpi_sub(MPI w, MPI u, MPI v);
int c_mpi_addm(MPI w, MPI u, MPI v, MPI m);
int c_mpi_subm(MPI w, MPI u, MPI v, MPI m);
int c_mpi_sub_ui(MPI w, MPI u, unsigned long vval);

/* ---- Rust arm (kept at the real names) ---- */
int mpi_add(MPI w, MPI u, MPI v);
int mpi_sub(MPI w, MPI u, MPI v);
int mpi_addm(MPI w, MPI u, MPI v, MPI m);
int mpi_subm(MPI w, MPI u, MPI v, MPI m);
int mpi_sub_ui(MPI w, MPI u, unsigned long vval);

static unsigned long cases, mism;
static int poison;

static void bad(const char *what)
{
	if (mism < 20)
		printf("MISMATCH %s\n", what);
	mism++;
}

static uint32_t rnd_state = 1;
static uint32_t rnd(void)
{
	rnd_state = rnd_state * 1103515245u + 12345u;
	return rnd_state;
}

/* A signed bignum, as a plain sign+magnitude array of 64-bit words, wide
 * enough that this harness's operands never overflow it. This is the
 * independent oracle: built from first principles, not from either port. */
struct big {
	int sign; /* 0 or 1, same convention as struct gcry_mpi */
	unsigned long w[NLIMBS * 2];
};

static void big_from_mpi(struct big *b, MPI m)
{
	int i;
	memset(b->w, 0, sizeof(b->w));
	for (i = 0; i < m->nlimbs; i++)
		b->w[i] = m->d[i];
	b->sign = (m->nlimbs != 0) ? m->sign : 0;
}

/* Unsigned compare/add/sub over the magnitude array, most-significant-first
 * carry propagation done the ordinary long-addition way -- no cleverness,
 * so it does not share a mistake with either port's carry logic. */
static int mag_cmp(const unsigned long *a, const unsigned long *b, int n)
{
	int i;
	for (i = n - 1; i >= 0; i--) {
		if (a[i] != b[i])
			return a[i] > b[i] ? 1 : -1;
	}
	return 0;
}

static void mag_add(unsigned long *r, const unsigned long *a, const unsigned long *b, int n)
{
	unsigned long cy = 0;
	int i;
	for (i = 0; i < n; i++) {
		unsigned long s = a[i] + b[i];
		unsigned long cy1 = s < a[i];
		unsigned long s2 = s + cy;
		unsigned long cy2 = s2 < s;
		r[i] = s2;
		cy = cy1 + cy2;
	}
}

/* a - b, a >= b (magnitude). */
static void mag_sub(unsigned long *r, const unsigned long *a, const unsigned long *b, int n)
{
	unsigned long borrow = 0;
	int i;
	for (i = 0; i < n; i++) {
		unsigned long ai = a[i];
		unsigned long bi = b[i] + borrow;
		unsigned long new_borrow = (bi < borrow) || (ai < bi);
		r[i] = ai - bi;
		borrow = new_borrow;
	}
}

static void big_add(struct big *r, const struct big *a, const struct big *b)
{
	if (a->sign == b->sign) {
		mag_add(r->w, a->w, b->w, NLIMBS * 2);
		r->sign = a->sign;
	} else if (mag_cmp(a->w, b->w, NLIMBS * 2) >= 0) {
		mag_sub(r->w, a->w, b->w, NLIMBS * 2);
		r->sign = a->sign;
	} else {
		mag_sub(r->w, b->w, a->w, NLIMBS * 2);
		r->sign = b->sign;
	}
	/* Zero is always positive, same convention mpi_add/mpi_sub use. */
	if (mag_cmp(r->w, (unsigned long[NLIMBS * 2]){0}, NLIMBS * 2) == 0)
		r->sign = 0;
}

static void big_negate(struct big *b)
{
	if (mag_cmp(b->w, (unsigned long[NLIMBS * 2]){0}, NLIMBS * 2) != 0)
		b->sign = !b->sign;
}

/* Compare an mpi's actual value against the reference, sign-and-magnitude,
 * not raw field equality -- normalization can legitimately produce fewer
 * limbs than the reference array holds, as long as the missing ones are 0. */
static int mpi_matches_big(MPI m, const struct big *ref)
{
	int i;
	if (m->nlimbs > NLIMBS * 2)
		return 0;
	for (i = 0; i < m->nlimbs; i++)
		if (m->d[i] != ref->w[i])
			return 0;
	for (; i < NLIMBS * 2; i++)
		if (ref->w[i] != 0)
			return 0;
	{
		int is_zero = 1;
		for (i = 0; i < NLIMBS * 2; i++)
			if (ref->w[i] != 0)
				is_zero = 0;
		if (is_zero)
			return m->nlimbs == 0;
	}
	return m->sign == ref->sign;
}

static MPI mk(int nlimbs, int sign, const unsigned long *limbs)
{
	MPI m = mpi_alloc(nlimbs > 0 ? (unsigned)nlimbs : 1);
	int i;
	for (i = 0; i < nlimbs; i++)
		m->d[i] = limbs[i];
	m->nlimbs = nlimbs;
	m->sign = sign;
	return m;
}

static void fill_random(unsigned long *limbs, int n, int *sign)
{
	int i;
	for (i = 0; i < n; i++)
		limbs[i] = ((unsigned long)rnd() << 32) | rnd();
	/* Trim a random number of leading (high) limbs to zero, so operand
	 * sizes vary rather than always filling every limb -- this is what
	 * exercises mpi_add's different-size branch. */
	{
		int trim = rnd() % (n + 1);
		for (i = n - trim; i < n; i++)
			limbs[i] = 0;
	}
	*sign = rnd() & 1;
}

static int normalize_len(const unsigned long *limbs, int n)
{
	while (n > 0 && limbs[n - 1] == 0)
		n--;
	return n;
}

static void run_add_sub(int nu, const unsigned long *ulimbs, int usign,
			 int nv, const unsigned long *vlimbs, int vsign)
{
	MPI uc, vc, ur, vr, wc, wr;
	struct big bu, bv, bref;

	uc = mk(nu, usign, ulimbs);
	vc = mk(nv, vsign, vlimbs);
	ur = mk(nu, usign, ulimbs);
	vr = mk(nv, vsign, vlimbs);
	wc = mpi_alloc(NLIMBS * 2 + 1);
	wr = mpi_alloc(NLIMBS * 2 + 1);

	big_from_mpi(&bu, uc);
	big_from_mpi(&bv, vc);

	/* mpi_add */
	c_mpi_add(wc, uc, vc);
	mpi_add(wr, ur, vr);
	cases++;
	if (wc->nlimbs != wr->nlimbs || wc->sign != wr->sign
	    || memcmp(wc->d, wr->d, (size_t)wc->nlimbs * sizeof(mpi_limb_t)) != 0)
		bad("mpi_add: arms disagree");
	big_add(&bref, &bu, &bv);
	cases++;
	if (!mpi_matches_big(wc, &bref) || !mpi_matches_big(wr, &bref))
		bad("mpi_add: disagrees with the independent reference");

	/* mpi_sub */
	c_mpi_sub(wc, uc, vc);
	mpi_sub(wr, ur, vr);
	cases++;
	if (wc->nlimbs != wr->nlimbs || wc->sign != wr->sign
	    || memcmp(wc->d, wr->d, (size_t)wc->nlimbs * sizeof(mpi_limb_t)) != 0)
		bad("mpi_sub: arms disagree");
	{
		struct big neg_bv = bv;
		big_negate(&neg_bv);
		big_add(&bref, &bu, &neg_bv);
	}
	cases++;
	if (!mpi_matches_big(wc, &bref) || !mpi_matches_big(wr, &bref))
		bad("mpi_sub: disagrees with the independent reference");

	mpi_free(uc); mpi_free(vc); mpi_free(ur); mpi_free(vr);
	mpi_free(wc); mpi_free(wr);
}

static void run_sub_ui(int nu, const unsigned long *ulimbs, int usign, unsigned long vval)
{
	MPI uc = mk(nu, usign, ulimbs);
	MPI ur = mk(nu, usign, ulimbs);
	MPI wc = mpi_alloc(NLIMBS * 2 + 1);
	MPI wr = mpi_alloc(NLIMBS * 2 + 1);
	int rc, rr;

	rc = c_mpi_sub_ui(wc, uc, vval);
	rr = mpi_sub_ui(wr, ur, vval);
	cases++;
	if (rc != rr)
		bad("mpi_sub_ui: return code differs");
	cases++;
	if (wc->nlimbs != wr->nlimbs || wc->sign != wr->sign
	    || memcmp(wc->d, wr->d, (size_t)wc->nlimbs * sizeof(mpi_limb_t)) != 0)
		bad("mpi_sub_ui: arms disagree");

	{
		struct big bu, bv, bref;
		unsigned long one[1] = { vval };

		big_from_mpi(&bu, uc);
		memset(&bv, 0, sizeof(bv));
		bv.w[0] = one[0];
		bv.sign = 0;
		big_negate(&bv);
		big_add(&bref, &bu, &bv);
		cases++;
		if (!mpi_matches_big(wc, &bref) || !mpi_matches_big(wr, &bref))
			bad("mpi_sub_ui: disagrees with the independent reference");
	}

	mpi_free(uc); mpi_free(ur); mpi_free(wc); mpi_free(wr);
}

int main(void)
{
	unsigned n;

	if (getenv("MPIADD_PROVE_CAN_FAIL"))
		poison = 1;

	/* Hand-picked edge cases: equal size, one empty, a carry that
	 * grows nlimbs, sizes differing by exactly one and by several. */
	{
		unsigned long a1[1] = { 5 }, b1[1] = { 3 };
		run_add_sub(1, a1, 0, 1, b1, 0);
		run_add_sub(1, a1, 0, 1, b1, 1);
		run_add_sub(1, a1, 1, 1, b1, 0);
	}
	{
		unsigned long allones[1] = { ~0UL }, one[1] = { 1 };
		run_add_sub(1, allones, 0, 1, one, 0);
	}
	{
		unsigned long a2[2] = { 1, 1 }, b1[1] = { 1 };
		run_add_sub(2, a2, 0, 1, b1, 0);
		run_add_sub(2, a2, 0, 1, b1, 1);
	}
	run_add_sub(0, NULL, 0, 1, (unsigned long[1]){ 7 }, 0);
	run_add_sub(1, (unsigned long[1]){ 7 }, 0, 0, NULL, 0);

	/* Broad random sweep across every size pair 0..NLIMBS and both
	 * signs on each side. */
	for (n = 0; n < 3000; n++) {
		unsigned long ua[NLIMBS], va[NLIMBS];
		int nu = rnd() % (NLIMBS + 1), nv = rnd() % (NLIMBS + 1);
		int usign, vsign;

		fill_random(ua, nu, &usign);
		fill_random(va, nv, &vsign);
		nu = normalize_len(ua, nu);
		nv = normalize_len(va, nv);
		run_add_sub(nu, ua, usign, nv, va, vsign);
	}

	/* mpi_sub_ui, across the same size/sign spread against a random
	 * small unsigned long. */
	for (n = 0; n < 2000; n++) {
		unsigned long ua[NLIMBS];
		int nu = rnd() % (NLIMBS + 1), usign;
		unsigned long vval = rnd() % 1000000u;

		fill_random(ua, nu, &usign);
		nu = normalize_len(ua, nu);
		run_sub_ui(nu, ua, usign, vval);
	}
	run_sub_ui(0, NULL, 0, 5);
	run_sub_ui(0, NULL, 0, 0);

	/* mpi_addm/mpi_subm: real coverage of the ?: tail call into
	 * mpi_mod(), which both arms share -- this checks the conditional
	 * itself, not mpi_mod()'s own arithmetic. */
	{
		MPI u = mk(1, 0, (unsigned long[1]){ 17 });
		MPI v = mk(1, 0, (unsigned long[1]){ 5 });
		MPI m = mk(1, 0, (unsigned long[1]){ 7 });
		MPI wc = mpi_alloc(4), wr = mpi_alloc(4);
		MPI u2 = mk(1, 0, (unsigned long[1]){ 17 });
		MPI v2 = mk(1, 0, (unsigned long[1]){ 5 });
		MPI m2 = mk(1, 0, (unsigned long[1]){ 7 });

		c_mpi_addm(wc, u, v, m);
		mpi_addm(wr, u2, v2, m2);
		cases++;
		if (wc->nlimbs != wr->nlimbs || wc->sign != wr->sign
		    || memcmp(wc->d, wr->d, (size_t)wc->nlimbs * sizeof(mpi_limb_t)) != 0)
			bad("mpi_addm: arms disagree");
		cases++;
		if (wc->nlimbs != 1 || wc->d[0] != 1) /* (17+5) mod 7 = 1 */
			bad("mpi_addm: (17+5) mod 7 != 1 (independent check)");

		mpi_free(u); mpi_free(v); mpi_free(m); mpi_free(wc); mpi_free(wr);
		mpi_free(u2); mpi_free(v2); mpi_free(m2);
	}
	{
		MPI u = mk(1, 0, (unsigned long[1]){ 17 });
		MPI v = mk(1, 0, (unsigned long[1]){ 5 });
		MPI m = mk(1, 0, (unsigned long[1]){ 7 });
		MPI wc = mpi_alloc(4), wr = mpi_alloc(4);
		MPI u2 = mk(1, 0, (unsigned long[1]){ 17 });
		MPI v2 = mk(1, 0, (unsigned long[1]){ 5 });
		MPI m2 = mk(1, 0, (unsigned long[1]){ 7 });

		c_mpi_subm(wc, u, v, m);
		mpi_subm(wr, u2, v2, m2);
		cases++;
		if (wc->nlimbs != wr->nlimbs || wc->sign != wr->sign
		    || memcmp(wc->d, wr->d, (size_t)wc->nlimbs * sizeof(mpi_limb_t)) != 0)
			bad("mpi_subm: arms disagree");
		cases++;
		if (wc->nlimbs != 1 || wc->d[0] != 5) /* (17-5) mod 7 = 5 */
			bad("mpi_subm: (17-5) mod 7 != 5 (independent check)");

		mpi_free(u); mpi_free(v); mpi_free(m); mpi_free(wc); mpi_free(wr);
		mpi_free(u2); mpi_free(v2); mpi_free(m2);
	}

	if (poison) {
		unsigned long a1[1] = { 5 }, b1[1] = { 3 };
		MPI u = mk(1, 0, a1), v = mk(1, 0, b1);
		MPI wc = mpi_alloc(4), wr = mpi_alloc(4);

		c_mpi_add(wc, u, v);
		mpi_add(wr, u, v);
		wr->d[0] ^= 1; /* deliberately break the recorded Rust answer */
		cases++;
		if (wc->d[0] != wr->d[0])
			bad("mpi_add: 1 + 1 = 2 (expected -- poisoned run)");
		mpi_free(u); mpi_free(v); mpi_free(wc); mpi_free(wr);
	}

	if (mism) {
		fprintf(stderr, "%lu/%lu cases MISMATCHED\n", mism, cases);
		return 1;
	}
	printf("%lu cases, 0 mismatches\n", cases);
	return 0;
}
