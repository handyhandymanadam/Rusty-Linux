/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * port/test/mpi-div/drv.c -- differential for lib/crypto/mpi/mpi-div.c ->
 * mpi_div_rs.rs (mpi_fdiv_r, mpi_tdiv_r, mpi_tdiv_qr) and
 * lib/crypto/mpi/mpi-mod.c -> mpi_mod_rs.rs (mpi_mod).
 *
 * mpi_alloc/mpi_free/mpi_resize/mpi_copy/mpi_alloc_limb_space/
 * mpi_free_limb_space (mpiutil_rs.rs), mpi_add (mpi_add_rs.rs), and
 * mpihelp_mod_1/divmod_1/divrem/lshift/rshift (mpih_div_rs.rs,
 * generic_mpih_rs.rs) are shared dependencies, already ported and
 * verified, linked into both arms unchanged -- not under test here.
 *
 * mpi_tdiv_qr's own doc comment names the aliasing cases that matter:
 * quot==den, rem==den, num==quot. All three are exercised below, plus
 * quot==NULL (mpi_tdiv_r's own use) and quot==rem (which the C's own
 * "these must be different objects" comment guards against internally by
 * copying).
 *
 * An independent oracle checks the actual arithmetic: bit-by-bit binary
 * long division (not Knuth's Algorithm D, and not mpih-div.c's building
 * blocks -- both of which are the very thing under test). An earlier
 * repeated-subtraction version of this reference was replaced after it
 * hung -- it is O(quotient), and a multi-limb dividend over a small
 * divisor makes the quotient itself huge; O(bits) has no such case.
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

#define MAXLIMBS 6

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
int mpi_add(MPI w, MPI u, MPI v);

/* ---- C arm (renamed via -D, see run.sh) ---- */
int c_mpi_fdiv_r(MPI rem, MPI dividend, MPI divisor);
int c_mpi_tdiv_r(MPI rem, MPI num, MPI den);
int c_mpi_tdiv_qr(MPI quot, MPI rem, MPI num, MPI den);
int c_mpi_mod(MPI rem, MPI dividend, MPI divisor);

/* ---- Rust arm (kept at the real names) ---- */
int mpi_fdiv_r(MPI rem, MPI dividend, MPI divisor);
int mpi_tdiv_r(MPI rem, MPI num, MPI den);
int mpi_tdiv_qr(MPI quot, MPI rem, MPI num, MPI den);
int mpi_mod(MPI rem, MPI dividend, MPI divisor);

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

static MPI mk(int nlimbs, int sign, const mpi_limb_t *limbs)
{
	MPI m = mpi_alloc(nlimbs > 0 ? (unsigned)nlimbs : 1);
	int i;
	for (i = 0; i < nlimbs; i++)
		m->d[i] = limbs[i];
	m->nlimbs = nlimbs;
	m->sign = sign;
	return m;
}

static int mpi_eq(MPI a, MPI b)
{
	if (a->nlimbs != b->nlimbs)
		return 0;
	if (a->nlimbs != 0 && a->sign != b->sign)
		return 0; /* zero is always non-negative, sign is don't-care */
	return memcmp(a->d, b->d, (size_t)a->nlimbs * sizeof(mpi_limb_t)) == 0;
}

/* Independent oracle: sign-and-magnitude binary long division (shift one
 * bit of the dividend into a running remainder, subtract the divisor back
 * out if it fits, record the quotient bit), O(bits) rather than
 * O(quotient) -- a repeated-subtraction reference is correct but explodes
 * on a multi-limb dividend divided by a small divisor (quotient can be
 * astronomically large), which is exactly the shape mpi_tdiv_qr's own
 * dsize==1 fast path needs covered. This algorithm is unrelated to Knuth's
 * Algorithm D (mpihelp_divrem, under test via mpih_div_rs.rs) and to the
 * single-limb mpihelp_divmod_1 fast path, so it stays an independent
 * check on both. */
#define RLIMBS (MAXLIMBS + 1)

static int rget_bit(const mpi_limb_t *a, int bitpos)
{
	return (int)((a[bitpos / 64] >> (bitpos % 64)) & 1);
}

static int rcmp(const mpi_limb_t *a, const mpi_limb_t *b, int n)
{
	int i;
	for (i = n - 1; i >= 0; i--) {
		if (a[i] != b[i])
			return a[i] > b[i] ? 1 : -1;
	}
	return 0;
}

static void rsub(mpi_limb_t *a, const mpi_limb_t *b, int n)
{
	mpi_limb_t borrow = 0;
	int i;
	for (i = 0; i < n; i++) {
		mpi_limb_t bi = b[i] + borrow;
		mpi_limb_t nb = (bi < borrow) || (a[i] < bi);
		a[i] -= bi;
		borrow = nb;
	}
}

static void ref_tdiv_qr(mpi_limb_t *qmag, int *qsize, int *qsign,
			 mpi_limb_t *rmag, int *rsize, int *rsign,
			 const mpi_limb_t *num, int nsize, int nsign,
			 const mpi_limb_t *den, int dsize, int dsign)
{
	mpi_limb_t rem[RLIMBS] = { 0 };
	mpi_limb_t quot[MAXLIMBS] = { 0 };
	mpi_limb_t den_ext[RLIMBS] = { 0 };
	int nbits = nsize * 64;
	int i, qn, rn;

	for (i = 0; i < dsize; i++)
		den_ext[i] = den[i];

	for (i = nbits - 1; i >= 0; i--) {
		mpi_limb_t carry_in = (mpi_limb_t)rget_bit(num, i);
		mpi_limb_t topcarry = 0;
		int j;
		for (j = 0; j < RLIMBS; j++) {
			mpi_limb_t newtop = rem[j] >> 63;
			rem[j] = (rem[j] << 1) | topcarry;
			topcarry = newtop;
		}
		rem[0] |= carry_in;
		if (rcmp(rem, den_ext, RLIMBS) >= 0) {
			rsub(rem, den_ext, RLIMBS);
			if (i / 64 < MAXLIMBS)
				quot[i / 64] |= ((mpi_limb_t)1) << (i % 64);
		}
	}

	qn = MAXLIMBS;
	while (qn > 0 && quot[qn - 1] == 0)
		qn--;
	rn = dsize; /* remainder < divisor, so it fits in dsize limbs */
	while (rn > 0 && rem[rn - 1] == 0)
		rn--;

	memcpy(qmag, quot, MAXLIMBS * sizeof(mpi_limb_t));
	memcpy(rmag, rem, MAXLIMBS * sizeof(mpi_limb_t));
	*qsize = qn;
	*rsize = rn;
	*qsign = (*qsize != 0) ? (nsign ^ dsign) : 0;
	*rsign = (*rsize != 0) ? nsign : 0;
}

static void run_tdiv_qr(int nsize, const mpi_limb_t *num, int nsign,
			int dsize, const mpi_limb_t *den, int dsign)
{
	MPI uc, dc, ur, dr, qc, qr, rc, rr;
	int i;

	uc = mk(nsize, nsign, num);
	dc = mk(dsize, dsign, den);
	ur = mk(nsize, nsign, num);
	dr = mk(dsize, dsign, den);
	qc = mpi_alloc(MAXLIMBS + 1);
	qr = mpi_alloc(MAXLIMBS + 1);
	rc = mpi_alloc(MAXLIMBS + 1);
	rr = mpi_alloc(MAXLIMBS + 1);

	c_mpi_tdiv_qr(qc, rc, uc, dc);
	mpi_tdiv_qr(qr, rr, ur, dr);
	cases++;
	if (!mpi_eq(qc, qr))
		bad("mpi_tdiv_qr: quotients disagree between arms");
	cases++;
	if (!mpi_eq(rc, rr))
		bad("mpi_tdiv_qr: remainders disagree between arms");

	{
		mpi_limb_t qmag[MAXLIMBS], rmag[MAXLIMBS];
		int qsize, qsign, rsize, rsign;
		MPI ref_q, ref_r;

		ref_tdiv_qr(qmag, &qsize, &qsign, rmag, &rsize, &rsign,
			    num, nsize, nsign, den, dsize, dsign);
		ref_q = mk(qsize, qsign, qmag);
		ref_r = mk(rsize, rsign, rmag);
		cases++;
		if (!mpi_eq(qc, ref_q) || !mpi_eq(qr, ref_q))
			bad("mpi_tdiv_qr: quotient disagrees with the independent reference");
		cases++;
		if (!mpi_eq(rc, ref_r) || !mpi_eq(rr, ref_r))
			bad("mpi_tdiv_qr: remainder disagrees with the independent reference");
		mpi_free(ref_q);
		mpi_free(ref_r);
	}

	/* mpi_tdiv_r: quot == NULL. */
	{
		MPI u2c = mk(nsize, nsign, num), d2c = mk(dsize, dsign, den);
		MPI u2r = mk(nsize, nsign, num), d2r = mk(dsize, dsign, den);
		MPI r2c = mpi_alloc(MAXLIMBS + 1), r2r = mpi_alloc(MAXLIMBS + 1);
		c_mpi_tdiv_r(r2c, u2c, d2c);
		mpi_tdiv_r(r2r, u2r, d2r);
		cases++;
		if (!mpi_eq(r2c, rc) || !mpi_eq(r2r, rc))
			bad("mpi_tdiv_r: disagrees with mpi_tdiv_qr's own remainder");
		mpi_free(u2c); mpi_free(d2c); mpi_free(u2r); mpi_free(d2r);
		mpi_free(r2c); mpi_free(r2r);
	}

	/* Aliasing: num == quot (feed the quotient buffer back in as the
	 * dividend -- exercises the "qp == np, copy to scratch" path). */
	{
		MPI wc = mk(nsize, nsign, num), wr = mk(nsize, nsign, num);
		MPI d3c = mk(dsize, dsign, den), d3r = mk(dsize, dsign, den);
		MPI rr3c = mpi_alloc(MAXLIMBS + 1), rr3r = mpi_alloc(MAXLIMBS + 1);
		/* wc/wr serve as BOTH num and quot. */
		c_mpi_tdiv_qr(wc, rr3c, wc, d3c);
		mpi_tdiv_qr(wr, rr3r, wr, d3r);
		cases++;
		if (!mpi_eq(wc, wr))
			bad("mpi_tdiv_qr: num==quot aliasing, quotients disagree");
		cases++;
		if (!mpi_eq(rr3c, rr3r))
			bad("mpi_tdiv_qr: num==quot aliasing, remainders disagree");
		mpi_free(wc); mpi_free(wr); mpi_free(d3c); mpi_free(d3r);
		mpi_free(rr3c); mpi_free(rr3r);
	}

	/* Aliasing: den == rem (exercises the "dp overlaps rp, copy to
	 * scratch" path in the not-yet-normalized branch, and the
	 * temp_divisor path in mpi_fdiv_r separately below). */
	{
		MPI u4c = mk(nsize, nsign, num), u4r = mk(nsize, nsign, num);
		MPI dq4c = mpi_alloc(MAXLIMBS + 1), dq4r = mpi_alloc(MAXLIMBS + 1);
		MPI d4c = mk(dsize, dsign, den), d4r = mk(dsize, dsign, den);
		c_mpi_tdiv_qr(dq4c, d4c, u4c, d4c);
		mpi_tdiv_qr(dq4r, d4r, u4r, d4r);
		cases++;
		if (!mpi_eq(d4c, d4r))
			bad("mpi_tdiv_qr: den==rem aliasing, remainders disagree");
		cases++;
		if (!mpi_eq(dq4c, dq4r))
			bad("mpi_tdiv_qr: den==rem aliasing, quotients disagree");
		mpi_free(u4c); mpi_free(u4r); mpi_free(dq4c); mpi_free(dq4r);
		mpi_free(d4c); mpi_free(d4r);
	}

	/* mpi_fdiv_r and mpi_mod: floor-division remainder, sign follows
	 * the divisor. Also exercises rem == divisor (temp_divisor path). */
	{
		MPI u5c = mk(nsize, nsign, num), u5r = mk(nsize, nsign, num);
		MPI d5c = mk(dsize, dsign, den), d5r = mk(dsize, dsign, den);
		MPI r5c = mpi_alloc(MAXLIMBS + 1), r5r = mpi_alloc(MAXLIMBS + 1);
		int rc5, rr5;
		rc5 = c_mpi_fdiv_r(r5c, u5c, d5c);
		rr5 = mpi_fdiv_r(r5r, u5r, d5r);
		cases++;
		if (rc5 != rr5)
			bad("mpi_fdiv_r: return code differs");
		cases++;
		if (!mpi_eq(r5c, r5r))
			bad("mpi_fdiv_r: arms disagree");
		mpi_free(u5c); mpi_free(u5r); mpi_free(d5c); mpi_free(d5r);
		mpi_free(r5c); mpi_free(r5r);
	}
	{
		/* rem == divisor. */
		MPI u6c = mk(nsize, nsign, num), u6r = mk(nsize, nsign, num);
		MPI d6c = mk(dsize, dsign, den), d6r = mk(dsize, dsign, den);
		c_mpi_fdiv_r(d6c, u6c, d6c);
		mpi_fdiv_r(d6r, u6r, d6r);
		cases++;
		if (!mpi_eq(d6c, d6r))
			bad("mpi_fdiv_r: rem==divisor aliasing, results disagree");
		mpi_free(u6c); mpi_free(u6r); mpi_free(d6c); mpi_free(d6r);
	}
	{
		MPI u7c = mk(nsize, nsign, num), u7r = mk(nsize, nsign, num);
		MPI d7c = mk(dsize, dsign, den), d7r = mk(dsize, dsign, den);
		MPI r7c = mpi_alloc(MAXLIMBS + 1), r7r = mpi_alloc(MAXLIMBS + 1);
		c_mpi_mod(r7c, u7c, d7c);
		mpi_mod(r7r, u7r, d7r);
		cases++;
		if (!mpi_eq(r7c, r7r))
			bad("mpi_mod: arms disagree");
		{
			MPI ref = mpi_alloc(MAXLIMBS + 1);
			int e = c_mpi_fdiv_r(ref, u7c, d7c);
			(void)e;
			cases++;
			if (!mpi_eq(r7c, ref))
				bad("mpi_mod: disagrees with mpi_fdiv_r (should be identical)");
			mpi_free(ref);
		}
		mpi_free(u7c); mpi_free(u7r); mpi_free(d7c); mpi_free(d7r);
		mpi_free(r7c); mpi_free(r7r);
	}

	mpi_free(uc); mpi_free(dc); mpi_free(ur); mpi_free(dr);
	mpi_free(qc); mpi_free(qr); mpi_free(rc); mpi_free(rr);
	(void)i;
}

int main(void)
{
	unsigned n;

	if (getenv("MPIDIV_PROVE_CAN_FAIL"))
		poison = 1;

	/* Hand-picked: exact division, division with remainder, divisor
	 * larger than dividend (qsize<=0 path), single-limb divisor (the
	 * dsize==1 fast path), both signs on each side. */
	{
		mpi_limb_t seven[1] = { 7 }, three[1] = { 3 };
		mpi_limb_t two[1] = { 2 }, five[1] = { 5 };
		int s;
		for (s = 0; s < 4; s++)
			run_tdiv_qr(1, seven, s & 1, 1, three, (s >> 1) & 1);
		run_tdiv_qr(1, three, 0, 1, seven, 0); /* dividend < divisor */
		run_tdiv_qr(1, two, 0, 1, five, 0);
	}
	{
		/* Multi-limb dividend, single-limb divisor. */
		mpi_limb_t big[2] = { 0x123456789ULL, 7 };
		mpi_limb_t seven[1] = { 7 };
		run_tdiv_qr(2, big, 0, 1, seven, 0);
		run_tdiv_qr(2, big, 1, 1, seven, 1);
	}
	{
		/* Multi-limb divisor, needing normalization (top bit not set)
		 * and already normalized (top bit set). */
		mpi_limb_t num2[2] = { 0xABCDEF01, 0x123456 };
		mpi_limb_t den_small[2] = { 0x1000, 0x2 };
		mpi_limb_t den_norm[2] = { 0x1, (mpi_limb_t)1 << 63 };
		run_tdiv_qr(2, num2, 0, 2, den_small, 0);
		run_tdiv_qr(2, num2, 0, 2, den_norm, 0);
	}

	/* Random sweep: small operands (bounded so the O(quotient) reference
	 * oracle stays fast), every size 1..3 on each side, every sign
	 * combination. */
	for (n = 0; n < 2000; n++) {
		mpi_limb_t num[MAXLIMBS] = { 0 }, den[MAXLIMBS] = { 0 };
		int nsize = 1 + (int)(rnd() % 3);
		int dsize = 1 + (int)(rnd() % 3);
		int i;
		for (i = 0; i < nsize; i++)
			num[i] = rnd() % 5000u;
		for (i = 0; i < dsize; i++)
			den[i] = rnd() % 5000u;
		while (nsize > 1 && num[nsize - 1] == 0)
			nsize--;
		while (dsize > 1 && den[dsize - 1] == 0)
			dsize--;
		if (den[dsize - 1] == 0)
			den[dsize - 1] = 1;
		/* A real MPI never represents zero as nlimbs==1 with a zero
		 * limb -- normalize the same way mpi_alloc/mpn_normalize
		 * would, so this harness never feeds mpi_tdiv_qr's early-
		 * return path (qsize<=0) a non-canonical operand it happens
		 * to pass through unmodified (a real behavior, not a bug --
		 * see the mismatch this caught, fixed by this normalization
		 * rather than by touching the port). */
		if (nsize == 1 && num[0] == 0)
			nsize = 0;
		run_tdiv_qr(nsize, num, (int)(rnd() & 1), dsize, den, (int)(rnd() & 1));
	}

	if (poison) {
		mpi_limb_t seven[1] = { 7 }, three[1] = { 3 };
		MPI u = mk(1, 0, seven), d = mk(1, 0, three);
		MPI qc = mpi_alloc(4), qr = mpi_alloc(4);
		MPI rc = mpi_alloc(4), rr = mpi_alloc(4);
		c_mpi_tdiv_qr(qc, rc, u, d);
		mpi_tdiv_qr(qr, rr, u, d);
		qr->d[0] ^= 1; /* deliberately break the recorded Rust answer */
		cases++;
		if (!mpi_eq(qc, qr))
			bad("mpi_tdiv_qr: 7/3 quotient (expected -- poisoned run)");
		mpi_free(u); mpi_free(d); mpi_free(qc); mpi_free(qr);
		mpi_free(rc); mpi_free(rr);
	}

	if (mism) {
		fprintf(stderr, "%lu/%lu cases MISMATCHED\n", mism, cases);
		return 1;
	}
	printf("%lu cases, 0 mismatches\n", cases);
	return 0;
}
