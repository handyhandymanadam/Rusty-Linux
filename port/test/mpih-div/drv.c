/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * port/test/mpih-div/drv.c -- differential for lib/crypto/mpi/mpih-div.c
 * -> mpih_div_rs.rs (mpihelp_mod_1, mpihelp_divmod_1, mpihelp_divrem).
 *
 * None of these three is EXPORT_SYMBOL, but all three are real symbols
 * other still-C files (mpi-div.c) call directly.
 *
 * mpihelp_add_n/sub_n/cmp/submul_1 are shared dependencies
 * (generic_mpih_rs.rs, already ported and verified), linked into both
 * arms, not under test here.
 *
 * A from-scratch binary long-division reference (ref_divmod below) checks
 * the actual arithmetic independently of both arms -- neither Knuth's
 * Algorithm D (what mpih-div.c implements) nor this file's own
 * udiv_qrnnd/umul_ppmm building blocks are anywhere in it, so it cannot
 * share a mistake with either port.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAXLIMBS 8 /* room for every operand/result this harness uses */

typedef unsigned long mpi_limb_t;

/* ---- Shared dependency: ONE implementation, linked into both arms ---- */
mpi_limb_t mpihelp_add_n(mpi_limb_t *r, const mpi_limb_t *a, const mpi_limb_t *b, int n);
mpi_limb_t mpihelp_sub_n(mpi_limb_t *r, const mpi_limb_t *a, const mpi_limb_t *b, int n);
mpi_limb_t mpihelp_submul_1(mpi_limb_t *res_ptr, const mpi_limb_t *s1_ptr, int s1_size, mpi_limb_t s2_limb);
int mpihelp_cmp(const mpi_limb_t *a, const mpi_limb_t *b, int n);

/* ---- C arm (renamed via -D, see run.sh) ---- */
mpi_limb_t c_mpihelp_mod_1(mpi_limb_t *dividend_ptr, int dividend_size, mpi_limb_t divisor_limb);
mpi_limb_t c_mpihelp_divmod_1(mpi_limb_t *quot_ptr, mpi_limb_t *dividend_ptr, int dividend_size, mpi_limb_t divisor_limb);
mpi_limb_t c_mpihelp_divrem(mpi_limb_t *qp, int qextra_limbs, mpi_limb_t *np, int nsize, mpi_limb_t *dp, int dsize);

/* ---- Rust arm (kept at the real names) ---- */
mpi_limb_t mpihelp_mod_1(mpi_limb_t *dividend_ptr, int dividend_size, mpi_limb_t divisor_limb);
mpi_limb_t mpihelp_divmod_1(mpi_limb_t *quot_ptr, mpi_limb_t *dividend_ptr, int dividend_size, mpi_limb_t divisor_limb);
mpi_limb_t mpihelp_divrem(mpi_limb_t *qp, int qextra_limbs, mpi_limb_t *np, int nsize, mpi_limb_t *dp, int dsize);

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

static int mag_cmp_local(const mpi_limb_t *a, const mpi_limb_t *b, int n);

static void fill_random(mpi_limb_t *limbs, int n)
{
	int i;
	for (i = 0; i < n; i++)
		limbs[i] = ((mpi_limb_t)rnd() << 32) | rnd();
}

/*
 * Independent oracle: plain bit-at-a-time binary long division of an
 * nsize-limb numerator by a dsize-limb, MSB-normalized denominator,
 * producing a (nsize - dsize + qextra_limbs)-limb quotient and a
 * dsize-limb remainder. qextra_limbs works by padding the numerator with
 * that many extra zero limbs at the LOW end before dividing -- exactly
 * what mpihelp_divrem's own doc comment says qextra_limbs means.
 */
static void ref_divmod(mpi_limb_t *quot, mpi_limb_t *rem,
			const mpi_limb_t *num, int nsize,
			const mpi_limb_t *den, int dsize, int qextra_limbs)
{
	mpi_limb_t r[MAXLIMBS] = { 0 };
	mpi_limb_t q[MAXLIMBS * 2] = { 0 };
	int total_n = nsize + qextra_limbs;
	int qsize = total_n - dsize;
	int bit;
	int overflow = 0; /* the bit ABOVE r's top limb -- see below */

	/* Process bits from the most significant limb/bit down to the
	 * least significant, most-significant-limb-first -- classic
	 * restoring binary long division.
	 *
	 * `r` is exactly `dsize` limbs, but the loop invariant ("r < den
	 * before each shift", maintained by the conditional subtraction
	 * below) only bounds r to strictly less than 2*den after shifting
	 * in one bit -- and if den's own top bit is set, 2*den can exceed
	 * `dsize` limbs by one bit. That bit shifted out of r's top limb
	 * is not noise to discard: dropping it (the first version of this
	 * function did) silently computes r mod 2^(64*dsize) instead of
	 * the true shifted value on roughly half of all normalized
	 * divisors, and it was CAUGHT because the C and Rust arms of the
	 * actual port agreed with each other and disagreed with this
	 * function -- exactly logs/porting-hazards.md guard 12's shape.
	 * `overflow` carries that bit; since the invariant guarantees
	 * `r < den` whenever overflow becomes set, the subsequent subtract
	 * always resolves it back to 0 (proof: overflow=1 means true
	 * r < 2*den (from the shift) and true r >= 2^(64*dsize) (that's
	 * what overflow means), so the low `dsize` limbs alone, r_val,
	 * satisfy r_val = true_r - 2^(64*dsize) < 2*den - 2^(64*dsize) <
	 * den since den < 2^(64*dsize) -- so r_val < den always when
	 * overflow fires, and ordinary wraparound subtraction of den from
	 * r_val gives exactly the correct post-subtraction remainder). */
	for (bit = total_n * 64 - 1; bit >= 0; bit--) {
		int limb_idx = bit / 64;
		int bit_idx = bit % 64;
		mpi_limb_t in_bit;
		int i;
		mpi_limb_t carry;

		if (limb_idx >= qextra_limbs && (limb_idx - qextra_limbs) < nsize)
			in_bit = (num[limb_idx - qextra_limbs] >> bit_idx) & 1;
		else
			in_bit = 0; /* the qextra_limbs zero-padding */

		/* r = (r << 1) | in_bit, across dsize limbs, plus overflow. */
		carry = in_bit;
		for (i = 0; i < dsize; i++) {
			mpi_limb_t new_carry = r[i] >> 63;
			r[i] = (r[i] << 1) | carry;
			carry = new_carry;
		}
		overflow = (int)carry;

		if (overflow || mag_cmp_local(r, den, dsize) >= 0) {
			mpi_limb_t borrow = 0;
			for (i = 0; i < dsize; i++) {
				mpi_limb_t di = den[i] + borrow;
				mpi_limb_t nb = (di < borrow) || (r[i] < di);
				r[i] -= di;
				borrow = nb;
			}
			if (bit >= 0) {
				int out_limb = bit / 64;
				q[out_limb] |= ((mpi_limb_t)1 << (bit % 64));
			}
		}
	}

	/* Export the FULL total_n-limb quotient, not just the low `qsize`
	 * limbs: mpihelp_divrem's own contract only wants `qsize` (the rest
	 * is its separate "most significant quotient limb" return value),
	 * but mpihelp_mod_1/mpihelp_divmod_1's dsize==1 contract wants all
	 * `nsize` (== total_n here) limbs directly. Copying the superset
	 * lets both callers slice out what they need. */
	memcpy(rem, r, (size_t)dsize * sizeof(mpi_limb_t));
	memcpy(quot, q, (size_t)total_n * sizeof(mpi_limb_t));
	(void)qsize;
}

static int mag_cmp_local(const mpi_limb_t *a, const mpi_limb_t *b, int n)
{
	int i;
	for (i = n - 1; i >= 0; i--)
		if (a[i] != b[i])
			return a[i] > b[i] ? 1 : -1;
	return 0;
}

static void run_divrem(int nsize, const mpi_limb_t *num,
			int dsize, const mpi_limb_t *den, int qextra_limbs)
{
	mpi_limb_t np_c[MAXLIMBS], np_r[MAXLIMBS];
	mpi_limb_t dp[MAXLIMBS];
	mpi_limb_t qp_c[MAXLIMBS * 2] = { 0 }, qp_r[MAXLIMBS * 2] = { 0 };
	mpi_limb_t msqc, msqr;
	mpi_limb_t ref_q[MAXLIMBS * 2] = { 0 }, ref_r[MAXLIMBS] = { 0 };

	memcpy(np_c, num, (size_t)nsize * sizeof(mpi_limb_t));
	memcpy(np_r, num, (size_t)nsize * sizeof(mpi_limb_t));
	memcpy(dp, den, (size_t)dsize * sizeof(mpi_limb_t));

	msqc = c_mpihelp_divrem(qp_c, qextra_limbs, np_c, nsize, dp, dsize);
	msqr = mpihelp_divrem(qp_r, qextra_limbs, np_r, nsize, dp, dsize);

	cases++;
	if (msqc != msqr)
		bad("mpihelp_divrem: most-significant-quotient-limb differs");
	cases++;
	if (memcmp(qp_c, qp_r, (size_t)(nsize - dsize + qextra_limbs) * sizeof(mpi_limb_t)) != 0)
		bad("mpihelp_divrem: quotient limbs differ between arms");
	cases++;
	if (memcmp(np_c, np_r, (size_t)dsize * sizeof(mpi_limb_t)) != 0)
		bad("mpihelp_divrem: remainder differs between arms");

	ref_divmod(ref_q, ref_r, num, nsize, den, dsize, qextra_limbs);
	cases++;
	{
		int qsize = nsize - dsize + qextra_limbs;
		mpi_limb_t full_q_c[MAXLIMBS * 2] = { 0 };
		memcpy(full_q_c, qp_c, (size_t)qsize * sizeof(mpi_limb_t));
		full_q_c[qsize] = msqc; /* the extra "always 0 or 1" limb */
		if (memcmp(full_q_c, ref_q, (size_t)(qsize + 1) * sizeof(mpi_limb_t)) != 0)
			bad("mpihelp_divrem: quotient disagrees with the independent reference");
	}
	cases++;
	if (memcmp(np_c, ref_r, (size_t)dsize * sizeof(mpi_limb_t)) != 0)
		bad("mpihelp_divrem: remainder disagrees with the independent reference");
}

static void run_mod_1(int nsize, const mpi_limb_t *num, mpi_limb_t divisor)
{
	mpi_limb_t nc[MAXLIMBS], nr[MAXLIMBS];
	mpi_limb_t rc, rr;
	mpi_limb_t den[1] = { divisor };
	mpi_limb_t ref_q[MAXLIMBS], ref_r[1];

	memcpy(nc, num, (size_t)nsize * sizeof(mpi_limb_t));
	memcpy(nr, num, (size_t)nsize * sizeof(mpi_limb_t));

	rc = c_mpihelp_mod_1(nc, nsize, divisor);
	rr = mpihelp_mod_1(nr, nsize, divisor);
	cases++;
	if (rc != rr)
		bad("mpihelp_mod_1: arms disagree");

	ref_divmod(ref_q, ref_r, num, nsize, den, 1, 0);
	cases++;
	if (rc != ref_r[0])
		bad("mpihelp_mod_1: disagrees with the independent reference");
}

static void run_divmod_1(int nsize, const mpi_limb_t *num, mpi_limb_t divisor)
{
	mpi_limb_t nc[MAXLIMBS], nr[MAXLIMBS];
	mpi_limb_t qc[MAXLIMBS] = { 0 }, qr[MAXLIMBS] = { 0 };
	mpi_limb_t rc, rr;
	mpi_limb_t den[1] = { divisor };
	mpi_limb_t ref_q[MAXLIMBS] = { 0 }, ref_r[1];

	memcpy(nc, num, (size_t)nsize * sizeof(mpi_limb_t));
	memcpy(nr, num, (size_t)nsize * sizeof(mpi_limb_t));

	rc = c_mpihelp_divmod_1(qc, nc, nsize, divisor);
	rr = mpihelp_divmod_1(qr, nr, nsize, divisor);
	cases++;
	if (rc != rr)
		bad("mpihelp_divmod_1: remainder differs between arms");
	cases++;
	if (memcmp(qc, qr, (size_t)nsize * sizeof(mpi_limb_t)) != 0)
		bad("mpihelp_divmod_1: quotient differs between arms");

	ref_divmod(ref_q, ref_r, num, nsize, den, 1, 0);
	cases++;
	if (memcmp(qc, ref_q, (size_t)nsize * sizeof(mpi_limb_t)) != 0)
		bad("mpihelp_divmod_1: quotient disagrees with the independent reference");
	cases++;
	if (rc != ref_r[0])
		bad("mpihelp_divmod_1: remainder disagrees with the independent reference");
}

/* Build a random nsize-limb value whose top limb has `steps` leading zero
 * bits -- exercises count_leading_zeros()'s whole range, both functions'
 * normalization path and (steps==0) their already-normalized path. */
static void fill_with_leading_zeros(mpi_limb_t *limbs, int n, int steps)
{
	fill_random(limbs, n);
	if (steps >= 64)
		limbs[n - 1] = 0;
	else if (steps > 0)
		limbs[n - 1] >>= steps;
	else
		limbs[n - 1] |= (mpi_limb_t)1 << 63; /* force normalized */
}

int main(void)
{
	unsigned n;

	if (getenv("MPIHDIV_PROVE_CAN_FAIL"))
		poison = 1;

	/* mpihelp_mod_1 / mpihelp_divmod_1: single-limb divisor, every
	 * normalization-shift amount, several dividend sizes. */
	{
		int steps[] = { 0, 1, 7, 31, 32, 63 };
		int sizes[] = { 1, 2, 3, 5, 8 };
		unsigned si, ni;
		for (si = 0; si < sizeof(steps) / sizeof(steps[0]); si++) {
			for (ni = 0; ni < sizeof(sizes) / sizeof(sizes[0]); ni++) {
				mpi_limb_t num[MAXLIMBS], d[1];
				fill_random(num, sizes[ni]);
				fill_with_leading_zeros(d, 1, steps[si]);
				if (d[0] == 0)
					d[0] = 1;
				run_mod_1(sizes[ni], num, d[0]);
				run_divmod_1(sizes[ni], num, d[0]);
			}
		}
	}
	for (n = 0; n < 3000; n++) {
		mpi_limb_t num[MAXLIMBS], d;
		int nsize = 1 + (int)(rnd() % MAXLIMBS);
		fill_random(num, nsize);
		d = ((mpi_limb_t)rnd() << 32) | rnd();
		if (d == 0)
			d = 1;
		run_mod_1(nsize, num, d);
		run_divmod_1(nsize, num, d);
	}

	/* mpihelp_divrem: dsize 1, 2, and >=3 (the three switch cases),
	 * every normalization-shift amount on the divisor's top limb,
	 * nsize - dsize spanning 0 (equal sizes) upward, qextra_limbs 0
	 * and nonzero. */
	{
		int dsizes[] = { 1, 2, 3, 4, 6 };
		int extra_over[] = { 0, 1, 3 };
		int steps[] = { 0, 1, 31, 63 };
		unsigned di, ei, si;

		for (di = 0; di < sizeof(dsizes) / sizeof(dsizes[0]); di++) {
			for (ei = 0; ei < sizeof(extra_over) / sizeof(extra_over[0]); ei++) {
				for (si = 0; si < sizeof(steps) / sizeof(steps[0]); si++) {
					mpi_limb_t den[MAXLIMBS], num[MAXLIMBS];
					int dsize = dsizes[di];
					int nsize = dsize + extra_over[ei];

					if (nsize > MAXLIMBS || dsize > MAXLIMBS)
						continue;
					fill_with_leading_zeros(den, dsize, steps[si]);
					den[dsize - 1] |= (mpi_limb_t)1 << 63; /* dp precondition #1 */
					fill_random(num, nsize);
					/* qextra_limbs 0 only for the hand-picked
					 * shift/size sweep -- the random sweep below
					 * covers qextra_limbs > 0. */
					run_divrem(nsize, num, dsize, den, 0);
				}
			}
		}
	}
	for (n = 0; n < 3000; n++) {
		mpi_limb_t den[MAXLIMBS], num[MAXLIMBS];
		int dsize = 1 + (int)(rnd() % 6);
		int extra_over = (int)(rnd() % 5);
		int nsize = dsize + extra_over;
		int qextra = (int)(rnd() % 3);

		if (nsize + qextra > MAXLIMBS)
			continue;
		fill_random(den, dsize);
		den[dsize - 1] |= (mpi_limb_t)1 << 63;
		fill_random(num, nsize);
		run_divrem(nsize, num, dsize, den, qextra);
	}

	if (poison) {
		mpi_limb_t num[2] = { 5, 0 }, d = 3;
		mpi_limb_t rc, rr;
		rc = c_mpihelp_mod_1(num, 1, d);
		rr = mpihelp_mod_1(num, 1, d);
		rr ^= 1; /* deliberately break the recorded Rust answer */
		cases++;
		if (rc != rr)
			bad("mpihelp_mod_1: 5 mod 3 (expected -- poisoned run)");
	}

	if (mism) {
		fprintf(stderr, "%lu/%lu cases MISMATCHED\n", mism, cases);
		return 1;
	}
	printf("%lu cases, 0 mismatches\n", cases);
	return 0;
}
