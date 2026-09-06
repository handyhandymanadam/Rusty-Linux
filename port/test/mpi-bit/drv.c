/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * port/test/mpi-bit/drv.c -- differential for lib/crypto/mpi/mpi-bit.c ->
 * mpi_bit_rs.rs (mpi_normalize, mpi_get_nbits, mpi_test_bit, mpi_set_bit,
 * mpi_rshift).
 *
 * mpi_alloc/mpi_resize (mpiutil_rs.rs) and mpihelp_rshift
 * (generic_mpih_rs.rs) are shared dependencies, already ported and
 * verified, linked into both arms unchanged -- not under test here.
 *
 * Independent oracle: OpenSSL's BIGNUM (BN_num_bits/BN_is_bit_set/
 * BN_rshift), same reasoning as port/test/mpi-mul-pow/drv.c. mpi_rshift
 * is a pure sign-and-magnitude shift (it copies x->sign = a->sign
 * unconditionally, never computing an arithmetic/two's-complement shift),
 * so the oracle shifts the absolute value only and the expected sign is
 * asserted separately, matching the C's own contract exactly.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/bn.h>

#define MAXLIMBS 40

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

/* ---- C arm (renamed via -D, see run.sh) ---- */
void c_mpi_normalize(MPI a);
unsigned c_mpi_get_nbits(MPI a);
int c_mpi_test_bit(MPI a, unsigned int n);
int c_mpi_set_bit(MPI a, unsigned int n);
int c_mpi_rshift(MPI x, MPI a, unsigned int n);

/* ---- Rust arm (kept at the real names) ---- */
void mpi_normalize(MPI a);
unsigned mpi_get_nbits(MPI a);
int mpi_test_bit(MPI a, unsigned int n);
int mpi_set_bit(MPI a, unsigned int n);
int mpi_rshift(MPI x, MPI a, unsigned int n);

static unsigned long cases, mism;
static int poison;

static void bad(const char *what)
{
	if (mism < 20)
		printf("MISMATCH %s\n", what);
	mism++;
}

static uint32_t rnd_state = 0xC001D00D;
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

static int mpi_eq(MPI a, MPI b)
{
	if (a->nlimbs != b->nlimbs)
		return 0;
	if (a->nlimbs != 0 && a->sign != b->sign)
		return 0;
	return memcmp(a->d, b->d, (size_t)a->nlimbs * sizeof(mpi_limb_t)) == 0;
}

static void fill_random_mpi(mpi_limb_t *a, int n)
{
	int i;
	for (i = 0; i < n; i++)
		a[i] = ((uint64_t)rnd() << 32) | rnd();
}

static BIGNUM *mpi_mag_to_bn(int nlimbs, const mpi_limb_t *limbs)
{
	if (nlimbs == 0) {
		BIGNUM *b = BN_new();
		BN_zero(b);
		return b;
	}
	return BN_lebin2bn((const unsigned char *)limbs,
			    (int)(nlimbs * sizeof(mpi_limb_t)), NULL);
}

static void run_get_nbits(int nlimbs, const mpi_limb_t *limbs)
{
	MPI ac = mk_mpi(nlimbs, 0, limbs), ar = mk_mpi(nlimbs, 0, limbs);
	unsigned nc = c_mpi_get_nbits(ac), nr = mpi_get_nbits(ar);
	BIGNUM *b = mpi_mag_to_bn(nlimbs, limbs);
	unsigned expect = (unsigned)BN_num_bits(b);

	cases++;
	if (nc != nr)
		bad("mpi_get_nbits: arms disagree");
	cases++;
	if (nc != expect)
		bad("mpi_get_nbits: disagrees with the independent BIGNUM reference");
	BN_free(b);
	mpi_free(ac); mpi_free(ar);
}

static void run_test_bit(int nlimbs, const mpi_limb_t *limbs, unsigned n)
{
	MPI ac = mk_mpi(nlimbs, 0, limbs), ar = mk_mpi(nlimbs, 0, limbs);
	int rc = c_mpi_test_bit(ac, n), rr = mpi_test_bit(ar, n);
	BIGNUM *b = mpi_mag_to_bn(nlimbs, limbs);
	int expect = BN_is_bit_set(b, (int)n) ? 1 : 0;

	cases++;
	if (rc != rr)
		bad("mpi_test_bit: arms disagree");
	cases++;
	if (rc != expect)
		bad("mpi_test_bit: disagrees with the independent BIGNUM reference");
	BN_free(b);
	mpi_free(ac); mpi_free(ar);
}

static void run_set_bit(int nlimbs, const mpi_limb_t *limbs, unsigned n)
{
	MPI ac = mk_mpi(nlimbs, 0, limbs), ar = mk_mpi(nlimbs, 0, limbs);
	int rc = c_mpi_set_bit(ac, n), rr = mpi_set_bit(ar, n);
	BIGNUM *b = mpi_mag_to_bn(nlimbs, limbs);
	BIGNUM *bc, *br;

	cases++;
	if (rc != rr || !mpi_eq(ac, ar))
		bad("mpi_set_bit: arms disagree");

	BN_set_bit(b, (int)n);
	bc = mpi_mag_to_bn(ac->nlimbs, ac->d);
	br = mpi_mag_to_bn(ar->nlimbs, ar->d);
	cases++;
	if (rc == 0 && (BN_cmp(bc, b) != 0 || BN_cmp(br, b) != 0))
		bad("mpi_set_bit: disagrees with the independent BIGNUM reference");

	BN_free(b); BN_free(bc); BN_free(br);
	mpi_free(ac); mpi_free(ar);
}

/* x != a (the copy path). */
static void run_rshift(int nlimbs, int sign, const mpi_limb_t *limbs, unsigned n)
{
	MPI ac = mk_mpi(nlimbs, sign, limbs), ar = mk_mpi(nlimbs, sign, limbs);
	MPI xc = mpi_alloc((unsigned)(nlimbs + 2)), xr = mpi_alloc((unsigned)(nlimbs + 2));
	int rc, rr;
	BIGNUM *b, *expect;

	rc = c_mpi_rshift(xc, ac, n);
	rr = mpi_rshift(xr, ar, n);
	cases++;
	if (rc != rr || !mpi_eq(xc, xr))
		bad("mpi_rshift: arms disagree (x != a)");

	b = mpi_mag_to_bn(nlimbs, limbs);
	expect = BN_new();
	BN_rshift(expect, b, (int)n);
	cases++;
	if (rc == 0) {
		BIGNUM *xc_mag = mpi_mag_to_bn(xc->nlimbs, xc->d);
		if (BN_cmp(xc_mag, expect) != 0 || (xc->nlimbs != 0 && xc->sign != sign))
			bad("mpi_rshift: disagrees with the independent BIGNUM reference (x != a)");
		BN_free(xc_mag);
	}
	BN_free(b); BN_free(expect);

	if (poison) {
		MPI xr2 = mpi_alloc((unsigned)(nlimbs + 2));
		mpi_rshift(xr2, ar, n);
		if (xr2->nlimbs > 0) {
			xr2->d[0] ^= 1;
			cases++;
			if (!mpi_eq(xc, xr2))
				bad("mpi_rshift: poisoned run (expected)");
		}
		mpi_free(xr2);
	}

	mpi_free(ac); mpi_free(ar); mpi_free(xc); mpi_free(xr);
}

/* x == a (the in-place path). */
static void run_rshift_inplace(int nlimbs, int sign, const mpi_limb_t *limbs, unsigned n)
{
	MPI ac = mk_mpi(nlimbs, sign, limbs), ar = mk_mpi(nlimbs, sign, limbs);
	int rc = c_mpi_rshift(ac, ac, n);
	int rr = mpi_rshift(ar, ar, n);

	cases++;
	if (rc != rr || !mpi_eq(ac, ar))
		bad("mpi_rshift: arms disagree (in place)");

	mpi_free(ac); mpi_free(ar);
}

int main(void)
{
	unsigned n;
	mpi_limb_t up[MAXLIMBS];

	if (getenv("MPIBIT_PROVE_CAN_FAIL"))
		poison = 1;

	/* mpi_normalize is exercised transitively by every mpi_get_nbits
	 * call below (it calls mpi_normalize() first) -- including cases
	 * with a stale zero top limb. */
	{
		mpi_limb_t v[3] = { 5, 1, 0 };
		run_get_nbits(3, v);
	}
	{
		mpi_limb_t zero[1] = { 0 };
		run_get_nbits(0, zero);
		run_get_nbits(1, zero);
	}
	{
		mpi_limb_t v[1] = { 255 };
		run_get_nbits(1, v);
	}
	{
		mpi_limb_t v[1] = { 256 };
		run_get_nbits(1, v);
	}

	{
		mpi_limb_t v[1] = { 10 };
		unsigned i;
		for (i = 0; i < 8; i++)
			run_test_bit(1, v, i);
		run_test_bit(1, v, 200);
	}
	{
		mpi_limb_t v[1] = { 0 };
		run_set_bit(1, v, 0);
		run_set_bit(1, v, 63);
		run_set_bit(1, v, 70); /* grows past the first limb */
	}
	{
		mpi_limb_t v[1] = { 10 };
		run_rshift(1, 0, v, 1);
		run_rshift(1, 0, v, 10); /* shifts entirely away */
		run_rshift_inplace(1, 0, v, 1);
	}
	{
		mpi_limb_t v[2] = { 7, 1 };
		run_rshift(2, 0, v, 64); /* exact-limb shift */
		run_rshift(2, 0, v, 65); /* whole-limb-plus-remainder */
		run_rshift_inplace(2, 0, v, 64);
		run_rshift_inplace(2, 0, v, 65);
	}
	{
		/* Negative operand: mpi_rshift copies sign unconditionally. */
		mpi_limb_t v[1] = { 10 };
		run_rshift(1, 1, v, 1);
	}

	/* Random sweep. */
	for (n = 0; n < 2000; n++) {
		int nlimbs = 1 + (int)(rnd() % 6);
		unsigned bit = rnd() % (64u * 8);

		fill_random_mpi(up, nlimbs);
		run_get_nbits(nlimbs, up);
		run_test_bit(nlimbs, up, bit);
	}
	for (n = 0; n < 500; n++) {
		int nlimbs = 1 + (int)(rnd() % 4);
		unsigned bit = rnd() % (64u * 6);

		fill_random_mpi(up, nlimbs);
		run_set_bit(nlimbs, up, bit);
	}
	for (n = 0; n < 800; n++) {
		int nlimbs = 1 + (int)(rnd() % 6);
		int sign = (int)(rnd() & 1);
		unsigned shift = rnd() % (64u * (unsigned)(nlimbs + 1));

		fill_random_mpi(up, nlimbs);
		run_rshift(nlimbs, sign, up, shift);
		run_rshift_inplace(nlimbs, sign, up, shift);
	}

	if (mism) {
		fprintf(stderr, "%lu/%lu cases MISMATCHED\n", mism, cases);
		return 1;
	}
	printf("%lu cases, 0 mismatches\n", cases);
	return 0;
}
