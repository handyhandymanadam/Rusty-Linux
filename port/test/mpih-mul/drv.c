/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * port/test/mpih-mul/drv.c -- differential for lib/crypto/mpi/mpih-mul.c ->
 * mpih_mul_rs.rs (mpihelp_mul, mpihelp_mul_karatsuba_case,
 * mpihelp_release_karatsuba_ctx, mpih_sqr_n_basecase, mpih_sqr_n).
 *
 * mpihelp_mul_1/addmul_1/add_n/sub_n/cmp (generic_mpih_rs.rs) and
 * mpi_alloc_limb_space/mpi_free_limb_space (mpiutil_rs.rs) are shared
 * dependencies, already ported and verified, linked into both arms
 * unchanged -- not under test here.
 *
 * An independent oracle checks the actual arithmetic: a from-scratch
 * schoolbook multiply using a separate accumulator array and 128-bit
 * widening per limb-pair -- a different algorithm from both the C's and
 * the port's shared Karatsuba/basecase machinery, so it cannot agree with
 * a bug the port and C share.
 *
 * Sizes are chosen to force every shape: below KARATSUBA_THRESHOLD (16,
 * the basecase schoolbook path), at or above it (real Karatsuba
 * recursion, both in mpihelp_mul's own dispatch and in mul_n/mpih_sqr_n's
 * odd/even split), and one hand-picked case whose "tail" after consuming
 * whole vsize-chunks is itself >= KARATSUBA_THRESHOLD, forcing
 * mpihelp_mul_karatsuba_case's own ctx->next recursive allocation (the
 * one path a random sweep might miss entirely if unlucky).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAXLIMBS 96

typedef unsigned long mpi_limb_t;

/* ---- Shared dependencies: ONE implementation, linked into both arms ---- */
mpi_limb_t *mpi_alloc_limb_space(unsigned nlimbs);
void mpi_free_limb_space(mpi_limb_t *a);

/* ---- karatsuba_ctx, shared shape (matches the real struct exactly) ---- */
struct karatsuba_ctx {
	struct karatsuba_ctx *next;
	mpi_limb_t *tspace;
	int tspace_size;
	mpi_limb_t *tp;
	int tp_size;
};

/* ---- C arm (renamed via -D, see run.sh) ---- */
int c_mpihelp_mul(mpi_limb_t *prodp, const mpi_limb_t *up, int usize,
		   const mpi_limb_t *vp, int vsize, mpi_limb_t *result);
int c_mpihelp_mul_karatsuba_case(mpi_limb_t *prodp, const mpi_limb_t *up, int usize,
				  const mpi_limb_t *vp, int vsize, struct karatsuba_ctx *ctx);
void c_mpihelp_release_karatsuba_ctx(struct karatsuba_ctx *ctx);
void c_mpih_sqr_n_basecase(mpi_limb_t *prodp, const mpi_limb_t *up, int size);
void c_mpih_sqr_n(mpi_limb_t *prodp, const mpi_limb_t *up, int size, mpi_limb_t *tspace);

/* ---- Rust arm (kept at the real names) ---- */
int mpihelp_mul(mpi_limb_t *prodp, const mpi_limb_t *up, int usize,
		 const mpi_limb_t *vp, int vsize, mpi_limb_t *result);
int mpihelp_mul_karatsuba_case(mpi_limb_t *prodp, const mpi_limb_t *up, int usize,
				const mpi_limb_t *vp, int vsize, struct karatsuba_ctx *ctx);
void mpihelp_release_karatsuba_ctx(struct karatsuba_ctx *ctx);
void mpih_sqr_n_basecase(mpi_limb_t *prodp, const mpi_limb_t *up, int size);
void mpih_sqr_n(mpi_limb_t *prodp, const mpi_limb_t *up, int size, mpi_limb_t *tspace);

static unsigned long cases, mism;
static int poison;

static void bad(const char *what)
{
	if (mism < 20)
		printf("MISMATCH %s\n", what);
	mism++;
}

static uint32_t rnd_state = 0xC0FFEE;
static uint32_t rnd(void)
{
	rnd_state = rnd_state * 1103515245u + 12345u;
	return rnd_state;
}

/* Independent oracle: schoolbook multiply, a separate accumulator array,
 * 128-bit widening per limb-pair -- unrelated to Karatsuba or to the
 * carry-propagation style mpihelp_mul_1/addmul_1 use. */
static void ref_mul(mpi_limb_t *prod, const mpi_limb_t *up, int usize,
		     const mpi_limb_t *vp, int vsize)
{
	int i, j;

	for (i = 0; i < usize + vsize; i++)
		prod[i] = 0;

	for (j = 0; j < vsize; j++) {
		unsigned __int128 carry = 0;

		for (i = 0; i < usize; i++) {
			unsigned __int128 t = (unsigned __int128)up[i] * vp[j] +
					       prod[i + j] + carry;
			prod[i + j] = (mpi_limb_t)t;
			carry = t >> 64;
		}
		i = usize;
		while (carry) {
			unsigned __int128 t = (unsigned __int128)prod[i + j] + carry;
			prod[i + j] = (mpi_limb_t)t;
			carry = t >> 64;
			i++;
		}
	}
}

static void fill_random(mpi_limb_t *a, int n)
{
	int i;
	for (i = 0; i < n; i++)
		a[i] = ((uint64_t)rnd() << 32) | rnd();
}

static void run_mul(int usize, const mpi_limb_t *up, int vsize, const mpi_limb_t *vp)
{
	mpi_limb_t prodc[2 * MAXLIMBS], prodr[2 * MAXLIMBS], prodref[2 * MAXLIMBS];
	mpi_limb_t resc, resr;
	int rc, rr;

	rc = c_mpihelp_mul(prodc, up, usize, vp, vsize, &resc);
	rr = mpihelp_mul(prodr, up, usize, vp, vsize, &resr);
	cases++;
	if (rc != rr)
		bad("mpihelp_mul: return code differs");
	cases++;
	if (memcmp(prodc, prodr, (size_t)(usize + vsize) * sizeof(mpi_limb_t)))
		bad("mpihelp_mul: product differs between arms");
	cases++;
	if (vsize > 0 && resc != resr)
		bad("mpihelp_mul: most-significant limb (result) differs between arms");

	if (vsize > 0) {
		ref_mul(prodref, up, usize, vp, vsize);
		cases++;
		if (memcmp(prodc, prodref, (size_t)(usize + vsize) * sizeof(mpi_limb_t)))
			bad("mpihelp_mul: disagrees with the independent schoolbook reference");
	}

	if (poison) {
		mpi_limb_t p2[2 * MAXLIMBS];
		mpi_limb_t r2;
		mpihelp_mul(p2, up, usize, vp, vsize, &r2);
		if (usize + vsize > 0)
			p2[0] ^= 1;
		cases++;
		/* memcmp is NONZERO for the (deliberately) differing
		 * buffers -- that is the poisoned run being caught. */
		if (memcmp(prodc, p2, (size_t)(usize + vsize) * sizeof(mpi_limb_t)))
			bad("mpihelp_mul: poisoned run (expected)");
	}
}

/* Direct karatsuba_case exercise, bypassing mpihelp_mul's own vsize<16
 * dispatch -- lets us force real Karatsuba recursion (and, via a large
 * enough "tail", ctx->next) at sizes mpihelp_mul's own small-first-operand
 * convention (usize >= vsize) wouldn't otherwise reach through a single
 * top-level call. Also exercises ctx reuse across repeated calls, the
 * shape mpi_powm's own loop relies on. */
static void run_karatsuba_case(int usize, const mpi_limb_t *up, int vsize, const mpi_limb_t *vp)
{
	mpi_limb_t prodc[2 * MAXLIMBS + 8], prodr[2 * MAXLIMBS + 8];
	mpi_limb_t prodref[2 * MAXLIMBS + 8];
	struct karatsuba_ctx cc, cr;
	int rc, rr, i;

	memset(&cc, 0, sizeof(cc));
	memset(&cr, 0, sizeof(cr));

	/* Call twice with the same ctx (same sizes) to exercise the
	 * tspace/tp REUSE branch, not just fresh allocation. */
	for (i = 0; i < 2; i++) {
		rc = c_mpihelp_mul_karatsuba_case(prodc, up, usize, vp, vsize, &cc);
		rr = mpihelp_mul_karatsuba_case(prodr, up, usize, vp, vsize, &cr);
		cases++;
		if (rc != rr)
			bad("mpihelp_mul_karatsuba_case: return code differs");
		cases++;
		if (memcmp(prodc, prodr, (size_t)(usize + vsize) * sizeof(mpi_limb_t)))
			bad("mpihelp_mul_karatsuba_case: product differs between arms");
	}

	ref_mul(prodref, up, usize, vp, vsize);
	cases++;
	if (memcmp(prodc, prodref, (size_t)(usize + vsize) * sizeof(mpi_limb_t)))
		bad("mpihelp_mul_karatsuba_case: disagrees with the independent reference");

	c_mpihelp_release_karatsuba_ctx(&cc);
	mpihelp_release_karatsuba_ctx(&cr);
}

static void run_sqr(int size, const mpi_limb_t *up)
{
	mpi_limb_t prodc[2 * MAXLIMBS], prodr[2 * MAXLIMBS], prodref[2 * MAXLIMBS];
	mpi_limb_t tspacec[2 * MAXLIMBS], tspacer[2 * MAXLIMBS];

	if (size < 16) {
		c_mpih_sqr_n_basecase(prodc, up, size);
		mpih_sqr_n_basecase(prodr, up, size);
	} else {
		c_mpih_sqr_n(prodc, up, size, tspacec);
		mpih_sqr_n(prodr, up, size, tspacer);
	}
	cases++;
	if (memcmp(prodc, prodr, (size_t)(2 * size) * sizeof(mpi_limb_t)))
		bad("mpih_sqr_n(_basecase): product differs between arms");

	ref_mul(prodref, up, size, up, size);
	cases++;
	if (memcmp(prodc, prodref, (size_t)(2 * size) * sizeof(mpi_limb_t)))
		bad("mpih_sqr_n(_basecase): disagrees with the independent reference (u*u)");
}

int main(void)
{
	unsigned n;
	mpi_limb_t up[MAXLIMBS], vp[MAXLIMBS];

	if (getenv("MPIHMUL_PROVE_CAN_FAIL"))
		poison = 1;

	/* Hand-picked: trivial single-limb, and known small products. */
	{
		mpi_limb_t seven[1] = { 7 }, five[1] = { 5 };
		run_mul(1, seven, 1, five);
		run_sqr(1, seven);
	}
	{
		/* Multi-limb, still basecase (both < 16). */
		mpi_limb_t u2[3] = { 0xFFFFFFFFFFFFFFFFULL, 0x123456789ABCDEF0ULL, 3 };
		mpi_limb_t v2[2] = { 0x1122334455667788ULL, 9 };
		run_mul(3, u2, 2, v2);
	}
	{
		/* Equal sizes straddling KARATSUBA_THRESHOLD exactly at 16:
		 * one below (basecase), one at (first Karatsuba step). */
		fill_random(up, 15);
		fill_random(vp, 15);
		run_mul(15, up, 15, vp);
		run_sqr(15, up);

		fill_random(up, 16);
		fill_random(vp, 16);
		run_mul(16, up, 16, vp);
		run_sqr(16, up);
	}
	{
		/* Deeper Karatsuba recursion: 32 limbs (one full recursive
		 * split), 64 limbs (two levels). */
		fill_random(up, 32);
		fill_random(vp, 32);
		run_mul(32, up, 32, vp);
		run_sqr(32, up);
		run_karatsuba_case(32, up, 32, vp);

		fill_random(up, 64);
		fill_random(vp, 64);
		run_mul(64, up, 64, vp);
		run_sqr(64, up);
	}
	{
		/* Odd sizes: mul_n/mpih_sqr_n's "size & 1" branch, at both
		 * scales. */
		fill_random(up, 17);
		fill_random(vp, 17);
		run_mul(17, up, 17, vp);
		run_sqr(17, up);

		fill_random(up, 33);
		fill_random(vp, 33);
		run_mul(33, up, 33, vp);
		run_sqr(33, up);
	}
	{
		/* Hand-picked to force mpihelp_mul_karatsuba_case's own
		 * ctx->next recursion: vsize=20, usize=39. The initial
		 * MPN_MUL_N_RECURSE consumes 20, leaving 19; the "while
		 * (usize >= vsize)" loop doesn't fire (19 < 20); the
		 * remaining tail (19) is still >= KARATSUBA_THRESHOLD (16),
		 * so the "else" branch allocates ctx->next and recurses. */
		fill_random(up, 39);
		fill_random(vp, 20);
		run_mul(39, up, 20, vp);
		run_karatsuba_case(39, up, 20, vp);
	}
	{
		/* usize a large multiple of vsize: exercises the "do { ...
		 * } while (usize >= vsize)" loop body running more than
		 * once (usize/vsize >= 3 here). */
		fill_random(up, 60);
		fill_random(vp, 16);
		run_mul(60, up, 16, vp);
	}

	/* Random sweep: usize in [1,80], vsize in [1,usize], every size
	 * relationship weighted toward small values (more interesting
	 * carry/threshold edges) but occasionally reaching the full range. */
	for (n = 0; n < 3000; n++) {
		int usize = 1 + (int)(rnd() % 80);
		int vsize = 1 + (int)(rnd() % (unsigned)usize);

		fill_random(up, usize);
		fill_random(vp, vsize);
		run_mul(usize, up, vsize, vp);
		if (n % 7 == 0)
			run_sqr(usize, up);
	}

	if (mism) {
		fprintf(stderr, "%lu/%lu cases MISMATCHED\n", mism, cases);
		return 1;
	}
	printf("%lu cases, 0 mismatches\n", cases);
	return 0;
}
