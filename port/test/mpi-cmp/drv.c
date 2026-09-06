/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * port/test/mpi-cmp/drv.c -- differential for lib/crypto/mpi/mpi-cmp.c.
 *
 * mpi_normalize() and mpihelp_cmp() are shared support code, not under
 * test here (mpihelp_cmp is already ported and verified in
 * generic_mpih_rs.rs; mpi_normalize is upstream C not yet ported, still a
 * real out-of-line symbol both arms call). What's compared is the two
 * arms' mpi_cmp()/mpi_cmp_ui() logic itself.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

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

void mpi_normalize(MPI a)
{
	for (; a->nlimbs && !a->d[a->nlimbs - 1]; a->nlimbs--)
		;
}

int mpihelp_cmp(mpi_limb_t *op1_ptr, mpi_limb_t *op2_ptr, int size)
{
	int i;
	mpi_limb_t op1_word, op2_word;

	for (i = size - 1; i >= 0; i--) {
		op1_word = op1_ptr[i];
		op2_word = op2_ptr[i];
		if (op1_word != op2_word)
			return (op1_word > op2_word) ? 1 : -1;
	}
	return 0;
}

/* ---- C arm (renamed) ---- */
int c_mpi_cmp_ui(MPI u, unsigned long v);
int c_mpi_cmp(MPI u, MPI v);

/* ---- Rust arm ---- */
int mpi_cmp_ui(MPI u, unsigned long v);
int mpi_cmp(MPI u, MPI v);

static unsigned long cases, mism;
static int poison;

static void bad(const char *what)
{
	if (mism < 20)
		printf("MISMATCH %s\n", what);
	mism++;
}

static MPI mk(int nlimbs, int alloced, int sign, mpi_limb_t *limbs)
{
	MPI m = malloc(sizeof(*m));
	m->alloced = alloced;
	m->nlimbs = nlimbs;
	m->nbits = 0;
	m->sign = sign;
	m->flags = 0;
	m->d = limbs;
	return m;
}

/* Cover: zero, one limb, several limbs, positive/negative, equal,
 * differing at the top limb, differing at a low limb only, with
 * trailing zero limbs that mpi_normalize() must strip first. */
static void run_ui(unsigned n, unsigned seed)
{
	unsigned s = seed;
	mpi_limb_t limbs[4];
	int nlimbs = n % 5;
	for (int i = 0; i < nlimbs; i++) {
		s = s * 1103515245u + 12345u;
		limbs[i] = s;
	}
	/* Occasionally force trailing zero limbs to exercise normalize. */
	if (nlimbs > 0 && (n % 3) == 0)
		limbs[nlimbs - 1] = 0;

	mpi_limb_t limbs_c[4], limbs_r[4];
	memcpy(limbs_c, limbs, sizeof(limbs));
	memcpy(limbs_r, limbs, sizeof(limbs));

	int sign = (n % 2);
	unsigned long v = (s * 2654435761u) % 5;
	if (n % 7 == 0)
		v = 0;

	MPI mc = mk(nlimbs, 4, sign, limbs_c);
	MPI mr = mk(nlimbs, 4, sign, limbs_r);

	int rc = c_mpi_cmp_ui(mc, v);
	int rr = mpi_cmp_ui(mr, v);
	cases++;
	if (rc != rr)
		bad("cmp_ui");
	if (mc->nlimbs != mr->nlimbs)
		bad("cmp_ui-normalize");

	free(mc);
	free(mr);
}

static void run_cmp(unsigned n, unsigned seed)
{
	unsigned s = seed;
	mpi_limb_t au[4], av[4];
	int na = n % 5;
	int nb = (n / 5) % 5;
	for (int i = 0; i < 4; i++) {
		s = s * 1103515245u + 12345u;
		au[i] = s;
		s = s * 1103515245u + 12345u;
		av[i] = s;
	}
	if (na > 0 && (n % 3) == 0)
		au[na - 1] = 0;
	if (nb > 0 && (n % 4) == 0)
		av[nb - 1] = 0;
	/* Occasionally make them equal to exercise the usize==vsize path. */
	if (n % 11 == 0) {
		nb = na;
		memcpy(av, au, sizeof(au));
	}

	int sign_u = (n % 2);
	int sign_v = ((n / 2) % 2);

	mpi_limb_t au_c[4], av_c[4], au_r[4], av_r[4];
	memcpy(au_c, au, sizeof(au)); memcpy(av_c, av, sizeof(av));
	memcpy(au_r, au, sizeof(au)); memcpy(av_r, av, sizeof(av));

	MPI uc = mk(na, 4, sign_u, au_c), vc = mk(nb, 4, sign_v, av_c);
	MPI ur = mk(na, 4, sign_u, au_r), vr = mk(nb, 4, sign_v, av_r);

	int rc = c_mpi_cmp(uc, vc);
	int rr = mpi_cmp(ur, vr);
	cases++;
	/* mpi_cmp's magnitude case returns a raw size difference, not a
	 * normalized -1/0/1 -- compare sign of result, not exact value,
	 * except in the always-equal-size paths where both arms compute
	 * the identical expression and must match exactly. */
	if ((rc == 0) != (rr == 0) || (rc > 0) != (rr > 0))
		bad("cmp-sign");
	if (na == nb && rc != rr)
		bad("cmp-exact");

	free(uc); free(vc); free(ur); free(vr);
}

int main(void)
{
	if (getenv("MPICMP_PROVE_CAN_FAIL"))
		poison = 1;

	for (unsigned n = 0; n < 4000; n++) {
		run_ui(n, n * 2654435761u + 1);
		run_cmp(n, n * 2654435761u + 7);
	}

	if (poison) {
		/* Feed each arm a genuinely different value, proving the
		 * harness can disagree: C arm compares 5 == 5, Rust arm
		 * compares 6 vs 5, so the two results must differ. */
		mpi_limb_t lc[1] = { 5 }, lr[1] = { 6 };
		MPI mc = mk(1, 1, 0, lc);
		MPI mr = mk(1, 1, 0, lr);
		int rc = c_mpi_cmp_ui(mc, 5);
		int rr = mpi_cmp_ui(mr, 5);
		cases++;
		if (rc != rr)
			bad("cmp_ui");
		free(mc); free(mr);
	}

	if (mism) {
		fprintf(stderr, "%lu/%lu cases MISMATCHED\n", mism, cases);
		return 1;
	}
	printf("%lu cases, 0 mismatches\n", cases);
	return 0;
}
