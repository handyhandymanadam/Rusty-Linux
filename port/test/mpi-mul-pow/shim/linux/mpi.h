#pragma once
/* Trimmed reproduction of include/linux/mpi.h: struct layout copied
 * verbatim, plus the declarations mpi-mul.c/mpi-pow.c and their
 * dependencies reference. */
#include <linux/types.h>

typedef unsigned long int mpi_limb_t;
typedef signed long int mpi_limb_signed_t;

struct gcry_mpi {
	int alloced;
	int nlimbs;
	int nbits;
	int sign;
	unsigned flags;
	mpi_limb_t *d;
};

typedef struct gcry_mpi *MPI;

MPI mpi_alloc(unsigned nlimbs);
void mpi_free(MPI a);
int mpi_resize(MPI a, unsigned nlimbs);
MPI mpi_copy(MPI a);
int mpi_add(MPI w, MPI u, MPI v);
int mpi_fdiv_r(MPI rem, MPI dividend, MPI divisor);
int mpi_tdiv_r(MPI rem, MPI num, MPI den);
int mpi_tdiv_qr(MPI quot, MPI rem, MPI num, MPI den);
int mpi_mod(MPI rem, MPI dividend, MPI divisor);
int mpi_mul(MPI w, MPI u, MPI v);
int mpi_mulm(MPI w, MPI u, MPI v, MPI m);
int mpi_powm(MPI res, MPI base, MPI exp, MPI mod);
