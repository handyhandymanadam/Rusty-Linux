#pragma once
/* Trimmed reproduction of include/linux/mpi.h: struct layout copied
 * verbatim (this differential exists to hold it constant), plus only the
 * declarations mpiutil.c and mpi-internal.h reference. Both arms are
 * checked against this SAME shim, so what's compared is the two ports'
 * logic, not this header. */
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
