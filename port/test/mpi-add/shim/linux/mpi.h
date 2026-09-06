#pragma once
/* Trimmed reproduction of include/linux/mpi.h: struct layout copied
 * verbatim, plus only the declarations mpi-add.c/mpi-sub-ui.c and
 * mpi-internal.h reference. */
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
int mpi_mod(MPI rem, MPI dividend, MPI divisor);
int mpi_sub_ui(MPI w, MPI u, unsigned long vval);
void mpi_normalize(MPI a);
