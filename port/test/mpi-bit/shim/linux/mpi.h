#pragma once
/* Trimmed reproduction of include/linux/mpi.h: struct layout copied
 * verbatim, plus the declarations mpi-bit.c and its dependencies
 * reference. */
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
void mpi_normalize(MPI a);
unsigned mpi_get_nbits(MPI a);
int mpi_test_bit(MPI a, unsigned int n);
int mpi_set_bit(MPI a, unsigned int n);
int mpi_rshift(MPI x, MPI a, unsigned int n);
