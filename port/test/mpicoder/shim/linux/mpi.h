#pragma once
/* Trimmed reproduction of include/linux/mpi.h: struct layout copied
 * verbatim, plus mpi_get_size() (static inline, duplicated here to match
 * the real header) and the entry points mpicoder.c references. */
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

/* Must be a plain integer literal, usable in `#if BYTES_PER_MPI_LIMB ==
 * 8` -- sizeof(...) is not valid in a preprocessor expression. */
#define BYTES_PER_MPI_LIMB 8

MPI mpi_alloc(unsigned nlimbs);
void mpi_free(MPI a);

static inline unsigned int mpi_get_size(MPI a)
{
	return a->nlimbs * BYTES_PER_MPI_LIMB;
}
