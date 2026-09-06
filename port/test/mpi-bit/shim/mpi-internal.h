#pragma once
/* Trimmed reproduction of lib/crypto/mpi/mpi-internal.h: only what
 * mpi-bit.c references. */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mpi.h>

#ifndef ENOMEM
#define ENOMEM 12
#endif

typedef mpi_limb_t *mpi_ptr_t;
typedef int mpi_size_t;

#define BITS_PER_MPI_LIMB (sizeof(mpi_limb_t) * 8)

static inline int RESIZE_IF_NEEDED(MPI a, unsigned b)
{
	if (a->alloced < b)
		return mpi_resize(a, b);
	return 0;
}

#define MPN_NORMALIZE(d, n)  \
	do {					\
		while ((n) > 0) {		\
			if ((d)[(n)-1])		\
				break;		\
			(n)--;			\
		}				\
	} while (0)

mpi_limb_t mpihelp_rshift(mpi_ptr_t wp, mpi_ptr_t up, mpi_size_t usize,
			  unsigned cnt);

#include "longlong.h"
