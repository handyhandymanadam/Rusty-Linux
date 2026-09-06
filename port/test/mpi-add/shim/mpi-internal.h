#pragma once
/* Trimmed reproduction of lib/crypto/mpi/mpi-internal.h: only what
 * mpi-add.c/mpi-sub-ui.c reference, PLUS the real mpi-inline.h at the end
 * (unmodified, via -I onto its real directory in run.sh) -- that header's
 * mpihelp_add_1/add/sub_1/sub bodies are exactly what this differential
 * checks the Rust reimplementation against, so it must be the genuine
 * upstream file, not a shim. */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mpi.h>

/* NOT `#include <linux/errno.h>` -- see port/test/mpiutil/shim/mpi-internal.h
 * for why that shadows a real system header glibc itself depends on. */
#ifndef ENOMEM
#define ENOMEM 12
#endif

typedef mpi_limb_t *mpi_ptr_t;
typedef int mpi_size_t;

static inline int RESIZE_IF_NEEDED(MPI a, unsigned b)
{
	if (a->alloced < b)
		return mpi_resize(a, b);
	return 0;
}

#define MPN_COPY(d, s, n) \
	do {					\
		mpi_size_t _i;			\
		for (_i = 0; _i < (n); _i++)	\
			(d)[_i] = (s)[_i];	\
	} while (0)

#define MPN_NORMALIZE(d, n)  \
	do {					\
		while ((n) > 0) {		\
			if ((d)[(n)-1])		\
				break;		\
			(n)--;			\
		}				\
	} while (0)

mpi_limb_t mpihelp_add_n(mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
			  mpi_ptr_t s2_ptr, mpi_size_t size);
mpi_limb_t mpihelp_sub_n(mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
			  mpi_ptr_t s2_ptr, mpi_size_t size);
int mpihelp_cmp(mpi_ptr_t op1_ptr, mpi_ptr_t op2_ptr, mpi_size_t size);

#include "mpi-inline.h"
