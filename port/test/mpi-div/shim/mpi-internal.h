#pragma once
/* Trimmed reproduction of lib/crypto/mpi/mpi-internal.h: only what
 * mpi-div.c/mpi-mod.c reference. Unlike port/test/mpih-div/'s shim, this
 * one does NOT need the real longlong.h -- mpi-div.c's only use of it is
 * count_leading_zeros() (from linux/count_zeros.h, which longlong.h just
 * includes), never udiv_qrnnd/umul_ppmm/add_ssaaaa/sub_ddmmss directly, so
 * a minimal shim longlong.h (in this same directory) is enough and avoids
 * needing UWtype/UHWtype/UDWtype predefined. */
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

mpi_ptr_t mpi_alloc_limb_space(unsigned nlimbs);
void mpi_free_limb_space(mpi_ptr_t a);
mpi_limb_t mpihelp_mod_1(mpi_ptr_t dividend_ptr, mpi_size_t dividend_size,
			  mpi_limb_t divisor_limb);
mpi_limb_t mpihelp_divmod_1(mpi_ptr_t quot_ptr, mpi_ptr_t dividend_ptr,
			     mpi_size_t dividend_size, mpi_limb_t divisor_limb);
mpi_limb_t mpihelp_divrem(mpi_ptr_t qp, mpi_size_t qextra_limbs,
			  mpi_ptr_t np, mpi_size_t nsize,
			  mpi_ptr_t dp, mpi_size_t dsize);
mpi_limb_t mpihelp_lshift(mpi_ptr_t wp, mpi_ptr_t up, mpi_size_t usize,
			  unsigned cnt);
mpi_limb_t mpihelp_rshift(mpi_ptr_t wp, mpi_ptr_t up, mpi_size_t usize,
			  unsigned cnt);

#include "longlong.h"
