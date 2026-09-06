#pragma once
/* Trimmed reproduction of lib/crypto/mpi/mpi-internal.h: only what
 * mpi-mul.c/mpi-pow.c reference. longlong.h is a minimal shim (see its
 * own comment) -- only count_leading_zeros() is used directly, never
 * udiv_qrnnd/umul_ppmm/add_ssaaaa/sub_ddmmss (those live inside
 * mpihelp_divrem/mpih_sqr_n/mpihelp_mul, already ported and linked as
 * separate, trusted dependencies here). */
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
#ifndef EINVAL
#define EINVAL 22
#endif

typedef mpi_limb_t *mpi_ptr_t;
typedef int mpi_size_t;

#define BITS_PER_MPI_LIMB (sizeof(mpi_limb_t) * 8)

#define KARATSUBA_THRESHOLD 16

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

struct karatsuba_ctx {
	struct karatsuba_ctx *next;
	mpi_ptr_t tspace;
	mpi_size_t tspace_size;
	mpi_ptr_t tp;
	mpi_size_t tp_size;
};

/* mpihelp_add_1() -- static inline in the real mpi-inline.h. Verbatim
 * body; mpi-pow.c doesn't call it directly, but mpihelp_sub() (below,
 * also static inline in the real header) needs its subtraction analogue
 * only -- this file still declares it for completeness/parity with the
 * real header's own structure, unused is fine. */
static inline mpi_limb_t
mpihelp_sub_1(mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
	      mpi_size_t s1_size, mpi_limb_t s2_limb)
{
	mpi_limb_t x;

	x = *s1_ptr++;
	s2_limb = x - s2_limb;
	*res_ptr++ = s2_limb;
	if (s2_limb > x) {
		while (--s1_size) {
			x = *s1_ptr++;
			*res_ptr++ = x - 1;
			if (x)
				goto leave;
		}
		return 1;
	}

leave:
	if (res_ptr != s1_ptr) {
		mpi_size_t i;
		for (i = 0; i < s1_size - 1; i++)
			res_ptr[i] = s1_ptr[i];
	}
	return 0;
}

mpi_limb_t mpihelp_sub_n(mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
			  mpi_ptr_t s2_ptr, mpi_size_t size);

static inline mpi_limb_t
mpihelp_sub(mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr, mpi_size_t s1_size,
	    mpi_ptr_t s2_ptr, mpi_size_t s2_size)
{
	mpi_limb_t cy = 0;

	if (s2_size)
		cy = mpihelp_sub_n(res_ptr, s1_ptr, s2_ptr, s2_size);
	if (s1_size - s2_size)
		cy = mpihelp_sub_1(res_ptr + s2_size, s1_ptr + s2_size,
				   s1_size - s2_size, cy);
	return cy;
}

mpi_ptr_t mpi_alloc_limb_space(unsigned nlimbs);
void mpi_free_limb_space(mpi_ptr_t a);
void mpi_assign_limb_space(MPI a, mpi_ptr_t ap, unsigned nlimbs);
mpi_limb_t mpihelp_lshift(mpi_ptr_t wp, mpi_ptr_t up, mpi_size_t usize,
			  unsigned cnt);
mpi_limb_t mpihelp_rshift(mpi_ptr_t wp, mpi_ptr_t up, mpi_size_t usize,
			  unsigned cnt);
mpi_limb_t mpihelp_divrem(mpi_ptr_t qp, mpi_size_t qextra_limbs,
			  mpi_ptr_t np, mpi_size_t nsize,
			  mpi_ptr_t dp, mpi_size_t dsize);
int mpihelp_mul(mpi_ptr_t prodp, mpi_ptr_t up, mpi_size_t usize,
		mpi_ptr_t vp, mpi_size_t vsize, mpi_limb_t *_result);
int mpihelp_mul_karatsuba_case(mpi_ptr_t prodp,
			       mpi_ptr_t up, mpi_size_t usize,
			       mpi_ptr_t vp, mpi_size_t vsize,
			       struct karatsuba_ctx *ctx);
void mpihelp_release_karatsuba_ctx(struct karatsuba_ctx *ctx);
void mpih_sqr_n_basecase(mpi_ptr_t prodp, mpi_ptr_t up, mpi_size_t size);
void mpih_sqr_n(mpi_ptr_t prodp, mpi_ptr_t up, mpi_size_t size,
		mpi_ptr_t tspace);

#include "longlong.h"
