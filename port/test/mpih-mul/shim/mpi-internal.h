#pragma once
/* Trimmed reproduction of lib/crypto/mpi/mpi-internal.h: only what
 * mpih-mul.c references. mpih-mul.c's own #include "mpi-internal.h" /
 * "longlong.h" are quoted, resolving via -I on this shim directory --
 * longlong.h is a trivial stub here, see its own comment for why. */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mpi.h>

#define ENOMEM 12

typedef mpi_limb_t *mpi_ptr_t;
typedef int mpi_size_t;

/* Verbatim from the real header (mpih-mul.c relies on this exact value). */
#define KARATSUBA_THRESHOLD 16
#if KARATSUBA_THRESHOLD < 2
#undef KARATSUBA_THRESHOLD
#define KARATSUBA_THRESHOLD 2
#endif

#define MPN_COPY(d, s, n) \
	do {					\
		mpi_size_t _i;			\
		for (_i = 0; _i < (n); _i++)	\
			(d)[_i] = (s)[_i];	\
	} while (0)

#define MPN_ZERO(d, n) \
	do {					\
		int  _i;			\
		for (_i = 0; _i < (n); _i++)	\
			(d)[_i] = 0;		\
	} while (0)

#define MPN_MUL_N_RECURSE(prodp, up, vp, size, tspace) \
	do {							\
		if ((size) < KARATSUBA_THRESHOLD)		\
			mul_n_basecase(prodp, up, vp, size);	\
		else						\
			mul_n(prodp, up, vp, size, tspace);	\
	} while (0);

#define MPN_SQR_N_RECURSE(prodp, up, size, tspace)		\
	do {							\
		if ((size) < KARATSUBA_THRESHOLD)		\
			mpih_sqr_n_basecase(prodp, up, size);	\
		else						\
			mpih_sqr_n(prodp, up, size, tspace);	\
	} while (0);

/* mpihelp_add_1() -- static inline in the real mpi-inline.h, which the
 * real mpi-internal.h #includes. Verbatim body; the only one of that
 * header's four functions mpih-mul.c actually calls. */
static inline mpi_limb_t
mpihelp_add_1(mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
	      mpi_size_t s1_size, mpi_limb_t s2_limb)
{
	mpi_limb_t x;

	x = *s1_ptr++;
	s2_limb += x;
	*res_ptr++ = s2_limb;
	if (s2_limb < x) {
		while (--s1_size) {
			x = *s1_ptr++ + 1;
			*res_ptr++ = x;
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

struct karatsuba_ctx {
	struct karatsuba_ctx *next;
	mpi_ptr_t tspace;
	mpi_size_t tspace_size;
	mpi_ptr_t tp;
	mpi_size_t tp_size;
};

mpi_ptr_t mpi_alloc_limb_space(unsigned nlimbs);
void mpi_free_limb_space(mpi_ptr_t a);

mpi_limb_t mpihelp_mul_1(mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
			 mpi_size_t s1_size, mpi_limb_t s2_limb);
mpi_limb_t mpihelp_add_n(mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
			 mpi_ptr_t s2_ptr, mpi_size_t size);
mpi_limb_t mpihelp_addmul_1(mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
			    mpi_size_t s1_size, mpi_limb_t s2_limb);
mpi_limb_t mpihelp_sub_n(mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
			 mpi_ptr_t s2_ptr, mpi_size_t size);
int mpihelp_cmp(mpi_ptr_t op1_ptr, mpi_ptr_t op2_ptr, mpi_size_t size);

void mpihelp_release_karatsuba_ctx(struct karatsuba_ctx *ctx);
int mpihelp_mul(mpi_ptr_t prodp, mpi_ptr_t up, mpi_size_t usize,
		mpi_ptr_t vp, mpi_size_t vsize, mpi_limb_t *_result);
void mpih_sqr_n_basecase(mpi_ptr_t prodp, mpi_ptr_t up, mpi_size_t size);
void mpih_sqr_n(mpi_ptr_t prodp, mpi_ptr_t up, mpi_size_t size,
		mpi_ptr_t tspace);
int mpihelp_mul_karatsuba_case(mpi_ptr_t prodp,
			       mpi_ptr_t up, mpi_size_t usize,
			       mpi_ptr_t vp, mpi_size_t vsize,
			       struct karatsuba_ctx *ctx);
