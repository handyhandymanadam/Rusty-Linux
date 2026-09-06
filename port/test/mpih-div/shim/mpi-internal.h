#pragma once
/* Trimmed reproduction of lib/crypto/mpi/mpi-internal.h: only what
 * mpih-div.c references. mpih-div.c's own #include "mpi-internal.h" /
 * "longlong.h" are quoted, resolving via -I on this shim directory first,
 * then (for longlong.h, which is NOT shimmed -- see run.sh) the real
 * upstream directory. */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mpi.h>

typedef mpi_limb_t *mpi_ptr_t;
typedef int mpi_size_t;

#define MPN_COPY_DECR(d, s, n) \
	do {					\
		mpi_size_t _i;			\
		for (_i = (n)-1; _i >= 0; _i--) \
			(d)[_i] = (s)[_i];	\
	} while (0)

mpi_limb_t mpihelp_add_n(mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
			  mpi_ptr_t s2_ptr, mpi_size_t size);
mpi_limb_t mpihelp_sub_n(mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
			  mpi_ptr_t s2_ptr, mpi_size_t size);
mpi_limb_t mpihelp_submul_1(mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
			     mpi_size_t s1_size, mpi_limb_t s2_limb);
int mpihelp_cmp(mpi_ptr_t op1_ptr, mpi_ptr_t op2_ptr, mpi_size_t size);

/* Define stuff for longlong.h -- verbatim from the real mpi-internal.h. */
#define W_TYPE_SIZE BITS_PER_MPI_LIMB
typedef mpi_limb_t UWtype;
typedef unsigned int UHWtype;
#if defined(__GNUC__)
typedef unsigned int UQItype __attribute__ ((mode(QI)));
typedef int SItype __attribute__ ((mode(SI)));
typedef unsigned int USItype __attribute__ ((mode(SI)));
typedef int DItype __attribute__ ((mode(DI)));
typedef unsigned int UDItype __attribute__ ((mode(DI)));
#else
typedef unsigned char UQItype;
typedef long SItype;
typedef unsigned long USItype;
#endif

/* Verbatim from the real mpi-internal.h. Only used inside mpih-div.c's
 * pre-inverted-divisor fast path, which is compile-time-dead on x86-64
 * (see mpih_div_rs.rs's own module doc) -- needed here only so that dead
 * branch still COMPILES, matching the real kernel build. */
#define UDIV_QRNND_PREINV(q, r, nh, nl, d, di)				\
	do {								\
		mpi_limb_t _ql __maybe_unused;				\
		mpi_limb_t _q, _r;					\
		mpi_limb_t _xh, _xl;					\
		umul_ppmm(_q, _ql, (nh), (di));				\
		_q += (nh);	/* DI is 2**BITS_PER_MPI_LIMB too small */ \
		umul_ppmm(_xh, _xl, _q, (d));				\
		sub_ddmmss(_xh, _r, (nh), (nl), _xh, _xl);		\
		if (_xh) {						\
			sub_ddmmss(_xh, _r, _xh, _r, 0, (d));		\
			_q++;						\
			if (_xh) {					\
				sub_ddmmss(_xh, _r, _xh, _r, 0, (d));	\
				_q++;					\
			}						\
		}							\
		if (_r >= (d)) {					\
			_r -= (d);					\
			_q++;						\
		}							\
		(r) = _r;						\
		(q) = _q;						\
	} while (0)
