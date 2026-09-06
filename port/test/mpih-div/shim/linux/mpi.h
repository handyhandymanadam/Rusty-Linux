#pragma once
/* Trimmed reproduction of include/linux/mpi.h: only the typedefs
 * mpih-div.c/longlong.h/mpi-internal.h reference. mpih-div.c itself never
 * touches struct gcry_mpi. */
#include <linux/types.h>

typedef unsigned long int mpi_limb_t;
typedef signed long int mpi_limb_signed_t;

#define BITS_PER_MPI_LIMB BITS_PER_LONG
