#pragma once
/* Trimmed to exactly what mpi-internal.h needs -- mpih-mul.c never touches
 * struct gcry_mpi/MPI itself, only raw limb arrays. */
typedef unsigned long int mpi_limb_t;

#define BYTES_PER_MPI_LIMB (BITS_PER_LONG / 8)
#define BITS_PER_MPI_LIMB BITS_PER_LONG
