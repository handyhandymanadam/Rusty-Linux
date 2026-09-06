#pragma once
/* Minimal reproduction of lib/crypto/mpi/mpi-internal.h: only what
 * mpi-cmp.c itself references. mpi-cmp.c's own #include "mpi-internal.h"
 * is quoted, so it resolves via -I on this shim directory when the
 * pristine file (which ships no local mpi-internal.h of its own) is
 * compiled standalone. */
#include <linux/mpi.h>

typedef mpi_limb_t *mpi_ptr_t;
typedef int mpi_size_t;

int mpihelp_cmp(mpi_ptr_t op1_ptr, mpi_ptr_t op2_ptr, mpi_size_t size);
