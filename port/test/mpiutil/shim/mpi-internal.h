#pragma once
/* Trimmed reproduction of lib/crypto/mpi/mpi-internal.h: only what
 * mpiutil.c itself references. mpiutil.c's own #include "mpi-internal.h"
 * is quoted, so it resolves via -I on this shim directory when the
 * pristine file (which ships no local mpi-internal.h of its own) is
 * compiled standalone. */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mpi.h>

/* NOT `#include <linux/errno.h>`: on this glibc, the REAL system header of
 * that same name is what `<errno.h>` itself includes internally
 * (bits/errno.h -> linux/errno.h) to get ENOMEM's value in the first
 * place. Shadowing that path with a shim -- even one that just wraps
 * `#include <errno.h>` -- makes glibc's own include of it a silent
 * `#pragma once` no-op, and ENOMEM is never actually defined. Defining it
 * directly avoids ever touching that path. */
#ifndef ENOMEM
#define ENOMEM 12
#endif

typedef mpi_limb_t *mpi_ptr_t;
typedef int mpi_size_t;

mpi_ptr_t mpi_alloc_limb_space(unsigned nlimbs);
void mpi_free_limb_space(mpi_ptr_t a);
void mpi_assign_limb_space(MPI a, mpi_ptr_t ap, unsigned nlimbs);
