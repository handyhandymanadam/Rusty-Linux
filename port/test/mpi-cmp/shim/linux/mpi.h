#pragma once
/* Minimal reproduction of include/linux/mpi.h: only what
 * lib/crypto/mpi/mpi-cmp.c itself references directly. Both arms (pristine
 * C and Rust) are checked against the SAME shim, so what's compared is the
 * two ports' logic, not this header. */

typedef unsigned long int mpi_limb_t;
typedef signed long int mpi_limb_signed_t;

struct gcry_mpi {
	int alloced;
	int nlimbs;
	int nbits;
	int sign;
	unsigned flags;
	mpi_limb_t *d;
};

typedef struct gcry_mpi *MPI;

void mpi_normalize(MPI a);
