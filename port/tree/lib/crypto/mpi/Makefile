# SPDX-License-Identifier: GPL-2.0
#
# MPI multiprecision maths library (from gpg)
#

obj-$(CONFIG_MPILIB) = mpi.o

# THE EIGHT generic_mpih-*.c AND mpih-cmp.c ARE GONE, not wrapped: none of
# their functions is EXPORT_SYMBOL, so none has a MODVERSIONS CRC and none
# needs a C entry symbol. All eight are one file,
# lib/crypto/mpi/generic_mpih_rs.rs, which explains there why.
mpi-y = \
	mpicoder.o			\
	mpi-add.o			\
	mpi-bit.o			\
	mpi-cmp.o			\
	mpi-sub-ui.o			\
	mpi-div.o			\
	mpi-mod.o			\
	mpi-mul.o			\
	mpih-div.o			\
	mpih-mul.o			\
	mpi-pow.o			\
	mpiutil.o

# --- THE CONFIG_RUST=n ARM.  logs/floor.md RAISE 2. ------------------------
# <base>_norust.c is installed by rig/apply.sh from port/pristine/ -- the
# sha256-verified upstream body, byte for byte, at a filename the Makefile can
# choose independently of the ported one. Generated on every apply, never
# committed, so it cannot drift.
ifdef CONFIG_RUST
mpi-y += generic_mpih_rs.o
else
mpi-y += generic_mpih-add1_norust.o generic_mpih-lshift_norust.o \
         generic_mpih-mul1_norust.o generic_mpih-mul2_norust.o \
         generic_mpih-mul3_norust.o generic_mpih-rshift_norust.o \
         generic_mpih-sub1_norust.o mpih-cmp_norust.o
endif
