# SPDX-License-Identifier: GPL-2.0
#
# MPI multiprecision maths library (from gpg)
#

obj-$(CONFIG_MPILIB) = mpi.o

# THE EIGHT generic_mpih-*.c AND mpih-cmp.c ARE GONE, not wrapped: none of
# their functions is EXPORT_SYMBOL, so none has a MODVERSIONS CRC and none
# needs a C entry symbol. All eight are one file,
# lib/crypto/mpi/generic_mpih_rs.rs, which explains there why.
#
# mpicoder.c was the last file left in this unconditional list --
# everything lib/crypto/mpi/ builds now comes from one of the two arms
# below. See logs/porting-hazards.md / STATUS.md for when that milestone
# landed.
mpi-y =

# --- THE CONFIG_RUST=n ARM.  logs/floor.md RAISE 2. ------------------------
# <base>_norust.c is installed by rig/apply.sh from port/pristine/ -- the
# sha256-verified upstream body, byte for byte, at a filename the Makefile can
# choose independently of the ported one. Generated on every apply, never
# committed, so it cannot drift.
ifdef CONFIG_RUST
mpi-y += generic_mpih_rs.o mpi_cmp_rs.o
# mpiutil.o here is the RETAINED THUNK (kmalloc/kcalloc/kfree/
# kfree_sensitive wrappers only) -- see mpiutil.c's own header comment and
# logs/allocation.md. The real functions are in mpiutil_rs.o.
mpi-y += mpiutil.o mpiutil_rs.o
# mpi-add.c and mpi-sub-ui.c are gone outright: no allocation, no arch
# dispatch, nothing to retain -- the bcd/int_pow shape, same as md5.c.
mpi-y += mpi_add_rs.o mpi_sub_ui_rs.o
# mpih-div.c is gone outright too: none of its three functions is
# EXPORT_SYMBOL (same as generic_mpih_rs.o's family), no allocation, and
# its one arch-conditional branch (the pre-inverted-divisor fast path) is
# compile-time-dead on x86-64 -- see mpih_div_rs.rs's own module doc.
mpi-y += mpih_div_rs.o
# mpi-div.c and mpi-mod.c: same reasoning, no allocation, no
# EXPORT_SYMBOL, both gone outright.
mpi-y += mpi_div_rs.o mpi_mod_rs.o
# mpih-mul.c: same reasoning again -- no EXPORT_SYMBOL among its five real
# symbols, and its one allocation (struct karatsuba_ctx's ->next chain)
# reuses mpiutil.c's existing kzalloc/kfree-shaped thunk rather than
# needing a new one. See mpih_mul_rs.rs's own module doc comment.
mpi-y += mpih_mul_rs.o
# mpi-mul.c: EXPORT_SYMBOL_GPL'd (mpi_mul/mpi_mulm), but per the
# gendwarfksyms-reads-Rust-DWARF fix, the export and its MODVERSIONS
# contract live directly in the Rust object (kabi_export!) -- no C entry
# thunk needed, same as md5.c's ten exports earlier this project. Fully
# gone outright.
mpi-y += mpi_mul_rs.o
# mpi-pow.c: same for mpi_powm's export, but cond_resched() (a scheduling
# primitive Rust cannot reach directly) keeps a one-function retained C
# thunk -- see mpi-pow.c's own header comment and mpi_pow_rs.rs's module
# doc comment.
mpi-y += mpi-pow.o mpi_pow_rs.o
# mpi-bit.c: four of its five real symbols are EXPORT_SYMBOL_GPL
# (mpi_get_nbits/mpi_test_bit/mpi_set_bit/mpi_rshift), same
# no-C-thunk-needed reasoning as mpi-mul.c/mpi-pow.c's own exports;
# mpi_normalize (not exported) is still a real symbol other crates
# (mpi_cmp_rs.rs, mpi_sub_ui_rs.rs) already call. Fully gone outright.
mpi-y += mpi_bit_rs.o
# mpicoder.c: all six symbols EXPORT_SYMBOL_GPL'd, same no-C-thunk-needed
# reasoning; kmalloc/kfree (mpi_get_buffer's plain, caller-freed buffer)
# reuse mpiutil.c's existing thunk, and sg_miter_start/_next/_stop/
# sg_nents_for_len are ordinary kernel functions, not macros -- no new
# thunk needed for those either. Fully gone outright.
mpi-y += mpicoder_rs.o
else
mpi-y += generic_mpih-add1_norust.o generic_mpih-lshift_norust.o \
         generic_mpih-mul1_norust.o generic_mpih-mul2_norust.o \
         generic_mpih-mul3_norust.o generic_mpih-rshift_norust.o \
         generic_mpih-sub1_norust.o mpih-cmp_norust.o \
         mpi-cmp_norust.o
mpi-y += mpiutil_norust.o
mpi-y += mpi-add_norust.o mpi-sub-ui_norust.o
mpi-y += mpih-div_norust.o
mpi-y += mpi-div_norust.o mpi-mod_norust.o
mpi-y += mpih-mul_norust.o
mpi-y += mpi-mul_norust.o
mpi-y += mpi-pow_norust.o
mpi-y += mpi-bit_norust.o
mpi-y += mpicoder_norust.o
endif
