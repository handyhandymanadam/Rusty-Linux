#pragma once
/* mpi-div.c's only use of longlong.h is count_leading_zeros(), from
 * linux/count_zeros.h, which the real longlong.h just #includes -- it
 * never calls udiv_qrnnd/umul_ppmm/add_ssaaaa/sub_ddmmss directly (those
 * are used inside mpihelp_divrem/mpihelp_mod_1/mpihelp_divmod_1, already
 * ported and linked as a separate, trusted dependency here). So this is a
 * minimal stand-in, not the real upstream file -- it avoids needing
 * UWtype/UHWtype/UDWtype predefined for macros this file never invokes. */
#include <linux/count_zeros.h>
