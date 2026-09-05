/* SPDX-License-Identifier: GPL-2.0
 *
 * The xz_dec_stream oracle: the PRISTINE lib/xz/xz_dec_stream.c itself,
 * compiled with its exported names moved aside so both arms live in one
 * binary. Not a transcription -- a copy would drift.
 *
 * CONFIGURATION, per logs/floor.md criterion 8. Our kernels build
 * XZ_DEC_ANY_CHECK=n, so this file does NOT define it and the oracle compiles
 * the same paths the kernel does. ref_stream_anycheck.c compiles the same
 * source WITH it, because it is a real Kconfig symbol other kernels set and
 * "compile both arms both ways" is the other way to satisfy criterion 8.
 *
 * The first version of this file defined XZ_DEC_ANY_CHECK unconditionally,
 * which would have tested a configuration no kernel of ours builds -- the
 * exact defect that raised the floor for lib/sort.c the day before.
 */
#define xz_dec_init	ref_xz_dec_init
#define xz_dec_run	ref_xz_dec_run
#define xz_dec_reset	ref_xz_dec_reset
#define xz_dec_end	ref_xz_dec_end

#include "../../pristine/lib/xz/xz_dec_stream.c"
