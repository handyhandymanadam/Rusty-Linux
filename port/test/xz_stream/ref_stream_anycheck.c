/* SPDX-License-Identifier: GPL-2.0
 *
 * The same pristine lib/xz/xz_dec_stream.c, compiled WITH XZ_DEC_ANY_CHECK.
 * See ref_stream.c for why both exist: floor.md criterion 8.
 */
#define XZ_DEC_ANY_CHECK
#define xz_dec_init	any_xz_dec_init
#define xz_dec_run	any_xz_dec_run
#define xz_dec_reset	any_xz_dec_reset
#define xz_dec_end	any_xz_dec_end

#include "../../pristine/lib/xz/xz_dec_stream.c"
