/* SPDX-License-Identifier: GPL-2.0
 *
 * The xz_dec_lzma2 oracle: the PRISTINE lib/xz/xz_dec_lzma2.c itself, with its
 * four entry points moved aside so both arms live in one binary.
 *
 * CONFIGURATION, per logs/floor.md criterion 8: XZ_DEC_MICROLZMA is NOT
 * defined, because CONFIG_XZ_DEC_MICROLZMA is n in both our kernel configs.
 * It is a real Kconfig symbol that fs/erofs selects, so the PORT must still
 * compile clean with it on -- RAISE 1 -- but the oracle compiles what our
 * kernel compiles.
 */
#define xz_dec_lzma2_create	ref_xz_dec_lzma2_create
#define xz_dec_lzma2_reset	ref_xz_dec_lzma2_reset
#define xz_dec_lzma2_run	ref_xz_dec_lzma2_run
#define xz_dec_lzma2_end	ref_xz_dec_lzma2_end

#include "../../pristine/lib/xz/xz_dec_lzma2.c"
