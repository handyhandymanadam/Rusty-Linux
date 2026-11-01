/* SPDX-License-Identifier: GPL-2.0
 *
 * The lzo1x_1_compress/lzorle1x_1_compress oracle: the PRISTINE
 * lib/lzo/lzo1x_compress.c, compiled with LZO_SAFE undefined (so NEED_OP is
 * the C's own no-op), with its two symbols renamed so both arms live in one
 * binary.
 */
#define lzo1x_1_compress	ref_lzo1x_1_compress
#define lzorle1x_1_compress	ref_lzorle1x_1_compress

#include "../../pristine/lib/lzo/lzo1x_compress.c"
