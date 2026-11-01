/* SPDX-License-Identifier: GPL-2.0
 *
 * The lzo1x_1_compress_safe/lzorle1x_1_compress_safe oracle: the PRISTINE
 * lib/lzo/lzo1x_compress_safe.c (which #defines LZO_SAFE/HAVE_OP and
 * #includes lzo1x_compress.c itself), with its two symbols renamed so both
 * arms live in one binary.
 */
#define lzo1x_1_compress_safe		ref_lzo1x_1_compress_safe
#define lzorle1x_1_compress_safe	ref_lzorle1x_1_compress_safe

#include "../../pristine/lib/lzo/lzo1x_compress_safe.c"
