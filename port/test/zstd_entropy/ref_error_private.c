/* SPDX-License-Identifier: GPL-2.0
 *
 * The error-string oracle: the PRISTINE lib/zstd/common/error_private.c with
 * its one symbol moved aside, so the Rust port can hold the real name and both
 * can be compared.
 *
 * ZSTD_STRIP_ERROR_STRINGS is NOT defined, per logs/floor.md criterion 8:
 * nothing in 6.18.49 defines it -- grep finds only the #ifdef in this very
 * file -- so the kernel compiles the table, and so does the oracle.
 */
#define ERR_getErrorString	ref_ERR_getErrorString
#include "../../pristine/lib/zstd/common/error_private.c"
