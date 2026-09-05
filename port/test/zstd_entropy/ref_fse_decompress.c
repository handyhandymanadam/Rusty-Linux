/* SPDX-License-Identifier: GPL-2.0
 *
 * The fse_decompress oracle: the PRISTINE lib/zstd/common/fse_decompress.c,
 * with its two globals moved aside, plus the cross-TU call it makes into
 * entropy_common.
 *
 * Note FSE_isError is NOT renamed here. This file defines it as a MACRO
 * (`#define FSE_isError ERR_isError`) rather than calling entropy_common's
 * function of that name, so renaming it would collide with that definition
 * and, worse, would silently change which of the two the file resolves to.
 */
#define FSE_buildDTable_wksp		ref_FSE_buildDTable_wksp
#define FSE_decompress_wksp_bmi2	ref_FSE_decompress_wksp_bmi2

/* defined by the other TU, called from this one */
#define FSE_readNCount_bmi2		ref_FSE_readNCount_bmi2

/* error_private.c is ported too, so the Rust holds the real name and
 * this arm must be pointed at the C copy explicitly. */
#define ERR_getErrorString	ref_ERR_getErrorString

#include "../../pristine/lib/zstd/common/fse_decompress.c"
