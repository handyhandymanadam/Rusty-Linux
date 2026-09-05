/* SPDX-License-Identifier: GPL-2.0
 *
 * The entropy_common oracle: the PRISTINE lib/zstd/common/entropy_common.c,
 * with every global it defines moved aside so both arms live in one binary.
 *
 * FSE_decompress_wksp_bmi2 is renamed too even though this file does not
 * define it: this TU CALLS it, and the call has to land in the C arm's copy
 * rather than the port's. That cross-TU edge is the whole reason the two
 * files are ported together -- see STATUS.md.
 *
 * CONFIGURATION, per logs/floor.md criterion 8: DEBUGLEVEL is left at its
 * default 0 and ZSTD_DEPS_NEED_* are left unset, which is what the kernel
 * build compiles. DYNAMIC_BMI2 is left to portability_macros.h to decide from
 * the compiler and target, exactly as in the kernel build; main.c asserts
 * which way it came out rather than assuming.
 */
#define FSE_versionNumber	ref_FSE_versionNumber
#define FSE_isError		ref_FSE_isError
#define FSE_getErrorName	ref_FSE_getErrorName
#define HUF_isError		ref_HUF_isError
#define HUF_getErrorName	ref_HUF_getErrorName
#define FSE_readNCount		ref_FSE_readNCount
#define FSE_readNCount_bmi2	ref_FSE_readNCount_bmi2
#define HUF_readStats		ref_HUF_readStats
#define HUF_readStats_wksp	ref_HUF_readStats_wksp

/* defined by the other TU, called from this one */
#define FSE_decompress_wksp_bmi2 ref_FSE_decompress_wksp_bmi2

/* error_private.c is ported too, so the Rust holds the real name and
 * this arm must be pointed at the C copy explicitly. */
#define ERR_getErrorString	ref_ERR_getErrorString

#include "../../pristine/lib/zstd/common/entropy_common.c"
