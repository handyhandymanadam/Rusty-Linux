/* SPDX-License-Identifier: GPL-2.0
 *
 * The zstd_common oracle: the PRISTINE lib/zstd/common/zstd_common.c with its
 * six globals moved aside, plus the call into error_private that it makes.
 *
 * ZSTD_isError IS NOT RENAMED HERE, and cannot be. zstd_internal.h:38 defines
 * it as a macro (`#define ZSTD_isError ERR_isError`, for inlining) and the .c
 * then `#undef`s it before defining the real function -- so any -D rename we
 * put in front is removed by that #undef before the definition is reached. The
 * rename is done on the OBJECT instead, with
 *
 *     objcopy --redefine-sym ZSTD_isError=ref_ZSTD_isError
 *
 * in run.sh. Renaming a symbol after the fact is worse than renaming it in the
 * source -- it is invisible from the file -- which is why it is spelled out
 * here and in run.sh rather than done quietly.
 */
#define ZSTD_versionNumber	ref_ZSTD_versionNumber
#define ZSTD_versionString	ref_ZSTD_versionString
#define ZSTD_getErrorName	ref_ZSTD_getErrorName
#define ZSTD_getErrorCode	ref_ZSTD_getErrorCode
#define ZSTD_getErrorString	ref_ZSTD_getErrorString

/* error_private.c is ported, so the Rust holds the real name */
#define ERR_getErrorString	ref_ERR_getErrorString

#include "../../pristine/lib/zstd/common/zstd_common.c"
