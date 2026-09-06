/* SPDX-License-Identifier: GPL-2.0
 *
 * The zstd_decompress_block oracle: the PRISTINE
 * lib/zstd/decompress/zstd_decompress_block.c, with every global it defines
 * moved aside so both arms live in one binary, and every cross-TU call it
 * makes into entropy_common/huf_decompress pointed at THEIR reference
 * copies (port/test/zstd_entropy/ref_entropy_common.c and
 * port/test/zstd_huf/ref_huf_decompress.c), reused rather than duplicated.
 *
 * CONFIGURATION, per logs/floor.md criterion 8: DYNAMIC_BMI2 is left to
 * portability_macros.h to decide from the compiler and target, exactly as
 * in the kernel build; main.c asserts which way it came out rather than
 * assuming.
 */
#define ZSTD_getcBlockSize		ref_ZSTD_getcBlockSize
#define ZSTD_decodeLiteralsBlock_wrapper	ref_ZSTD_decodeLiteralsBlock_wrapper
#define ZSTD_buildFSETable		ref_ZSTD_buildFSETable
#define ZSTD_decodeSeqHeaders		ref_ZSTD_decodeSeqHeaders
#define ZSTD_decompressBlock_internal	ref_ZSTD_decompressBlock_internal
#define ZSTD_checkContinuity		ref_ZSTD_checkContinuity
#define ZSTD_decompressBlock_deprecated	ref_ZSTD_decompressBlock_deprecated
#define ZSTD_decompressBlock		ref_ZSTD_decompressBlock

/* defined by entropy_common/huf_decompress, called from here.
 * FSE_isError/HUF_isError are NOT renamed: zstd_internal.h defines both as
 * plain macros to ERR_isError (a static inline), so they never cross a TU
 * boundary and renaming them only redefines the macro with a warning. */
#define FSE_readNCount			ref_FSE_readNCount
#define HUF_decompress1X_usingDTable	ref_HUF_decompress1X_usingDTable
#define HUF_decompress4X_usingDTable	ref_HUF_decompress4X_usingDTable
#define HUF_decompress1X1_DCtx_wksp	ref_HUF_decompress1X1_DCtx_wksp
#define HUF_decompress1X2_DCtx_wksp	ref_HUF_decompress1X2_DCtx_wksp
#define HUF_decompress1X_DCtx_wksp	ref_HUF_decompress1X_DCtx_wksp
#define HUF_decompress4X_hufOnly_wksp	ref_HUF_decompress4X_hufOnly_wksp

/* error_private.c is ported too, so the Rust holds the real name and this
 * arm must be pointed at the C copy explicitly (not called directly by
 * zstd_decompress_block.c, but pulled in transitively through
 * error_private.h's static inlines, which reference it by name in some
 * configurations). */
#define ERR_getErrorString		ref_ERR_getErrorString

#include "../../pristine/lib/zstd/decompress/zstd_decompress_block.c"
