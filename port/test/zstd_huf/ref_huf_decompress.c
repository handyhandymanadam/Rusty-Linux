/* SPDX-License-Identifier: GPL-2.0
 *
 * The huf_decompress oracle: the PRISTINE lib/zstd/decompress/huf_decompress.c
 * with its nine globals moved aside, plus the cross-TU call into
 * entropy_common that it makes.
 *
 * CONFIGURATION, per logs/floor.md criterion 8: ZSTD_ENABLE_ASM_X86_64_BMI2 is
 * a hard `#define 0` in common/portability_macros.h, so the hand-written
 * assembly decoder is compiled out of the kernel and out of this oracle alike;
 * DYNAMIC_BMI2 is left to that header to derive, and main.c asserts which way
 * it came out rather than assuming.
 */
#define HUF_readDTableX1_wksp		ref_HUF_readDTableX1_wksp
#define HUF_readDTableX2_wksp		ref_HUF_readDTableX2_wksp
#define HUF_decompress1X1_DCtx_wksp	ref_HUF_decompress1X1_DCtx_wksp
#define HUF_decompress1X2_DCtx_wksp	ref_HUF_decompress1X2_DCtx_wksp
#define HUF_decompress1X_DCtx_wksp	ref_HUF_decompress1X_DCtx_wksp
#define HUF_decompress1X_usingDTable	ref_HUF_decompress1X_usingDTable
#define HUF_decompress4X_usingDTable	ref_HUF_decompress4X_usingDTable
#define HUF_decompress4X_hufOnly_wksp	ref_HUF_decompress4X_hufOnly_wksp
#define HUF_selectDecoder		ref_HUF_selectDecoder

/* defined by entropy_common, called from here */
#define HUF_readStats_wksp		ref_HUF_readStats_wksp
#define ERR_getErrorString		ref_ERR_getErrorString

#include "../../pristine/lib/zstd/decompress/huf_decompress.c"
