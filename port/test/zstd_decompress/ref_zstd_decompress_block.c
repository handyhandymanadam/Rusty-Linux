/* SPDX-License-Identifier: GPL-2.0
 *
 * Part of the zstd_decompress oracle stack: the PRISTINE
 * lib/zstd/decompress/zstd_decompress_block.c, renamed. This file is not
 * itself under differential test here (that is decompress-porter's file,
 * port/decompress); it exists only so ref_zstd_decompress.c's ref_ arm has
 * something to call ZSTD_decompressBlock_internal/ZSTD_checkContinuity/
 * ZSTD_buildFSETable/ZSTD_getcBlockSize into, fully isolated from the real
 * names the Rust arm calls (which resolve to the SAME pristine C, unrenamed
 * -- see run.sh: this file's real-named twin, compiled without renaming, is
 * what zstd_decompress_rs.rs links against).
 */
#define ZSTD_buildFSETable		ref_ZSTD_buildFSETable
#define ZSTD_checkContinuity		ref_ZSTD_checkContinuity
#define ZSTD_decodeLiteralsBlock_wrapper ref_ZSTD_decodeLiteralsBlock_wrapper
#define ZSTD_decodeSeqHeaders		ref_ZSTD_decodeSeqHeaders
#define ZSTD_decompressBlock		ref_ZSTD_decompressBlock
#define ZSTD_decompressBlock_deprecated ref_ZSTD_decompressBlock_deprecated
#define ZSTD_decompressBlock_internal	ref_ZSTD_decompressBlock_internal
#define ZSTD_getcBlockSize		ref_ZSTD_getcBlockSize

/* defined by entropy_common, called from here */
#define FSE_readNCount			ref_FSE_readNCount

/* defined by huf_decompress, called from here */
#define HUF_decompress1X1_DCtx_wksp	ref_HUF_decompress1X1_DCtx_wksp
#define HUF_decompress1X2_DCtx_wksp	ref_HUF_decompress1X2_DCtx_wksp
#define HUF_decompress1X_DCtx_wksp	ref_HUF_decompress1X_DCtx_wksp
#define HUF_decompress1X_usingDTable	ref_HUF_decompress1X_usingDTable
#define HUF_decompress4X_hufOnly_wksp	ref_HUF_decompress4X_hufOnly_wksp
#define HUF_decompress4X_usingDTable	ref_HUF_decompress4X_usingDTable
#define HUF_selectDecoder		ref_HUF_selectDecoder

#include "../../pristine/lib/zstd/decompress/zstd_decompress_block.c"
