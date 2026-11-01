/* SPDX-License-Identifier: GPL-2.0
 *
 * The zstd_decompress oracle: the PRISTINE lib/zstd/decompress/zstd_decompress.c
 * with its 61 globals moved aside, plus every cross-TU call it makes into
 * zstd_decompress_block, zstd_ddict, entropy_common, huf_decompress and
 * xxhash -- all of which are renamed too, so this arm is a fully isolated
 * pristine-C stack, sharing nothing with the Rust arm's real-named symbols.
 */
#define ZSTD_copyDCtx			ref_ZSTD_copyDCtx
#define ZSTD_createDCtx			ref_ZSTD_createDCtx
#define ZSTD_createDCtx_advanced	ref_ZSTD_createDCtx_advanced
#define ZSTD_createDStream		ref_ZSTD_createDStream
#define ZSTD_createDStream_advanced	ref_ZSTD_createDStream_advanced
#define ZSTD_DCtx_getParameter		ref_ZSTD_DCtx_getParameter
#define ZSTD_DCtx_loadDictionary	ref_ZSTD_DCtx_loadDictionary
#define ZSTD_DCtx_loadDictionary_advanced ref_ZSTD_DCtx_loadDictionary_advanced
#define ZSTD_DCtx_loadDictionary_byReference ref_ZSTD_DCtx_loadDictionary_byReference
#define ZSTD_DCtx_refDDict		ref_ZSTD_DCtx_refDDict
#define ZSTD_DCtx_refPrefix		ref_ZSTD_DCtx_refPrefix
#define ZSTD_DCtx_refPrefix_advanced	ref_ZSTD_DCtx_refPrefix_advanced
#define ZSTD_DCtx_reset			ref_ZSTD_DCtx_reset
#define ZSTD_DCtx_setFormat		ref_ZSTD_DCtx_setFormat
#define ZSTD_DCtx_setMaxWindowSize	ref_ZSTD_DCtx_setMaxWindowSize
#define ZSTD_DCtx_setParameter		ref_ZSTD_DCtx_setParameter
#define ZSTD_decodingBufferSize_min	ref_ZSTD_decodingBufferSize_min
#define ZSTD_decompress			ref_ZSTD_decompress
#define ZSTD_decompressBegin		ref_ZSTD_decompressBegin
#define ZSTD_decompressBegin_usingDDict	ref_ZSTD_decompressBegin_usingDDict
#define ZSTD_decompressBegin_usingDict	ref_ZSTD_decompressBegin_usingDict
#define ZSTD_decompressBound		ref_ZSTD_decompressBound
#define ZSTD_decompressContinue	ref_ZSTD_decompressContinue
#define ZSTD_decompressDCtx		ref_ZSTD_decompressDCtx
#define ZSTD_decompressionMargin	ref_ZSTD_decompressionMargin
#define ZSTD_decompressStream		ref_ZSTD_decompressStream
#define ZSTD_decompressStream_simpleArgs ref_ZSTD_decompressStream_simpleArgs
#define ZSTD_decompress_usingDDict	ref_ZSTD_decompress_usingDDict
#define ZSTD_decompress_usingDict	ref_ZSTD_decompress_usingDict
#define ZSTD_dParam_getBounds		ref_ZSTD_dParam_getBounds
#define ZSTD_DStreamInSize		ref_ZSTD_DStreamInSize
#define ZSTD_DStreamOutSize		ref_ZSTD_DStreamOutSize
#define ZSTD_estimateDCtxSize		ref_ZSTD_estimateDCtxSize
#define ZSTD_estimateDStreamSize	ref_ZSTD_estimateDStreamSize
#define ZSTD_estimateDStreamSize_fromFrame ref_ZSTD_estimateDStreamSize_fromFrame
#define ZSTD_findDecompressedSize	ref_ZSTD_findDecompressedSize
#define ZSTD_findFrameCompressedSize	ref_ZSTD_findFrameCompressedSize
#define ZSTD_frameHeaderSize		ref_ZSTD_frameHeaderSize
#define ZSTD_freeDCtx			ref_ZSTD_freeDCtx
#define ZSTD_freeDStream		ref_ZSTD_freeDStream
#define ZSTD_getDecompressedSize	ref_ZSTD_getDecompressedSize
#define ZSTD_getDictID_fromDict	ref_ZSTD_getDictID_fromDict
#define ZSTD_getDictID_fromFrame	ref_ZSTD_getDictID_fromFrame
#define ZSTD_getFrameContentSize	ref_ZSTD_getFrameContentSize
#define ZSTD_getFrameHeader		ref_ZSTD_getFrameHeader
#define ZSTD_getFrameHeader_advanced	ref_ZSTD_getFrameHeader_advanced
#define ZSTD_initDStream		ref_ZSTD_initDStream
#define ZSTD_initDStream_usingDDict	ref_ZSTD_initDStream_usingDDict
#define ZSTD_initDStream_usingDict	ref_ZSTD_initDStream_usingDict
#define ZSTD_initStaticDCtx		ref_ZSTD_initStaticDCtx
#define ZSTD_initStaticDStream		ref_ZSTD_initStaticDStream
#define ZSTD_insertBlock		ref_ZSTD_insertBlock
#define ZSTD_isFrame			ref_ZSTD_isFrame
#define ZSTD_isSkippableFrame		ref_ZSTD_isSkippableFrame
#define ZSTD_loadDEntropy		ref_ZSTD_loadDEntropy
#define ZSTD_nextInputType		ref_ZSTD_nextInputType
#define ZSTD_nextSrcSizeToDecompress	ref_ZSTD_nextSrcSizeToDecompress
#define ZSTD_readSkippableFrame		ref_ZSTD_readSkippableFrame
#define ZSTD_resetDStream		ref_ZSTD_resetDStream
#define ZSTD_sizeof_DCtx		ref_ZSTD_sizeof_DCtx
#define ZSTD_sizeof_DStream		ref_ZSTD_sizeof_DStream

/* defined by zstd_decompress_block, called from here */
#define ZSTD_buildFSETable		ref_ZSTD_buildFSETable
#define ZSTD_checkContinuity		ref_ZSTD_checkContinuity
#define ZSTD_decompressBlock_internal	ref_ZSTD_decompressBlock_internal
#define ZSTD_getcBlockSize		ref_ZSTD_getcBlockSize

/* defined by zstd_ddict, called from here */
#define ZSTD_DDict_dictContent		ref_ZSTD_DDict_dictContent
#define ZSTD_DDict_dictSize		ref_ZSTD_DDict_dictSize
#define ZSTD_copyDDictParameters	ref_ZSTD_copyDDictParameters
#define ZSTD_freeDDict			ref_ZSTD_freeDDict
#define ZSTD_createDDict_advanced	ref_ZSTD_createDDict_advanced
#define ZSTD_getDictID_fromDDict	ref_ZSTD_getDictID_fromDDict
#define ZSTD_sizeof_DDict		ref_ZSTD_sizeof_DDict

/* defined by zstd_common, called from here */
#define ZSTD_getErrorCode		ref_ZSTD_getErrorCode

/* defined by entropy_common, called from here */
#define FSE_readNCount			ref_FSE_readNCount

/* defined by huf_decompress, called from here */
#define HUF_readDTableX2_wksp		ref_HUF_readDTableX2_wksp

/* defined by lib/xxhash.c, called from here */
#define xxh64_reset			ref_xxh64_reset
#define xxh64_update			ref_xxh64_update
#define xxh64_digest			ref_xxh64_digest
#define xxh64				ref_xxh64

#include "../../pristine/lib/zstd/decompress/zstd_decompress.c"
