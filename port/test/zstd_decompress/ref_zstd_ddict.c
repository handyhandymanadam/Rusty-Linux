/* SPDX-License-Identifier: GPL-2.0
 *
 * Part of the zstd_decompress oracle stack: the PRISTINE
 * lib/zstd/decompress/zstd_ddict.c, renamed. Like ref_zstd_decompress_block.c,
 * this file is not itself under differential test here -- zstd_ddict.c stays
 * C on both arms (real-named, unrenamed, shared) -- but the ref_ arm needs
 * its own fully-isolated copy because it calls back into
 * ZSTD_loadDEntropy(), which IS one of zstd_decompress.c's own globals and
 * therefore renamed on the ref_ side.
 */
#define ZSTD_copyDDictParameters	ref_ZSTD_copyDDictParameters
#define ZSTD_createDDict		ref_ZSTD_createDDict
#define ZSTD_createDDict_advanced	ref_ZSTD_createDDict_advanced
#define ZSTD_createDDict_byReference	ref_ZSTD_createDDict_byReference
#define ZSTD_DDict_dictContent		ref_ZSTD_DDict_dictContent
#define ZSTD_DDict_dictSize		ref_ZSTD_DDict_dictSize
#define ZSTD_estimateDDictSize		ref_ZSTD_estimateDDictSize
#define ZSTD_freeDDict			ref_ZSTD_freeDDict
#define ZSTD_getDictID_fromDDict	ref_ZSTD_getDictID_fromDDict
#define ZSTD_initStaticDDict		ref_ZSTD_initStaticDDict
#define ZSTD_sizeof_DDict		ref_ZSTD_sizeof_DDict

/* defined by zstd_decompress, called from here */
#define ZSTD_loadDEntropy		ref_ZSTD_loadDEntropy

#include "../../pristine/lib/zstd/decompress/zstd_ddict.c"
