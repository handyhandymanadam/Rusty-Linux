/* SPDX-License-Identifier: GPL-2.0
 *
 * The zstd_ddict oracle: the PRISTINE lib/zstd/decompress/zstd_ddict.c, with
 * every global it defines moved aside so both arms live in one binary.
 *
 * ZSTD_loadDEntropy is zstd_decompress.c's, not this file's -- a call INTO
 * a file this port does not own and does not touch. Real entropy-table
 * building is out of scope here (and under active, unrelated development in
 * zstd_decompress_rs.rs elsewhere); both arms link against an IDENTICAL
 * deterministic stub (stub_loadentropy.c) instead, so this harness proves
 * zstd_ddict's OWN propagation of that call's result -- dictID parsing,
 * entropyPresent bookkeeping, error mapping -- not zstd_decompress.c's
 * unrelated internals.
 */
#define ZSTD_DDict_dictContent		ref_ZSTD_DDict_dictContent
#define ZSTD_DDict_dictSize		ref_ZSTD_DDict_dictSize
#define ZSTD_copyDDictParameters	ref_ZSTD_copyDDictParameters
/* Real signature takes `ZSTD_customMem` by value (a 3-word struct); main.c
 * calls a flattened (customAlloc, customFree, opaque) shape instead (to
 * match what a Rust caller passes without going through a repr(C) struct
 * literal at the FFI boundary too), so the real function is renamed ONE
 * further step aside and a shim below bridges the two shapes. */
#define ZSTD_createDDict_advanced	real_ZSTD_createDDict_advanced
#define ZSTD_createDDict		ref_ZSTD_createDDict
#define ZSTD_createDDict_byReference	ref_ZSTD_createDDict_byReference
#define ZSTD_initStaticDDict		ref_ZSTD_initStaticDDict
#define ZSTD_freeDDict			ref_ZSTD_freeDDict
#define ZSTD_estimateDDictSize		ref_ZSTD_estimateDDictSize
#define ZSTD_sizeof_DDict		ref_ZSTD_sizeof_DDict
#define ZSTD_getDictID_fromDDict	ref_ZSTD_getDictID_fromDDict
#define ZSTD_loadDEntropy		ref_ZSTD_loadDEntropy

#include "../../pristine/lib/zstd/decompress/zstd_ddict.c"

typedef void *(*ref_alloc_fn)(void *opaque, size_t size);
typedef void (*ref_free_fn)(void *opaque, void *address);

void *ref_ZSTD_createDDict_advanced(const void *dict, size_t dictSize,
				     ZSTD_dictLoadMethod_e dictLoadMethod,
				     ZSTD_dictContentType_e dictContentType,
				     ref_alloc_fn customAlloc, ref_free_fn customFree, void *opaque)
{
	ZSTD_customMem cMem;
	cMem.customAlloc = customAlloc;
	cMem.customFree = customFree;
	cMem.opaque = opaque;
	return real_ZSTD_createDDict_advanced(dict, dictSize, dictLoadMethod, dictContentType, cMem);
}
