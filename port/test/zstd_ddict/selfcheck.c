/* SPDX-License-Identifier: GPL-2.0
 *
 * Harness smoke test: the "rs" arm is a second call into the SAME pristine C,
 * so `run.sh --selfcheck` exercises every line of main.c with an arm that
 * cannot disagree. Proves the plumbing, not the port.
 */
#include <stddef.h>

typedef void *(*alloc_fn)(void *opaque, size_t size);
typedef void (*free_fn)(void *opaque, void *address);

const void *ref_ZSTD_DDict_dictContent(const void *ddict);
const void *rs_ZSTD_DDict_dictContent(const void *ddict) { return ref_ZSTD_DDict_dictContent(ddict); }

size_t ref_ZSTD_DDict_dictSize(const void *ddict);
size_t rs_ZSTD_DDict_dictSize(const void *ddict) { return ref_ZSTD_DDict_dictSize(ddict); }

void ref_ZSTD_copyDDictParameters(void *dctx, const void *ddict);
void rs_ZSTD_copyDDictParameters(void *dctx, const void *ddict) { ref_ZSTD_copyDDictParameters(dctx, ddict); }

void *ref_ZSTD_createDDict_advanced(const void *dict, size_t dictSize, unsigned dictLoadMethod, unsigned dictContentType, alloc_fn customAlloc, free_fn customFree, void *opaque);
void *rs_ZSTD_createDDict_advanced(const void *dict, size_t dictSize, unsigned dictLoadMethod, unsigned dictContentType, alloc_fn customAlloc, free_fn customFree, void *opaque)
{ return ref_ZSTD_createDDict_advanced(dict, dictSize, dictLoadMethod, dictContentType, customAlloc, customFree, opaque); }

void *ref_ZSTD_initStaticDDict(void *sBuffer, size_t sBufferSize, const void *dict, size_t dictSize, unsigned dictLoadMethod, unsigned dictContentType);
void *rs_ZSTD_initStaticDDict(void *sBuffer, size_t sBufferSize, const void *dict, size_t dictSize, unsigned dictLoadMethod, unsigned dictContentType)
{ return ref_ZSTD_initStaticDDict(sBuffer, sBufferSize, dict, dictSize, dictLoadMethod, dictContentType); }

size_t ref_ZSTD_freeDDict(void *ddict);
size_t rs_ZSTD_freeDDict(void *ddict) { return ref_ZSTD_freeDDict(ddict); }

size_t ref_ZSTD_estimateDDictSize(size_t dictSize, unsigned dictLoadMethod);
size_t rs_ZSTD_estimateDDictSize(size_t dictSize, unsigned dictLoadMethod) { return ref_ZSTD_estimateDDictSize(dictSize, dictLoadMethod); }

size_t ref_ZSTD_sizeof_DDict(const void *ddict);
size_t rs_ZSTD_sizeof_DDict(const void *ddict) { return ref_ZSTD_sizeof_DDict(ddict); }

unsigned ref_ZSTD_getDictID_fromDDict(const void *ddict);
unsigned rs_ZSTD_getDictID_fromDDict(const void *ddict) { return ref_ZSTD_getDictID_fromDDict(ddict); }
