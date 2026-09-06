/* SPDX-License-Identifier: GPL-2.0
 *
 * Harness smoke test: the "rs" arm is a second call into the SAME pristine C,
 * so `run.sh --selfcheck` exercises every line of main.c with an arm that
 * cannot disagree. It proves the plumbing, not the port. Smoke test, not a
 * stopping rule (logs/floor.md RULE T2).
 */
#include <stddef.h>

size_t ref_ZSTD_decompressBlock_internal(void *dctx, void *dst, size_t dstCapacity, const void *src, size_t srcSize, int streaming);
size_t rs_ZSTD_decompressBlock_internal(void *dctx, void *dst, size_t dstCapacity, const void *src, size_t srcSize, int streaming)
{ return ref_ZSTD_decompressBlock_internal(dctx, dst, dstCapacity, src, srcSize, streaming); }

void ref_ZSTD_checkContinuity(void *dctx, const void *dst, size_t dstSize);
void rs_ZSTD_checkContinuity(void *dctx, const void *dst, size_t dstSize)
{ ref_ZSTD_checkContinuity(dctx, dst, dstSize); }

size_t ref_ZSTD_decompressBlock_deprecated(void *dctx, void *dst, size_t dstCapacity, const void *src, size_t srcSize);
size_t rs_ZSTD_decompressBlock_deprecated(void *dctx, void *dst, size_t dstCapacity, const void *src, size_t srcSize)
{ return ref_ZSTD_decompressBlock_deprecated(dctx, dst, dstCapacity, src, srcSize); }

size_t ref_ZSTD_getcBlockSize(const void *src, size_t srcSize, void *bpPtr);
size_t rs_ZSTD_getcBlockSize(const void *src, size_t srcSize, void *bpPtr)
{ return ref_ZSTD_getcBlockSize(src, srcSize, bpPtr); }
