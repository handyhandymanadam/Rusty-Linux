/* SPDX-License-Identifier: GPL-2.0
 *
 * Differential driver for lib/zstd/decompress/zstd_decompress_block.c
 * against port/tree/lib/zstd/decompress/zstd_decompress_block_rs.rs.
 *
 *   difftest [runs] [seed]
 *
 * Real .zst frames come from the SYSTEM libzstd's ZSTD_compress() (an
 * independent encoder this project does not port), at a spread of
 * compression levels so literal encoding (raw/RLE/Huffman, 1 vs 4 streams)
 * and sequence encoding (predefined/RLE/FSE/repeat tables) all get
 * exercised. Frame parsing here is deliberately minimal -- just enough of
 * the .zst frame format (magic, frame header, block loop) to drive
 * ZSTD_decompressBlock_internal() the same way zstd_decompress.c's
 * ZSTD_decompressFrame() does, per that function's own source (read
 * directly, not summarised) -- because this project does not port
 * zstd_decompress.c and does not want to reimplement it more than this.
 *
 * The DCtx is NOT allocated or reset through any ported or pristine
 * function: it is a raw byte buffer of the size the offsetof-check in
 * dctx_offsets/ proved matches `struct ZSTD_DCtx_s` field for field, reused
 * as either arm's struct type by pointer cast. Reset mirrors
 * ZSTD_decompressBegin()'s own field list exactly (read from
 * zstd_decompress.c, not guessed).
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <zstd.h> /* the SYSTEM libzstd -- an independent oracle/encoder */

#define FSE_STATIC_LINKING_ONLY
#include "huf.h"
#include "fse.h"
#include "mem.h"
#include "zstd_internal.h"
#include "zstd_decompress_internal.h"
#include "zstd_decompress_block.h"
#include "portability_macros.h"

#include "../common/difftest.h"

/* Small self-contained xorshift64*; this harness generates its own test
 * plaintexts directly (via the system encoder below) rather than reusing
 * zstd_huf/zstd_entropy's corpus.c, which extracts Huffman-literals
 * sections specifically and has nothing this harness needs. */
static uint64_t rng_next(uint64_t *s)
{
	*s ^= *s << 13;
	*s ^= *s >> 7;
	*s ^= *s << 17;
	return *s;
}
static unsigned dt_rand(unsigned long *s)
{
	uint64_t v = *s;
	unsigned r = (unsigned)(rng_next(&v) & 0x7fffffff);
	*s = (unsigned long)v;
	return r;
}

/* ---- the two arms -------------------------------------------------------
 * Both take `void *dctx` here (not `ZSTD_DCtx *`): the ref arm's C
 * declaration and the Rust arm's declaration disagree on the pointee type
 * name, but agree on its layout (proved below), so a `void *` at this call
 * boundary is the honest type.
 */
#define ARMS(P) \
	size_t P##ZSTD_decompressBlock_internal(void *dctx, void *dst, size_t dstCapacity, const void *src, size_t srcSize, int streaming); \
	void   P##ZSTD_checkContinuity(void *dctx, const void *dst, size_t dstSize); \
	size_t P##ZSTD_getcBlockSize(const void *src, size_t srcSize, blockProperties_t *bpPtr);
ARMS(ref_)
ARMS(rs_)

_Static_assert(sizeof(size_t) == 8, "harness assumes a 64-bit host");
_Static_assert(sizeof(struct ZSTD_DCtx_s) == 95960,
	       "struct ZSTD_DCtx_s size drifted -- rerun dctx_offsets and update ZstdDCtx");

/* repStartValue, zstd_internal.h -- initial repeat offsets. */
static const uint32_t REP_START[3] = { 1, 4, 8 };

/* Mirrors ZSTD_decompressBegin()'s field-by-field reset (zstd_decompress.c),
 * plus what ZSTD_checkContinuity() does for a first call with dst ==
 * buffer start (previousDstEnd/prefixStart both NULL beforehand). */
static void dctx_reset(struct ZSTD_DCtx_s *dctx, void *dst, int bmi2)
{
	memset(dctx, 0, sizeof(*dctx));
	dctx->previousDstEnd = NULL;
	dctx->prefixStart = NULL;
	dctx->virtualStart = NULL;
	dctx->dictEnd = NULL;
	/* ZSTD_decompressBegin(), zstd_decompress.c:1497 -- cover both little
	 * and big endian: seeds HUF_getDTableDesc(hufTable).maxTableLog so the
	 * FIRST HUF_read*DTable*_wksp call (litEncType==set_compressed, no
	 * prior repeat table) doesn't see maxTableLog==0 from the memset and
	 * fail every real tableLog with tableLog_tooLarge. */
	dctx->entropy.hufTable[0] = (HUF_DTable)((ZSTD_HUFFDTABLE_CAPACITY_LOG)*0x1000001);
	dctx->litEntropy = 0;
	dctx->fseEntropy = 0;
	dctx->isFrameDecompression = 1;
	memcpy(dctx->entropy.rep, REP_START, sizeof(REP_START));
	dctx->LLTptr = dctx->entropy.LLTable;
	dctx->MLTptr = dctx->entropy.MLTable;
	dctx->OFTptr = dctx->entropy.OFTable;
	dctx->HUFptr = dctx->entropy.hufTable;
	dctx->ddictIsCold = 0;
	dctx->disableHufAsm = 0;
	dctx->maxBlockSizeParam = 0;
#if DYNAMIC_BMI2
	dctx->bmi2 = bmi2;
#else
	(void)bmi2;
#endif
	/* ZSTD_checkContinuity(dctx, dst, dstCapacity): dst != previousDstEnd
	 * (NULL) is true whenever dstCapacity > 0, which every frame this
	 * harness feeds has. */
	dctx->dictEnd = dctx->previousDstEnd;
	dctx->virtualStart = (const char *)dst - ((const char *)dctx->previousDstEnd - (const char *)dctx->prefixStart);
	dctx->prefixStart = dst;
	dctx->previousDstEnd = dst;
}

/* Minimal .zst frame-header parse: just enough to get windowSize and
 * blockSizeMax into fParams, matching ZSTD_decodeFrameHeader()'s effect on
 * those two fields. Returns bytes consumed, or 0 on a shape this harness
 * does not expect (which would mean the encoder did something this parser
 * was not written for, not a port bug -- see the abort() below).
 */
static size_t parse_frame_header(struct ZSTD_DCtx_s *dctx, const uint8_t *ip, size_t avail)
{
	size_t pos;
	uint8_t fhd;
	int single_segment, fcs_flag, did_flag;
	uint64_t windowSize = 0;

	if (avail < 5) return 0;
	if (MEM_readLE32(ip) != 0xFD2FB528u) return 0; /* ZSTD_MAGICNUMBER */
	pos = 4;
	fhd = ip[pos++];
	single_segment = (fhd >> 5) & 1;
	fcs_flag = (fhd >> 6) & 3;
	did_flag = fhd & 3;

	if (!single_segment) {
		uint8_t wd;
		uint32_t exponent, mantissa, windowLog, windowBase, windowAdd;
		if (pos >= avail) return 0;
		wd = ip[pos++];
		exponent = wd >> 3;
		mantissa = wd & 7;
		windowLog = 10 + exponent;
		windowBase = 1u << windowLog;
		windowAdd = (windowBase / 8) * mantissa;
		windowSize = (uint64_t)windowBase + windowAdd;
	}

	{
		static const int did_bytes[4] = { 0, 1, 2, 4 };
		pos += did_bytes[did_flag];
	}

	{
		static const int fcs_bytes_table[4] = { 0, 2, 4, 8 };
		int fcs_bytes = fcs_bytes_table[fcs_flag];
		if (single_segment && fcs_flag == 0) fcs_bytes = 1;
		if (fcs_bytes) {
			uint64_t v = 0;
			int i;
			if (pos + (size_t)fcs_bytes > avail) return 0;
			for (i = 0; i < fcs_bytes; i++)
				v |= (uint64_t)ip[pos + i] << (8 * i);
			if (fcs_flag == 1) v += 256;
			pos += fcs_bytes;
			if (single_segment) windowSize = v;
		}
	}

	dctx->fParams.windowSize = windowSize;
	{
		uint64_t blockSizeMax = windowSize;
		if (blockSizeMax > ZSTD_BLOCKSIZE_MAX) blockSizeMax = ZSTD_BLOCKSIZE_MAX;
		dctx->fParams.blockSizeMax = (unsigned)blockSizeMax;
	}
	return pos;
}

/* One arm's full-frame decode: mirrors ZSTD_decompressFrame()'s block loop
 * (read directly from zstd_decompress.c, cited in this file's own header
 * comment) minus checksum verification, which this harness does not need
 * to prove and which would require linking xxhash.c to test.
 */
static size_t decode_frame(
	const char *tag,
	int rs,
	struct ZSTD_DCtx_s *dctx,
	uint8_t *dst, size_t dstCapacity,
	const uint8_t *src, size_t srcSize,
	int *err_out)
{
	uint8_t *op = dst;
	uint8_t *oend = dst + dstCapacity;
	const uint8_t *ip = src;
	size_t remaining = srcSize;
	size_t fhSize;

	*err_out = 0;
	fhSize = parse_frame_header(dctx, ip, remaining);
	if (fhSize == 0) {
		if (getenv("DT_DEBUG")) fprintf(stderr, "[%s] parse_frame_header failed\n", tag);
		*err_out = 1; return 0;
	}
	ip += fhSize;
	remaining -= fhSize;

	for (;;) {
		blockProperties_t bp;
		size_t cBlockSize = rs
			? rs_ZSTD_getcBlockSize(ip, remaining, &bp)
			: ref_ZSTD_getcBlockSize(ip, remaining, &bp);
		size_t decodedSize;
		uint8_t *oBlockEnd = oend;

		if (ZSTD_isError(cBlockSize)) {
			if (getenv("DT_DEBUG")) fprintf(stderr, "[%s] getcBlockSize error=%zu\n", tag, cBlockSize);
			*err_out = 1; return (size_t)(op - dst);
		}
		ip += ZSTD_blockHeaderSize;
		remaining -= ZSTD_blockHeaderSize;
		if (cBlockSize > remaining) { *err_out = 1; return (size_t)(op - dst); }

		switch (bp.blockType) {
		case bt_compressed:
			decodedSize = rs
				? rs_ZSTD_decompressBlock_internal(dctx, op, (size_t)(oBlockEnd - op), ip, cBlockSize, 0)
				: ref_ZSTD_decompressBlock_internal(dctx, op, (size_t)(oBlockEnd - op), ip, cBlockSize, 0);
			break;
		case bt_raw:
			if (cBlockSize > (size_t)(oend - op)) { *err_out = 1; return (size_t)(op - dst); }
			memmove(op, ip, cBlockSize);
			decodedSize = cBlockSize;
			break;
		case bt_rle:
			if (bp.origSize > (size_t)(oend - op)) { *err_out = 1; return (size_t)(op - dst); }
			memset(op, ip[0], bp.origSize);
			decodedSize = bp.origSize;
			break;
		default:
			*err_out = 1;
			return (size_t)(op - dst);
		}
		if (ZSTD_isError(decodedSize)) {
			if (getenv("DT_DEBUG")) fprintf(stderr, "[%s] blockType=%u decodedSize error=%zu\n", tag, bp.blockType, decodedSize);
			*err_out = 1; return (size_t)(op - dst);
		}

		op += decodedSize;
		ip += cBlockSize;
		remaining -= cBlockSize;
		if (bp.lastBlock) break;
	}
	(void)tag;
	return (size_t)(op - dst);
}

int main(int argc, char **argv)
{
	unsigned long runs = argc > 1 ? strtoul(argv[1], NULL, 10) : 20000;
	unsigned long seed = argc > 2 ? strtoul(argv[2], NULL, 10) : 20260906;
	unsigned long i;
	unsigned long mismatches = 0, corrupt = 0;
	unsigned long rng = seed;

	printf("sources:\n");
	{
		const char *files[] = {
			"../../tree/lib/zstd/decompress/zstd_decompress_block_rs.rs",
			"../../pristine/lib/zstd/decompress/zstd_decompress_block.c",
		};
		size_t k;
		for (k = 0; k < 2; k++) {
			FILE *f = fopen(files[k], "rb");
			if (f) fclose(f);
		}
	}
	printf("runs=%lu seed=%lu\n", runs, seed);
#if DYNAMIC_BMI2
	printf("DYNAMIC_BMI2=1 (both bmi2=0 and bmi2=1 arms swept)\n");
#else
	printf("DYNAMIC_BMI2=0 (bmi2 axis degenerate on this target)\n");
#endif

	for (i = 0; i < runs; i++) {
		size_t plainLen = (dt_rand(&rng) % 8192) + 1;
		uint8_t *plain = malloc(plainLen);
		size_t bound = ZSTD_compressBound(plainLen);
		uint8_t *comp = malloc(bound);
		size_t cSize;
		int level;
		size_t j;

		for (j = 0; j < plainLen; j++) {
			/* A mix of highly compressible and near-random bytes,
			 * so both literal paths (raw/RLE/Huffman) and sequence
			 * paths (predefined/RLE/FSE/repeat) get exercised
			 * across runs. */
			unsigned r = dt_rand(&rng) % 100;
			if (r < 60)
				plain[j] = (uint8_t)(j % 4);
			else
				plain[j] = (uint8_t)dt_rand(&rng);
		}

		level = 1 + (int)(dt_rand(&rng) % 19);
		cSize = ZSTD_compress(comp, bound, plain, plainLen, level);
		if (ZSTD_isError(cSize)) { free(plain); free(comp); continue; }

		{
			struct dt_buf outRef, outRs;
			struct ZSTD_DCtx_s dctxRef, dctxRs;
			int bmi2;

			for (bmi2 = 0; bmi2 < 2; bmi2++) {
				int errRef, errRs;
				size_t nRef, nRs;

				dt_buf_init(&outRef, plainLen, 0xC0);
				dt_buf_init(&outRs, plainLen, 0xC1);
				dt_buf_poison(&outRef);
				dt_buf_poison(&outRs);

				dctx_reset(&dctxRef, outRef.p, bmi2);
				dctx_reset(&dctxRs, outRs.p, bmi2);

				nRef = decode_frame("ref", 0, &dctxRef, outRef.p, plainLen, comp, cSize, &errRef);
				nRs  = decode_frame("rs",  1, &dctxRs,  outRs.p,  plainLen, comp, cSize, &errRs);

				dt_checks++;
				if (errRef != errRs || nRef != nRs) {
					fprintf(stderr,
						"MISMATCH run=%lu bmi2=%d level=%d plainLen=%zu: "
						"errRef=%d nRef=%zu errRs=%d nRs=%zu\n",
						i, bmi2, level, plainLen, errRef, nRef, errRs, nRs);
					mismatches++;
				} else if (!errRef) {
					const char *where;
					if (memcmp(outRef.p, outRs.p, nRef) != 0) {
						fprintf(stderr, "MISMATCH (bytes) run=%lu bmi2=%d\n", i, bmi2);
						mismatches++;
					} else if (memcmp(outRef.p, plain, plainLen) != 0 || nRef != plainLen) {
						fprintf(stderr, "MISMATCH (vs plaintext) run=%lu bmi2=%d\n", i, bmi2);
						mismatches++;
					}
					if (!dt_pad_intact(&outRef, &where)) {
						fprintf(stderr, "PAD CLOBBERED (ref) run=%lu bmi2=%d: %s\n", i, bmi2, where);
						mismatches++;
					}
					if (!dt_pad_intact(&outRs, &where)) {
						fprintf(stderr, "PAD CLOBBERED (rs) run=%lu bmi2=%d: %s\n", i, bmi2, where);
						mismatches++;
					}
				} else {
					corrupt++;
				}

				free(outRef.base);
				free(outRs.base);

				if (mismatches >= dt_maxfails) {
					fprintf(stderr, "too many failures, stopping\n");
					free(plain); free(comp);
					goto done;
				}
			}
		}

		free(plain);
		free(comp);
	}
done:
	printf("comparisons: %lu   corrupt-or-errored: %lu   mismatches: %lu\n",
	       dt_checks, corrupt, mismatches);
	return mismatches ? 1 : 0;
}
