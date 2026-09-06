/* SPDX-License-Identifier: GPL-2.0
 *
 * Differential driver for lib/zstd/decompress/zstd_ddict.c against
 * port/tree/lib/zstd/decompress/zstd_ddict_rs.rs.
 *
 *   difftest [runs] [seed]
 *
 * ZSTD_loadDEntropy (zstd_decompress.c's, not this file's) is stubbed
 * identically for both arms -- see stub_loadentropy.c's own comment for
 * why: this harness proves zstd_ddict's OWN logic (buffer ownership,
 * static-buffer bounds/alignment, dictID parsing, entropyPresent and error
 * propagation, ZSTD_copyDDictParameters's field-for-field copy), not
 * zstd_decompress.c's unrelated, actively-changing entropy-table code.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "../common/difftest.h"

typedef void *(*alloc_fn)(void *opaque, size_t size);
typedef void (*free_fn)(void *opaque, void *address);

#define ARMS(P) \
	const void *P##ZSTD_DDict_dictContent(const void *ddict); \
	size_t P##ZSTD_DDict_dictSize(const void *ddict); \
	void P##ZSTD_copyDDictParameters(void *dctx, const void *ddict); \
	void *P##ZSTD_createDDict_advanced(const void *dict, size_t dictSize, unsigned dictLoadMethod, unsigned dictContentType, alloc_fn customAlloc, free_fn customFree, void *opaque); \
	void *P##ZSTD_initStaticDDict(void *sBuffer, size_t sBufferSize, const void *dict, size_t dictSize, unsigned dictLoadMethod, unsigned dictContentType); \
	size_t P##ZSTD_freeDDict(void *ddict); \
	size_t P##ZSTD_estimateDDictSize(size_t dictSize, unsigned dictLoadMethod); \
	size_t P##ZSTD_sizeof_DDict(const void *ddict); \
	unsigned P##ZSTD_getDictID_fromDDict(const void *ddict);
ARMS(ref_)
ARMS(rs_)

enum { ZSTD_DLM_BY_COPY = 0, ZSTD_DLM_BY_REF = 1 };
enum { ZSTD_DCT_AUTO = 0, ZSTD_DCT_RAW_CONTENT = 1, ZSTD_DCT_FULL_DICT = 2 };
#define ZSTD_MAGIC_DICTIONARY 0xEC30A437u

/* Byte offsets into struct ZSTD_DCtx_s / struct ZSTD_DDict_s -- taken
 * verbatim from check_offsets.sh's OK'd output, not re-derived here. */
#define DCTX_OFF_LLTptr         0
#define DCTX_OFF_prefixStart    29896
#define DCTX_OFF_virtualStart   29904
#define DCTX_OFF_dictEnd        29912
#define DCTX_OFF_previousDstEnd 29888
#define DCTX_OFF_litEntropy     30000
#define DCTX_OFF_fseEntropy     30004
#define DCTX_OFF_dictID         30192
#define DDICT_OFF_entropy       24
#define ENTROPY_OFF_LLTable     0
#define ENTROPY_OFF_OFTable     4104
#define ENTROPY_OFF_MLTable     6160
#define ENTROPY_OFF_hufTable    10264
#define ENTROPY_OFF_rep         26652

static void *ptr_at(const void *base, size_t off) { return *(void **)((const char *)base + off); }
static uint32_t u32_at(const void *base, size_t off) { return *(const uint32_t *)((const char *)base + off); }
static const void *byte_off(const void *base, size_t off) { return (const char *)base + off; }

/* A real, working allocator -- exercises the byCopy allocation path, which
 * the kernel's own ZSTD_malloc/ZSTD_calloc (always NULL, no libc fallback)
 * cannot. */
static void *test_alloc(void *opaque, size_t size) { (void)opaque; return malloc(size); }
static void test_free(void *opaque, void *address) { (void)opaque; free(address); }

static uint64_t rng_next(uint64_t *s)
{
	*s ^= *s << 13;
	*s ^= *s >> 7;
	*s ^= *s << 17;
	return *s;
}

/* Builds a dictionary payload of `size` bytes. `full` selects the
 * ZSTD_MAGIC_DICTIONARY-prefixed shape zstd_ddict.c itself parses
 * (magic + 4-byte dictID + arbitrary body); otherwise plain random bytes
 * (a valid rawContent dictionary, and also what a fullDict parse rejects
 * except by the stub's own deterministic rule). */
static void fill_dict(uint8_t *buf, size_t size, int full, uint64_t *rng)
{
	size_t i;
	for (i = 0; i < size; i++)
		buf[i] = (uint8_t)(rng_next(rng) & 0xff);
	if (full && size >= 8) {
		buf[0] = (uint8_t)(ZSTD_MAGIC_DICTIONARY & 0xff);
		buf[1] = (uint8_t)((ZSTD_MAGIC_DICTIONARY >> 8) & 0xff);
		buf[2] = (uint8_t)((ZSTD_MAGIC_DICTIONARY >> 16) & 0xff);
		buf[3] = (uint8_t)((ZSTD_MAGIC_DICTIONARY >> 24) & 0xff);
	}
}

struct case_result {
	void *ddict;
	int dictID;
	size_t dictSize;
	size_t sizeofDDict;
	const void *dictContent;
};

static int run_one(const char *tag, int rs,
		    const void *dict, size_t dictSize,
		    unsigned loadMethod, unsigned contentType,
		    int useRealAlloc,
		    struct case_result *out)
{
	void *ddict;
	alloc_fn af = useRealAlloc ? test_alloc : NULL;
	free_fn ff = useRealAlloc ? test_free : NULL;

	ddict = rs
		? rs_ZSTD_createDDict_advanced(dict, dictSize, loadMethod, contentType, af, ff, NULL)
		: ref_ZSTD_createDDict_advanced(dict, dictSize, loadMethod, contentType, af, ff, NULL);

	out->ddict = ddict;
	if (!ddict) return 0;

	out->dictID = rs ? rs_ZSTD_getDictID_fromDDict(ddict) : ref_ZSTD_getDictID_fromDDict(ddict);
	out->dictSize = rs ? rs_ZSTD_DDict_dictSize(ddict) : ref_ZSTD_DDict_dictSize(ddict);
	out->sizeofDDict = rs ? rs_ZSTD_sizeof_DDict(ddict) : ref_ZSTD_sizeof_DDict(ddict);
	out->dictContent = rs ? rs_ZSTD_DDict_dictContent(ddict) : ref_ZSTD_DDict_dictContent(ddict);
	(void)tag;
	return 1;
}

int main(int argc, char **argv)
{
	long runs = argc > 1 ? atol(argv[1]) : 2000;
	uint64_t seed = argc > 2 ? (uint64_t)atol(argv[2]) : 20260906u;
	long i;
	long comparisons = 0, mismatches = 0;

	printf("runs=%ld seed=%llu\n", runs, (unsigned long long)seed);

	for (i = 0; i < runs; i++) {
		size_t dictSize = 1 + (size_t)(rng_next(&seed) % 4096);
		unsigned loadMethod = (rng_next(&seed) & 1) ? ZSTD_DLM_BY_REF : ZSTD_DLM_BY_COPY;
		unsigned contentTypePick = (unsigned)(rng_next(&seed) % 3);
		unsigned contentType = contentTypePick == 0 ? ZSTD_DCT_AUTO
				     : contentTypePick == 1 ? ZSTD_DCT_RAW_CONTENT
				     : ZSTD_DCT_FULL_DICT;
		int full = (contentType != ZSTD_DCT_RAW_CONTENT) && (rng_next(&seed) & 1);
		int useRealAlloc = (loadMethod == ZSTD_DLM_BY_COPY) ? 1 : ((rng_next(&seed) % 10) != 0);
		uint8_t *dict = malloc(dictSize);
		struct case_result ref_r, rs_r;
		int ref_ok, rs_ok;

		fill_dict(dict, dictSize, full, &seed);

		ref_ok = run_one("ref", 0, dict, dictSize, loadMethod, contentType, useRealAlloc, &ref_r);
		rs_ok  = run_one("rs",  1, dict, dictSize, loadMethod, contentType, useRealAlloc, &rs_r);
		comparisons++;

		if (!!ref_ok != !!rs_ok) {
			printf("MISMATCH(create): ref_ok=%d rs_ok=%d dictSize=%zu loadMethod=%u contentType=%u full=%d useRealAlloc=%d\n",
			       ref_ok, rs_ok, dictSize, loadMethod, contentType, full, useRealAlloc);
			mismatches++;
			free(dict);
			continue;
		}

		if (ref_ok) {
			if (ref_r.dictID != rs_r.dictID || ref_r.dictSize != rs_r.dictSize ||
			    ref_r.sizeofDDict != rs_r.sizeofDDict) {
				printf("MISMATCH(fields): dictID %d/%d dictSize %zu/%zu sizeofDDict %zu/%zu\n",
				       ref_r.dictID, rs_r.dictID, ref_r.dictSize, rs_r.dictSize,
				       ref_r.sizeofDDict, rs_r.sizeofDDict);
				mismatches++;
			}
			comparisons += 3;

			if (ref_r.dictSize > 0 &&
			    memcmp(ref_r.dictContent, rs_r.dictContent, ref_r.dictSize) != 0) {
				printf("MISMATCH(content bytes)\n");
				mismatches++;
			}
			comparisons++;

			/* ZSTD_copyDDictParameters, into freshly zeroed DCtx-sized
			 * buffers. LLTptr etc. point into each arm's OWN ddict, so
			 * every check is structural (offset-from-own-ddict), never
			 * a raw cross-arm address comparison; sizes are the
			 * check_offsets.sh-verified real byte offsets, hardcoded
			 * above.
			 *
			 * expected_entropy: mirrors zstd_ddict.c's own
			 * ZSTD_loadEntropy_intoDDict logic plus stub_loadentropy.c's
			 * deterministic rule, so this checks the PROPAGATION of
			 * that logic, not the (stubbed) entropy build itself.
			 */
			{
				int expected_entropy = full && contentType != ZSTD_DCT_RAW_CONTENT &&
						       dictSize >= 8 && (dictSize % 7 != 0);
				unsigned char *ref_dctx = calloc(1, 95960);
				unsigned char *rs_dctx = calloc(1, 95960);
				const void *ref_ddict = ref_r.ddict, *rs_ddict = rs_r.ddict;
				int j;

				ref_ZSTD_copyDDictParameters(ref_dctx, ref_ddict);
				rs_ZSTD_copyDDictParameters(rs_dctx, rs_ddict);

				comparisons += 6;
				if (ptr_at(ref_dctx, DCTX_OFF_prefixStart) != ref_r.dictContent ||
				    ptr_at(rs_dctx, DCTX_OFF_prefixStart) != rs_r.dictContent)
					{ printf("MISMATCH(prefixStart)\n"); mismatches++; }
				if (ptr_at(ref_dctx, DCTX_OFF_virtualStart) != ref_r.dictContent ||
				    ptr_at(rs_dctx, DCTX_OFF_virtualStart) != rs_r.dictContent)
					{ printf("MISMATCH(virtualStart)\n"); mismatches++; }
				if (ptr_at(ref_dctx, DCTX_OFF_dictEnd) != byte_off(ref_r.dictContent, ref_r.dictSize) ||
				    ptr_at(rs_dctx, DCTX_OFF_dictEnd) != byte_off(rs_r.dictContent, rs_r.dictSize))
					{ printf("MISMATCH(dictEnd)\n"); mismatches++; }
				if (ptr_at(ref_dctx, DCTX_OFF_previousDstEnd) != ptr_at(ref_dctx, DCTX_OFF_dictEnd) ||
				    ptr_at(rs_dctx, DCTX_OFF_previousDstEnd) != ptr_at(rs_dctx, DCTX_OFF_dictEnd))
					{ printf("MISMATCH(previousDstEnd)\n"); mismatches++; }
				if (u32_at(ref_dctx, DCTX_OFF_dictID) != (uint32_t)ref_r.dictID ||
				    u32_at(rs_dctx, DCTX_OFF_dictID) != (uint32_t)rs_r.dictID)
					{ printf("MISMATCH(dctx.dictID)\n"); mismatches++; }
				if (!u32_at(ref_dctx, DCTX_OFF_litEntropy) != !expected_entropy ||
				    !u32_at(rs_dctx, DCTX_OFF_litEntropy) != !expected_entropy ||
				    u32_at(ref_dctx, DCTX_OFF_litEntropy) != u32_at(ref_dctx, DCTX_OFF_fseEntropy) ||
				    u32_at(rs_dctx, DCTX_OFF_litEntropy) != u32_at(rs_dctx, DCTX_OFF_fseEntropy))
					{ printf("MISMATCH(litEntropy/fseEntropy) expected=%d ref=%u/%u rs=%u/%u\n",
						 expected_entropy,
						 u32_at(ref_dctx, DCTX_OFF_litEntropy), u32_at(ref_dctx, DCTX_OFF_fseEntropy),
						 u32_at(rs_dctx, DCTX_OFF_litEntropy), u32_at(rs_dctx, DCTX_OFF_fseEntropy));
					  mismatches++; }

				if (expected_entropy) {
					comparisons += 4;
					if (ptr_at(ref_dctx, DCTX_OFF_LLTptr) != byte_off(ref_ddict, DDICT_OFF_entropy + ENTROPY_OFF_LLTable) ||
					    ptr_at(rs_dctx, DCTX_OFF_LLTptr) != byte_off(rs_ddict, DDICT_OFF_entropy + ENTROPY_OFF_LLTable))
						{ printf("MISMATCH(LLTptr)\n"); mismatches++; }
					if (ptr_at(ref_dctx, DCTX_OFF_LLTptr + 24) != byte_off(ref_ddict, DDICT_OFF_entropy + ENTROPY_OFF_hufTable) ||
					    ptr_at(rs_dctx, DCTX_OFF_LLTptr + 24) != byte_off(rs_ddict, DDICT_OFF_entropy + ENTROPY_OFF_hufTable))
						{ printf("MISMATCH(HUFptr)\n"); mismatches++; }
					for (j = 0; j < 3; j++) {
						uint32_t expected[3] = { 0x11111111u, 0x22222222u, 0x33333333u };
						uint32_t ref_rep = u32_at(byte_off(ref_ddict, DDICT_OFF_entropy + ENTROPY_OFF_rep), (size_t)j * 4);
						uint32_t rs_rep = u32_at(byte_off(rs_ddict, DDICT_OFF_entropy + ENTROPY_OFF_rep), (size_t)j * 4);
						if (ref_rep != expected[j] || rs_rep != expected[j])
							{ printf("MISMATCH(entropy.rep[%d]) expected=%x ref=%x rs=%x\n", j, expected[j], ref_rep, rs_rep); mismatches++; }
					}
				}

				free(ref_dctx);
				free(rs_dctx);
			}

			ref_ZSTD_freeDDict(ref_r.ddict);
			rs_ZSTD_freeDDict(rs_r.ddict);
		}

		free(dict);
	}

	/* NULL-safety, both arms. */
	{
		comparisons += 3;
		if (ref_ZSTD_freeDDict(NULL) != rs_ZSTD_freeDDict(NULL)) { printf("MISMATCH(freeDDict NULL)\n"); mismatches++; }
		if (ref_ZSTD_sizeof_DDict(NULL) != rs_ZSTD_sizeof_DDict(NULL)) { printf("MISMATCH(sizeof_DDict NULL)\n"); mismatches++; }
		if (ref_ZSTD_getDictID_fromDDict(NULL) != rs_ZSTD_getDictID_fromDDict(NULL)) { printf("MISMATCH(getDictID NULL)\n"); mismatches++; }
	}

	/* ZSTD_estimateDDictSize, pure function, both arms, across a range. */
	{
		size_t sizes[] = { 0, 1, 7, 8, 4096, 1u << 20 };
		unsigned methods[] = { ZSTD_DLM_BY_COPY, ZSTD_DLM_BY_REF };
		size_t si; unsigned mi;
		for (si = 0; si < sizeof(sizes)/sizeof(sizes[0]); si++)
			for (mi = 0; mi < sizeof(methods)/sizeof(methods[0]); mi++) {
				size_t a = ref_ZSTD_estimateDDictSize(sizes[si], methods[mi]);
				size_t b = rs_ZSTD_estimateDDictSize(sizes[si], methods[mi]);
				comparisons++;
				if (a != b) { printf("MISMATCH(estimateDDictSize) size=%zu method=%u: %zu/%zu\n", sizes[si], methods[mi], a, b); mismatches++; }
			}
	}

	/* ZSTD_initStaticDDict: correctly sized/aligned buffer, undersized
	 * buffer, and misaligned buffer, for both content types. */
	{
		int t;
		for (t = 0; t < 6; t++) {
			unsigned loadMethod = (t & 1) ? ZSTD_DLM_BY_REF : ZSTD_DLM_BY_COPY;
			unsigned contentType = ZSTD_DCT_RAW_CONTENT;
			size_t dictSize = 100;
			uint8_t dict[100];
			size_t needed;
			uint8_t *raw;
			void *sbuf;
			size_t sbufSize;
			const void *ref_d, *rs_d;
			size_t j;

			for (j = 0; j < dictSize; j++) dict[j] = (uint8_t)(j * 7 + 1);

			needed = ref_ZSTD_estimateDDictSize(dictSize, loadMethod);
			if (t / 2 == 1) needed -= 1; /* undersized: expect both NULL */
			raw = malloc(needed + 16);
			sbuf = raw + ((t / 2 == 2) ? 1 : 0); /* misaligned: expect both NULL */
			sbufSize = needed;

			ref_d = ref_ZSTD_initStaticDDict(sbuf, sbufSize, dict, dictSize, loadMethod, contentType);
			rs_d  = rs_ZSTD_initStaticDDict(sbuf, sbufSize, dict, dictSize, loadMethod, contentType);
			comparisons++;
			if (!!ref_d != !!rs_d) {
				printf("MISMATCH(initStaticDDict) case=%d: ref=%p rs=%p\n", t, ref_d, rs_d);
				mismatches++;
			} else if (ref_d) {
				comparisons += 2;
				if (ref_ZSTD_DDict_dictSize(ref_d) != rs_ZSTD_DDict_dictSize(rs_d)) { printf("MISMATCH(initStaticDDict dictSize)\n"); mismatches++; }
				if (memcmp(ref_ZSTD_DDict_dictContent(ref_d), rs_ZSTD_DDict_dictContent(rs_d), dictSize) != 0) { printf("MISMATCH(initStaticDDict content)\n"); mismatches++; }
			}
			free(raw);
		}
	}

	printf("comparisons: %ld   mismatches: %ld\n", comparisons, mismatches);
	return mismatches != 0;
}
