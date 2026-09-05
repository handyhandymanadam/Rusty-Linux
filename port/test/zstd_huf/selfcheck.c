/* SPDX-License-Identifier: GPL-2.0
 *
 * Harness smoke test: the "rs" arm is a second call into the SAME pristine C,
 * so `run.sh --selfcheck` exercises every line of main.c with an arm that
 * cannot disagree. It proves the plumbing and, more usefully, that the corpus
 * drives each of the six cases to a SUCCESSFUL return often enough to be worth
 * running. It proves nothing about the port. Smoke test, not a stopping rule
 * (logs/floor.md RULE T2).
 */
#include <stddef.h>
typedef unsigned int U32;
typedef unsigned int HUF_DTable;

#define FWD8(name) \
	size_t ref_##name(HUF_DTable *a, void *b, size_t c, const void *d, \
			  size_t e, void *f, size_t g, int h); \
	size_t rs_##name(HUF_DTable *a, void *b, size_t c, const void *d, \
			 size_t e, void *f, size_t g, int h) \
	{ return ref_##name(a, b, c, d, e, f, g, h); }

FWD8(HUF_decompress1X1_DCtx_wksp)
FWD8(HUF_decompress1X2_DCtx_wksp)
FWD8(HUF_decompress1X_DCtx_wksp)
FWD8(HUF_decompress4X_hufOnly_wksp)

#define FWD_USING(name) \
	size_t ref_##name(void *a, size_t b, const void *c, size_t d, \
			  const HUF_DTable *e, int f); \
	size_t rs_##name(void *a, size_t b, const void *c, size_t d, \
			 const HUF_DTable *e, int f) \
	{ return ref_##name(a, b, c, d, e, f); }

FWD_USING(HUF_decompress1X_usingDTable)
FWD_USING(HUF_decompress4X_usingDTable)

#define FWD_READ(name) \
	size_t ref_##name(HUF_DTable *a, const void *b, size_t c, void *d, \
			  size_t e, int f); \
	size_t rs_##name(HUF_DTable *a, const void *b, size_t c, void *d, \
			 size_t e, int f) \
	{ return ref_##name(a, b, c, d, e, f); }

FWD_READ(HUF_readDTableX1_wksp)
FWD_READ(HUF_readDTableX2_wksp)

U32 ref_HUF_selectDecoder(size_t a, size_t b);
U32 rs_HUF_selectDecoder(size_t a, size_t b) { return ref_HUF_selectDecoder(a, b); }
