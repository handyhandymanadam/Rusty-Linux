/* SPDX-License-Identifier: GPL-2.0
 *
 * Differential driver for lib/zstd/decompress/huf_decompress.c against
 * port/tree/lib/zstd/decompress/huf_decompress_rs.rs.
 *
 *   difftest [runs] [seed]
 *
 * The comparison machinery -- poisoned buffers, canaries on both sides, raw
 * size_t return comparison -- is port/test/common/difftest.h, shared so the
 * harnesses cannot drift into comparing different amounts.
 *
 * FLAGS ARE AN AXIS, and a wide one. HUF_flags_bmi2 picks a whole second
 * compiled body; HUF_flags_disableFast picks a different decode loop
 * (HUF_decompress4X1_usingDTable_internal's fast path versus its safe one);
 * HUF_flags_disableAsm should be inert here because
 * ZSTD_ENABLE_ASM_X86_64_BMI2 is a hard `#define 0`, and the run asserts that
 * rather than trusting it. Every case sweeps all eight combinations and
 * requires the arms to agree on each.
 *
 * TABLES ARE COMPARED, NOT SHARED. For the usingDTable entries each arm builds
 * its OWN DTable and the two tables are compared byte for byte before either
 * is used. Handing the C's table to the Rust would hide exactly the class of
 * bug those entry points exist to expose.
 */
#include <stdint.h>

#define FSE_STATIC_LINKING_ONLY
#include "huf.h"
#include "fse.h"
#include "mem.h"
#include "portability_macros.h"
#include "error_private.h"

#include "../common/difftest.h"
#include "corpus.h"

/* ---- the two arms ------------------------------------------------------ */
#define ARMS(P) \
	size_t P##HUF_decompress1X1_DCtx_wksp(HUF_DTable *, void *, size_t, const void *, size_t, void *, size_t, int); \
	size_t P##HUF_decompress1X2_DCtx_wksp(HUF_DTable *, void *, size_t, const void *, size_t, void *, size_t, int); \
	size_t P##HUF_decompress1X_DCtx_wksp(HUF_DTable *, void *, size_t, const void *, size_t, void *, size_t, int); \
	size_t P##HUF_decompress4X_hufOnly_wksp(HUF_DTable *, void *, size_t, const void *, size_t, void *, size_t, int); \
	size_t P##HUF_decompress1X_usingDTable(void *, size_t, const void *, size_t, const HUF_DTable *, int); \
	size_t P##HUF_decompress4X_usingDTable(void *, size_t, const void *, size_t, const HUF_DTable *, int); \
	size_t P##HUF_readDTableX1_wksp(HUF_DTable *, const void *, size_t, void *, size_t, int); \
	size_t P##HUF_readDTableX2_wksp(HUF_DTable *, const void *, size_t, void *, size_t, int); \
	U32    P##HUF_selectDecoder(size_t, size_t);
ARMS(ref_)
ARMS(rs_)

/* ---- configuration facts, asserted rather than assumed ----------------- */
_Static_assert(sizeof(size_t) == 8, "harness assumes a 64-bit host");
/* Byte order is a HOST fact, not a harness choice -- see the same block in
 * port/test/zstd_entropy/main.c. What must be asserted is not "the host is
 * little-endian" but "the shim derived the host's order correctly": if that
 * correction ever breaks, BOTH arms compile the wrong byteswap paths together
 * and the differential cannot see it. This assert can. */
_Static_assert(MEM_LITTLE_ENDIAN ==
	       (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__),
	       "shim's MEM_LITTLE_ENDIAN disagrees with the host byte order");

/* DYNAMIC_BMI2 is 1 only on x86 without compile-time BMI2. Off x86 the axis is
 * degenerate, not broken. */
#if defined(__x86_64__) || defined(__i386__)
#  if !defined(__BMI2__)
_Static_assert(DYNAMIC_BMI2 == 1, "bmi2 axis is dead: DYNAMIC_BMI2 is 0 here");
#  else
_Static_assert(DYNAMIC_BMI2 == 0, "DYNAMIC_BMI2 should be 0 when __BMI2__ is set");
#  endif
#else
_Static_assert(DYNAMIC_BMI2 == 0, "DYNAMIC_BMI2 unexpectedly 1 off x86");
#endif
_Static_assert(ZSTD_ENABLE_ASM_X86_64_BMI2 == 0,
	       "the asm decoder is compiled IN here but not in the kernel");
_Static_assert(HUF_TABLELOG_MAX == 12, "");

/* ---- sizes ------------------------------------------------------------- */
#define DT_U32		HUF_DTABLE_SIZE(HUF_TABLELOG_MAX)	/* X2 is the larger */
#define DT_BYTES	(DT_U32 * sizeof(HUF_DTable))
#define WKSP_BYTES	HUF_DECOMPRESS_WORKSPACE_SIZE
#define DST_BYTES	(160 * 1024)	/* a literals block caps at 128 KB */

struct arm {
	struct dt_buf dt, dst, wksp;
};

static void arm_init(struct arm *a, unsigned char tag)
{
	dt_buf_init(&a->dt,   DT_BYTES,   tag ^ 0x01);
	dt_buf_init(&a->dst,  DST_BYTES,  tag ^ 0x02);
	dt_buf_init(&a->wksp, WKSP_BYTES, tag ^ 0x03);
}

#define B_DT	0x1
#define B_DST	0x2
#define B_WKSP	0x4

static void arm_poison(struct arm *a, unsigned char tag, unsigned mask)
{
	if (mask & B_DT)   { a->dt.tag   = tag ^ 0x01; dt_buf_poison(&a->dt); }
	if (mask & B_DST)  { a->dst.tag  = tag ^ 0x02; dt_buf_poison(&a->dst); }
	if (mask & B_WKSP) { a->wksp.tag = tag ^ 0x03; dt_buf_poison(&a->wksp); }
}

/* DTable[0] IS AN INPUT, not just output space.
 *
 * It carries the DTableDesc -- maxTableLog, tableType, tableLog -- and
 * HUF_readDTableX2_wksp rejects `maxTableLog > HUF_TABLELOG_MAX` before it
 * looks at a single byte of the tree (huf_decompress.c:1197), while X1 checks
 * `tableLog > dtd.maxTableLog+1` (:406). Poisoning it left garbage there and
 * the first selfcheck run showed exactly what that costs: readDTableX2
 * succeeded 56 times in 3,401 and HUF_decompress1X2_DCtx_wksp 4 times in
 * 3,332 -- the double-symbol decoder, half the file, was effectively untested
 * while the harness reported zero mismatches.
 *
 * Every real caller sets it: zstd_decompress.c:1497 and zstd_ddict.c:135 both
 * write `ZSTD_HUFFDTABLE_CAPACITY_LOG * 0x1000001`, the doubled-byte form that
 * lands 12 at whichever end the struct reads. So does the harness -- but not
 * always, because a caller passing a table too small IS a real error path. */
#define DT_DESC_OK ((HUF_DTable)(12u * 0x1000001u))

static void dt_seed_desc(struct arm *a, struct arm *b, uint64_t *s,
			 unsigned long *n_gooddesc)
{
	HUF_DTable v;

	if (rng_below(s, 8) == 0) {
		v = (HUF_DTable)rng_next(s);	/* the error path */
	} else {
		v = DT_DESC_OK;
		(*n_gooddesc)++;
	}
	memcpy(a->dt.p, &v, sizeof v);
	memcpy(b->dt.p, &v, sizeof v);
}

/* The eight flag combinations that select code, plus the one that should not. */
static const struct { int v; const char *name; } FLAGS[] = {
	{ 0,							"none" },
	{ HUF_flags_bmi2,					"bmi2" },
	{ HUF_flags_disableFast,				"disableFast" },
	{ HUF_flags_bmi2 | HUF_flags_disableFast,		"bmi2|disableFast" },
	{ HUF_flags_disableAsm,					"disableAsm" },
	{ HUF_flags_bmi2 | HUF_flags_disableAsm,		"bmi2|disableAsm" },
	{ HUF_flags_bmi2 | HUF_flags_disableFast | HUF_flags_disableAsm,
								"all three" },
};
#define NFLAGS ((int)(sizeof FLAGS / sizeof FLAGS[0]))

/* ---- counters ---------------------------------------------------------- */
static unsigned long n_case[6], ok_case[6];
static unsigned long n_mut, n_clean, n_gooddesc, n_formmatch;
static const char *case_name[6] = {
	"HUF_decompress4X_hufOnly_wksp", "HUF_decompress1X1_DCtx_wksp",
	"HUF_decompress1X2_DCtx_wksp",   "HUF_decompress1X_DCtx_wksp",
	"readDTableX1 + usingDTable",    "readDTableX2 + usingDTable",
};

int main(int argc, char **argv)
{
	unsigned long runs = argc > 1 ? strtoul(argv[1], NULL, 0) : 20000;
	uint64_t seed = argc > 2 ? strtoull(argv[2], NULL, 0) : 20260904;
	uint64_t s = seed ? seed : 1;
	struct arm A, B;
	unsigned long run;
	unsigned pool, i;

	arm_init(&A, 0x10);
	arm_init(&B, 0x10);

	printf("runs=%lu seed=%llu\n", runs, (unsigned long long)seed);
	printf("DYNAMIC_BMI2=%d  ZSTD_ENABLE_ASM_X86_64_BMI2=%d  "
	       "MEM_LITTLE_ENDIAN=%d\n",
	       DYNAMIC_BMI2, ZSTD_ENABLE_ASM_X86_64_BMI2, MEM_LITTLE_ENDIAN);

	pool = corpus_build(&s);
	printf("corpus: %u Huffman literals sections harvested from real "
	       "libzstd frames\n\n", pool);
	if (pool < 20) {
		fprintf(stderr, "CORPUS FAILURE: only %u sections harvested; "
			"the run would prove almost nothing\n", pool);
		return 3;
	}

	/* HUF_selectDecoder is pure over two size_ts. Sweep it rather than
	 * sampling: it is the branch that decides X1 versus X2 for every
	 * literals block in the kernel. */
	for (i = 0; i < 4096; i++) {
		size_t dstSize = i * 37 + 1;
		size_t cSrcSize = (i * 11) % 4096 + 1;

		dt_cmp_u32(0, "HUF_selectDecoder", "ret",
			   ref_HUF_selectDecoder(dstSize, cSrcSize),
			   rs_HUF_selectDecoder(dstSize, cSrcSize));
	}

	for (run = 1; run <= runs; run++) {
		int which = (int)rng_below(&s, 6);
		int mutate = rng_below(&s, 3) != 0;	/* 2 in 3 corrupted */
		int fi = (int)rng_below(&s, NFLAGS);
		int flags = FLAGS[fi].v;
		unsigned char tag = (unsigned char)rng_next(&s);
		unsigned muts = 0;
		const struct lits *L = corpus_pick(&s, mutate, &muts);
		size_t dstCap;

		/* A one-stream section fed to a four-stream entry point is a
		 * legitimate error case, but it must not be the MAJORITY of
		 * them or the success paths go untested. Cases 1-3 are the
		 * one-stream entries and case 0 is the four-stream one, so
		 * seven times in eight the corpus is re-drawn until the form
		 * matches. */
		if (rng_below(&s, 8) != 0) {
			int want_single = (which >= 1 && which <= 3);
			int tries = 0;

			while (L->single != want_single && ++tries < 64)
				L = corpus_pick(&s, mutate, &muts);
			if (L->single == want_single)
				n_formmatch++;
		}
		dstCap = L->regen <= DST_BYTES ? L->regen : DST_BYTES;
		size_t wkspSize = WKSP_BYTES;
		size_t ra, rb;

		if (mutate) n_mut++; else n_clean++;
		/* sometimes starve the workspace, and sometimes the output */
		if (rng_below(&s, 8) == 0)
			wkspSize = rng_below(&s, WKSP_BYTES);
		if (rng_below(&s, 8) == 0)
			dstCap = rng_below(&s, (uint32_t)dstCap + 1);
		n_case[which]++;

		switch (which) {
		case 0: case 1: case 2: case 3: {
			unsigned mask = B_DT | B_DST | B_WKSP;

			arm_poison(&A, tag, mask);
			arm_poison(&B, tag, mask);
			dt_seed_desc(&A, &B, &s, &n_gooddesc);
#define CALL(fn) \
	ra = ref_##fn((HUF_DTable *)A.dt.p, A.dst.p, dstCap, L->buf, L->len, \
		      A.wksp.p, wkspSize, flags); \
	rb = rs_##fn((HUF_DTable *)B.dt.p, B.dst.p, dstCap, L->buf, L->len, \
		     B.wksp.p, wkspSize, flags)
			if (which == 0)      { CALL(HUF_decompress4X_hufOnly_wksp); }
			else if (which == 1) { CALL(HUF_decompress1X1_DCtx_wksp); }
			else if (which == 2) { CALL(HUF_decompress1X2_DCtx_wksp); }
			else                 { CALL(HUF_decompress1X_DCtx_wksp); }
#undef CALL
			dt_cmp_ret(run, case_name[which], ra, rb);
			dt_cmp_buf(run, case_name[which], "dst", &A.dst, &B.dst);
			dt_cmp_buf(run, case_name[which], "DTable", &A.dt, &B.dt);
			dt_cmp_buf(run, case_name[which], "workSpace",
				   &A.wksp, &B.wksp);
			if (!ERR_isError(ra))
				ok_case[which]++;
			break;
		}
		default: {	/* 4 and 5: build a table, then use it */
			int x2 = (which == 5);
			size_t ta, tb;

			arm_poison(&A, tag, B_DT | B_WKSP);
			arm_poison(&B, tag, B_DT | B_WKSP);
			dt_seed_desc(&A, &B, &s, &n_gooddesc);
			if (x2) {
				ta = ref_HUF_readDTableX2_wksp((HUF_DTable *)A.dt.p,
					L->buf, L->len, A.wksp.p, wkspSize, flags);
				tb = rs_HUF_readDTableX2_wksp((HUF_DTable *)B.dt.p,
					L->buf, L->len, B.wksp.p, wkspSize, flags);
			} else {
				ta = ref_HUF_readDTableX1_wksp((HUF_DTable *)A.dt.p,
					L->buf, L->len, A.wksp.p, wkspSize, flags);
				tb = rs_HUF_readDTableX1_wksp((HUF_DTable *)B.dt.p,
					L->buf, L->len, B.wksp.p, wkspSize, flags);
			}
			dt_cmp_ret(run, case_name[which], ta, tb);
			dt_cmp_buf(run, case_name[which], "DTable", &A.dt, &B.dt);
			dt_cmp_buf(run, case_name[which], "workSpace",
				   &A.wksp, &B.wksp);
			if (ERR_isError(ta))
				break;
			ok_case[which]++;

			/* Each arm now decodes the streams that follow the tree
			 * description, USING ITS OWN TABLE. */
			{
				size_t off = ta <= L->len ? ta : L->len;
				const uint8_t *body = L->buf + off;
				size_t blen = L->len - off;

				arm_poison(&A, tag, B_DST);
				arm_poison(&B, tag, B_DST);
				ra = ref_HUF_decompress1X_usingDTable(A.dst.p,
					dstCap, body, blen,
					(const HUF_DTable *)A.dt.p, flags);
				rb = rs_HUF_decompress1X_usingDTable(B.dst.p,
					dstCap, body, blen,
					(const HUF_DTable *)B.dt.p, flags);
				dt_cmp_ret(run, "HUF_decompress1X_usingDTable",
					   ra, rb);
				dt_cmp_buf(run, "HUF_decompress1X_usingDTable",
					   "dst", &A.dst, &B.dst);

				arm_poison(&A, tag, B_DST);
				arm_poison(&B, tag, B_DST);
				ra = ref_HUF_decompress4X_usingDTable(A.dst.p,
					dstCap, body, blen,
					(const HUF_DTable *)A.dt.p, flags);
				rb = rs_HUF_decompress4X_usingDTable(B.dst.p,
					dstCap, body, blen,
					(const HUF_DTable *)B.dt.p, flags);
				dt_cmp_ret(run, "HUF_decompress4X_usingDTable",
					   ra, rb);
				dt_cmp_buf(run, "HUF_decompress4X_usingDTable",
					   "dst", &A.dst, &B.dst);
			}
			break;
		}
		}
	}

	printf("%-34s %10s %10s\n", "case", "runs", "succeeded");
	for (i = 0; i < 6; i++)
		printf("%-34s %10lu %10lu\n", case_name[i], n_case[i], ok_case[i]);
	printf("\ninputs: %lu pristine, %lu corrupted, %lu stream-form matched,\n"
	       "        %lu with a valid DTable descriptor\n",
	       n_clean, n_mut, n_formmatch, n_gooddesc);
	printf("comparisons: %lu   mismatches: %lu\n", dt_checks, dt_fails);

	/* STATUS.md lesson 9: a clean result with an implausible volume has not
	 * checked anything. */
	if (runs >= 2000) {
		unsigned dead = 0;
		for (i = 0; i < 6; i++)
			if (!ok_case[i])
				dead++;
		if (dead) {
			fprintf(stderr, "\nCORPUS FAILURE: %u of 6 cases never "
				"once succeeded\n", dead);
			return 3;
		}
	}
	return dt_fails ? 1 : 0;
}
