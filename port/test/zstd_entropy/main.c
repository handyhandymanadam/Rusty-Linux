/* SPDX-License-Identifier: GPL-2.0
 *
 * Differential driver for lib/zstd/common/{entropy_common,fse_decompress}.c
 * against port/tree/lib/zstd/common/entropy_common_rs.rs.
 *
 *   difftest [runs] [seed]
 *
 * WHAT IS COMPARED. Not just the return value. Every byte either arm could
 * have written: the output buffers, the out-parameters, AND the padding on
 * both sides of every buffer. Each buffer is poisoned with a deterministic
 * pattern before the call and the WHOLE padded region is compared afterwards,
 * so a port that writes one element further than the C fails here even when
 * the logical result is identical. The padding is then re-checked against the
 * poison, because a stray write both arms make is invisible to a comparison
 * of the two arms against each other.
 *
 * Return values are compared as raw size_t. A zstd error code is
 * `0 - ZSTD_error_*`, so two DIFFERENT errors are both "an error" and would
 * pass a test that only asked `isError(a) == isError(b)`. They must be equal.
 *
 * bmi2 IS AN AXIS. DYNAMIC_BMI2 is 1 on x86-64, so FSE_readNCount_bmi2 and
 * HUF_readStats_wksp each have two compiled bodies that differ only in
 * instruction selection for ZSTD_highbit32/countTrailingZeros32. They must
 * agree with each other as well as across the arms, so every case runs both
 * ways and the four results are compared as a set.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define FSE_STATIC_LINKING_ONLY
#include "fse.h"
#include "huf.h"
#include "mem.h"
#include "portability_macros.h"

#include "corpus.h"

/* ---- the two arms ------------------------------------------------------ */
size_t ref_FSE_readNCount_bmi2(short *, unsigned *, unsigned *, const void *, size_t, int);
size_t ref_FSE_readNCount(short *, unsigned *, unsigned *, const void *, size_t);
size_t ref_HUF_readStats_wksp(BYTE *, size_t, U32 *, U32 *, U32 *, const void *, size_t, void *, size_t, int);
size_t ref_HUF_readStats(BYTE *, size_t, U32 *, U32 *, U32 *, const void *, size_t);
size_t ref_FSE_buildDTable_wksp(FSE_DTable *, const short *, unsigned, unsigned, void *, size_t);
size_t ref_FSE_decompress_wksp_bmi2(void *, size_t, const void *, size_t, unsigned, void *, size_t, int);

size_t rs_FSE_readNCount_bmi2(short *, unsigned *, unsigned *, const void *, size_t, int);
size_t rs_FSE_readNCount(short *, unsigned *, unsigned *, const void *, size_t);
size_t rs_HUF_readStats_wksp(BYTE *, size_t, U32 *, U32 *, U32 *, const void *, size_t, void *, size_t, int);
size_t rs_HUF_readStats(BYTE *, size_t, U32 *, U32 *, U32 *, const void *, size_t);
size_t rs_FSE_buildDTable_wksp(FSE_DTable *, const short *, unsigned, unsigned, void *, size_t);
size_t rs_FSE_decompress_wksp_bmi2(void *, size_t, const void *, size_t, unsigned, void *, size_t, int);

unsigned ref_FSE_versionNumber(void);
unsigned ref_FSE_isError(size_t);
const char *ref_FSE_getErrorName(size_t);
unsigned ref_HUF_isError(size_t);
const char *ref_HUF_getErrorName(size_t);

const char *ref_ERR_getErrorString(int code);

unsigned    ref_ZSTD_versionNumber(void);
const char *ref_ZSTD_versionString(void);
unsigned    ref_ZSTD_isError(size_t);
const char *ref_ZSTD_getErrorName(size_t);
int         ref_ZSTD_getErrorCode(size_t);
const char *ref_ZSTD_getErrorString(int);

unsigned    rs_ZSTD_versionNumber(void);
const char *rs_ZSTD_versionString(void);
unsigned    rs_ZSTD_isError(size_t);
const char *rs_ZSTD_getErrorName(size_t);
int         rs_ZSTD_getErrorCode(size_t);
const char *rs_ZSTD_getErrorString(int);
const char *rs_ERR_getErrorString(int code);

unsigned rs_FSE_versionNumber(void);
unsigned rs_FSE_isError(size_t);
const char *rs_FSE_getErrorName(size_t);
unsigned rs_HUF_isError(size_t);
const char *rs_HUF_getErrorName(size_t);

/* ---- the configuration facts, asserted rather than assumed -------------
 *
 * STATUS.md lesson 11: a shim that compiles is not a shim that matches. Each
 * of these selects a code path in the oracle, and getting one wrong makes
 * both arms equally wrong -- which the differential cannot see.
 */
_Static_assert(sizeof(size_t) == 8, "harness assumes a 64-bit host");
/* Byte order is a HOST fact, not a harness choice. Pinning it to 1 pinned the
 * whole harness to x86-64, and is why nothing in this tree had ever been run
 * big-endian: measured 2026-09-04, this line was the FIRST thing that stopped
 * an s390x cross-build, before any port code was reached.
 *
 * What must be asserted is not "the host is little-endian" but "the shim
 * derived the host's order correctly". mem.h:101 keys MEM_LITTLE_ENDIAN off
 * `#if defined(__LITTLE_ENDIAN)`, which glibc's <endian.h> makes true on every
 * host; port/test/common/shim/linux/kernel.h undefines the false one to
 * correct that. If that correction ever breaks, MEM_LITTLE_ENDIAN and
 * __BYTE_ORDER__ disagree -- and BOTH arms would then compile the wrong
 * byteswap paths together, which the differential cannot see. This assert can.
 */
_Static_assert(MEM_LITTLE_ENDIAN ==
	       (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__),
	       "shim's MEM_LITTLE_ENDIAN disagrees with the host byte order");

/* DYNAMIC_BMI2 is 1 only on x86 (portability_macros.h:61-71). Off x86 the
 * bmi2 axis is DEGENERATE, not broken: bmi2=0 and bmi2=1 reach one compiled
 * body, so the loops below still exercise the dispatch wrappers and cost
 * nothing, they just stop being a second axis. Asserting the value per target
 * keeps the original guard's job -- catching DYNAMIC_BMI2 silently going 0 on
 * x86 -- without claiming x86 is the only host. main() prints it either way.
 */
#if defined(__x86_64__) || defined(__i386__)
_Static_assert(DYNAMIC_BMI2 == 1, "bmi2 axis is dead: DYNAMIC_BMI2 is 0 here");
#else
_Static_assert(DYNAMIC_BMI2 == 0, "DYNAMIC_BMI2 unexpectedly 1 off x86");
#endif
_Static_assert(FSE_MAX_SYMBOL_VALUE == 255, "");
_Static_assert(FSE_TABLELOG_ABSOLUTE_MAX == 15, "");
_Static_assert(HUF_TABLELOG_MAX == 12, "");

/* ---- poisoned buffers with canaries on both sides ---------------------- */
#define PAD 64

struct buf {
	unsigned char *base;	/* PAD + len + PAD */
	unsigned char *p;	/* the usable part */
	size_t len;
	size_t total;
	unsigned char tag;
};

static void buf_init(struct buf *b, size_t len, unsigned char tag)
{
	b->len = len;
	b->total = len + 2 * PAD;
	b->base = malloc(b->total);
	if (!b->base) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	b->p = b->base + PAD;
	b->tag = tag;
}

/* A pattern that varies with position, so a copy from the wrong offset does
 * not accidentally reproduce it. */
static void buf_poison(struct buf *b)
{
	size_t i;
	for (i = 0; i < b->total; i++)
		b->base[i] = (unsigned char)(b->tag ^ (i * 31u) ^ 0xA5u);
}

static int buf_pad_intact(const struct buf *b, const char **where)
{
	size_t i;
	for (i = 0; i < b->total; i++) {
		if (i == PAD)
			i = PAD + b->len;
		if (i >= b->total)
			break;
		if (b->base[i] != (unsigned char)(b->tag ^ (i * 31u) ^ 0xA5u)) {
			*where = i < PAD ? "before" : "after";
			return 0;
		}
	}
	return 1;
}

/* ---- one comparison ---------------------------------------------------- */
static unsigned long fails;
static unsigned long checks;

static void fail(unsigned long run, const char *what, const char *detail)
{
	fprintf(stderr, "MISMATCH run %lu: %s: %s\n", run, what, detail);
	if (++fails >= 10) {
		fprintf(stderr, "too many mismatches, stopping\n");
		exit(1);
	}
}

static void cmp_ret(unsigned long run, const char *what, size_t a, size_t b)
{
	char d[160];
	checks++;
	if (a == b)
		return;
	snprintf(d, sizeof d,
		 "ret ref=%zu (0x%zx, isError=%u) rs=%zu (0x%zx, isError=%u)",
		 a, a, ERR_isError(a), b, b, ERR_isError(b));
	fail(run, what, d);
}

static void cmp_buf(unsigned long run, const char *what, const char *name,
		    const struct buf *a, const struct buf *b)
{
	char d[200];
	const char *where;
	size_t i;

	checks++;
	if (memcmp(a->base, b->base, a->total) != 0) {
		for (i = 0; i < a->total && a->base[i] == b->base[i]; i++)
			;
		snprintf(d, sizeof d,
			 "%s differs at byte %zd (relative to the usable start; "
			 "ref=0x%02x rs=0x%02x)",
			 name, (ptrdiff_t)i - PAD, a->base[i], b->base[i]);
		fail(run, what, d);
		return;
	}
	if (!buf_pad_intact(a, &where)) {
		snprintf(d, sizeof d, "%s: BOTH arms wrote the %s padding", name, where);
		fail(run, what, d);
	}
}

static void cmp_u32(unsigned long run, const char *what, const char *name,
		    unsigned a, unsigned b)
{
	char d[128];
	checks++;
	if (a == b)
		return;
	snprintf(d, sizeof d, "%s: ref=%u rs=%u", name, a, b);
	fail(run, what, d);
}

/* ---- sizes ------------------------------------------------------------- */
#define NCOUNT_N	(FSE_MAX_SYMBOL_VALUE + 1)
#define HW_N		(HUF_SYMBOLVALUE_MAX + 1)
#define RANK_N		(HUF_TABLELOG_MAX + 1)
#define HUF_WKSP_B	(HUF_READ_STATS_WORKSPACE_SIZE_U32 * sizeof(U32))
#define DT_B		FSE_DTABLE_SIZE(FSE_TABLELOG_ABSOLUTE_MAX)
#define BUILD_WKSP_B	FSE_BUILD_DTABLE_WKSP_SIZE(FSE_TABLELOG_ABSOLUTE_MAX, FSE_MAX_SYMBOL_VALUE)
#define DEC_WKSP_B	FSE_DECOMPRESS_WKSP_SIZE(FSE_TABLELOG_ABSOLUTE_MAX, FSE_MAX_SYMBOL_VALUE)
#define DST_B		4096
#define SRC_B		512

/* Per-arm working set. */
struct arm {
	struct buf ncount, hw, rank, hufwksp, dt, bwksp, dst, dwksp;
	unsigned maxSV, tableLog, nbSymbols, hufTableLog;
};

static void arm_init(struct arm *a, unsigned char tag)
{
	buf_init(&a->ncount,  NCOUNT_N * sizeof(short), tag ^ 0x01);
	buf_init(&a->hw,      HW_N,                     tag ^ 0x02);
	buf_init(&a->rank,    RANK_N * sizeof(U32),     tag ^ 0x03);
	buf_init(&a->hufwksp, HUF_WKSP_B,               tag ^ 0x04);
	buf_init(&a->dt,      DT_B,                     tag ^ 0x05);
	buf_init(&a->bwksp,   BUILD_WKSP_B,             tag ^ 0x06);
	buf_init(&a->dst,     DST_B,                    tag ^ 0x07);
	buf_init(&a->dwksp,   DEC_WKSP_B,               tag ^ 0x08);
}

/* Which buffers a case touches. Poisoning the others is not wrong, it is just
 * slow -- dt is 130KB and the two workspaces are 33KB each, so repoisoning all
 * of them twice per call made the soak memset-bound rather than decoder-bound.
 * Each case poisons exactly what it passes in. */
#define B_NCOUNT	0x01
#define B_HW		0x02
#define B_RANK		0x04
#define B_HUFWKSP	0x08
#define B_DT		0x10
#define B_BWKSP		0x20
#define B_DST		0x40
#define B_DWKSP		0x80

/* The tag differs per arm so that "both arms poisoned identically" is a
 * property we get by re-poisoning to the SAME tag before each call, not one
 * we inherit by accident. */
static void arm_poison(struct arm *a, unsigned char tag, unsigned mask)
{
	if (mask & B_NCOUNT)  { a->ncount.tag  = tag ^ 0x01; buf_poison(&a->ncount); }
	if (mask & B_HW)      { a->hw.tag      = tag ^ 0x02; buf_poison(&a->hw); }
	if (mask & B_RANK)    { a->rank.tag    = tag ^ 0x03; buf_poison(&a->rank); }
	if (mask & B_HUFWKSP) { a->hufwksp.tag = tag ^ 0x04; buf_poison(&a->hufwksp); }
	if (mask & B_DT)      { a->dt.tag      = tag ^ 0x05; buf_poison(&a->dt); }
	if (mask & B_BWKSP)   { a->bwksp.tag   = tag ^ 0x06; buf_poison(&a->bwksp); }
	if (mask & B_DST)     { a->dst.tag     = tag ^ 0x07; buf_poison(&a->dst); }
	if (mask & B_DWKSP)   { a->dwksp.tag   = tag ^ 0x08; buf_poison(&a->dwksp); }
	a->maxSV = a->tableLog = a->nbSymbols = a->hufTableLog = 0xDEADBEEF;
}

/* The five one-line wrappers above are dead in-tree -- nothing in the kernel
 * references them (see STATUS.md's nm table) -- but the port still has to
 * define them, so they still have to be right. They are pure functions of a
 * size_t, so they get swept exhaustively over the interesting range once at
 * startup rather than sampled per run. */
static void sweep_wrappers(void)
{
	size_t code;

	checks++;
	if (ref_FSE_versionNumber() != rs_FSE_versionNumber())
		fail(0, "FSE_versionNumber", "differs");

	/* lib/zstd/common/zstd_common.c is ported too. ZSTD_versionString is
	 * built by the C preprocessor stringifying three macros; the Rust
	 * spells it out, so comparing them here is what stops the two drifting
	 * when the kernel bumps its bundled zstd. */
	cmp_u32(0, "ZSTD_versionNumber", "ret",
		ref_ZSTD_versionNumber(), rs_ZSTD_versionNumber());
	checks++;
	{
		const char *a = ref_ZSTD_versionString();
		const char *b = rs_ZSTD_versionString();

		if (!a || !b || strcmp(a, b) != 0) {
			char d[160];
			snprintf(d, sizeof d, "ref=\"%s\" rs=\"%s\"",
				 a ? a : "(null)", b ? b : "(null)");
			fail(0, "ZSTD_versionString", d);
		}
	}

	/* The isError boundary is (size_t)-120: sweep both sides of it, and
	 * the wrap, rather than sampling. */
	for (code = 0; code <= 300; code++) {
		size_t v = (size_t)0 - code;
		const char *a, *b;

		cmp_u32(0, "ZSTD_isError", "ret",
			ref_ZSTD_isError(v), rs_ZSTD_isError(v));
		cmp_u32(0, "ZSTD_isError", "ret(small)",
			ref_ZSTD_isError(code), rs_ZSTD_isError(code));
		cmp_u32(0, "ZSTD_getErrorCode", "ret",
			(unsigned)ref_ZSTD_getErrorCode(v),
			(unsigned)rs_ZSTD_getErrorCode(v));
		cmp_u32(0, "ZSTD_getErrorCode", "ret(small)",
			(unsigned)ref_ZSTD_getErrorCode(code),
			(unsigned)rs_ZSTD_getErrorCode(code));

		a = ref_ZSTD_getErrorName(v);
		b = rs_ZSTD_getErrorName(v);
		checks++;
		if (!a || !b || strcmp(a, b) != 0)
			fail(0, "ZSTD_getErrorName", "differs");
		a = ref_ZSTD_getErrorString((int)code);
		b = rs_ZSTD_getErrorString((int)code);
		checks++;
		if (!a || !b || strcmp(a, b) != 0)
			fail(0, "ZSTD_getErrorString", "differs");
	}

	/* lib/zstd/common/error_private.c is ported too. Its one function is
	 * pure and total over the enum, so it is swept exhaustively over the
	 * whole defined range and well past it -- the C's `default` arm has to
	 * agree with the Rust's `_` arm for every value neither names. */
	for (code = 0; code <= 4096; code++) {
		int c = (int)code;
		const char *a = ref_ERR_getErrorString(c);
		const char *b = rs_ERR_getErrorString(c);

		checks++;
		if (!a || !b || strcmp(a, b) != 0) {
			char d[240];
			snprintf(d, sizeof d, "code %d: ref=\"%s\" rs=\"%s\"",
				 c, a ? a : "(null)", b ? b : "(null)");
			fail(0, "ERR_getErrorString", d);
		}
	}
	/* and the negative half, which ERR_getErrorCode can never produce but
	 * which the C signature admits */
	for (code = 1; code <= 4096; code++) {
		int c = -(int)code;
		const char *a = ref_ERR_getErrorString(c);
		const char *b = rs_ERR_getErrorString(c);

		checks++;
		if (!a || !b || strcmp(a, b) != 0) {
			char d[240];
			snprintf(d, sizeof d, "code %d: ref=\"%s\" rs=\"%s\"",
				 c, a ? a : "(null)", b ? b : "(null)");
			fail(0, "ERR_getErrorString", d);
		}
	}

	/* every error enum, plus the ordinary small returns either side of the
	 * isError boundary */
	for (code = 0; code <= 300; code++) {
		size_t v = (size_t)0 - code;
		const char *a, *b;

		cmp_u32(0, "FSE_isError", "ret", ref_FSE_isError(v), rs_FSE_isError(v));
		cmp_u32(0, "HUF_isError", "ret", ref_HUF_isError(v), rs_HUF_isError(v));
		cmp_u32(0, "FSE_isError", "ret(small)",
			ref_FSE_isError(code), rs_FSE_isError(code));

		a = ref_FSE_getErrorName(v);
		b = rs_FSE_getErrorName(v);
		checks++;
		if (!a || !b || strcmp(a, b) != 0) {
			char d[160];
			snprintf(d, sizeof d, "code -%zu: ref=\"%s\" rs=\"%s\"",
				 code, a ? a : "(null)", b ? b : "(null)");
			fail(0, "FSE_getErrorName", d);
		}
		a = ref_HUF_getErrorName(v);
		b = rs_HUF_getErrorName(v);
		checks++;
		if (!a || !b || strcmp(a, b) != 0) {
			char d[160];
			snprintf(d, sizeof d, "code -%zu: ref=\"%s\" rs=\"%s\"",
				 code, a ? a : "(null)", b ? b : "(null)");
			fail(0, "HUF_getErrorName", d);
		}
	}
}

/* ---- counters, so a clean run with implausible volume is visible ------- */
static unsigned long ok_ncount, ok_hufstats, ok_build, ok_decomp;
static unsigned long n_ncount, n_hufstats, n_build, n_decomp;
static unsigned long bmi2_split;

int main(int argc, char **argv)
{
	unsigned long runs = argc > 1 ? strtoul(argv[1], NULL, 0) : 20000;
	uint64_t seed = argc > 2 ? strtoull(argv[2], NULL, 0) : 20260904;
	struct arm A, B;
	unsigned char *src = malloc(SRC_B);
	short *saved_ncount = malloc(NCOUNT_N * sizeof(short));
	unsigned saved_maxSV = 0, saved_tableLog = 0;
	int have_saved = 0;
	unsigned long run;
	uint64_t s = seed ? seed : 1;

	if (!src || !saved_ncount)
		return 2;
	arm_init(&A, 0x10);
	arm_init(&B, 0x10);

	printf("runs=%lu seed=%llu\n", runs, (unsigned long long)seed);
	printf("DYNAMIC_BMI2=%d  MEM_LITTLE_ENDIAN=%d  sizeof(size_t)=%zu\n",
	       DYNAMIC_BMI2, MEM_LITTLE_ENDIAN, sizeof(size_t));

	sweep_wrappers();

	for (run = 1; run <= runs; run++) {
		int shape = (int)rng_below(&s, 3);
		int which = (int)rng_below(&s, 4);
		unsigned char tag = (unsigned char)rng_next(&s);
		size_t len;

		switch (which) {
		case 0: {	/* FSE_readNCount / _bmi2 */
			unsigned maxSV_in = rng_below(&s, FSE_MAX_SYMBOL_VALUE + 1);
			size_t ra[2], rb[2];
			int bmi2;

			len = gen_ncount(&s, src, SRC_B, shape);
			n_ncount++;

			for (bmi2 = 0; bmi2 < 2; bmi2++) {
				arm_poison(&A, tag, B_NCOUNT);
				arm_poison(&B, tag, B_NCOUNT);
				A.maxSV = B.maxSV = maxSV_in;
				ra[bmi2] = ref_FSE_readNCount_bmi2(
					(short *)A.ncount.p, &A.maxSV, &A.tableLog,
					src, len, bmi2);
				rb[bmi2] = rs_FSE_readNCount_bmi2(
					(short *)B.ncount.p, &B.maxSV, &B.tableLog,
					src, len, bmi2);
				cmp_ret(run, "FSE_readNCount_bmi2", ra[bmi2], rb[bmi2]);
				cmp_buf(run, "FSE_readNCount_bmi2", "normalizedCounter",
					&A.ncount, &B.ncount);
				cmp_u32(run, "FSE_readNCount_bmi2", "*maxSVPtr",
					A.maxSV, B.maxSV);
				cmp_u32(run, "FSE_readNCount_bmi2", "*tableLogPtr",
					A.tableLog, B.tableLog);
			}
			/* The two bodies differ only in instruction selection;
			 * they must agree with each other too. */
			if (ra[0] != ra[1] || rb[0] != rb[1]) {
				bmi2_split++;
				fail(run, "FSE_readNCount", "bmi2=0 and bmi2=1 disagree");
			}
			if (!ERR_isError(ra[0])) {
				ok_ncount++;
				/* A normalizedCounter that FSE_readNCount
				 * accepted is the only cheap source of input
				 * FSE_buildDTable can get past its checks:
				 * the counts sum to exactly 1<<tableLog. Keep
				 * the three together -- the triple is what is
				 * well-formed, not the array on its own. */
				memcpy(saved_ncount, A.ncount.p,
				       NCOUNT_N * sizeof(short));
				saved_maxSV = A.maxSV;
				saved_tableLog = A.tableLog;
				have_saved = 1;
			}
			/* the non-bmi2 public wrapper too */
			arm_poison(&A, tag, B_NCOUNT);
			arm_poison(&B, tag, B_NCOUNT);
			A.maxSV = B.maxSV = maxSV_in;
			cmp_ret(run, "FSE_readNCount",
				ref_FSE_readNCount((short *)A.ncount.p, &A.maxSV,
						   &A.tableLog, src, len),
				rs_FSE_readNCount((short *)B.ncount.p, &B.maxSV,
						  &B.tableLog, src, len));
			cmp_buf(run, "FSE_readNCount", "normalizedCounter",
				&A.ncount, &B.ncount);
			cmp_u32(run, "FSE_readNCount", "*maxSVPtr", A.maxSV, B.maxSV);
			cmp_u32(run, "FSE_readNCount", "*tableLogPtr",
				A.tableLog, B.tableLog);
			break;
		}
		case 1: {	/* HUF_readStats_wksp / HUF_readStats */
			/* shape 3 is the well-formed generator; it needs the
			 * full destination or oSize >= hwSize rejects it
			 * before a single weight is examined. */
			int hshape = (int)rng_below(&s, 4);
			size_t hwSize = hshape >= 3 ? HW_N : 1 + rng_below(&s, HW_N);
			size_t wkspSize = HUF_WKSP_B;
			size_t ra[2], rb[2];
			int f;

			/* sometimes starve the workspace, to reach the
			 * FSE_decompress_wksp size checks */
			if (rng_below(&s, 8) == 0)
				wkspSize = rng_below(&s, (uint32_t)HUF_WKSP_B);

			len = gen_hufstats(&s, src, SRC_B, hshape);
			n_hufstats++;

			for (f = 0; f < 2; f++) {
				int flags = f ? HUF_flags_bmi2 : 0;

				arm_poison(&A, tag, B_HW | B_RANK | B_HUFWKSP);
				arm_poison(&B, tag, B_HW | B_RANK | B_HUFWKSP);
				ra[f] = ref_HUF_readStats_wksp(
					A.hw.p, hwSize, (U32 *)A.rank.p,
					&A.nbSymbols, &A.hufTableLog, src, len,
					A.hufwksp.p, wkspSize, flags);
				rb[f] = rs_HUF_readStats_wksp(
					B.hw.p, hwSize, (U32 *)B.rank.p,
					&B.nbSymbols, &B.hufTableLog, src, len,
					B.hufwksp.p, wkspSize, flags);
				cmp_ret(run, "HUF_readStats_wksp", ra[f], rb[f]);
				cmp_buf(run, "HUF_readStats_wksp", "huffWeight",
					&A.hw, &B.hw);
				cmp_buf(run, "HUF_readStats_wksp", "rankStats",
					&A.rank, &B.rank);
				cmp_buf(run, "HUF_readStats_wksp", "workSpace",
					&A.hufwksp, &B.hufwksp);
				cmp_u32(run, "HUF_readStats_wksp", "*nbSymbolsPtr",
					A.nbSymbols, B.nbSymbols);
				cmp_u32(run, "HUF_readStats_wksp", "*tableLogPtr",
					A.hufTableLog, B.hufTableLog);
			}
			if (ra[0] != ra[1] || rb[0] != rb[1]) {
				bmi2_split++;
				fail(run, "HUF_readStats_wksp",
				     "flags=0 and flags=HUF_flags_bmi2 disagree");
			}
			if (!ERR_isError(ra[0]))
				ok_hufstats++;

			arm_poison(&A, tag, B_HW | B_RANK);
			arm_poison(&B, tag, B_HW | B_RANK);
			cmp_ret(run, "HUF_readStats",
				ref_HUF_readStats(A.hw.p, hwSize, (U32 *)A.rank.p,
						  &A.nbSymbols, &A.hufTableLog,
						  src, len),
				rs_HUF_readStats(B.hw.p, hwSize, (U32 *)B.rank.p,
						 &B.nbSymbols, &B.hufTableLog,
						 src, len));
			cmp_buf(run, "HUF_readStats", "huffWeight", &A.hw, &B.hw);
			cmp_buf(run, "HUF_readStats", "rankStats", &A.rank, &B.rank);
			cmp_u32(run, "HUF_readStats", "*nbSymbolsPtr",
				A.nbSymbols, B.nbSymbols);
			cmp_u32(run, "HUF_readStats", "*tableLogPtr",
				A.hufTableLog, B.hufTableLog);
			break;
		}
		case 2: {	/* FSE_buildDTable_wksp */
			unsigned maxSV, tableLog;
			size_t wkspSize = BUILD_WKSP_B;
			short *na, *nb;
			int probe;

			/* THE CONTRACT, and why this case is narrower than the
			 * others. FSE_buildDTable_wksp requires normalizedCounter
			 * to be a valid normalised distribution for
			 * (maxSymbolValue, tableLog) -- the thing FSE_readNCount
			 * produces. Feed it arbitrary counts and it does not
			 * return an error, it SEGFAULTS: highThreshold is a U32
			 * decremented once per lowprob (-1) symbol with nothing
			 * bounding it against the table size, so more than
			 * 1<<tableLog lowprob symbols wraps it and
			 * tableDecode[highThreshold--] writes far outside dt.
			 * That is a defect in the pristine C, it is recorded in
			 * STATUS.md as an upstream candidate, and it is NOT
			 * reachable in-tree -- so the harness stays inside the
			 * contract rather than pretending the crash is the
			 * port's fault.
			 *
			 * So: the counter always comes from a successful
			 * FSE_readNCount, and only the parameters the function
			 * genuinely validates get perturbed. */
			if (!have_saved)
				break;
			n_build++;

			arm_poison(&A, tag, B_NCOUNT | B_DT | B_BWKSP);
			arm_poison(&B, tag, B_NCOUNT | B_DT | B_BWKSP);
			na = (short *)A.ncount.p;
			nb = (short *)B.ncount.p;
			memcpy(na, saved_ncount, NCOUNT_N * sizeof(short));
			memcpy(nb, saved_ncount, NCOUNT_N * sizeof(short));
			maxSV = saved_maxSV;
			tableLog = saved_tableLog;

			/* the three checks the function documents */
			probe = (int)rng_below(&s, 8);
			if (probe == 1)
				wkspSize = rng_below(&s, (uint32_t)BUILD_WKSP_B);
			else if (probe == 2)
				maxSV = FSE_MAX_SYMBOL_VALUE + 1 + rng_below(&s, 4096);
			else if (probe == 3)
				tableLog = FSE_MAX_TABLELOG + 1 + rng_below(&s, 16);

			{
				size_t r = ref_FSE_buildDTable_wksp(
					(FSE_DTable *)A.dt.p, na, maxSV,
					tableLog, A.bwksp.p, wkspSize);
				size_t t = rs_FSE_buildDTable_wksp(
					(FSE_DTable *)B.dt.p, nb, maxSV,
					tableLog, B.bwksp.p, wkspSize);
				cmp_ret(run, "FSE_buildDTable_wksp", r, t);
				if (!ERR_isError(r))
					ok_build++;
			}
			cmp_buf(run, "FSE_buildDTable_wksp", "dt", &A.dt, &B.dt);
			cmp_buf(run, "FSE_buildDTable_wksp", "workSpace",
				&A.bwksp, &B.bwksp);
			cmp_buf(run, "FSE_buildDTable_wksp", "normalizedCounter",
				&A.ncount, &B.ncount);
			break;
		}
		default: {	/* FSE_decompress_wksp_bmi2 */
			size_t dstCap = rng_below(&s, DST_B + 1);
			size_t wkspSize = DEC_WKSP_B;
			unsigned maxLog = rng_below(&s, 17);
			size_t ra[2], rb[2];
			int bmi2;

			if (rng_below(&s, 8) == 0)
				wkspSize = rng_below(&s, (uint32_t)DEC_WKSP_B);

			len = gen_fseblock(&s, src, SRC_B, shape);
			n_decomp++;

			for (bmi2 = 0; bmi2 < 2; bmi2++) {
				arm_poison(&A, tag, B_DST | B_DWKSP);
				arm_poison(&B, tag, B_DST | B_DWKSP);
				ra[bmi2] = ref_FSE_decompress_wksp_bmi2(
					A.dst.p, dstCap, src, len, maxLog,
					A.dwksp.p, wkspSize, bmi2);
				rb[bmi2] = rs_FSE_decompress_wksp_bmi2(
					B.dst.p, dstCap, src, len, maxLog,
					B.dwksp.p, wkspSize, bmi2);
				cmp_ret(run, "FSE_decompress_wksp_bmi2",
					ra[bmi2], rb[bmi2]);
				cmp_buf(run, "FSE_decompress_wksp_bmi2", "dst",
					&A.dst, &B.dst);
				cmp_buf(run, "FSE_decompress_wksp_bmi2", "workSpace",
					&A.dwksp, &B.dwksp);
			}
			if (ra[0] != ra[1] || rb[0] != rb[1]) {
				bmi2_split++;
				fail(run, "FSE_decompress_wksp_bmi2",
				     "bmi2=0 and bmi2=1 disagree");
			}
			if (!ERR_isError(ra[0]))
				ok_decomp++;
			break;
		}
		}
	}

	printf("\n%-28s %10s %10s\n", "case", "runs", "succeeded");
	printf("%-28s %10lu %10lu\n", "FSE_readNCount",        n_ncount,   ok_ncount);
	printf("%-28s %10lu %10lu\n", "HUF_readStats",         n_hufstats, ok_hufstats);
	printf("%-28s %10lu %10lu\n", "FSE_buildDTable_wksp",  n_build,    ok_build);
	printf("%-28s %10lu %10lu\n", "FSE_decompress_wksp",   n_decomp,   ok_decomp);
	printf("\ncomparisons: %lu   mismatches: %lu   bmi2 splits: %lu\n",
	       checks, fails, bmi2_split);

	/* STATUS.md lesson 9: a clean result with an implausible volume has not
	 * checked anything. These floors are deliberately low -- they catch a
	 * corpus that stopped reaching the decoder at all, not a corpus that
	 * merely got less productive. */
	if (runs >= 2000) {
		if (!ok_ncount || !ok_hufstats || !ok_build || !ok_decomp) {
			fprintf(stderr,
				"\nCORPUS FAILURE: a case never once succeeded; "
				"the run proves nothing about the success paths\n");
			return 3;
		}
	}
	return fails ? 1 : 0;
}
