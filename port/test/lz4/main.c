/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Differential test for lib/lz4/lz4_decompress.c -> lz4_decompress_rs.rs.
 *
 * Two arms in one binary. The only difference between them is which
 * implementation is called; the corpus and the encoder are shared, and the
 * encoder is the one the kernel ships beside this decoder
 * (lib/lz4/lz4_compress.c) rather than a system liblz4.
 *
 * FOUR STAGES, because LZ4_decompress_generic() has eight instantiations and
 * three of the six directives are only reachable through the streaming API:
 *
 *   block     LZ4_decompress_safe, _safe_partial and _fast on standalone
 *             blocks. Covers noDict with and without partialDecoding, and
 *             withPrefix64k via the fast path.
 *   dict      LZ4_decompress_safe_usingDict with an external dictionary --
 *             the usingExtDict directive, which nothing else reaches.
 *   stream    LZ4_decompress_safe_continue over a ring buffer, which walks
 *             all three of prefix / small-prefix / double-dict as the ring
 *             wraps. Each arm keeps its own ring and its own state, and both
 *             are compared after every block.
 *   corrupt   bit-flipped streams through _safe only. NOT through _fast:
 *             that one has no input bound by design, so a corrupt stream
 *             reads wild memory in BOTH arms and the comparison would be
 *             between two undefined behaviours.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/lz4.h>
#include "lz4defs.h"

/* READ BACK, NOT ASSUMED. lz4defs.h picks its word size and byte order from
 * these, and getting either wrong compiles a different program than the kernel
 * does -- which is how this harness spent its first hour. */
_Static_assert(LZ4_ARCH64 == (sizeof(void *) == 8),
	       "the oracle's word size disagrees with the host's");
/* Was `LZ4_LITTLE_ENDIAN == 1`, which pinned this harness to x86-64 and is one
 * of the reasons nothing in this tree had ever run big-endian. The fact worth
 * asserting is that the oracle agrees with the HOST -- a shim that mis-derives
 * byte order makes BOTH arms compile the same wrong paths, which no
 * differential can see. See port/test/common/run-be.sh. */
_Static_assert(LZ4_LITTLE_ENDIAN ==
	       (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__),
	       "the oracle's byte order disagrees with the host's");

/* The oracle -- pristine C, renamed. */
int ref_LZ4_decompress_safe(const char *s, char *d, int cs, int ds);
int ref_LZ4_decompress_safe_partial(const char *s, char *d, int cs, int t, int c);
int ref_LZ4_decompress_fast(const char *s, char *d, int os);
int ref_LZ4_setStreamDecode(LZ4_streamDecode_t *sd, const char *dict, int n);
int ref_LZ4_decompress_safe_continue(LZ4_streamDecode_t *sd, const char *s,
				     char *d, int cs, int ms);
int ref_LZ4_decompress_fast_continue(LZ4_streamDecode_t *sd, const char *s,
				     char *d, int os);
int ref_LZ4_decompress_safe_usingDict(const char *s, char *d, int cs, int ms,
				      const char *ds, int dn);
int ref_LZ4_decompress_fast_usingDict(const char *s, char *d, int os,
				      const char *ds, int dn);

/* The port. */
int rust_LZ4_decompress_safe(const char *s, char *d, int cs, int ds);
int rust_LZ4_decompress_safe_partial(const char *s, char *d, int cs, int t, int c);
int rust_LZ4_decompress_fast(const char *s, char *d, int os);
int rust_LZ4_setStreamDecode(LZ4_streamDecode_t *sd, const char *dict, int n);
int rust_LZ4_decompress_safe_continue(LZ4_streamDecode_t *sd, const char *s,
				      char *d, int cs, int ms);
int rust_LZ4_decompress_fast_continue(LZ4_streamDecode_t *sd, const char *s,
				      char *d, int os);
int rust_LZ4_decompress_safe_usingDict(const char *s, char *d, int cs, int ms,
				       const char *ds, int dn);
int rust_LZ4_decompress_fast_usingDict(const char *s, char *d, int os,
				       const char *ds, int dn);

extern void lz4_rs_abi(uint64_t *out);

/* port/test/lz4/sysenc.c -- see the header comment there for why the corpus
   encoder is liblz4 and not lib/lz4/lz4_compress.c. */
int sys_lz4_compress(const char *src, char *dst, int n, int cap);

/* --------------------------------------------------------------------- */

static uint64_t rng_s;
static uint32_t rnd(void)
{
	rng_s ^= rng_s << 13;
	rng_s ^= rng_s >> 7;
	rng_s ^= rng_s << 17;
	return (uint32_t)(rng_s >> 32);
}
static uint32_t rnd_n(uint32_t n) { return n ? rnd() % n : 0; }

static unsigned long long fails;

static void fail(const char *what, const char *detail)
{
	printf("MISMATCH  %s  %s\n", what, detail);
	fails++;
}

/* A corpus with real LZ4 structure: literal runs, long matches, short
   offsets, incompressible stretches. Uniform random data compresses to
   nothing but literals and reaches none of the match paths.

   THE FIRST VERSION OF THIS FUNCTION WROTE PAST ITS BUFFER, and the way it
   showed up is worth keeping: `k = cap - n` could be 0 and the loop was
   `while (k--)` on an unsigned, so it wrapped and ran 2^64 times. The
   symptoms were "malloc(): corrupted top size", then a decompressor
   rejecting its own encoder's output, then a segfault -- three different
   faces of one off-by-one, none of them anywhere near the port. Both arms
   agreed on every one of them, which is what said the harness was wrong
   rather than the Rust: a differential cannot notice that the QUESTION is
   malformed. Every loop below is now bounded by a computed count. */
static unsigned long gen(unsigned char *b, unsigned long cap)
{
	unsigned long n = 0;
	int kind = (int)rnd_n(4);

	while (n < cap) {
		unsigned long room = cap - n;
		unsigned long k, j;

		switch (kind) {
		case 0:					/* incompressible */
			k = 1 + rnd_n(64);
			if (k > room)
				k = room;
			for (j = 0; j < k; j++)
				b[n + j] = (unsigned char)rnd();
			n += k;
			break;
		case 1: {				/* long runs */
			unsigned char c = (unsigned char)rnd();

			k = 1 + rnd_n(200);
			if (k > room)
				k = room;
			for (j = 0; j < k; j++)
				b[n + j] = c;
			n += k;
			break;
		}
		case 2:					/* short alphabet */
			k = 1 + rnd_n(300);
			if (k > room)
				k = room;
			for (j = 0; j < k; j++)
				b[n + j] = (unsigned char)('a' + rnd_n(4));
			n += k;
			break;
		default:				/* back-references */
			if (n > 8) {
				unsigned long off = 1 + rnd_n((uint32_t)(n > 4096 ? 4096 : n));

				k = 1 + rnd_n(300);
				if (k > room)
					k = room;
				for (j = 0; j < k; j++) {
					b[n] = b[n - off];
					n++;
				}
			} else {
				b[n++] = (unsigned char)rnd();
			}
			break;
		}
		if (rnd_n(8) == 0)
			kind = (int)rnd_n(4);
	}
	return n;
}

#define ABI_SLOTS 5

static int abi_check(void)
{
	uint64_t got[ABI_SLOTS], want[ABI_SLOTS];
	static const char *const names[ABI_SLOTS] = {
		"sizeof(internal)", "externalDict", "extDictSize",
		"prefixEnd", "prefixSize",
	};
	int i, bad = 0;

	want[0] = sizeof(LZ4_streamDecode_t_internal);
	want[1] = offsetof(LZ4_streamDecode_t_internal, externalDict);
	want[2] = offsetof(LZ4_streamDecode_t_internal, extDictSize);
	want[3] = offsetof(LZ4_streamDecode_t_internal, prefixEnd);
	want[4] = offsetof(LZ4_streamDecode_t_internal, prefixSize);

	lz4_rs_abi(got);
	for (i = 0; i < ABI_SLOTS; i++)
		if (got[i] != want[i]) {
			printf("  ABI MISMATCH %-18s rust %3llu  C %3llu\n", names[i],
			       (unsigned long long)got[i], (unsigned long long)want[i]);
			bad = 1;
		}
	printf("  ABI: %d offsets of LZ4_streamDecode_t_internal against\n"
	       "       offsetof() on include/linux/lz4.h, %s\n", ABI_SLOTS,
	       bad ? "MISMATCHED" : "all agree");
	return bad;
}

#define PMAX  (96 * 1024)
#define CMAX  (PMAX + PMAX / 255 + 64)
#define SLACK (64 * 1024)
#define BLK   (4 * 1024)

int main(int argc, char **argv)
{
	unsigned long long runs = argc > 1 ? strtoull(argv[1], NULL, 0) : 20000;
	unsigned long long seed = argc > 2 ? strtoull(argv[2], NULL, 0) : 20260903;
	unsigned long long i, blocks = 0, plain_bytes = 0, corrupt_runs = 0;
	static unsigned char plain[PMAX], comp[CMAX];
	static unsigned char oa[SLACK + PMAX + 64], ob[SLACK + PMAX + 64];
	unsigned char *da = oa + SLACK, *db = ob + SLACK;

	setvbuf(stdout, NULL, _IONBF, 0);
	rng_s = seed ? seed : 1;
	printf("lz4_decompress differential: %llu runs, seed %llu\n", runs, seed);
	printf("  oracle built with LZ4_ARCH64=%d LZ4_LITTLE_ENDIAN=%d "
	       "sizeof(void *)=%zu\n", LZ4_ARCH64, LZ4_LITTLE_ENDIAN,
	       sizeof(void *));
	if (abi_check())
		return 2;


	for (i = 0; i < runs; i++) {
		unsigned long n, cl;
		int ra_, rb_, outcap;
		char detail[160];

		n = 1 + rnd_n(PMAX - 1);
		n = gen(plain, n);
		cl = (unsigned long)sys_lz4_compress((const char *)plain,
						     (char *)comp, (int)n,
						     sizeof(comp));
		if (cl == 0)
			continue;
		plain_bytes += n;

		/* ---- encoder sanity, before anything else touches memory ---- */
		{
			static unsigned char sc[8192], sp[8192];
			int sl = (int)(1 + rnd_n(4000));
			int scl, sd;

			if ((unsigned long)sl > n)
				sl = (int)n;
			scl = sys_lz4_compress((const char *)plain, (char *)sc,
					       sl, (int)sizeof(sc));
			sd = ref_LZ4_decompress_safe((const char *)sc, (char *)sp,
						     scl, (int)sizeof(sp));
			if (scl <= 0 || sd != sl ||
			    memcmp(sp, plain, (size_t)sl) != 0) {
				snprintf(detail, sizeof(detail),
					 "sl=%d scl=%d sd=%d", sl, scl, sd);
				fail("ENCODER round trip (nothing to do with the port)",
				     detail);
				break;
			}
		}

		/* ---- safe ----
		 * THE OUTPUT CAPACITY IS AN AXIS. A generous buffer puts `oend`
		 * far past where decoding ends, so the format's LASTLITERALS
		 * reserve -- the last five bytes must be literals -- is never
		 * approached and the check that enforces it is unreachable. A
		 * sabotage of that check survived the whole suite until this
		 * varied. Real callers (squashfs, erofs, zram) pass the exact
		 * size, so the exact size is the common case here too. */
		outcap = (rnd_n(4) == 0) ? PMAX : (int)n;

		memset(oa, 0xAA, sizeof(oa));
		memset(ob, 0x55, sizeof(ob));
		ra_ = ref_LZ4_decompress_safe((const char *)comp, (char *)da,
					      (int)cl, outcap);
		rb_ = rust_LZ4_decompress_safe((const char *)comp, (char *)db,
					       (int)cl, outcap);
		snprintf(detail, sizeof(detail), "safe n=%lu cl=%lu ref=%d rs=%d",
			 n, cl, ra_, rb_);
		if (ra_ != rb_)
			fail("return value", detail);
		else if (ra_ > 0 && memcmp(da, db, (size_t)ra_) != 0)
			fail("output", detail);
		else if (ra_ != (int)n)
			fail("round trip", detail);

		/* ---- safe_partial ---- */
		{
			int target = (int)rnd_n((uint32_t)n + 1);

			memset(oa, 0xAA, sizeof(oa));
			memset(ob, 0x55, sizeof(ob));
			ra_ = ref_LZ4_decompress_safe_partial((const char *)comp,
					(char *)da, (int)cl, target, PMAX);
			rb_ = rust_LZ4_decompress_safe_partial((const char *)comp,
					(char *)db, (int)cl, target, PMAX);
			snprintf(detail, sizeof(detail),
				 "partial n=%lu target=%d ref=%d rs=%d",
				 n, target, ra_, rb_);
			if (ra_ != rb_)
				fail("partial return value", detail);
			else if (ra_ > 0 && memcmp(da, db, (size_t)ra_) != 0)
				fail("partial output", detail);
		}

		/* ---- fast ---- valid streams only; it has no input bound. */
		memset(oa, 0xAA, sizeof(oa));
		memset(ob, 0x55, sizeof(ob));
		ra_ = ref_LZ4_decompress_fast((const char *)comp, (char *)da, (int)n);
		rb_ = rust_LZ4_decompress_fast((const char *)comp, (char *)db, (int)n);
		snprintf(detail, sizeof(detail), "fast n=%lu ref=%d rs=%d", n, ra_, rb_);
		if (ra_ != rb_)
			fail("fast return value", detail);
		else if (memcmp(da, db, n) != 0)
			fail("fast output", detail);
		else if (ra_ != (int)cl)
			fail("fast consumed the wrong length", detail);

		/* ---- usingDict: the usingExtDict directive ---- */
		if (n > 64) {
			unsigned long dn = 1 + rnd_n(4096);
			static unsigned char dict[8192];
			unsigned long dl;

			if (dn > sizeof(dict))
				dn = sizeof(dict);
			for (dl = 0; dl < dn; dl++)
				dict[dl] = plain[dl % n];

			cl = (unsigned long)sys_lz4_compress((const char *)plain,
					(char *)comp, (int)n, sizeof(comp));
			memset(oa, 0xAA, sizeof(oa));
			memset(ob, 0x55, sizeof(ob));
			ra_ = ref_LZ4_decompress_safe_usingDict((const char *)comp,
					(char *)da, (int)cl, PMAX,
					(const char *)dict, (int)dn);
			rb_ = rust_LZ4_decompress_safe_usingDict((const char *)comp,
					(char *)db, (int)cl, PMAX,
					(const char *)dict, (int)dn);
			snprintf(detail, sizeof(detail),
				 "usingDict n=%lu dn=%lu ref=%d rs=%d",
				 n, dn, ra_, rb_);
			if (ra_ != rb_)
				fail("usingDict return value", detail);
			else if (ra_ > 0 && memcmp(da, db, (size_t)ra_) != 0)
				fail("usingDict output", detail);
		}

		/* ---- corrupt: safe only ---- */
		if (cl > 8 && rnd_n(3) == 0) {
			static unsigned char bad_[CMAX];
			int flips = 1 + (int)rnd_n(3);

			memcpy(bad_, comp, cl);
			while (flips--)
				bad_[rnd_n((uint32_t)cl)] ^= (unsigned char)(1u << rnd_n(8));

			memset(oa, 0xAA, sizeof(oa));
			memset(ob, 0x55, sizeof(ob));
			ra_ = ref_LZ4_decompress_safe((const char *)bad_, (char *)da,
						      (int)cl, outcap);
			rb_ = rust_LZ4_decompress_safe((const char *)bad_, (char *)db,
						       (int)cl, outcap);
			snprintf(detail, sizeof(detail),
				 "corrupt cl=%lu ref=%d rs=%d", cl, ra_, rb_);
			if (ra_ != rb_)
				fail("corrupt return value", detail);
			else if (ra_ > 0 && memcmp(da, db, (size_t)ra_) != 0)
				fail("corrupt output", detail);
			corrupt_runs++;
		}

		/* ---- stream: LZ4_decompress_safe_continue over consecutive
		 * blocks ----
		 *
		 * THE BLOCKS ARE COMPRESSED INDEPENDENTLY, with
		 * LZ4_compress_default, not with LZ4_compress_fast_continue.
		 * That is deliberate. What is under test is the DECODER's
		 * streaming dispatch -- withPrefix64k once prefixSize passes
		 * 64 KiB, withSmallPrefix below it, doubleDict once an external
		 * dictionary exists -- and that dispatch depends only on the
		 * decoder's own state, not on how the block was encoded.
		 * Independent blocks decode correctly under any of the three.
		 *
		 * Driving the streaming ENCODER as well was tried and abandoned:
		 * 6.18's LZ4_compress_fast_continue() lacks upstream's
		 *     if ((dictSize-1 < 4-1) && (dictEnd != source)) {
		 *             dictSize = 0; dictionary = source; }
		 * so a zeroed stream's first block is compressed in external-
		 * dictionary mode against a NULL dictionary. Not reachable in
		 * the kernel -- the only in-tree caller,
		 * drivers/block/zram/backend_lz4.c:82, calls LZ4_loadDict()
		 * first -- and not this port's problem either way, since
		 * lz4_compress.c is not ported. Noted in STATUS.md.
		 */
		{
			LZ4_streamDecode_t sda, sdb;
			unsigned long pos = 0;
			int nb = 1 + (int)rnd_n(24);
			int b;

			memset(&sda, 0, sizeof(sda));
			memset(&sdb, 0, sizeof(sdb));
			memset(oa, 0xAA, sizeof(oa));
			memset(ob, 0x55, sizeof(ob));

			for (b = 0; b < nb; b++) {
				int bl = (int)(1 + rnd_n(BLK - 1));
				int cbl;

				if (pos + (unsigned long)bl > n)
					bl = (int)(n - pos);
				if (bl <= 0)
					break;

				cbl = sys_lz4_compress(
						(const char *)plain + pos,
						(char *)comp, bl,
						(int)sizeof(comp));
				if (cbl <= 0)
					break;
				ra_ = ref_LZ4_decompress_safe_continue(&sda,
						(const char *)comp,
						(char *)(da + pos), cbl, bl);
				rb_ = rust_LZ4_decompress_safe_continue(&sdb,
						(const char *)comp,
						(char *)(db + pos), cbl, bl);
				snprintf(detail, sizeof(detail),
					 "stream block=%d bl=%d pos=%lu ref=%d rs=%d",
					 b, bl, pos, ra_, rb_);
				if (ra_ != rb_) {
					fail("stream return value", detail);
					break;
				}
				if (ra_ > 0 &&
				    memcmp(da + pos, db + pos, (size_t)ra_) != 0) {
					fail("stream output", detail);
					break;
				}
				if (ra_ > 0 &&
				    memcmp(da + pos, plain + pos, (size_t)ra_) != 0) {
					fail("stream round trip", detail);
					break;
				}
				if (sda.internal_donotuse.prefixSize !=
					sdb.internal_donotuse.prefixSize ||
				    sda.internal_donotuse.extDictSize !=
					sdb.internal_donotuse.extDictSize) {
					fail("stream state", detail);
					break;
				}
				pos += (unsigned long)bl;
				blocks++;
			}
		}

		if (fails > 6)
			break;
	}

	printf("\n");
	printf("  runs       %llu, %llu plaintext bytes per arm\n", i, plain_bytes);
	printf("  stages     safe, safe_partial, fast, usingDict, corrupt (%llu), "
	       "stream (%llu blocks)\n", corrupt_runs, blocks);
	printf("\n");
	if (fails) {
		printf("FAILED -- %llu mismatches\n", fails);
		return 1;
	}
	printf("OK -- 0 mismatches\n");
	return 0;
}
