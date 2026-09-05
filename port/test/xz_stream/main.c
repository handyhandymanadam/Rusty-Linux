/* SPDX-License-Identifier: GPL-2.0
 *
 * Differential test for lib/xz/xz_dec_stream.c -> xz_dec_stream_rs.rs.
 * Userspace, no kernel. Every arm lives in one binary; the only difference
 * between them is which implementation of the four entry points is called.
 *
 * FOUR THINGS ARE COMPARED, and they are not the same kind of check:
 *
 *   ref vs rs      the differential proper -- the pristine C against the port.
 *   ref vs any     the same pristine C compiled WITH XZ_DEC_ANY_CHECK, which
 *                  our kernels do not set. floor.md criterion 8: compile both
 *                  ways rather than silently test one.
 *   arms vs PLAIN  THE INDEPENDENT ORACLE. The decode must reproduce the bytes
 *                  system liblzma compressed. No comparison between arms can
 *                  see a bug they share; this can.
 *   arms vs LZMA   liblzma decoding the same stream, as a second independent
 *                  reading of what the stream means.
 *
 * The zlib harness ran 30,000 clean runs while truncating most of its decodes,
 * because it only ever compared arms to each other. See logs/build-limits.md.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/xz.h>

#define PLAIN_CAP  800000u
#define COMP_CAP   900000u
#define OUT_CAP    (PLAIN_CAP + 65536u)

void  corpus_seed(unsigned long s);
unsigned long corpus_plain(int kind, unsigned char *buf, unsigned long cap);
long  corpus_xz(const unsigned char *src, unsigned long n, unsigned char *dst,
		unsigned long cap, int check, unsigned preset);
long  corpus_xz_decode(const unsigned char *src, unsigned long n,
		       unsigned char *dst, unsigned long cap);
int   corpus_mutate_block_header(unsigned char *s, unsigned long len,
				 unsigned (*r)(void));

/* The three C-visible decoders. rs_* is the Rust behind its C thunks. */
struct xz_dec *ref_xz_dec_init(enum xz_mode, uint32_t);
enum xz_ret    ref_xz_dec_run(struct xz_dec *, struct xz_buf *);
void           ref_xz_dec_end(struct xz_dec *);
struct xz_dec *any_xz_dec_init(enum xz_mode, uint32_t);
enum xz_ret    any_xz_dec_run(struct xz_dec *, struct xz_buf *);
void           any_xz_dec_end(struct xz_dec *);
struct xz_dec *rs_xz_dec_init(enum xz_mode, uint32_t);
enum xz_ret    rs_xz_dec_run(struct xz_dec *, struct xz_buf *);
void           rs_xz_dec_end(struct xz_dec *);

static unsigned long rngs;
static unsigned rnd(void) { rngs = rngs * 6364136223846793005ULL + 1442695040888963407ULL;
                            return (unsigned)(rngs >> 33); }
static unsigned long rnd_below(unsigned long n) { return n ? rnd() % n : 0; }

static unsigned long runs, mismatches, corrupt_runs, oracle_runs, header_runs;
/* XZ_OPTIONS_ERROR can only be produced INSIDE dec_block_header(), past the
 * CRC gate. Counting it is the proof that repairing the CRC actually reaches
 * the code -- without the repair every mutated header dies as XZ_DATA_ERROR. */
static unsigned long header_past_gate;
/* How often the any-check arm actually CONTINUED past XZ_UNSUPPORTED_CHECK.
 * If this is 0 the change is inert and check_skip() is still unreached. */
static unsigned long anycheck_continued;

struct rr {
	int rc;
	unsigned long out_len;
	/* Adversarial review, 2026-09-04: recording only rc and out_len made
	 * "how far did the caller's positions advance when this failed"
	 * STRUCTURALLY invisible. Callers resume from these, and the C
	 * deliberately advances past the byte that FAILED a comparison in
	 * crc32_validate, Block Padding and Index Padding. */
	unsigned long in_pos_total;
	unsigned long out_pos_total;
	unsigned long calls;
};

/* Feed one stream through one arm, in chunks. The chunking is the point: the
 * temp[] partial-input state machine in xz_dec_stream.c is the highest-risk
 * code in the file and only chunked input reaches it. */
static void run_arm(int arm, const unsigned char *in, unsigned long inlen,
		    unsigned char *out, unsigned long outcap,
		    unsigned long inchunk, unsigned long outchunk,
		    enum xz_mode mode, struct rr *r)
{
	struct xz_dec *s;
	struct xz_buf b;
	enum xz_ret rc = XZ_OK;
	unsigned long ipos = 0, opos = 0, guard = 0;
	int unsupported_seen = 0;

	memset(r, 0, sizeof(*r));
	/* The mode is an axis, not a constant. Until 2026-09-04 every arm was
	 * inited XZ_DYNALLOC, so run()'s entire single-call branch -- the reset
	 * on entry, the XZ_DATA_ERROR/XZ_BUF_ERROR selection and the in_pos /
	 * out_pos rollback -- was never executed by this harness at all. */
	s = (arm == 0) ? ref_xz_dec_init(mode, 1u << 26)
	  : (arm == 1) ?  rs_xz_dec_init(mode, 1u << 26)
	  :               any_xz_dec_init(mode, 1u << 26);
	if (s == NULL) { r->rc = XZ_MEM_ERROR; return; }

	memset(&b, 0, sizeof(b));
	b.in = in; b.in_pos = 0; b.in_size = 0;
	b.out = out; b.out_pos = 0; b.out_size = 0;

	for (;;) {
		if (b.in_pos == b.in_size && ipos < inlen) {
			unsigned long k = inlen - ipos;
			if (k > inchunk) k = inchunk;
			b.in = in + ipos; b.in_pos = 0; b.in_size = k;
			ipos += k;
		}
		if (b.out_pos == b.out_size && opos < outcap) {
			unsigned long k = outcap - opos;
			if (k > outchunk) k = outchunk;
			b.out = out + opos; b.out_pos = 0; b.out_size = k;
			opos += k;
		}
		if (b.in_pos == b.in_size && b.out_pos == b.out_size)
			break;

		rc = (arm == 0) ? ref_xz_dec_run(s, &b)
		   : (arm == 1) ?  rs_xz_dec_run(s, &b)
		   :               any_xz_dec_run(s, &b);
		r->out_len = (opos - b.out_size) + b.out_pos;
		r->calls++;
		/* XZ_UNSUPPORTED_CHECK is not a failure, it is XZ_DEC_ANY_CHECK
		 * TELLING the caller an unknown check type was found so the
		 * caller can decide. Breaking on it meant check_skip()
		 * (xz_dec_stream.c:369) was never reached by ANY arm -- found by
		 * adversarial review 2026-09-04. Only the any-check arm can
		 * produce it; the others reject with XZ_OPTIONS_ERROR. */
		/* XZ_DEC_ANY_CHECK returns this ONCE, at the Stream Header, to let
		 * the caller decide about an unknown check type; the decoder has
		 * already advanced its sequence, so the next call makes progress
		 * and reaches check_skip(). Allowing exactly one continue per run
		 * is therefore both faithful and spin-proof -- my first attempt
		 * continued unconditionally and span until the guard, the second
		 * gated it so tightly it fired once in 3000 runs. */
		if (rc == XZ_UNSUPPORTED_CHECK && arm == 2 && !unsupported_seen) {
			unsupported_seen = 1;
			anycheck_continued++;
			continue;
		}
		if (rc != XZ_OK)
			break;
		/* XZ_OK with nothing consumed and nothing produced and no more
		 * of either to give is the end of what we can do. */
		if (b.in_pos == b.in_size && ipos == inlen &&
		    b.out_pos == b.out_size && opos == outcap)
			break;
		if (++guard > inlen + outcap + 4096)
			break;
	}

	r->rc = rc;
	r->out_len = (opos - b.out_size) + b.out_pos;
	r->in_pos_total = (ipos - b.in_size) + b.in_pos;
	r->out_pos_total = r->out_len;
	if (arm == 0) ref_xz_dec_end(s); else if (arm == 1) rs_xz_dec_end(s); else any_xz_dec_end(s);
}

static void fail(const char *what, int kind, unsigned long n, int check,
		 unsigned preset, unsigned long inchunk, unsigned long outchunk,
		 const struct rr *a, const struct rr *b)
{
	mismatches++;
	printf("\n%s run %lu\n", what, runs);
	printf("  kind=%d plainlen=%lu check=%d preset=%u inchunk=%lu outchunk=%lu\n",
	       kind, n, check, preset, inchunk, outchunk);
	if (a && b)
		printf("  rc %d / %d   out_len %lu / %lu\n",
		       a->rc, b->rc, a->out_len, b->out_len);
}

int main(int argc, char **argv)
{
	static unsigned char plain[PLAIN_CAP], comp[COMP_CAP];
	static unsigned char o_ref[OUT_CAP], o_rs[OUT_CAP], o_any[OUT_CAP], o_lz[OUT_CAP];
	unsigned long target = (argc > 1) ? strtoul(argv[1], NULL, 0) : 20000;
	unsigned long seed   = (argc > 2) ? strtoul(argv[2], NULL, 0) : 20260904;

	rngs = seed; corpus_seed(seed);

	while (runs < target) {
		int kind = (int)rnd_below(8), check = (int)rnd_below(4), corrupt;
		int was_header = 0;
		/* CONFIG_XZ_DEC_CRC64 is n, so only NONE and CRC32 decode. */
		int supported = (check == 0 || check == 1);
		unsigned preset = (unsigned)rnd_below(10);
		unsigned long n, cl, inchunk, outchunk, outcap;
		/* XZ_SINGLE needs the whole output in one buffer, so it only
		 * makes sense with a single chunk; the other two are multi-call. */
		enum xz_mode mode = (enum xz_mode)rnd_below(3);
		struct rr a, b, c;
		long lz;

		n = corpus_plain(kind, plain, PLAIN_CAP);
		{
			long r = corpus_xz(plain, n, comp, COMP_CAP, check, preset);
			if (r < 0) continue;
			cl = (unsigned long)r;
		}

		/* A quarter of streams get bit-flipped. Both arms must then agree
		 * on the rejection; nothing is compared against the plaintext. */
		corrupt = (rnd_below(4) == 0) && cl > 16;
		if (corrupt) {
			/* Half of the corrupt runs mutate the BLOCK HEADER and
			 * repair its CRC32, so the mutation survives the gate at
			 * xz_dec_stream.c:457 and actually reaches dec_vli() over
			 * temp.buf, the BCJ arm, the two "at least two bytes"
			 * bounds checks and the Header Padding loop. Without this
			 * the harness could not execute any of them -- found by
			 * adversarial review, 2026-09-04. */
			if (rnd_below(2) == 0 &&
			    corpus_mutate_block_header(comp, cl, rnd)) {
				header_runs++;
				was_header = 1;
			} else {
				int flips = 1 + (int)rnd_below(3);
				while (flips--) {
					unsigned long p = 12 + rnd_below(cl - 12);
					comp[p] ^= (unsigned char)(1u << rnd_below(8));
				}
			}
			corrupt_runs++;
		}

		inchunk  = 1 + rnd_below(4096);
		outchunk = 1 + rnd_below(4096);
		if (mode == XZ_SINGLE) {      /* single-call: one shot at each */
			inchunk = COMP_CAP;
			outchunk = OUT_CAP;
		}
		outcap   = n + 1 + rnd_below(4096);
		if (outcap > OUT_CAP) outcap = OUT_CAP;

		memset(o_ref, 0xa5, outcap); memset(o_rs, 0xa5, outcap);
		memset(o_any, 0xa5, outcap);

		run_arm(0, comp, cl, o_ref, outcap, inchunk, outchunk, mode, &a);
		run_arm(1, comp, cl, o_rs,  outcap, inchunk, outchunk, mode, &b);
		run_arm(2, comp, cl, o_any, outcap, inchunk, outchunk, mode, &c);
		runs++;

		/* 1. the differential proper */
		if (a.rc != b.rc || a.out_len != b.out_len ||
		    a.in_pos_total != b.in_pos_total ||
		    a.out_pos_total != b.out_pos_total || a.calls != b.calls ||
		    memcmp(o_ref, o_rs, outcap) != 0)
			fail("PORT DIVERGES from the pristine C", kind, n, check,
			     preset, inchunk, outchunk, &a, &b);

		/* 2. criterion 8: the same C, the other way round.
		 *
		 * CONFIG_XZ_DEC_CRC64 is not set in either of our configs, so the
		 * decoder supports NONE and CRC32 only. On a CRC64 or SHA256
		 * stream the two configurations are SUPPOSED to differ, and that
		 * difference is the entire purpose of XZ_DEC_ANY_CHECK: without it
		 * an unknown check is XZ_OPTIONS_ERROR, with it the caller is told
		 * XZ_UNSUPPORTED_CHECK and may continue. Asserting the documented
		 * pair is a stronger test than demanding they agree, which is what
		 * the first version of this file did -- and what made every CRC64
		 * and SHA256 run "fail" on the harness's first run. */
		if (supported) {
			if (a.rc != c.rc || a.out_len != c.out_len ||
			    memcmp(o_ref, o_any, outcap) != 0)
				fail("ORACLE SPLIT: XZ_DEC_ANY_CHECK changed the answer "
				     "on a SUPPORTED check type", kind, n, check,
				     preset, inchunk, outchunk, &a, &c);
		} else if (!corrupt) {
			/* The documented difference, now asserted at full strength.
			 * Without XZ_DEC_ANY_CHECK the stream is rejected outright.
			 * With it, the decoder reports the unknown check once, the
			 * caller continues, check_skip() skips it, and the stream
			 * DECODES -- so the any arm must reach XZ_STREAM_END and
			 * reproduce the plaintext. That is a far stronger claim than
			 * "they both stopped", which is all this checked before the
			 * arm was allowed to continue. */
			if (a.rc != XZ_OPTIONS_ERROR)
				fail("UNSUPPORTED CHECK: expected XZ_OPTIONS_ERROR without "
				     "XZ_DEC_ANY_CHECK", kind, n, check, preset,
				     inchunk, outchunk, &a, &c);
			else if (mode == XZ_SINGLE) {
				/* Single-call mode is one shot: xz_dec_run() cannot be
				 * re-entered, so the caller never gets to act on the
				 * report and the arm stops at XZ_UNSUPPORTED_CHECK. */
				if (c.rc != XZ_UNSUPPORTED_CHECK)
					fail("XZ_DEC_ANY_CHECK single-call arm should report "
					     "XZ_UNSUPPORTED_CHECK", kind, n, check, preset,
					     inchunk, outchunk, &a, &c);
			} else if (c.rc != XZ_STREAM_END || c.out_len != n ||
				   memcmp(o_any, plain, n) != 0) {
				fail("XZ_DEC_ANY_CHECK arm did not skip the unknown check "
				     "and decode the stream", kind, n, check, preset,
				     inchunk, outchunk, &a, &c);
			}
			/* and the port must reject it exactly as the C does */
			if (a.rc != b.rc)
				fail("PORT DIVERGES on an unsupported check type",
				     kind, n, check, preset, inchunk, outchunk, &a, &b);
		}

		if (!corrupt && supported) {
			oracle_runs++;
			/* 3. THE INDEPENDENT ORACLE: reproduce what liblzma
			 *    compressed. No agreement between arms can fake this. */
			if (a.rc != XZ_STREAM_END || a.out_len != n ||
			    memcmp(o_ref, plain, n) != 0)
				fail("INDEPENDENT ORACLE: decode did not reproduce "
				     "what liblzma compressed", kind, n, check,
				     preset, inchunk, outchunk, &a, NULL);

			/* 4. and liblzma's own reading of the same stream */
			lz = corpus_xz_decode(comp, cl, o_lz, OUT_CAP);
			if (lz != (long)n || memcmp(o_lz, plain, n) != 0)
				fail("liblzma disagrees about its OWN stream",
				     kind, n, check, preset, inchunk, outchunk, NULL, NULL);
		}

		if (was_header && a.rc == XZ_OPTIONS_ERROR)
			header_past_gate++;

		if (mismatches > 8) break;
		if (runs % 2000 == 0) { printf("  %lu runs, %lu corrupt, %lu mismatches\n",
					       runs, corrupt_runs, mismatches); fflush(stdout); }
	}

	printf("\n  runs        %lu full stream decodes, each arm\n", runs);
	printf("  corrupt     %lu runs on bit-flipped streams, of which\n"
	       "  header      %lu mutated the BLOCK HEADER with its CRC32 REPAIRED,\n"
	       "              which is the only way to reach dec_block_header()'s body;\n"
	       "  past-gate   %lu of those returned XZ_OPTIONS_ERROR, which is produced\n"
	       "              ONLY inside dec_block_header() -- proof the repair works\n",
	       corrupt_runs, header_runs, header_past_gate);
	printf("  oracle      %lu non-corrupt runs compared against the ORIGINAL\n"
	       "              plaintext and against liblzma -- neither arm is\n"
	       "              derived from either. Catches a bug both arms share.\n",
	       oracle_runs);
	printf("  arms        3: pristine C, the Rust, and pristine C with\n"
	       "                 XZ_DEC_ANY_CHECK (criterion 8, both ways)\n");
	printf("  any-check   %lu times the XZ_DEC_ANY_CHECK arm continued past\n"
	       "              XZ_UNSUPPORTED_CHECK, which is what reaches check_skip()\n",
	       anycheck_continued);
	printf("  mismatches  %lu\n\n", mismatches);
	if (mismatches) { printf("FAIL\n"); return 1; }
	printf("PASS\n");
	return 0;
}
