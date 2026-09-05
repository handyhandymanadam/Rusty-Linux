/* SPDX-License-Identifier: GPL-2.0
 *
 * Differential test for lib/xz/xz_dec_lzma2.c -> xz_dec_lzma2_rs.rs.
 *
 * Drives xz_dec_lzma2_run() DIRECTLY on raw LZMA2 chunk streams, not through
 * the .xz container. An adversarial review of the xz_dec_stream port on
 * 2026-09-04 showed that feeding only complete containers leaves the inner
 * layer's error paths unreachable, because the container rejects malformed
 * input at the header CRC first.
 *
 * Everything the review had to retrofit there is here from the start:
 *   - the MODE is an axis, so the single-call branch is executed
 *   - in_pos / out_pos are compared after EVERY call, including the erroring
 *     one, because callers resume from them
 *   - an INDEPENDENT ORACLE (liblzma, and the original plaintext) so a bug
 *     both arms share is visible
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/xz.h>

#define PLAIN_CAP  400000u
#define COMP_CAP   600000u
#define OUT_CAP    (PLAIN_CAP + 65536u)

void  corpus_seed(unsigned long s);
unsigned long corpus_plain(int kind, unsigned char *buf, unsigned long cap);
long  corpus_lzma2(const unsigned char *src, unsigned long n, unsigned char *dst,
		   unsigned long cap, unsigned preset, int *props, uint32_t *dict);
long  corpus_lzma2_decode(const unsigned char *src, unsigned long n,
			  unsigned char *dst, unsigned long cap, uint32_t dict);

struct xz_dec_lzma2;
struct xz_dec_lzma2 *ref_xz_dec_lzma2_create(enum xz_mode, uint32_t);
enum xz_ret          ref_xz_dec_lzma2_reset(struct xz_dec_lzma2 *, uint8_t);
enum xz_ret          ref_xz_dec_lzma2_run(struct xz_dec_lzma2 *, struct xz_buf *);
void                 ref_xz_dec_lzma2_end(struct xz_dec_lzma2 *);
struct xz_dec_lzma2 *rs_xz_dec_lzma2_create(enum xz_mode, uint32_t);
enum xz_ret          rs_xz_dec_lzma2_reset(struct xz_dec_lzma2 *, uint8_t);
enum xz_ret          rs_xz_dec_lzma2_run(struct xz_dec_lzma2 *, struct xz_buf *);
void                 rs_xz_dec_lzma2_end(struct xz_dec_lzma2 *);

static unsigned long rngs;
static unsigned rnd(void) { rngs = rngs * 6364136223846793005ULL + 1442695040888963407ULL;
                            return (unsigned)(rngs >> 33); }
static unsigned long rnd_below(unsigned long n) { return n ? rnd() % n : 0; }

static unsigned long runs, mismatches, corrupt_runs, oracle_runs;

struct rr {
	int create_ok, reset_rc, rc;
	unsigned long out_len, in_pos_total, calls;
};

static void run_arm(int arm, const unsigned char *in, unsigned long inlen,
		    unsigned char *out, unsigned long outcap,
		    unsigned long inchunk, unsigned long outchunk,
		    enum xz_mode mode, uint32_t dict_max, uint8_t props,
		    struct rr *r)
{
	struct xz_dec_lzma2 *s;
	struct xz_buf b;
	enum xz_ret rc = XZ_OK;
	unsigned long ipos = 0, opos = 0, guard = 0;

	memset(r, 0, sizeof(*r));
	s = (arm == 0) ? ref_xz_dec_lzma2_create(mode, dict_max)
		       :  rs_xz_dec_lzma2_create(mode, dict_max);
	if (s == NULL) { r->create_ok = 0; return; }
	r->create_ok = 1;

	r->reset_rc = (arm == 0) ? ref_xz_dec_lzma2_reset(s, props)
				 :  rs_xz_dec_lzma2_reset(s, props);
	if (r->reset_rc != XZ_OK) {
		if (arm == 0) ref_xz_dec_lzma2_end(s); else rs_xz_dec_lzma2_end(s);
		return;
	}

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

		rc = (arm == 0) ? ref_xz_dec_lzma2_run(s, &b)
				:  rs_xz_dec_lzma2_run(s, &b);
		r->calls++;
		if (rc != XZ_OK)
			break;
		if (b.in_pos == b.in_size && ipos == inlen &&
		    b.out_pos == b.out_size && opos == outcap)
			break;
		if (++guard > inlen + outcap + 4096)
			break;
	}

	r->rc = rc;
	r->out_len = (opos - b.out_size) + b.out_pos;
	r->in_pos_total = (ipos - b.in_size) + b.in_pos;
	if (arm == 0) ref_xz_dec_lzma2_end(s); else rs_xz_dec_lzma2_end(s);
}

static void fail(const char *what, int kind, unsigned long n, unsigned preset,
		 int props, unsigned long inchunk, unsigned long outchunk,
		 enum xz_mode mode, const struct rr *a, const struct rr *b)
{
	mismatches++;
	printf("\n%s run %lu\n", what, runs);
	printf("  kind=%d plainlen=%lu preset=%u props=%d inchunk=%lu outchunk=%lu mode=%d\n",
	       kind, n, preset, props, inchunk, outchunk, (int)mode);
	if (a && b)
		printf("  create %d/%d  reset %d/%d  rc %d/%d  out_len %lu/%lu  in_pos %lu/%lu  calls %lu/%lu\n",
		       a->create_ok, b->create_ok, a->reset_rc, b->reset_rc, a->rc, b->rc,
		       a->out_len, b->out_len, a->in_pos_total, b->in_pos_total,
		       a->calls, b->calls);
}

int main(int argc, char **argv)
{
	static unsigned char plain[PLAIN_CAP], comp[COMP_CAP];
	static unsigned char o_ref[OUT_CAP], o_rs[OUT_CAP], o_lz[OUT_CAP];
	unsigned long target = (argc > 1) ? strtoul(argv[1], NULL, 0) : 20000;
	unsigned long seed   = (argc > 2) ? strtoul(argv[2], NULL, 0) : 20260904;

	rngs = seed; corpus_seed(seed);

	while (runs < target) {
		int kind = (int)rnd_below(8), corrupt, props;
		unsigned preset = (unsigned)rnd_below(10);
		uint32_t dict;
		unsigned long n, cl, inchunk, outchunk, outcap;
		enum xz_mode mode = (enum xz_mode)rnd_below(3);
		struct rr a, b;
		long lz;

		n = corpus_plain(kind, plain, PLAIN_CAP);
		{
			long r = corpus_lzma2(plain, n, comp, COMP_CAP, preset, &props, &dict);
			if (r < 0) continue;
			cl = (unsigned long)r;
		}

		/* A quarter corrupt. Unlike the container harness there is no CRC
		 * gate here, so a flipped bit reaches the range decoder and the
		 * dictionary directly -- which is the entire reason this test
		 * drives the inner layer rather than the pipeline. */
		corrupt = (rnd_below(4) == 0) && cl > 2;
		if (corrupt) {
			int flips = 1 + (int)rnd_below(3);
			while (flips--) {
				unsigned long p = rnd_below(cl);
				comp[p] ^= (unsigned char)(1u << rnd_below(8));
			}
			corrupt_runs++;
		}

		inchunk  = 1 + rnd_below(4096);
		outchunk = 1 + rnd_below(4096);
		outcap   = n + 1 + rnd_below(4096);
		if (outcap > OUT_CAP) outcap = OUT_CAP;
		if (mode == XZ_SINGLE) { inchunk = COMP_CAP; outchunk = OUT_CAP; }

		memset(o_ref, 0xa5, outcap); memset(o_rs, 0xa5, outcap);

		run_arm(0, comp, cl, o_ref, outcap, inchunk, outchunk, mode, dict,
			(uint8_t)props, &a);
		run_arm(1, comp, cl, o_rs,  outcap, inchunk, outchunk, mode, dict,
			(uint8_t)props, &b);
		runs++;

		if (a.create_ok != b.create_ok || a.reset_rc != b.reset_rc ||
		    a.rc != b.rc || a.out_len != b.out_len ||
		    a.in_pos_total != b.in_pos_total || a.calls != b.calls ||
		    memcmp(o_ref, o_rs, outcap) != 0)
			fail("PORT DIVERGES from the pristine C", kind, n, preset,
			     props, inchunk, outchunk, mode, &a, &b);

		if (!corrupt) {
			oracle_runs++;
			/* THE INDEPENDENT ORACLE: reproduce what liblzma compressed. */
			if (a.out_len != n || memcmp(o_ref, plain, n) != 0)
				fail("INDEPENDENT ORACLE: decode did not reproduce "
				     "what liblzma compressed", kind, n, preset, props,
				     inchunk, outchunk, mode, &a, &b);
			lz = corpus_lzma2_decode(comp, cl, o_lz, OUT_CAP, dict);
			if (lz != (long)n || memcmp(o_lz, plain, n) != 0)
				fail("liblzma disagrees about its OWN stream", kind, n,
				     preset, props, inchunk, outchunk, mode, NULL, NULL);
		}

		if (mismatches > 8) break;
		if (runs % 2000 == 0) { printf("  %lu runs, %lu corrupt, %lu mismatches\n",
					       runs, corrupt_runs, mismatches); fflush(stdout); }
	}

	printf("\n  runs        %lu raw LZMA2 decodes, each arm\n", runs);
	printf("  corrupt     %lu runs on bit-flipped streams -- no CRC gate here,\n"
	       "              so the flips reach the range decoder directly\n", corrupt_runs);
	printf("  oracle      %lu non-corrupt runs compared against the ORIGINAL\n"
	       "              plaintext and against liblzma\n", oracle_runs);
	printf("  axes        mode (all three), dictionary size, lc/lp/pb via preset,\n"
	       "              input and output chunking, and in_pos compared per call\n");
	printf("  mismatches  %lu\n\n", mismatches);
	if (mismatches) { printf("FAIL\n"); return 1; }
	printf("PASS\n");
	return 0;
}
