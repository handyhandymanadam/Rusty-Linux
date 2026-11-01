/* SPDX-License-Identifier: GPL-2.0
 *
 * Differential driver for lib/lzo/lzo1x_compress.c + lzo1x_compress_safe.c
 * -> port/tree/lib/lzo/lzo1x_compress_rs.rs.
 *
 *   difftest [runs] [seed]
 *
 * Four function pairs, one binary: lzo1x_1_compress[_safe] and
 * lzorle1x_1_compress[_safe]. The non-`_safe` pair is only ever driven with
 * a worst-case-sized `dst` (its own documented contract -- `NEED_OP` never
 * fires there); the `_safe` pair is additionally driven with deliberately
 * undersized buffers to exercise LZO_E_OUTPUT_OVERRUN on both arms.
 *
 * Round-trip: every compressed output that both arms agree on is ALSO fed
 * through the pristine lzo1x_decompress_safe() (already ported and
 * differentially tested elsewhere; used here as an oracle, not under test)
 * and checked against the original input -- a correctness proof independent
 * of ref-vs-rs byte equality.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "../common/difftest.h"

typedef int (*compress_fn)(const unsigned char *src, size_t src_len,
			    unsigned char *dst, size_t *dst_len, void *wrkmem);

int ref_lzo1x_1_compress(const unsigned char *src, size_t src_len, unsigned char *dst, size_t *dst_len, void *wrkmem);
int ref_lzorle1x_1_compress(const unsigned char *src, size_t src_len, unsigned char *dst, size_t *dst_len, void *wrkmem);
int ref_lzo1x_1_compress_safe(const unsigned char *src, size_t src_len, unsigned char *dst, size_t *dst_len, void *wrkmem);
int ref_lzorle1x_1_compress_safe(const unsigned char *src, size_t src_len, unsigned char *dst, size_t *dst_len, void *wrkmem);

int rs_lzo1x_1_compress(const unsigned char *src, size_t src_len, unsigned char *dst, size_t *dst_len, void *wrkmem);
int rs_lzorle1x_1_compress(const unsigned char *src, size_t src_len, unsigned char *dst, size_t *dst_len, void *wrkmem);
int rs_lzo1x_1_compress_safe(const unsigned char *src, size_t src_len, unsigned char *dst, size_t *dst_len, void *wrkmem);
int rs_lzorle1x_1_compress_safe(const unsigned char *src, size_t src_len, unsigned char *dst, size_t *dst_len, void *wrkmem);

/* Divergence 1's proof: the SAME pristine C without the 64-bit unaligned
 * fast path -- see run.sh's own comment. */
int refu_lzo1x_1_compress(const unsigned char *src, size_t src_len, unsigned char *dst, size_t *dst_len, void *wrkmem);
int refu_lzorle1x_1_compress(const unsigned char *src, size_t src_len, unsigned char *dst, size_t *dst_len, void *wrkmem);
int refu_lzo1x_1_compress_safe(const unsigned char *src, size_t src_len, unsigned char *dst, size_t *dst_len, void *wrkmem);
int refu_lzorle1x_1_compress_safe(const unsigned char *src, size_t src_len, unsigned char *dst, size_t *dst_len, void *wrkmem);

/* The already-ported, already-tested decompressor: the round-trip oracle. */
int lzo1x_decompress_safe(const unsigned char *src, size_t src_len, unsigned char *dst, size_t *dst_len);

#define LZO1X_1_MEM_COMPRESS (8192 * sizeof(unsigned short))
#define lzo1x_worst_compress(x) ((x) + ((x) / 16) + 64 + 3 + 2)
#define LZO_E_OK 0
#define LZO_E_OUTPUT_OVERRUN (-5)

static uint64_t rng_next(uint64_t *s)
{
	*s ^= *s << 13;
	*s ^= *s >> 7;
	*s ^= *s << 17;
	return *s;
}

/* A mix of shapes LZO's match finder actually branches on: pure random
 * (mostly literals), all-zero (the RLE zero-run path), a repeating pattern
 * (short matches), and run-length-friendly text-like data (long matches).
 */
static void fill(uint8_t *buf, size_t len, int shape, uint64_t *rng)
{
	size_t i;
	switch (shape) {
	case 0:
		for (i = 0; i < len; i++)
			buf[i] = (uint8_t)(rng_next(rng) & 0xff);
		break;
	case 1:
		memset(buf, 0, len);
		break;
	case 2:
		for (i = 0; i < len; i++)
			buf[i] = (uint8_t)(i % (1 + (rng_next(rng) % 32)));
		break;
	default:
		for (i = 0; i < len; i++) {
			if (rng_next(rng) % 10 == 0)
				buf[i] = (uint8_t)(rng_next(rng) & 0xff);
			else
				buf[i] = (uint8_t)('a' + (i % 7));
		}
		break;
	}
}

struct pair {
	const char *name;
	compress_fn ref, rs;
	int safe;
	unsigned char bitstream; /* 0 = lzo1x_1, 1 = lzorle1x_1: informational only */
};

static void run_case(unsigned long run, const struct pair *p,
		      const uint8_t *src, size_t src_len, void *ref_wrk, void *rs_wrk)
{
	size_t worst = lzo1x_worst_compress(src_len);
	struct dt_buf ref_dst, rs_dst;
	size_t ref_len = worst, rs_len = worst;
	int ref_ret, rs_ret;

	/* SAME tag on both arms, deliberately -- see port/test/zstd_decompress/
	 * main.c's comment: identical tags make the padding identical between
	 * arms too, which is what makes comparing the FULL padded buffer
	 * (dt_cmp_buf) meaningful. */
	dt_buf_init(&ref_dst, worst, (unsigned char)run);
	dt_buf_init(&rs_dst, worst, (unsigned char)run);
	dt_buf_poison(&ref_dst);
	dt_buf_poison(&rs_dst);

	ref_ret = p->ref(src, src_len, ref_dst.p, &ref_len, ref_wrk);
	rs_ret = p->rs(src, src_len, rs_dst.p, &rs_len, rs_wrk);

	dt_cmp_ret(run, p->name, (size_t)ref_ret, (size_t)rs_ret);
	dt_cmp_u32(run, p->name, "dst_len", (unsigned)ref_len, (unsigned)rs_len);
	dt_cmp_buf(run, p->name, "dst", &ref_dst, &rs_dst);

	if (ref_ret == LZO_E_OK && rs_ret == LZO_E_OK && ref_len == rs_len) {
		/* Round-trip the RS arm's own output through the oracle
		 * decompressor. */
		uint8_t *round = malloc(src_len ? src_len : 1);
		size_t round_len = src_len;
		int dret = lzo1x_decompress_safe(rs_dst.p, rs_len, round, &round_len);

		dt_checks++;
		if (dret != LZO_E_OK) {
			dt_fail(run, p->name, "round-trip: decompress failed");
		} else if (round_len != src_len || (src_len && memcmp(round, src, src_len) != 0)) {
			dt_fail(run, p->name, "round-trip: decompressed bytes differ from input");
		}
		free(round);
	}

	if (p->safe) {
		/* Deliberately undersized dst: both arms must agree on
		 * LZO_E_OUTPUT_OVERRUN (or, for tiny inputs that fit even a
		 * tiny buffer, on success -- compared either way). */
		size_t tiny = worst > 4 ? worst / 4 : 0;
		struct dt_buf ref_tiny, rs_tiny;
		size_t ref_tiny_len = tiny, rs_tiny_len = tiny;
		int ref_tiny_ret, rs_tiny_ret;

		dt_buf_init(&ref_tiny, worst, (unsigned char)(run + 1));
		dt_buf_init(&rs_tiny, worst, (unsigned char)(run + 1));
		dt_buf_poison(&ref_tiny);
		dt_buf_poison(&rs_tiny);

		ref_tiny_ret = p->ref(src, src_len, ref_tiny.p, &ref_tiny_len, ref_wrk);
		rs_tiny_ret = p->rs(src, src_len, rs_tiny.p, &rs_tiny_len, rs_wrk);

		dt_cmp_ret(run, p->name, (size_t)ref_tiny_ret, (size_t)rs_tiny_ret);
		dt_cmp_u32(run, p->name, "tiny dst_len", (unsigned)ref_tiny_len, (unsigned)rs_tiny_len);
		/* Only the bytes actually claimed written are meaningful on an
		 * overrun path (both arms bail at possibly-different partial
		 * offsets is NOT expected -- NEED_OP checks before every
		 * write, so a mismatch here is real); compare the whole
		 * padded buffer regardless, same as the full-size case. */
		dt_cmp_buf(run, p->name, "tiny dst", &ref_tiny, &rs_tiny);

		free(ref_tiny.base);
		free(rs_tiny.base);
	}

	free(ref_dst.base);
	free(rs_dst.base);
}

/* Divergence 1's proof: ref_ (64-bit fast path) vs refu_ (byte-at-a-time /
 * 32-bit path), same pristine C, same input -- must produce byte-identical
 * output. Lighter than run_case(): no round-trip, no tiny-buffer arm, just
 * the core claim.
 */
static void run_divergence_case(unsigned long run, const char *name,
				 compress_fn ref, compress_fn refu,
				 const uint8_t *src, size_t src_len, void *wrk_a, void *wrk_b)
{
	size_t worst = lzo1x_worst_compress(src_len);
	struct dt_buf a, b;
	size_t a_len = worst, b_len = worst;
	int a_ret, b_ret;

	dt_buf_init(&a, worst, (unsigned char)(run + 2));
	dt_buf_init(&b, worst, (unsigned char)(run + 2));
	dt_buf_poison(&a);
	dt_buf_poison(&b);

	a_ret = ref(src, src_len, a.p, &a_len, wrk_a);
	b_ret = refu(src, src_len, b.p, &b_len, wrk_b);

	dt_cmp_ret(run, name, (size_t)a_ret, (size_t)b_ret);
	dt_cmp_u32(run, name, "dst_len", (unsigned)a_len, (unsigned)b_len);
	dt_cmp_buf(run, name, "dst", &a, &b);

	free(a.base);
	free(b.base);
}

int main(int argc, char **argv)
{
	long runs = argc > 1 ? atol(argv[1]) : 20000;
	uint64_t seed = argc > 2 ? (uint64_t)atol(argv[2]) : 20260906u;
	long i;
	void *ref_wrk = malloc(LZO1X_1_MEM_COMPRESS);
	void *rs_wrk = malloc(LZO1X_1_MEM_COMPRESS);

	const struct pair pairs[4] = {
		{ "lzo1x_1_compress", ref_lzo1x_1_compress, rs_lzo1x_1_compress, 0, 0 },
		{ "lzorle1x_1_compress", ref_lzorle1x_1_compress, rs_lzorle1x_1_compress, 0, 1 },
		{ "lzo1x_1_compress_safe", ref_lzo1x_1_compress_safe, rs_lzo1x_1_compress_safe, 1, 0 },
		{ "lzorle1x_1_compress_safe", ref_lzorle1x_1_compress_safe, rs_lzorle1x_1_compress_safe, 1, 1 },
	};

	printf("runs=%ld seed=%llu\n", runs, (unsigned long long)seed);

	for (i = 0; i < runs; i++) {
		size_t len = (size_t)(rng_next(&seed) % 8192);
		int shape = (int)(rng_next(&seed) % 4);
		uint8_t *src = malloc(len ? len : 1);
		int p;

		fill(src, len, shape, &seed);

		for (p = 0; p < 4; p++)
			run_case((unsigned long)i, &pairs[p], src, len, ref_wrk, rs_wrk);

		run_divergence_case((unsigned long)i, "lzo1x_1_compress(divergence)",
				     ref_lzo1x_1_compress, refu_lzo1x_1_compress, src, len, ref_wrk, rs_wrk);
		run_divergence_case((unsigned long)i, "lzorle1x_1_compress(divergence)",
				     ref_lzorle1x_1_compress, refu_lzorle1x_1_compress, src, len, ref_wrk, rs_wrk);
		run_divergence_case((unsigned long)i, "lzo1x_1_compress_safe(divergence)",
				     ref_lzo1x_1_compress_safe, refu_lzo1x_1_compress_safe, src, len, ref_wrk, rs_wrk);
		run_divergence_case((unsigned long)i, "lzorle1x_1_compress_safe(divergence)",
				     ref_lzorle1x_1_compress_safe, refu_lzorle1x_1_compress_safe, src, len, ref_wrk, rs_wrk);

		free(src);
	}

	printf("comparisons: %lu   mismatches: %lu\n", dt_checks, dt_fails);
	return dt_fails != 0;
}
