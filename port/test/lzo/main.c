/* Differential test for lib/lzo/lzo1x_decompress_safe.c -> ..._rs.rs.
 *
 * WHAT IS COMPARED
 *   Three arms over one corpus, in one binary:
 *
 *     ref_    pristine C, CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS on
 *     refu_   the SAME pristine C with it off, taking its byte-at-a-time
 *             paths instead of the eight-byte ones
 *     rust    the port, which has only one path and uses read_unaligned()
 *
 *   Arm C is not decoration. The port's first recorded divergence is that it
 *   compiles the wide-access variant unconditionally, on the argument that
 *   read_unaligned() is correct everywhere. Running the C's other spelling
 *   beside it is what turns that argument into a measurement.
 *
 * WHERE THE CORPUS COMES FROM
 *   lib/lzo/lzo1x_compress.c, out of port/pristine/ -- the encoder the
 *   kernel actually ships next to this decoder. No system liblzo2: a corpus
 *   built by a different implementation would be testing agreement with
 *   something the kernel does not use. Both entry points are driven, because
 *   lzorle1x_1_compress() sets bitstream_version 1 and that is the only way
 *   to reach the decoder's zero-run branch at all.
 *
 * THE DIMENSIONS THAT MATTER
 *   LZO is one-shot, so there is no chunking axis as there was for inflate.
 *   What replaces it is the SHAPE OF FAILURE: the output buffer is
 *   deliberately made too small, the input deliberately truncated, and one
 *   run in four bit-flipped, because five of the function's six exits are
 *   error exits and a corpus of well-formed streams would never see them.
 */
/* Standard headers FIRST: the kernel's <linux/lzo.h> is a copy of the real
 * one and assumes size_t is already in scope, as it is inside the kernel. */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <linux/lzo.h>

extern int ref_lzo1x_decompress_safe(const unsigned char *in, size_t in_len,
				     unsigned char *out, size_t *out_len);
extern int refu_lzo1x_decompress_safe(const unsigned char *in, size_t in_len,
				      unsigned char *out, size_t *out_len);
extern int rust_lzo1x_decompress_safe(const unsigned char *in, size_t in_len,
				      unsigned char *out, size_t *out_len);

extern int lzo1x_1_compress(const unsigned char *src, size_t src_len,
			    unsigned char *dst, size_t *dst_len, void *wrkmem);
extern int lzorle1x_1_compress(const unsigned char *src, size_t src_len,
			       unsigned char *dst, size_t *dst_len, void *wrkmem);

/* ---- rng ---------------------------------------------------------------- */

static uint64_t rng_s;
static void rng_seed(uint64_t s) { rng_s = s ? s : 0x9e3779b97f4a7c15ULL; }
static uint64_t rng_u64(void)
{
	rng_s ^= rng_s << 13;
	rng_s ^= rng_s >> 7;
	rng_s ^= rng_s << 17;
	return rng_s;
}
static unsigned rng_below(unsigned n) { return n ? (unsigned)(rng_u64() % n) : 0; }

/* ---- corpus ------------------------------------------------------------- */

#define PLAIN_CAP (256u * 1024u)
#define COMP_CAP  (lzo1x_worst_compress(PLAIN_CAP) + 64)
#define OUT_CAP   (PLAIN_CAP + 4096)

static const char *const WORDS[] = {
	"the", "kernel", "compress", "window", "distance", "length", "code",
	"buffer", "rust", "match", "literal", "deflate", "table", "stream",
	"a", "of", "and", "to", "in", "is", "it", "that", "for", "with",
};
#define NWORDS ((int)(sizeof(WORDS) / sizeof(WORDS[0])))

static unsigned char *files[6];
static unsigned long file_len[6];
static int nfiles;

static void load_file(const char *path)
{
	FILE *f = fopen(path, "rb");
	unsigned char *b;
	long n;

	if (!f || nfiles == 6)
		return;
	b = malloc(PLAIN_CAP);
	n = (long)fread(b, 1, PLAIN_CAP, f);
	fclose(f);
	if (n <= 0) { free(b); return; }
	files[nfiles] = b;
	file_len[nfiles] = (unsigned long)n;
	nfiles++;
}

static unsigned char *mix_scratch;

#define NGEN 13

static unsigned long gen(int kind, unsigned char *b)
{
	unsigned long n, i;
	unsigned k;

	switch (kind) {
	case 0:				/* zeros -- the RLE zero-run path */
		n = 1 + rng_below(PLAIN_CAP - 1);
		memset(b, 0, n);
		return n;
	case 1: {			/* one repeated byte */
		unsigned char c = (unsigned char)rng_below(256);
		n = 1 + rng_below(70000);
		memset(b, c, n);
		return n;
	}
	case 2: {			/* short period */
		unsigned char p[8];
		k = 2 + rng_below(7);
		for (i = 0; i < k; i++) p[i] = (unsigned char)rng_below(256);
		n = k + rng_below(70000);
		for (i = 0; i < n; i++) b[i] = p[i % k];
		return n;
	}
	case 3:				/* incompressible -- all literal runs */
		n = 1 + rng_below(60000);
		for (i = 0; i < n; i++) b[i] = (unsigned char)rng_u64();
		return n;
	case 4: {			/* small alphabet -- short matches */
		unsigned char alpha[8];
		k = 2 + rng_below(7);
		for (i = 0; i < k; i++) alpha[i] = (unsigned char)rng_below(256);
		n = 1 + rng_below(120000);
		for (i = 0; i < n; i++) b[i] = alpha[rng_below(k)];
		return n;
	}
	case 5: {			/* text */
		n = 0;
		while (n < 40000 + rng_below(60000)) {
			const char *w = WORDS[rng_below(NWORDS)];
			unsigned long l = strlen(w);

			if (n + l + 2 >= PLAIN_CAP) break;
			memcpy(b + n, w, l);
			n += l;
			b[n++] = (rng_below(12) == 0) ? '\n' : ' ';
		}
		return n ? n : 1;
	}
	case 6:				/* counter */
		n = 1 + rng_below(90000);
		for (i = 0; i < n; i++) b[i] = (unsigned char)i;
		return n;
	case 7: {			/* long-range repeats */
		unsigned long blk = 4096 + rng_below(20000);
		unsigned long reps = 2 + rng_below(8);

		if (blk > PLAIN_CAP / 2) blk = PLAIN_CAP / 2;
		for (i = 0; i < blk; i++) b[i] = (unsigned char)rng_u64();
		n = blk;
		while (reps-- && n + blk < PLAIN_CAP) {
			memcpy(b + n, b, blk);
			n += blk;
		}
		return n;
	}
	case 8: {			/* sparse zeros with noise -- RLE edges */
		n = 1 + rng_below(150000);
		memset(b, 0, n);
		for (i = 0; i < n / 200 + 1; i++)
			b[rng_below((unsigned)n)] = (unsigned char)rng_u64();
		return n;
	}
	case 9: {			/* alternating long runs */
		unsigned char c0 = (unsigned char)rng_below(256);
		unsigned char c1 = (unsigned char)rng_below(256);
		n = 0;
		while (n < 40000 + rng_below(80000)) {
			unsigned long r = 1 + rng_below(600);

			if (n + r >= PLAIN_CAP) break;
			memset(b + n, (n & 1) ? c1 : c0, r);
			n += r;
		}
		return n ? n : 1;
	}
	case 10: {			/* very short inputs -- the header paths */
		n = 1 + rng_below(40);
		for (i = 0; i < n; i++) b[i] = (unsigned char)rng_u64();
		return n;
	}
	case 11: {			/* mixture */
		unsigned long parts = 2 + rng_below(4);
		unsigned char *tmp = mix_scratch;

		n = 0;
		while (parts--) {
			unsigned long m = gen((int)rng_below(10), tmp);

			if (m > 30000) m = 30000;
			if (n + m >= PLAIN_CAP) break;
			memcpy(b + n, tmp, m);
			n += m;
		}
		return n ? n : 1;
	}
	default: {			/* real files off the disk */
		unsigned long off, m;

		if (!nfiles) return gen(5, b);
		k = rng_below((unsigned)nfiles);
		m = file_len[k];
		off = rng_below((unsigned)m);
		n = m - off;
		if (n > PLAIN_CAP) n = PLAIN_CAP;
		memcpy(b, files[k] + off, n);
		return n ? n : 1;
	}
	}
}

/* ---- one decompression -------------------------------------------------- */

struct rr {
	int rc;
	size_t out_len;
};

static void run(int arm, const unsigned char *cin, size_t clen,
		unsigned char *outbuf, size_t outcap, struct rr *r)
{
	size_t ol = outcap;

	r->rc = (arm == 0) ? ref_lzo1x_decompress_safe(cin, clen, outbuf, &ol)
	      : (arm == 1) ? rust_lzo1x_decompress_safe(cin, clen, outbuf, &ol)
			   : refu_lzo1x_decompress_safe(cin, clen, outbuf, &ol);
	r->out_len = ol;
}

int main(int argc, char **argv)
{
	unsigned long want = (argc > 1) ? strtoul(argv[1], NULL, 0) : 50000;
	unsigned long seed = (argc > 2) ? strtoul(argv[2], NULL, 0) : 20260903;
	unsigned char *plain, *comp, *o_ref, *o_rs, *o_ru;
	void *wrk;
	unsigned long runs = 0, mismatches = 0, bytes = 0;
	unsigned long n_corrupt = 0, n_short_out = 0, n_trunc = 0, n_rle = 0;
	unsigned long n_tail = 0, n_runt = 0;
	unsigned long rc_hist[12] = { 0 };
	int i;

	printf("lzo differential: pristine lzo1x_decompress_safe.c vs the port\n");

	mix_scratch = malloc(PLAIN_CAP);
	plain = malloc(PLAIN_CAP);
	comp  = malloc(COMP_CAP);
	o_ref = malloc(OUT_CAP);
	o_rs  = malloc(OUT_CAP);
	o_ru  = malloc(OUT_CAP);
	wrk   = malloc(LZO1X_MEM_COMPRESS);
	if (!mix_scratch || !plain || !comp || !o_ref || !o_rs || !o_ru || !wrk) {
		printf("  out of memory\n");
		return 2;
	}

	load_file("port/tree/lib/lzo/lzo1x_decompress_safe_rs.rs");
	load_file("port/pristine/lib/lzo/lzo1x_compress.c");
	load_file("notes/STATUS.md");
	load_file("notes/GOALS.md");
	printf("  corpus: %d generators, encoder is the pristine in-tree one\n", NGEN);

	rng_seed(seed);

	while (runs < want) {
		unsigned long n;
		size_t cl, outcap;
		int kind, rle, corrupt, trunc, shortout;
		struct rr a, b, c;

		kind = (int)rng_below(NGEN);
		n = gen(kind, plain);

		rle = rng_below(2);
		cl = COMP_CAP;
		if ((rle ? lzorle1x_1_compress : lzo1x_1_compress)
		    (plain, n, comp, &cl, wrk) != LZO_E_OK)
			continue;
		if (rle) n_rle++;

		/* Inputs shorter than three bytes are rejected before anything
		   else is read. Nothing the encoder emits is that short, so
		   without this the very first exit is never taken. */
		if (rng_below(40) == 0) {
			cl = rng_below(3);
			n_runt++;
		}

		/* Trailing junk after a well-formed stream is the only way to
		   reach LZO_E_INPUT_NOT_CONSUMED: the EOF marker is found with
		   ip still short of ip_end. */
		if (rng_below(6) == 0 && cl + 8 < COMP_CAP) {
			unsigned e = 1 + rng_below(7);

			while (e--)
				comp[cl++] = (unsigned char)rng_u64();
			n_tail++;
		}

		/* Truncated input reaches the NEED_IP exits. */
		trunc = (rng_below(6) == 0) && cl > 4;
		if (trunc) {
			cl -= 1 + rng_below((unsigned)(cl / 2));
			n_trunc++;
		}

		/* A too-small output buffer reaches the NEED_OP exits. */
		shortout = (rng_below(5) == 0);
		outcap = shortout ? (n ? rng_below((unsigned)n) : 0) : n;
		if (outcap > OUT_CAP) outcap = OUT_CAP;
		if (shortout) n_short_out++;

		/* Bit flips reach LOOKBEHIND_OVERRUN and LZO_E_ERROR. */
		corrupt = (rng_below(4) == 0) && cl > 4;
		if (corrupt) {
			int flips = 1 + (int)rng_below(3);

			while (flips--)
				comp[rng_below((unsigned)cl)] ^=
					(unsigned char)(1u << rng_below(8));
			n_corrupt++;
		}

		/* Same sentinel in all three, so comparing the WHOLE buffer also
		   catches an arm that wrote past the length it reported. */
		memset(o_ref, 0xa5, OUT_CAP);
		memset(o_rs,  0xa5, OUT_CAP);
		memset(o_ru,  0xa5, OUT_CAP);

		run(0, comp, cl, o_ref, outcap, &a);
		run(1, comp, cl, o_rs,  outcap, &b);
		run(2, comp, cl, o_ru,  outcap, &c);

		runs++;
		bytes += a.out_len;
		if (a.rc <= 0 && a.rc > -11)
			rc_hist[-a.rc]++;

		if (a.rc != c.rc || a.out_len != c.out_len ||
		    memcmp(o_ref, o_ru, OUT_CAP) != 0) {
			mismatches++;
			printf("\nORACLE SPLIT run %lu: the C's two unaligned-access "
			       "spellings disagree with each other\n", runs);
			printf("  kind=%d n=%lu rle=%d trunc=%d shortout=%d corrupt=%d\n",
			       kind, n, rle, trunc, shortout, corrupt);
			if (mismatches > 8) break;
		}

		if (a.rc != b.rc || a.out_len != b.out_len ||
		    memcmp(o_ref, o_rs, OUT_CAP) != 0) {
			unsigned long j, at = OUT_CAP;

			for (j = 0; j < OUT_CAP; j++)
				if (o_ref[j] != o_rs[j]) { at = j; break; }
			mismatches++;
			printf("\nMISMATCH run %lu\n", runs);
			printf("  kind=%d plainlen=%lu rle=%d complen=%zu outcap=%zu\n",
			       kind, n, rle, cl, outcap);
			printf("  trunc=%d shortout=%d corrupt=%d seed=%lu\n",
			       trunc, shortout, corrupt, seed);
			printf("  rc       %d / %d\n", a.rc, b.rc);
			printf("  out_len  %zu / %zu\n", a.out_len, b.out_len);
			if (at < OUT_CAP)
				printf("  first differing byte at %lu: %02x / %02x\n",
				       at, o_ref[at], o_rs[at]);
			if (mismatches > 8) {
				printf("\nstopping after 8 mismatches\n");
				break;
			}
		}

		if ((runs % 5000) == 0) {
			printf("  %lu runs, %lu MiB out, %lu corrupt, 0 mismatches\r",
			       runs, bytes >> 20, n_corrupt);
			fflush(stdout);
		}
	}

	printf("\n");
	printf("  runs        %lu decompressions, each arm\n", runs);
	printf("  bytes       %lu produced and compared per arm (%lu MiB)\n",
	       bytes, bytes >> 20);
	printf("  rle         %lu runs on bitstream_version 1 (the zero-run path)\n", n_rle);
	printf("  truncated   %lu   short output buffer %lu   bit-flipped %lu\n",
	       n_trunc, n_short_out, n_corrupt);
	printf("  trailing junk appended to %lu runs; %lu runt inputs (< 3 bytes)\n",
	       n_tail, n_runt);
	printf("  return codes reached:\n");
	{
		static const char *const names[] = {
			"LZO_E_OK", "LZO_E_ERROR", "?", "?",
			"LZO_E_INPUT_OVERRUN", "LZO_E_OUTPUT_OVERRUN",
			"LZO_E_LOOKBEHIND_OVERRUN", "?", "LZO_E_INPUT_NOT_CONSUMED",
		};
		for (i = 0; i < 9; i++)
			if (rc_hist[i])
				printf("    %-28s %lu\n", names[i], rc_hist[i]);
	}
	printf("  arms        3: pristine C (wide access), pristine C (byte-wise),\n"
	       "                 and the Rust; all three compared every run\n");
	printf("  mismatches  %lu\n", mismatches);

	for (i = 0; i < nfiles; i++)
		free(files[i]);
	free(mix_scratch); free(plain); free(comp);
	free(o_ref); free(o_rs); free(o_ru); free(wrk);
	return mismatches ? 1 : 0;
}
