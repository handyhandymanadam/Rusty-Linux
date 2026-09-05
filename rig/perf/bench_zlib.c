/* The zlib_inflate arms of the §4 rig.
 *
 * SEPARATE FILE because these need the kernel's <linux/zlib.h> out of
 * port/test/zlib_inflate/shim, and bench.c is built against the top-level
 * lib shim. Keeping them apart is cheaper than reconciling two shims.
 *
 * SEVEN benchmarks rather than one, and that is the whole point.
 * PRIOR-ART.md §5 records a TWELVE-FOLD spread on a decompression routine
 * between two corpus inputs, from a single mechanism. A lone "inflate"
 * number here would be worth almost nothing; what is worth something is the
 * spread across shapes, so the corpus is varied deliberately: one repeated
 * byte, period three, period sixteen, text, incompressible, long-range
 * repeats, and text again fed through small output buffers so the match
 * copies come out of the sliding window instead of the output.
 *
 * WHAT IS ACTUALLY BEING TIMED. inflate_fast() cannot be called on its own
 * -- it needs a built inflate_state -- so each iteration runs a whole
 * zlib_inflateInit2/inflate/inflateEnd cycle. Both arms carry the identical
 * surrounding machinery, so the DIFFERENCE is still the ported function,
 * but the ratio is diluted toward 1 by everything else in the pipeline.
 * That dilution is real and is not corrected for; the row is not a claim
 * about the function in isolation.
 */
#include <linux/zlib.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* port/test/zlib_inflate/corpus.c -- the only unit that sees the system zlib */
extern long corpus_compress(const unsigned char *src, unsigned long n,
                            int level, int window_bits, int mem_level,
                            int strategy, unsigned char *dst,
                            unsigned long dcap);

extern int ref_zlib_inflateInit2(z_streamp strm, int windowBits);
extern int ref_zlib_inflate(z_streamp strm, int flush);
extern int ref_zlib_inflateEnd(z_streamp strm);
extern int ref_zlib_inflate_workspacesize(void);

extern int rs_zlib_inflateInit2(z_streamp strm, int windowBits);
extern int rs_zlib_inflate(z_streamp strm, int flush);
extern int rs_zlib_inflateEnd(z_streamp strm);
extern int rs_zlib_inflateEnd(z_streamp strm);

#define ZPLAIN (256u * 1024u)
#define ZCOMP  (ZPLAIN + ZPLAIN / 2 + 4096u)

struct zc {
	unsigned char *comp;
	unsigned long clen;
	unsigned char *out;
	unsigned long plain_len;
	unsigned long outchunk;
	void *ws_ref;
	void *ws_rs;
};

static const char *const ZWORDS[] = {
	"the", "kernel", "inflate", "window", "distance", "length", "code",
	"buffer", "rust", "match", "literal", "deflate", "table", "stream",
};

static void zgen(int kind, unsigned char *b, unsigned long n)
{
	static const unsigned char p3[3] = { 0x01, 0x02, 0x03 };
	unsigned long i;
	uint32_t s = 12345;

	switch (kind) {
	case 0:					/* one repeated byte */
		memset(b, 0x5a, n);
		return;
	case 1:					/* period three */
		for (i = 0; i < n; i++)
			b[i] = p3[i % 3];
		return;
	case 2:					/* period sixteen */
		for (i = 0; i < n; i++)
			b[i] = (unsigned char)((i % 16) * 17 + 3);
		return;
	case 3:					/* text */
		i = 0;
		while (i < n) {
			const char *w = ZWORDS[(s >> 16) % 14];
			unsigned long l = strlen(w);

			s = s * 1103515245u + 12345u;
			if (i + l + 1 >= n)
				break;
			memcpy(b + i, w, l);
			i += l;
			b[i++] = ' ';
		}
		while (i < n)
			b[i++] = ' ';
		return;
	case 4:					/* incompressible */
		for (i = 0; i < n; i++) {
			s = s * 1103515245u + 12345u;
			b[i] = (unsigned char)(s >> 16);
		}
		return;
	default: {				/* long-range repeats */
		unsigned long blk = 8192;

		for (i = 0; i < blk && i < n; i++) {
			s = s * 1103515245u + 12345u;
			b[i] = (unsigned char)(s >> 16);
		}
		for (i = blk; i < n; i++)
			b[i] = b[i - blk];
		return;
	}
	}
}

/* kind, output chunk (0 = one buffer, no window path) */
static const struct { int kind; unsigned long outchunk; } ZSPEC[] = {
	{ 0, 0 }, { 1, 0 }, { 2, 0 }, { 3, 0 }, { 4, 0 }, { 5, 0 }, { 3, 300 },
};
#define NZ ((int)(sizeof(ZSPEC) / sizeof(ZSPEC[0])))

static struct zc zcorp[NZ];
static int zbuilt;

static void zbuild(void)
{
	unsigned char *plain;
	int i;

	if (zbuilt)
		return;
	zbuilt = 1;
	plain = malloc(ZPLAIN);
	if (!plain)
		abort();

	for (i = 0; i < NZ; i++) {
		struct zc *z = &zcorp[i];
		long cl;

		zgen(ZSPEC[i].kind, plain, ZPLAIN);
		z->comp = malloc(ZCOMP);
		z->out = malloc(ZPLAIN + 64);
		z->ws_ref = malloc((size_t)ref_zlib_inflate_workspacesize());
		z->ws_rs = malloc((size_t)ref_zlib_inflate_workspacesize());
		if (!z->comp || !z->out || !z->ws_ref || !z->ws_rs)
			abort();
		cl = corpus_compress(plain, ZPLAIN, 6, 15, 8, 0, z->comp, ZCOMP);
		if (cl < 0)
			abort();
		z->clen = (unsigned long)cl;
		z->plain_len = ZPLAIN;
		z->outchunk = ZSPEC[i].outchunk ? ZSPEC[i].outchunk : ZPLAIN;
	}
	free(plain);
}

static uint64_t zone(struct zc *z, int arm)
{
	z_stream s;
	unsigned long ipos = 0, opos = 0;
	int rc;

	memset(&s, 0, sizeof(s));
	s.workspace = arm ? z->ws_rs : z->ws_ref;
	rc = arm ? rs_zlib_inflateInit2(&s, 15) : ref_zlib_inflateInit2(&s, 15);
	if (rc != Z_OK)
		return 0;

	for (;;) {
		if (s.avail_in == 0 && ipos < z->clen) {
			s.next_in = z->comp + ipos;
			s.avail_in = z->clen - ipos;
			ipos = z->clen;
		}
		if (s.avail_out == 0 && opos < z->plain_len) {
			unsigned long k = z->plain_len - opos;

			if (k > z->outchunk)
				k = z->outchunk;
			s.next_out = z->out + opos;
			s.avail_out = k;
			opos += k;
		}
		if (s.avail_in == 0 && s.avail_out == 0)
			break;
		rc = arm ? rs_zlib_inflate(&s, Z_NO_FLUSH)
			 : ref_zlib_inflate(&s, Z_NO_FLUSH);
		if (rc != Z_OK)
			break;
		if (s.avail_in == 0 && ipos == z->clen &&
		    s.avail_out == 0 && opos == z->plain_len)
			break;
	}
	if (arm)
		rs_zlib_inflateEnd(&s);
	else
		ref_zlib_inflateEnd(&s);
	return s.total_out;
}

uint64_t zinf_c(unsigned long n, void *ctx);
uint64_t zinf_c(unsigned long n, void *ctx)
{
	uint64_t acc = 0;

	for (unsigned long i = 0; i < n; i++)
		acc += zone((struct zc *)ctx, 0);
	return acc;
}

uint64_t zinf_rust(unsigned long n, void *ctx);
uint64_t zinf_rust(unsigned long n, void *ctx)
{
	uint64_t acc = 0;

	for (unsigned long i = 0; i < n; i++)
		acc += zone((struct zc *)ctx, 1);
	return acc;
}

#define ZSETUP(i)                                   \
	void *zsetup_##i(void);                     \
	void *zsetup_##i(void)                      \
	{                                           \
		zbuild();                           \
		return &zcorp[i];                   \
	}
ZSETUP(0) ZSETUP(1) ZSETUP(2) ZSETUP(3) ZSETUP(4) ZSETUP(5) ZSETUP(6)
