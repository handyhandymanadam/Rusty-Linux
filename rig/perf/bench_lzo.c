/* The LZO arms of the §4 rig.
 *
 * SEPARATE FILE because these need the kernel's <linux/lzo.h> and lzodefs.h
 * out of port/test/lzo/shim, and bench.c is built against the top-level lib
 * shim.
 *
 * SIX benchmarks, not one, for the reason PRIOR-ART.md §5 gives: a single
 * number in a decompressor family is worth almost nothing, and the spread
 * across corpus shapes is the measurement.
 *
 * UNLIKE THE INFLATE ROWS, THESE ARE NOT DILUTED. inflate_fast() cannot be
 * called on its own, so those rows time a whole inflateInit2/inflate/End
 * cycle around it. lzo1x_decompress_safe() is one-shot and takes plain
 * buffers, so each iteration here is one call to the function under test and
 * nothing else. The two families' ratios are therefore NOT comparable to
 * each other, only within themselves.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <linux/lzo.h>

extern int ref_lzo1x_decompress_safe(const unsigned char *in, size_t in_len,
				     unsigned char *out, size_t *out_len);
extern int rust_lzo1x_decompress_safe(const unsigned char *in, size_t in_len,
				      unsigned char *out, size_t *out_len);
extern int lzo1x_1_compress(const unsigned char *src, size_t src_len,
			    unsigned char *dst, size_t *dst_len, void *wrkmem);
extern int lzorle1x_1_compress(const unsigned char *src, size_t src_len,
			       unsigned char *dst, size_t *dst_len, void *wrkmem);

#define LPLAIN (256u * 1024u)

struct lzc {
	unsigned char *comp;
	size_t clen;
	unsigned char *out;
	size_t plain_len;
};

static const char *const LWORDS[] = {
	"the", "kernel", "compress", "window", "distance", "length", "code",
	"buffer", "rust", "match", "literal", "deflate", "table", "stream",
};

static void lgen(int kind, unsigned char *b, size_t n)
{
	static const unsigned char p3[3] = { 0x01, 0x02, 0x03 };
	size_t i;
	uint32_t s = 12345;

	switch (kind) {
	case 0: memset(b, 0x5a, n); return;
	case 1: for (i = 0; i < n; i++) b[i] = p3[i % 3]; return;
	case 2:
		i = 0;
		while (i < n) {
			const char *w = LWORDS[(s >> 16) % 14];
			size_t l = strlen(w);

			s = s * 1103515245u + 12345u;
			if (i + l + 1 >= n) break;
			memcpy(b + i, w, l);
			i += l;
			b[i++] = ' ';
		}
		while (i < n) b[i++] = ' ';
		return;
	case 3:
		for (i = 0; i < n; i++) {
			s = s * 1103515245u + 12345u;
			b[i] = (unsigned char)(s >> 16);
		}
		return;
	case 4: {
		size_t blk = 8192;

		for (i = 0; i < blk && i < n; i++) {
			s = s * 1103515245u + 12345u;
			b[i] = (unsigned char)(s >> 16);
		}
		for (i = blk; i < n; i++) b[i] = b[i - blk];
		return;
	}
	default: memset(b, 0, n); return;
	}
}

/* kind, use the RLE encoder */
static const struct { int kind; int rle; } LSPEC[] = {
	{ 0, 0 }, { 1, 0 }, { 2, 0 }, { 3, 0 }, { 4, 0 }, { 5, 1 },
};
#define NL ((int)(sizeof(LSPEC) / sizeof(LSPEC[0])))

static struct lzc lcorp[NL];
static int lbuilt;

static void lbuild(void)
{
	unsigned char *plain;
	void *wrk;
	int i;

	if (lbuilt)
		return;
	lbuilt = 1;
	plain = malloc(LPLAIN);
	wrk = malloc(LZO1X_MEM_COMPRESS);
	if (!plain || !wrk)
		abort();

	for (i = 0; i < NL; i++) {
		struct lzc *z = &lcorp[i];
		size_t cl = lzo1x_worst_compress(LPLAIN) + 64;

		lgen(LSPEC[i].kind, plain, LPLAIN);
		z->comp = malloc(cl);
		z->out = malloc(LPLAIN + 64);
		if (!z->comp || !z->out)
			abort();
		if ((LSPEC[i].rle ? lzorle1x_1_compress : lzo1x_1_compress)
		    (plain, LPLAIN, z->comp, &cl, wrk) != LZO_E_OK)
			abort();
		z->clen = cl;
		z->plain_len = LPLAIN;
	}
	free(plain);
	free(wrk);
}

uint64_t lzo_c(unsigned long n, void *ctx);
uint64_t lzo_c(unsigned long n, void *ctx)
{
	struct lzc *z = (struct lzc *)ctx;
	uint64_t acc = 0;

	for (unsigned long i = 0; i < n; i++) {
		size_t ol = z->plain_len;

		ref_lzo1x_decompress_safe(z->comp, z->clen, z->out, &ol);
		acc += ol;
	}
	return acc;
}

uint64_t lzo_rust(unsigned long n, void *ctx);
uint64_t lzo_rust(unsigned long n, void *ctx)
{
	struct lzc *z = (struct lzc *)ctx;
	uint64_t acc = 0;

	for (unsigned long i = 0; i < n; i++) {
		size_t ol = z->plain_len;

		rust_lzo1x_decompress_safe(z->comp, z->clen, z->out, &ol);
		acc += ol;
	}
	return acc;
}

#define LSETUP(i)                                   \
	void *lsetup_##i(void);                     \
	void *lsetup_##i(void)                      \
	{                                           \
		lbuild();                           \
		return &lcorp[i];                   \
	}
LSETUP(0) LSETUP(1) LSETUP(2) LSETUP(3) LSETUP(4) LSETUP(5)
