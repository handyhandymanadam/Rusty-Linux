/* THE INLINING PRIZE, zlib_inflate arm.
 *
 * The question this answers: what does putting Rust INSIDE the LTO graph buy,
 * on OUR shape of code? Not on a block driver in a VM, which is the only
 * published number (Hindborg, Kangrejos 2023: "No observable performance
 * difference for rnull").
 *
 * Both arms run the SAME code -- C zlib_inflate() calling the ported Rust
 * inflate_fast(). The only difference is whether the link had -flto=thin, so
 * the difference IS cross-language optimisation and nothing else.
 *
 * WHY INSTRUCTIONS AND NOT SECONDS. Two arms means two binaries, and two
 * binaries differ in layout; the rig's own note records that "a single binary
 * constitutes just one sample from the space of program layouts", which is
 * why bench.c puts both arms in one binary. That trick is unavailable here --
 * the arms differ by how they were LINKED. So the primary measure is retired
 * instructions under callgrind, which is deterministic and layout-independent.
 * Wall time is reported too, and is NOT the citable number.
 */
#include <linux/zlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern long corpus_compress(const unsigned char *src, unsigned long n,
                            int level, int window_bits, int mem_level,
                            int strategy, unsigned char *dst,
                            unsigned long dcap);
extern int zlib_inflateInit2(z_streamp strm, int windowBits);
extern int zlib_inflate(z_streamp strm, int flush);
extern int zlib_inflateEnd(z_streamp strm);
extern int zlib_inflate_workspacesize(void);

#define RAW (1u << 18)

/* Deterministic, and deliberately match-heavy: long-range repeats are what
 * drive inflate_fast()'s copy loop, which is the ported code. */
static void gen(unsigned char *b, unsigned long n)
{
	static const char *w[] = { "the ", "quick ", "brown ", "fox ", "jumps ",
				   "over ", "lazy ", "dog " };
	unsigned long i = 0;
	unsigned s = 12345;
	while (i < n) {
		s = s * 1103515245u + 12345u;
		const char *p = w[(s >> 16) & 7];
		unsigned long l = strlen(p);
		if (i + l > n) break;
		memcpy(b + i, p, l);
		i += l;
	}
	while (i < n) b[i++] = ' ';
}

int main(int argc, char **argv)
{
	unsigned long iters = (argc > 1) ? strtoul(argv[1], NULL, 10) : 400;
	/* Block size: 0 means one stream over the whole buffer (the original
	 * shape). Anything else splits the input into independent streams of
	 * that size -- which is how squashfs, zram, initramfs and ubifs
	 * actually call this code, and it multiplies the number of times the
	 * C->Rust boundary is crossed for the same total bytes. Adversarial
	 * review showed the effect is 18x larger at 512 bytes than at one
	 * 256 KB stream, so a single shape cannot carry the conclusion. */
	unsigned long bs = (argc > 2) ? strtoul(argv[2], NULL, 10) : 0;
	if (bs == 0 || bs > RAW) bs = RAW;
	unsigned nblk = (unsigned)(RAW / bs);

	unsigned char *raw = malloc(RAW), *comp = malloc(RAW * 2);
	unsigned char *out = malloc(RAW + 64);
	void *ws = malloc((size_t)zlib_inflate_workspacesize());
	long *clen = calloc(nblk, sizeof(long));
	long *coff = calloc(nblk, sizeof(long));
	if (!raw || !comp || !out || !ws || !clen || !coff) return 2;

	gen(raw, RAW);
	long at = 0;
	for (unsigned b = 0; b < nblk; b++) {
		long n = corpus_compress(raw + (unsigned long)b * bs, bs, 6, -15, 8, 0,
					 comp + at, RAW * 2 - at);
		if (n <= 0) { fprintf(stderr, "compress failed\n"); return 2; }
		coff[b] = at; clen[b] = n; at += n;
	}

	unsigned long acc = 0, crossings = 0;
	for (unsigned long it = 0; it < iters; it++) {
		for (unsigned b = 0; b < nblk; b++) {
			z_stream s;
			memset(&s, 0, sizeof s);
			s.workspace = ws;
			s.next_in = comp + coff[b];  s.avail_in = (uInt)clen[b];
			s.next_out = out;            s.avail_out = RAW + 64;
			if (zlib_inflateInit2(&s, -15) != Z_OK) return 3;
			int r = zlib_inflate(&s, Z_FINISH);
			if (r != Z_STREAM_END && r != Z_OK) { fprintf(stderr, "inflate %d\n", r); return 3; }
			zlib_inflateEnd(&s);
			acc += s.total_out;
			acc ^= out[b & 63];
			crossings++;
		}
	}
	/* Printed so nothing above can be optimised away, and so the number of
	 * BOUNDARY CROSSINGS is reported next to the result -- the ratio is
	 * meaningless without it. */
	printf("%lu %lu %lu %lu\n", iters, bs, crossings, acc);
	return 0;
}
