/* SPDX-License-Identifier: GPL-2.0
 *
 * Corpus for the lib/zstd Huffman-decoder differential.
 *
 * WHERE THE INPUT COMES FROM, AND WHY IT IS NOT GENERATED. HUF_decompress*
 * consumes a Huffman tree description followed by one or four bitstreams. A
 * generator for that is a Huffman ENCODER, and a corpus encoder that does not
 * round-trip is the fault notes/STATUS.md lesson 12 records costing two hours on
 * lib/lz4. The kernel's own encoder is not even built (CONFIG_ZSTD_COMPRESS is
 * n), so the corpus is LIFTED OUT OF REAL FRAMES instead: SYSTEM libzstd
 * compresses generated plaintexts, this walks each frame's block headers, and
 * every Compressed_Literals_Block's payload becomes one corpus entry with its
 * Regenerated_Size and stream count read from the section header.
 *
 * That also makes the corpus an INDEPENDENT instrument. libzstd is not derived
 * from the kernel's decoder, so the sections it chooses to emit -- which table
 * logs, which stream counts, which weight distributions -- are not the ones
 * our decoder would have picked for itself.
 *
 * The valid sections are then MUTATED, because the decoder's job is to reject
 * corrupt input safely and the error paths are most of the code. A mutation
 * count is reported per run so a corpus that stopped corrupting anything is
 * visible rather than silent.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zstd.h>
#include "corpus.h"

uint64_t rng_next(uint64_t *s)
{
	uint64_t x = *s;
	x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
	*s = x;
	return x * 0x2545F4914F6CDD1DULL;
}

uint32_t rng_below(uint64_t *s, uint32_t n)
{
	return n ? (uint32_t)(rng_next(s) % n) : 0;
}

#define POOL_MAX   4096
#define PLAIN_MAX  (96 * 1024)
#define COMP_MAX   (128 * 1024)
#define LITS_MAX   (128 * 1024)

static struct lits pool[POOL_MAX];
static unsigned pool_n;
static uint8_t *pool_store;
static size_t pool_used;
static uint8_t scratch[LITS_MAX];

/* Six shapes, chosen so libzstd is pushed down different literal encodings:
 * skewed bytes want a deep Huffman table, near-uniform text a shallow one,
 * long repeats push literals down to almost nothing. */
static size_t make_plain(uint64_t *s, int shape, uint8_t *p, size_t cap)
{
	static const char *w[] = { "the ", "kernel ", "decoder ", "reads ", "a ",
		"literals ", "section ", "and ", "writes ", "bytes ", "out ",
		"after ", "checking ", "every ", "single ", "bound " };
	size_t n = 0;

	switch (shape) {
	case 0:
		while (n < cap - 32)
			n += (size_t)sprintf((char *)p + n, "%s", w[rng_next(s) % 16]);
		break;
	case 1:					/* heavily skewed: deep table */
		for (n = 0; n < cap; n++) {
			uint64_t r = rng_next(s);
			p[n] = (uint8_t)((r % 1000) < 800 ? 'e'
					 : (r % 1000) < 950 ? 'a' + (r % 6)
					 : r % 256);
		}
		break;
	case 2:					/* near-uniform: shallow table */
		for (n = 0; n < cap; n++)
			p[n] = (uint8_t)(rng_next(s) % 200);
		break;
	case 3:					/* long repeats */
		for (n = 0; n < 128 && n < cap; n++)
			p[n] = (uint8_t)('a' + (rng_next(s) % 26));
		while (n < cap) {
			size_t len = 8 + rng_next(s) % 300, off = rng_next(s) % n;
			if (len > cap - n) len = cap - n;
			if (off + len > n) len = n - off;
			if (!len) { p[n++] = (uint8_t)rng_next(s); continue; }
			memcpy(p + n, p + off, len);
			n += len;
		}
		break;
	case 4:					/* two alphabets, alternating */
		for (n = 0; n < cap; n++)
			p[n] = (uint8_t)((n / 512) % 2 ? 'A' + (rng_next(s) % 5)
						      : 128 + (rng_next(s) % 60));
		break;
	default:
		for (n = 0; n < cap; n++)
			p[n] = (uint8_t)((rng_next(s) % 7) ? 'x' : rng_next(s));
	}
	return n > cap ? cap : n;
}

static uint32_t rd24(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);
}

/* Walk one frame and push every Compressed_Literals_Block into the pool. */
static void harvest(const uint8_t *f, size_t n)
{
	size_t i;
	uint8_t fhd;
	unsigned fcs_flag, single_seg, dict_flag, fcs_size;

	if (n < 6 || rd24(f) != 0x2FB528u || f[3] != 0xFD)
		return;
	i = 4;
	fhd = f[i++];
	fcs_flag = fhd >> 6;
	single_seg = (fhd >> 5) & 1;
	dict_flag = fhd & 3;
	if (!single_seg)
		i++;
	i += dict_flag == 3 ? 4 : dict_flag;
	fcs_size = fcs_flag == 0 ? (single_seg ? 1u : 0u)
		 : fcs_flag == 1 ? 2u : fcs_flag == 2 ? 4u : 8u;
	i += fcs_size;

	for (;;) {
		uint32_t bh, bsize;
		unsigned last, btype;

		if (i + 3 > n)
			return;
		bh = rd24(f + i);
		i += 3;
		last = bh & 1;
		btype = (bh >> 1) & 3;
		bsize = bh >> 3;
		if (i + bsize > n)
			return;

		if (btype == 2 && bsize >= 5) {
			const uint8_t *b = f + i;
			unsigned ltype = b[0] & 3;
			unsigned sfmt = (b[0] >> 2) & 3;

			if (ltype == 2) {	/* Compressed_Literals_Block */
				uint64_t v = 0;
				unsigned hdr, bits;
				size_t regen, csize;
				unsigned k;

				if (sfmt <= 1)      { hdr = 3; bits = 10; }
				else if (sfmt == 2) { hdr = 4; bits = 14; }
				else                { hdr = 5; bits = 18; }
				for (k = 0; k < hdr; k++)
					v |= (uint64_t)b[k] << (8 * k);
				regen = (size_t)((v >> 4) & ((1u << bits) - 1));
				csize = (size_t)((v >> (4 + bits)) & ((1u << bits) - 1));

				if (csize && hdr + csize <= bsize &&
				    csize <= LITS_MAX && pool_n < POOL_MAX &&
				    pool_used + csize <= (size_t)POOL_MAX * 4096) {
					memcpy(pool_store + pool_used, b + hdr, csize);
					pool[pool_n].buf = pool_store + pool_used;
					pool[pool_n].len = csize;
					pool[pool_n].regen = regen;
					/* Size_Format 00 is the ONE-stream form;
					 * 01, 10 and 11 are all four-stream. */
					pool[pool_n].single = (sfmt == 0);
					pool_used += csize;
					pool_n++;
				}
			}
		}
		i += bsize;
		if (last)
			return;
	}
}

unsigned corpus_build(uint64_t *s)
{
	uint8_t *plain = malloc(PLAIN_MAX);
	uint8_t *comp = malloc(COMP_MAX);
	int shape, level;

	pool_store = malloc((size_t)POOL_MAX * 4096);
	if (!plain || !comp || !pool_store) {
		fprintf(stderr, "corpus: out of memory\n");
		exit(2);
	}
	for (shape = 0; shape < 6; shape++) {
		for (level = 1; level <= 19; level += 1) {
			size_t pl = make_plain(s, shape, plain, PLAIN_MAX);
			size_t cl = ZSTD_compress(comp, COMP_MAX, plain, pl, level);

			if (!ZSTD_isError(cl))
				harvest(comp, cl);
		}
	}
	free(plain);
	free(comp);
	return pool_n;
}

const struct lits *corpus_pick(uint64_t *s, int mutate, unsigned *mutations)
{
	static struct lits out;
	const struct lits *p = &pool[rng_below(s, pool_n)];
	unsigned m = 0;

	out = *p;
	if (!mutate || !p->len)
		return &out;

	memcpy(scratch, p->buf, p->len);
	out.buf = scratch;
	/* Mostly light corruption -- a single flipped bit still parses far
	 * enough to reach the decode loops, where the interesting checks are.
	 * Heavy corruption mostly dies in the tree description. */
	m = 1 + rng_below(s, 3);
	{
		unsigned k;
		for (k = 0; k < m; k++)
			scratch[rng_below(s, (uint32_t)p->len)] ^=
				(uint8_t)(1u << rng_below(s, 8));
	}
	/* and sometimes lie about the sizes, which is what a corrupt section
	 * header would do to an otherwise valid payload */
	if (rng_below(s, 4) == 0)
		out.len = rng_below(s, (uint32_t)p->len + 1);
	if (rng_below(s, 4) == 0)
		out.regen = rng_below(s, 70000);
	*mutations = m;
	return &out;
}
