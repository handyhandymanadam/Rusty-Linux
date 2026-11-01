/* SPDX-License-Identifier: GPL-2.0
 *
 * Corpus for the lib/zstd entropy-header differential.
 *
 * These three functions are PARSERS OF UNTRUSTED INPUT -- everything they
 * read comes off the wire inside a zstd frame -- so the corpus is weighted
 * towards malformed input rather than away from it. Fully random bytes are
 * the single most productive shape here, which is the opposite of the
 * decompressor harnesses, where random bytes bounce off the first header
 * check.
 *
 * The catch is that random bytes also bounce, just later, so the shapes below
 * bias the FIELDS THAT GATE THE PARSER -- the tableLog nibble for NCount, the
 * first byte for HUF_readStats -- while leaving everything past the gate
 * random. main.c counts how many inputs each shape drives to a SUCCESSFUL
 * return and prints it, because a corpus that only ever exercises the error
 * paths is a corpus that has not tested the decoder (notes/STATUS.md lesson 9).
 */
#include "corpus.h"

uint64_t rng_next(uint64_t *s)
{
	uint64_t x = *s;
	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	*s = x;
	return x * 0x2545F4914F6CDD1DULL;
}

uint32_t rng_below(uint64_t *s, uint32_t n)
{
	return n ? (uint32_t)(rng_next(s) % n) : 0;
}

static void fill_random(uint64_t *s, uint8_t *buf, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++)
		buf[i] = (uint8_t)(rng_next(s) >> 24);
}

/* FSE_MIN_TABLELOG is 5 and FSE_TABLELOG_ABSOLUTE_MAX is 15, so the low
 * nibble of byte 0 is tableLog-5 and only 0..10 can parse. Random bytes hit
 * that 11 times in 16; shape 1 hits it always. */
size_t gen_ncount(uint64_t *s, uint8_t *buf, size_t cap, int shape)
{
	size_t len;

	switch (shape) {
	case 0:		/* pure random, mostly short -- the error paths */
		len = rng_below(s, 24);
		break;
	case 1:		/* random, but always long enough to clear hbSize<8 */
		len = 8 + rng_below(s, 40);
		break;
	default:	/* long, and byte 0 forced to a legal tableLog */
		len = 8 + rng_below(s, (uint32_t)(cap - 8));
		break;
	}
	if (len > cap)
		len = cap;
	fill_random(s, buf, len);
	if (shape >= 2 && len > 0)
		buf[0] = (uint8_t)((buf[0] & 0xF0) | rng_below(s, 11));
	return len;
}

/* A WELL-FORMED Huffman weight header, direct (non-FSE) form.
 *
 * Random bytes reach HUF_readStats's success path 14 times in 10,000: the
 * decoder demands that the weights satisfy Kraft equality exactly -- after
 * summing (1<<w)>>1 over the weights, the remainder up to the next power of
 * two must ITSELF be a clean power of two -- and chance does not supply that.
 * A corpus that only ever exercises the error paths has not tested the
 * decoder, so this builds the constraint in rather than waiting for it.
 *
 * Construction. Pick a tableLog L. Spend a budget of 2^L on weights, each
 * weight w costing 2^(w-1), which is exactly the Kraft sum the decoder
 * recomputes. Weight-1 symbols are always emitted in PAIRS, because the
 * decoder rejects an odd rankStats[1] and rejects fewer than two -- and
 * because pairing keeps the budget even, so it can never strand a single
 * unit that would force an odd count. Shuffle, then drop the last weight:
 * that one is the "implied" weight the decoder reconstructs from the
 * remainder, and dropping it is what makes the header well-formed rather
 * than merely plausible.
 *
 * Only the direct form is generated. The FSE-compressed form would need an
 * FSE ENCODER, and a corpus encoder that does not round-trip is the fault
 * notes/STATUS.md lesson 12 records; the FSE weight path is covered instead by the
 * end-to-end layer, which gets its headers from real zstd frames.
 */
static size_t gen_hufstats_valid(uint64_t *s, uint8_t *buf, size_t cap)
{
	uint8_t w[300];
	uint32_t n = 0, L, budget, i, j, oSize;
	size_t need;

	L = 1 + rng_below(s, 12);		/* 1..12 == HUF_TABLELOG_MAX */
	budget = 1u << L;

	/* the mandatory even, >=2 population of rank 1 */
	w[n++] = 1;
	w[n++] = 1;
	budget -= 2;

	while (budget > 0 && n < 250) {
		uint32_t maxw = 1;		/* largest w with 2^(w-1) <= budget */
		while ((1u << maxw) <= budget && maxw < L)
			maxw++;
		{
			uint32_t pick = 1 + rng_below(s, maxw);
			if (pick == 1) {
				if (budget < 2)
					break;
				w[n++] = 1;
				w[n++] = 1;
				budget -= 2;
			} else {
				w[n++] = (uint8_t)pick;
				budget -= 1u << (pick - 1);
			}
		}
	}
	if (budget != 0)			/* ran out of room; unusable */
		return 0;

	/* sprinkle in unused symbols, which cost nothing and must survive */
	for (i = 0; i < 8 && n < 250; i++)
		if (rng_next(s) & 1)
			w[n++] = 0;

	/* Fisher-Yates, then guarantee the dropped (implied) weight is nonzero:
	 * the decoder computes it from a remainder it assumes is positive. */
	for (i = n; i > 1; i--) {
		j = rng_below(s, i);
		{ uint8_t t = w[i - 1]; w[i - 1] = w[j]; w[j] = t; }
	}
	for (i = n; i > 0; i--) {
		if (w[i - 1] != 0) {
			uint8_t t = w[i - 1]; w[i - 1] = w[n - 1]; w[n - 1] = t;
			break;
		}
	}
	if (w[n - 1] == 0)
		return 0;

	oSize = n - 1;				/* the last one is implied */
	if (oSize == 0 || oSize > 128)
		return 0;
	need = 1 + (oSize + 1) / 2;
	if (need > cap)
		return 0;

	buf[0] = (uint8_t)(127 + oSize);
	for (i = 0; i < oSize; i += 2) {
		uint8_t hi = w[i];
		uint8_t lo = (i + 1 < oSize) ? w[i + 1] : 0;
		buf[1 + i / 2] = (uint8_t)((hi << 4) | lo);
	}
	return need;
}

/* HUF_readStats branches on byte 0: >=128 is a direct 4-bit weight table of
 * (byte0-127) weights, <128 is an FSE-compressed table of byte0 bytes. Both
 * branches matter, so shape 2 alternates them deliberately rather than
 * leaving the split to chance. */
size_t gen_hufstats(uint64_t *s, uint8_t *buf, size_t cap, int shape)
{
	size_t len;

	if (shape >= 3) {
		len = gen_hufstats_valid(s, buf, cap);
		if (len)
			return len;
		shape = 2;		/* construction failed; fall back */
	}

	switch (shape) {
	case 0:
		len = rng_below(s, 20);
		break;
	case 1:
		len = 1 + rng_below(s, 64);
		break;
	default:
		len = 1 + rng_below(s, (uint32_t)(cap - 1));
		break;
	}
	if (len > cap)
		len = cap;
	fill_random(s, buf, len);
	if (shape >= 2 && len > 0) {
		if (rng_next(s) & 1) {
			/* direct: oSize = byte0-127, and iSize = (oSize+1)/2
			 * must fit in len-1, or it is rejected before the
			 * loop ever runs. */
			uint32_t max_o = (uint32_t)((len - 1) * 2);
			if (max_o > 128)
				max_o = 128;
			if (max_o >= 1)
				buf[0] = (uint8_t)(128 + rng_below(s, max_o));
		} else {
			/* FSE: iSize = byte0 must satisfy iSize+1 <= len */
			buf[0] = (uint8_t)rng_below(s, (uint32_t)len);
		}
	}
	return len;
}

/* FSE_decompress_wksp reads an NCount header and then a bitstream, so its
 * corpus is an NCount candidate with a tail glued on. */
size_t gen_fseblock(uint64_t *s, uint8_t *buf, size_t cap, int shape)
{
	size_t head = gen_ncount(s, buf, cap > 48 ? 48 : cap, shape);
	size_t tail;

	if (head >= cap)
		return head;
	tail = rng_below(s, (uint32_t)(cap - head));
	fill_random(s, buf + head, tail);
	return head + tail;
}
