/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ZSTD_HUF_CORPUS_H
#define ZSTD_HUF_CORPUS_H
#include <stddef.h>
#include <stdint.h>

uint64_t rng_next(uint64_t *s);
uint32_t rng_below(uint64_t *s, uint32_t n);

/* One Huffman literals section, lifted out of a real zstd frame. */
struct lits {
	const uint8_t *buf;	/* the literals payload: tree description + streams */
	size_t len;		/* Compressed_Size from the section header */
	size_t regen;		/* Regenerated_Size -- the decoded length */
	int single;		/* 1 = one stream (1X), 0 = four streams (4X) */
};

/* Build the pool by compressing generated plaintexts with SYSTEM libzstd and
 * walking the frames. Returns how many sections were found. */
unsigned corpus_build(uint64_t *s);

/* Pick one, optionally corrupted. `mutations` is how many bytes were flipped;
 * the returned buffer is scratch owned by the corpus. */
const struct lits *corpus_pick(uint64_t *s, int mutate, unsigned *mutations);

#endif
