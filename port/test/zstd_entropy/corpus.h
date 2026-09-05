/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ZSTD_ENTROPY_CORPUS_H
#define ZSTD_ENTROPY_CORPUS_H
#include <stddef.h>
#include <stdint.h>

/* xorshift64*, so the corpus is reproducible from the seed alone. */
uint64_t rng_next(uint64_t *s);
uint32_t rng_below(uint64_t *s, uint32_t n);

/* Fill `buf` with an FSE NCount header candidate; returns its length.
 * `shape` selects how much structure to impose -- see corpus.c. */
size_t gen_ncount(uint64_t *s, uint8_t *buf, size_t cap, int shape);

/* Fill `buf` with a Huffman weight header candidate; returns its length. */
size_t gen_hufstats(uint64_t *s, uint8_t *buf, size_t cap, int shape);

/* Fill `buf` with an FSE-compressed block candidate for FSE_decompress_wksp. */
size_t gen_fseblock(uint64_t *s, uint8_t *buf, size_t cap, int shape);

#endif
