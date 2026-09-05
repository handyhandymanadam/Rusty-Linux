/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_LINUX_XXHASH_H
#define _SHIM_LINUX_XXHASH_H
#include <linux/types.h>
struct xxh32_state {
	uint32_t total_len_32;
	uint32_t large_len;
	uint32_t v1, v2, v3, v4;
	uint32_t mem32[4];
	uint32_t memsize;
};
struct xxh64_state {
	uint64_t total_len;
	uint64_t v1, v2, v3, v4;
	uint64_t mem64[4];
	uint32_t memsize;
};
void xxh32_copy_state(struct xxh32_state *dst, const struct xxh32_state *src);
void xxh64_copy_state(struct xxh64_state *dst, const struct xxh64_state *src);
uint32_t xxh32(const void *input, size_t length, uint32_t seed);
uint64_t xxh64(const void *input, size_t length, uint64_t seed);
void xxh32_reset(struct xxh32_state *state, uint32_t seed);
void xxh64_reset(struct xxh64_state *state, uint64_t seed);
int xxh64_update(struct xxh64_state *state, const void *input, size_t length);
uint64_t xxh64_digest(const struct xxh64_state *state);
#endif
