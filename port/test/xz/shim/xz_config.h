/* SPDX-License-Identifier: 0BSD */
/*
 * Userspace shim for building the PRISTINE lib/xz/xz_dec_bcj.c as the
 * differential's oracle.
 *
 * xz_private.h includes this by name when __KERNEL__ is not defined -- it is
 * the path upstream XZ Embedded already uses, so nothing has to be faked into
 * looking like a kernel. Only what xz_dec_bcj.c actually touches is here.
 *
 * <linux/xz.h> is the REAL header out of src/linux/include, not a copy:
 * struct xz_buf is the caller's layout and notes/GOALS.md §5 puts it out of bounds,
 * so a transcription of it in a test would be the one place a drift could
 * hide.
 */
#ifndef XZ_CONFIG_H
#define XZ_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <linux/xz.h>

#define kmalloc(size, flags) malloc(size)
#define kfree(ptr)           free(ptr)
#define GFP_KERNEL           0

#define min_t(type, a, b) ((type)(a) < (type)(b) ? (type)(a) : (type)(b))

#define memeq(a, b, size)  (memcmp(a, b, size) == 0)
#define memzero(buf, size) memset(buf, 0, size)

static inline uint32_t get_unaligned_le32(const void *p)
{
	const uint8_t *b = (const uint8_t *)p;

	return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
	       ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static inline uint32_t get_unaligned_be32(const void *p)
{
	const uint8_t *b = (const uint8_t *)p;

	return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
	       ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

static inline void put_unaligned_le32(uint32_t v, void *p)
{
	uint8_t *b = (uint8_t *)p;

	b[0] = (uint8_t)v;
	b[1] = (uint8_t)(v >> 8);
	b[2] = (uint8_t)(v >> 16);
	b[3] = (uint8_t)(v >> 24);
}

static inline void put_unaligned_be32(uint32_t v, void *p)
{
	uint8_t *b = (uint8_t *)p;

	b[0] = (uint8_t)(v >> 24);
	b[1] = (uint8_t)(v >> 16);
	b[2] = (uint8_t)(v >> 8);
	b[3] = (uint8_t)v;
}

#define get_le32(p) get_unaligned_le32(p)

#endif
