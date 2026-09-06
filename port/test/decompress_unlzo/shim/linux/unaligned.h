/* Userspace shim: big-endian unaligned accessors (decompress_unlzo.c only
 * uses the BE forms, unlike decompress_unlz4.c's LE ones). */
#ifndef _SHIM_UNLZO_LINUX_UNALIGNED_H
#define _SHIM_UNLZO_LINUX_UNALIGNED_H
#include <stdint.h>

static inline uint16_t get_unaligned_be16(const void *p)
{
	const uint8_t *b = (const uint8_t *)p;
	return (uint16_t)((b[0] << 8) | b[1]);
}

static inline uint32_t get_unaligned_be32(const void *p)
{
	const uint8_t *b = (const uint8_t *)p;
	return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
	       ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}
#endif
