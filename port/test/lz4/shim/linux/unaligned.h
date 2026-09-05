/* Userspace shim: the kernel's packed-struct unaligned accessors.
 *
 * Written out rather than reusing port/test/lib/shim's memcpy version,
 * because lzodefs.h's COPY4/COPY8 nest get_unaligned() inside
 * put_unaligned() on `const` pointers and the memcpy version discards the
 * qualifier. This is the shape include/asm-generic/unaligned.h actually uses.
 */
#ifndef _SHIM_LINUX_UNALIGNED_H
#define _SHIM_LINUX_UNALIGNED_H

/* lz4defs.h includes this FIRST and then uses likely()/__always_inline/
 * BUILD_BUG_ON before it reaches <linux/kernel.h>, so they have to be here
 * rather than in the kernel.h shim. */
#ifndef likely
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#ifndef BUILD_BUG_ON
#define BUILD_BUG_ON(cond) ((void)sizeof(char[1 - 2 * !!(cond)]))
#endif
#include <stdint.h>
#include <string.h>

#define __get_unaligned_t(type, ptr) ({						\
	const struct { type x; } __attribute__((packed, may_alias)) *__pptr =	\
		(const void *)(ptr);						\
	__pptr->x;								\
})

#define __put_unaligned_t(type, val, ptr) do {					\
	struct { type x; } __attribute__((packed, may_alias)) *__pptr =		\
		(void *)(ptr);							\
	__pptr->x = (val);							\
} while (0)

#define get_unaligned(ptr)      __get_unaligned_t(__typeof__(*(ptr)), (ptr))
#define put_unaligned(val, ptr) __put_unaligned_t(__typeof__(*(ptr)), (val), (ptr))

static inline uint16_t get_unaligned_le16(const void *p)
{
	const uint8_t *b = (const uint8_t *)p;

	return (uint16_t)b[0] | ((uint16_t)b[1] << 8);
}

static inline uint32_t get_unaligned_le32(const void *p)
{
	const uint8_t *b = (const uint8_t *)p;

	return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
	       ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static inline void put_unaligned_le16(uint16_t v, void *p)
{
	uint8_t *b = (uint8_t *)p;

	b[0] = (uint8_t)v;
	b[1] = (uint8_t)(v >> 8);
}
static inline void put_unaligned_le32(uint32_t v, void *p)
{
	uint8_t *b = (uint8_t *)p;

	b[0] = (uint8_t)v;
	b[1] = (uint8_t)(v >> 8);
	b[2] = (uint8_t)(v >> 16);
	b[3] = (uint8_t)(v >> 24);
}
#endif
