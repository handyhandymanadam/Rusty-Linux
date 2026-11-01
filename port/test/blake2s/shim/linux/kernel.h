#pragma once
#include <stddef.h>
#include "types.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define likely(x) (x)
#define unlikely(x) (x)
#define __maybe_unused __attribute__((unused))

/* x86-64 is little-endian, same as every real kernel build this project
 * targets, so both of these are true no-ops -- not stubs standing in for
 * missing behavior. */
static inline void le32_to_cpu_array(u32 *buf, size_t words)
{
	(void)buf;
	(void)words;
}
static inline void cpu_to_le32_array(u32 *buf, size_t words)
{
	(void)buf;
	(void)words;
}
static inline u32 ror32(u32 word, unsigned int shift)
{
	return (word >> (shift & 31)) | (word << ((-shift) & 31));
}
