#pragma once
#include <string.h>
#include "types.h"

/* Host is x86-64: little-endian, unaligned access is fine. */

static inline u32 get_unaligned_be32(const void *p)
{
	u32 v;
	memcpy(&v, p, 4);
	return __builtin_bswap32(v);
}

static inline void put_unaligned_be32(u32 v, void *p)
{
	v = __builtin_bswap32(v);
	memcpy(p, &v, 4);
}

static inline u64 get_unaligned_be64(const void *p)
{
	u64 v;
	memcpy(&v, p, 8);
	return __builtin_bswap64(v);
}

static inline void put_unaligned_be64(u64 v, void *p)
{
	v = __builtin_bswap64(v);
	memcpy(p, &v, 8);
}

static inline __be64 cpu_to_be64(u64 v)
{
	return __builtin_bswap64(v);
}

static inline __be32 cpu_to_be32(u32 v)
{
	return __builtin_bswap32(v);
}
