#pragma once
/* This machine is little-endian, matching every config this project
 * builds -- cpu_to_beNN() is exactly a byte-swap. */
#include <linux/types.h>

static inline __be32 cpu_to_be32(uint32_t x)
{
	return __builtin_bswap32(x);
}

static inline __be64 cpu_to_be64(uint64_t x)
{
	return __builtin_bswap64(x);
}
