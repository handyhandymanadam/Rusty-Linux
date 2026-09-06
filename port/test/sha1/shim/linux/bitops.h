#pragma once
#include "types.h"

static inline u32 rol32(u32 word, unsigned int shift)
{
	return (word << shift) | (word >> (32 - shift));
}

static inline u32 ror32(u32 word, unsigned int shift)
{
	return (word >> shift) | (word << (32 - shift));
}
