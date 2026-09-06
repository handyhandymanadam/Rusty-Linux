#pragma once
/* Nothing aes.c uses directly comes from <linux/crypto.h> itself; included
 * transitively upstream but empty is sufficient for this differential.
 * ror32() (really from <linux/bitops.h>, pulled in transitively in the
 * real kernel) is defined here since this header is always included. */
#include "types.h"
#define ____cacheline_aligned

static inline u32 ror32(u32 word, unsigned int shift)
{
	return (word >> shift) | (word << (32 - shift));
}
