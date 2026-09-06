#pragma once
#include <stddef.h>
#include "types.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define REPEAT_BYTE(x) ((~0UL / 0xff) * (x))
#define likely(x) (x)
#define unlikely(x) (x)
#define __init
#define __exit
#define __maybe_unused __attribute__((unused))

static inline u64 ror64(u64 word, unsigned int shift)
{
	return (word >> shift) | (word << (64 - shift));
}
