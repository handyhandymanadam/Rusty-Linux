#pragma once
#include <string.h>
#include "types.h"

/* Host is x86-64: little-endian, unaligned access is fine. */

static inline u32 get_unaligned_le32(const void *p)
{
	u32 v;
	memcpy(&v, p, 4);
	return v;
}

static inline void put_unaligned_le32(u32 v, void *p)
{
	memcpy(p, &v, 4);
}
