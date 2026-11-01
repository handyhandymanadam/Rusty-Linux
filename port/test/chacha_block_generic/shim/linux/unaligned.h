#pragma once
#include "types.h"

static inline void put_unaligned_le32(u32 val, void *p)
{
	u8 *b = (u8 *)p;
	b[0] = (u8)(val);
	b[1] = (u8)(val >> 8);
	b[2] = (u8)(val >> 16);
	b[3] = (u8)(val >> 24);
}

static inline u32 get_unaligned_le32(const void *p)
{
	const u8 *b = (const u8 *)p;
	return (u32)b[0] | ((u32)b[1] << 8) | ((u32)b[2] << 16) | ((u32)b[3] << 24);
}
