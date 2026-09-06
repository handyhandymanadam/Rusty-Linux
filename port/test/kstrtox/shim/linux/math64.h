#pragma once
#include "linux/types.h"

/* div_u64(u64, u32) is plain division at BITS_PER_LONG == 64 -- see
 * include/linux/math64.h. The host is x86-64, so this is not a shortcut. */
static inline u64 div_u64(u64 dividend, u32 divisor)
{
	return dividend / divisor;
}
