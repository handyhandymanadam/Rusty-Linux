#pragma once
#include <string.h>

static inline void memzero_explicit(void *s, size_t count)
{
	memset(s, 0, count);
}
