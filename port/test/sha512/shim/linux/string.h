#pragma once
#include <string.h>

static inline void memzero_explicit(void *s, size_t n)
{
	memset(s, 0, n);
}
