#pragma once
#include <linux/types.h>
#include <assert.h>

#define BITS_PER_LONG 64

#define BUG_ON(cond) assert(!(cond))

#define swap(a, b) \
	do { __typeof__(a) _tmp = (a); (a) = (b); (b) = _tmp; } while (0)

#define min_t(type, a, b) ((type)(a) < (type)(b) ? (type)(a) : (type)(b))
