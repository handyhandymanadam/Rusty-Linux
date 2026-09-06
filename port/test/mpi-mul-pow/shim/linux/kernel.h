#pragma once
#include <linux/types.h>
#include <assert.h>

#define BUG_ON(cond) assert(!(cond))

#define swap(a, b) \
	do { __typeof__(a) _tmp = (a); (a) = (b); (b) = _tmp; } while (0)
