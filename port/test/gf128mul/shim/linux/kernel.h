#pragma once
#include <linux/types.h>
#include <string.h>
#define PTR_ALIGN(p, a) ((__typeof__(p))(((uintptr_t)(p) + (a) - 1) & ~(uintptr_t)((a) - 1)))
