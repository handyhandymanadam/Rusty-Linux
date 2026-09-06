#pragma once
#include <limits.h>

#define __must_check
#define __user
#define noinline
#define unlikely(x) __builtin_expect(!!(x), 0)
#define likely(x)   __builtin_expect(!!(x), 1)
