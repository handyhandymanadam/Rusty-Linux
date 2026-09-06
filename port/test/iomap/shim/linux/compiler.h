#pragma once
#define unlikely(x) __builtin_expect(!!(x), 0)
#define likely(x)   __builtin_expect(!!(x), 1)
#define __always_inline inline __attribute__((always_inline))
