#pragma once
#define unlikely(x) __builtin_expect(!!(x), 0)
#define likely(x)   __builtin_expect(!!(x), 1)
#define __always_inline inline __attribute__((always_inline))
#define typecheck(type, x) ((void)0)
#define READ_ONCE(x) (*(const volatile __typeof__(x) *)&(x))
#define WRITE_ONCE(x, val) (*(volatile __typeof__(x) *)&(x) = (val))
