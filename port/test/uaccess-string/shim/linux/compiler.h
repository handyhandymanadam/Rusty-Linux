#pragma once
#define __always_inline inline __attribute__((always_inline))
#define __user
#define __force
#define unlikely(x) __builtin_expect(!!(x), 0)
#define likely(x)   __builtin_expect(!!(x), 1)
/* No ftrace in this userspace differential -- a no-op here, real in the
 * kernel build (include/linux/compiler_types.h). */
#define notrace
