#ifndef _SHIM_UNLZO_LINUX_COMPILER_H
#define _SHIM_UNLZO_LINUX_COMPILER_H
#include <string.h>
#ifndef likely
#define likely(x)   __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif
#endif
