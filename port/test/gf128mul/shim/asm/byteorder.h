#pragma once
#include <stdint.h>
/* little-endian x86-64 host, as the kernel target */
#define cpu_to_be64(x) ((uint64_t)__builtin_bswap64((uint64_t)(x)))
#define be64_to_cpu(x) ((uint64_t)__builtin_bswap64((uint64_t)(x)))
#define cpu_to_le64(x) ((uint64_t)(x))
#define le64_to_cpu(x) ((uint64_t)(x))
