#include <stdint.h>
typedef uint8_t u8; typedef uint64_t u64; typedef int64_t s64; typedef uint64_t __be64;
#define be64_to_cpu(x) __builtin_bswap64(x)
#define cpu_to_be64(x) __builtin_bswap64(x)
static inline void crypto_xor(u8 *dst, const u8 *src, unsigned int n) { while (n--) *dst++ ^= *src++; }
