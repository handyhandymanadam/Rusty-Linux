/* Just enough kernel for the pristine kernel/time/timeconv.c to compile in userspace. */
#include <stdint.h>
#include <stdbool.h>
typedef int64_t time64_t; typedef uint64_t u64; typedef uint32_t u32; typedef uint16_t u16; typedef int64_t s64; typedef uint8_t u8;
struct tm { int tm_sec, tm_min, tm_hour, tm_mday, tm_mon; long tm_year; int tm_wday, tm_yday; };
#define EXPORT_SYMBOL(x)
#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))
#define lower_32_bits(n) ((u32)((n) & 0xffffffff))
static inline s64 div_s64_rem(s64 dividend, int divisor, int *remainder) { *remainder = dividend % divisor; return dividend / divisor; }
static inline u64 div64_u64_rem(u64 dividend, u64 divisor, u64 *remainder) { *remainder = dividend % divisor; return dividend / divisor; }
