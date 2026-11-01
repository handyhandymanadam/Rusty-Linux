/* Stand-ins for what the pristine slice of kernel/time/clocksource.c uses. */
#ifndef REFSHIM_H
#define REFSHIM_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
typedef int64_t s64; typedef uint64_t u64; typedef int32_t s32; typedef uint32_t u32;
#define NSEC_PER_SEC 1000000000L
#define NSEC_PER_USEC 1000L
#define do_div(n, base) ({ uint32_t __b = (base); uint32_t __r = (uint32_t)((n) % __b); (n) /= __b; __r; })
#define min(a, b) ({ __typeof__(a) _a = (a); __typeof__(b) _b = (b); _a < _b ? _a : _b; })
extern long max_skew_usec; extern int warns;
#define MAX_SKEW_USEC max_skew_usec
#define WATCHDOG_THRESHOLD (NSEC_PER_SEC >> 5)
#define WATCHDOG_MAX_SKEW (MAX_SKEW_USEC * NSEC_PER_USEC)
#define WARN_ON_ONCE(c) ({ int __c = !!(c); if (__c) warns++; __c; })
#define WARN_ONCE(c, ...) ({ int __c = !!(c); if (__c) warns++; __c; })
#define pr_info(...) printf(__VA_ARGS__)
#define EXPORT_SYMBOL_GPL(x)
struct clocksource {
	u64 mask; u32 mult; u32 shift; u64 max_idle_ns; u32 maxadj; u32 uncertainty_margin; u64 max_cycles; u64 max_raw_delta; const char *name;
};
static inline s64 clocksource_cyc2ns(u64 cycles, u32 mult, u32 shift) { return ((u64) cycles * mult) >> shift; }
#endif
