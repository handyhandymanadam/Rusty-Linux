/* Stand-ins for what the pristine slice of kernel/sched/pelt.c uses. */
#ifndef REFSHIM_H
#define REFSHIM_H
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64; typedef int64_t s64;
#define unlikely(x) __builtin_expect(!!(x), 0)
#define __always_inline inline __attribute__((always_inline))
#define __maybe_unused __attribute__((unused))
#define static_assert(x) _Static_assert(x, #x)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define WRITE_ONCE(x, v) ((x) = (v))
#define SCHED_CAPACITY_SHIFT 10
#include "sched-pelt.h"
#define PELT_MIN_DIVIDER (LOAD_AVG_MAX - 1024)
struct sched_avg { u64 last_update_time, load_sum, runnable_sum; u32 util_sum, period_contrib; unsigned long load_avg, runnable_avg, util_avg; unsigned int util_est; };
static inline u64 mul_u64_u32_shr(u64 a, u32 mul, unsigned int shift) { return (u64)(((unsigned __int128)a * mul) >> shift); }
static inline u64 div_u64(u64 a, u32 b) { return a / b; }
static inline u32 get_pelt_divider(struct sched_avg *avg) { return PELT_MIN_DIVIDER + avg->period_contrib; }
#endif
