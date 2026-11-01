/* Stand-ins for what the pristine slice of kernel/time/clockevents.c uses. */
#ifndef REFSHIM_H
#define REFSHIM_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
typedef int64_t s64; typedef uint64_t u64; typedef int32_t s32; typedef uint32_t u32; typedef int64_t ktime_t;
#define NSEC_PER_SEC 1000000000L
#define KTIME_MAX INT64_MAX
#define ETIME 62
#define do_div(n, base) ({ uint32_t __b = (base); uint32_t __r = (uint32_t)((n) % __b); (n) /= __b; __r; })
#define min(a, b) ({ __typeof__(a) _a = (a); __typeof__(b) _b = (b); _a < _b ? _a : _b; })
#define max(a, b) ({ __typeof__(a) _a = (a); __typeof__(b) _b = (b); _a > _b ? _a : _b; })
extern int warns, hz_;
#define MIN_DELTA_LIMIT (NSEC_PER_SEC / hz_)
#define WARN_ON(c) ({ int __c = !!(c); if (__c) warns++; __c; })
#define WARN_ON_ONCE(c) ({ int __c = !!(c); if (__c) warns++; __c; })
#define WARN_ONCE(c, ...) ({ int __c = !!(c); if (__c) warns++; __c; })
#define KERN_WARNING "W:"
#define printk_deferred(...) printf(__VA_ARGS__)
#define EXPORT_SYMBOL_GPL(x)
#define CLOCK_EVT_FEAT_PERIODIC 0x000001
#define CLOCK_EVT_FEAT_ONESHOT 0x000002
#define CLOCK_EVT_FEAT_KTIME 0x000004
enum clock_event_state { CLOCK_EVT_STATE_DETACHED, CLOCK_EVT_STATE_SHUTDOWN, CLOCK_EVT_STATE_PERIODIC, CLOCK_EVT_STATE_ONESHOT, CLOCK_EVT_STATE_ONESHOT_STOPPED };
struct clock_event_device {
	int (*set_next_event)(unsigned long evt, struct clock_event_device *); int (*set_next_ktime)(ktime_t expires, struct clock_event_device *);
	ktime_t next_event; u64 max_delta_ns; u64 min_delta_ns; u32 mult; u32 shift; enum clock_event_state state_use_accessors; unsigned int features; unsigned long retries;
	unsigned long min_delta_ticks; unsigned long max_delta_ticks; const char *name;
};
extern ktime_t now_ns;
static inline ktime_t ktime_get(void) { return now_ns; }
static inline ktime_t ktime_add_ns(ktime_t kt, u64 ns) { return kt + (s64)ns; }
static inline ktime_t ktime_sub(ktime_t a, ktime_t b) { return a - b; }
static inline s64 ktime_to_ns(ktime_t kt) { return kt; }
static inline bool clockevent_state_shutdown(struct clock_event_device *dev) { return dev->state_use_accessors == CLOCK_EVT_STATE_SHUTDOWN; }
static inline bool clockevent_state_oneshot(struct clock_event_device *dev) { return dev->state_use_accessors == CLOCK_EVT_STATE_ONESHOT; }
static inline int clockevent_get_state(struct clock_event_device *dev) { return dev->state_use_accessors; }
void clocks_calc_mult_shift(u32 *mult, u32 *shift, u32 from, u32 to, u32 maxsec);
static inline void clockevents_calc_mult_shift(struct clock_event_device *ce, u32 freq, u32 maxsec) { clocks_calc_mult_shift(&ce->mult, &ce->shift, NSEC_PER_SEC, freq, maxsec); }
#endif
