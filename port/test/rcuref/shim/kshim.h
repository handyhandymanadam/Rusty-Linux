/* kernel shim for the rcuref differential: atomic_t, the primitives lib/rcuref.c uses, and a counting WARN_ONCE */
#ifndef KSHIM_H
#define KSHIM_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define static_assert _Static_assert
#define EXPORT_SYMBOL_GPL(x)
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
typedef struct { int counter; } atomic_t;
typedef struct { atomic_t refcnt; } rcuref_t;
static inline int atomic_read(const atomic_t *a) { return __atomic_load_n(&a->counter, __ATOMIC_RELAXED); }
static inline void atomic_set(atomic_t *a, int v) { __atomic_store_n(&a->counter, v, __ATOMIC_RELAXED); }
static inline bool atomic_try_cmpxchg_release(atomic_t *a, int *old, int new)
{
	return __atomic_compare_exchange_n(&a->counter, old, new, false, __ATOMIC_RELEASE, __ATOMIC_RELAXED);
}
#define smp_acquire__after_ctrl_dep() __atomic_thread_fence(__ATOMIC_ACQUIRE)
extern int warn_count;
#define WARN_ONCE(cond, ...) ({ static bool once_; bool c_ = !!(cond); warn_count += c_; if (c_ && !once_) once_ = true; c_; })
#define RCUREF_ONEREF		0x00000000U
#define RCUREF_MAXREF		0x7FFFFFFFU
#define RCUREF_SATURATED	0xA0000000U
#define RCUREF_RELEASED		0xC0000000U
#define RCUREF_DEAD		0xE0000000U
#define RCUREF_NOREF		0xFFFFFFFFU
bool rcuref_get_slowpath(rcuref_t *ref);
bool rcuref_put_slowpath(rcuref_t *ref, unsigned int cnt);
#endif
