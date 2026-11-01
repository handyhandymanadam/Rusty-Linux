/* kernel shim for the refcount differential: refcount_t, the atomics lib/refcount.c uses, counting WARN_ONCE and lock stand-ins that log their calls */
#ifndef KSHIM_H
#define KSHIM_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define static_assert _Static_assert
#define EXPORT_SYMBOL(x)
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
typedef struct { int counter; } atomic_t;
typedef struct { atomic_t refs; } refcount_t;
static inline int atomic_read(const atomic_t *a) { return __atomic_load_n(&a->counter, __ATOMIC_RELAXED); }
static inline void atomic_set(atomic_t *a, int v) { __atomic_store_n(&a->counter, v, __ATOMIC_RELAXED); }
/* a hook that runs once just before the next cmpxchg: lets the test change the counter between the read and the exchange, like a racing CPU */
extern void (*race_hook)(atomic_t *);
static inline bool atomic_try_cmpxchg_release(atomic_t *a, int *old, int new)
{
	if (race_hook) { void (*h)(atomic_t *) = race_hook; race_hook = NULL; h(a); }
	return __atomic_compare_exchange_n(&a->counter, old, new, false, __ATOMIC_RELEASE, __ATOMIC_RELAXED);
}
#define REFCOUNT_SATURATED (-1073741824)
enum refcount_saturation_type { REFCOUNT_ADD_NOT_ZERO_OVF, REFCOUNT_ADD_OVF, REFCOUNT_ADD_UAF, REFCOUNT_SUB_UAF, REFCOUNT_DEC_LEAK };
static inline void refcount_set(refcount_t *r, int n) { atomic_set(&r->refs, n); }
extern int dec_and_test_result;	/* what the next refcount_dec_and_test() says (the real one would decrement); logged by the test */
static inline bool refcount_dec_and_test(refcount_t *r) { return --r->refs.counter == 0; }
void refcount_warn_saturate(refcount_t *r, enum refcount_saturation_type t);
bool refcount_dec_if_one(refcount_t *r);
bool refcount_dec_not_one(refcount_t *r);
extern int warn_count;
extern int warn_log[64], nwarn;
#define WARN_ONCE(c, ...) ({ static bool once_; bool c_ = !!(c); if (c_ && !once_) { once_ = true; if (nwarn < 64) warn_log[nwarn++] = __LINE__; warn_count++; } c_; })
struct mutex { int locked; }; typedef struct { int locked; } spinlock_t;
extern int lock_log[256], nlock;
static inline void mutex_lock(struct mutex *m) { m->locked = 1; lock_log[nlock++ & 255] = 1; }
static inline void mutex_unlock(struct mutex *m) { m->locked = 0; lock_log[nlock++ & 255] = 2; }
static inline void spin_lock(spinlock_t *l) { l->locked = 1; lock_log[nlock++ & 255] = 3; }
static inline void spin_unlock(spinlock_t *l) { l->locked = 0; lock_log[nlock++ & 255] = 4; }
#define spin_lock_irqsave(l, f) do { (l)->locked = 1; (f) = 77; lock_log[nlock++ & 255] = 5; } while (0)
#define spin_unlock_irqrestore(l, f) do { (l)->locked = 0; lock_log[nlock++ & 255] = 6 + ((f) == 77); } while (0)
#endif
