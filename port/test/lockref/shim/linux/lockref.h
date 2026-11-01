/* Just enough of include/linux/lockref.h + spinlock for lib/lockref.c in userspace: a one-word test-and-set lock. */
#ifndef KSHIM_LOCKREF_H
#define KSHIM_LOCKREF_H
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#define static_assert _Static_assert
#define USE_CMPXCHG_LOCKREF 1
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define BUILD_BUG_ON(x) _Static_assert(!(x), "bug")
#define READ_ONCE(x) __atomic_load_n(&(x), __ATOMIC_RELAXED)
typedef struct { struct { volatile uint32_t raw_lock; } rlock; } spinlock_t;
typedef uint64_t aligned_u64 __attribute__((aligned(8)));
struct lockref {
	union {
		aligned_u64 lock_count;
		struct { spinlock_t lock; int count; };
	};
};
void kshim_lock(volatile uint32_t *l);
void kshim_unlock(volatile uint32_t *l);
#define spin_lock(l) kshim_lock(&(l)->rlock.raw_lock)
#define spin_unlock(l) kshim_unlock(&(l)->rlock.raw_lock)
#define assert_spin_locked(l) do { if (!(l)->rlock.raw_lock) { fprintf(stderr, "assert_spin_locked failed\n"); abort(); } } while (0)
#define arch_spin_value_unlocked(l) ((l) == 0)
#define try_cmpxchg64_relaxed(p, oldp, new) __atomic_compare_exchange_n((p), (oldp), (new), 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED)
static inline void lockref_init(struct lockref *l) { l->lock.rlock.raw_lock = 0; l->count = 1; }
void lockref_get(struct lockref *);
int lockref_put_return(struct lockref *);
bool lockref_get_not_zero(struct lockref *);
bool lockref_put_or_lock(struct lockref *);
void lockref_mark_dead(struct lockref *);
bool lockref_get_not_dead(struct lockref *);
#endif
