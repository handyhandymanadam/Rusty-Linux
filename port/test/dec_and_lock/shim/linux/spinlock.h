#ifndef SH_SPINLOCK_H
#define SH_SPINLOCK_H
#include <pthread.h>
#include <stdlib.h>
typedef struct { pthread_mutex_t m; volatile int held; } spinlock_t;
typedef spinlock_t raw_spinlock_t;
extern long n_spin_lock, n_spin_unlock, n_raw_lock, n_raw_unlock;
#define FLAGS_MAGIC 0xA5A5UL
extern int *hook_counter; /* when set, the next lock taken bumps this counter once: a borrower that got its reference in just before us */
static inline void __lk(spinlock_t *l) { pthread_mutex_lock(&l->m); l->held = 1; if (hook_counter) { (*hook_counter)++; hook_counter = NULL; } }
static inline void __unlk(spinlock_t *l) { l->held = 0; pthread_mutex_unlock(&l->m); }
static inline void spin_lock(spinlock_t *l) { __lk(l); __atomic_fetch_add(&n_spin_lock, 1, __ATOMIC_RELAXED); }
static inline void spin_unlock(spinlock_t *l) { __atomic_fetch_add(&n_spin_unlock, 1, __ATOMIC_RELAXED); __unlk(l); }
#define spin_lock_irqsave(l, f) do { spin_lock(l); (f) = FLAGS_MAGIC; } while (0)
#define spin_unlock_irqrestore(l, f) do { if ((f) != FLAGS_MAGIC) abort(); spin_unlock(l); } while (0)
static inline void raw_spin_lock(raw_spinlock_t *l) { __lk(l); __atomic_fetch_add(&n_raw_lock, 1, __ATOMIC_RELAXED); }
static inline void raw_spin_unlock(raw_spinlock_t *l) { __atomic_fetch_add(&n_raw_unlock, 1, __ATOMIC_RELAXED); __unlk(l); }
#define raw_spin_lock_irqsave(l, f) do { raw_spin_lock(l); (f) = FLAGS_MAGIC; } while (0)
#define raw_spin_unlock_irqrestore(l, f) do { if ((f) != FLAGS_MAGIC) abort(); raw_spin_unlock(l); } while (0)
#endif
