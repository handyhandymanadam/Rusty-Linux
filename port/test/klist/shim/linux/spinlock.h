#ifndef SH_SPINLOCK_H
#define SH_SPINLOCK_H
#include <pthread.h>
typedef struct { pthread_mutex_t m; int init; } spinlock_t;
extern long lock_ops;
#define __SPIN_LOCK_UNLOCKED(n) { PTHREAD_MUTEX_INITIALIZER, 1 }
#define DEFINE_SPINLOCK(x) spinlock_t x = __SPIN_LOCK_UNLOCKED(x)
#define spin_lock_init(l) do { pthread_mutex_init(&(l)->m, NULL); (l)->init = 1; } while (0)
#define spin_lock(l) do { pthread_mutex_lock(&(l)->m); lock_ops++; } while (0)
#define spin_unlock(l) pthread_mutex_unlock(&(l)->m)
#define spin_lock_irqsave(l, f) do { (f) = 0; spin_lock(l); } while (0)
#define spin_unlock_irqrestore(l, f) do { (void)(f); spin_unlock(l); } while (0)
#endif
