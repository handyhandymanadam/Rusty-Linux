/* kernel shim for the percpu-refcount differential: per-CPU counters (4 "CPUs", the current one test-controlled), an RCU callback queue the test runs as
 * "grace periods", wait queues that run pending callbacks before returning (the simulated sleep), lock stand-ins, counting WARN_ONCE. */
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
#define READ_ONCE(x) (*(volatile __typeof__(x) *)&(x))
#define WRITE_ONCE(x, v) (*(volatile __typeof__(x) *)&(x) = (v))
#define smp_store_release(p, v) __atomic_store_n((p), (v), __ATOMIC_RELEASE)
#define BITS_PER_LONG 64
#define ENOMEM 12
#define GFP_KERNEL 0
#define __percpu
#define __must_check
#define __maybe_unused
#define max_t(t, a, b) ((t)(a) > (t)(b) ? (t)(a) : (t)(b))
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
typedef unsigned int gfp_t;
typedef struct { int counter; } atomic_t;
typedef struct { long counter; } atomic_long_t;
static inline long atomic_long_read(const atomic_long_t *a) { return __atomic_load_n(&a->counter, __ATOMIC_RELAXED); }
static inline void atomic_long_set(atomic_long_t *a, long v) { __atomic_store_n(&a->counter, v, __ATOMIC_RELAXED); }
static inline void atomic_long_add(long n, atomic_long_t *a) { __atomic_fetch_add(&a->counter, n, __ATOMIC_RELAXED); }
static inline bool atomic_long_sub_and_test(long n, atomic_long_t *a) { return __atomic_sub_fetch(&a->counter, n, __ATOMIC_SEQ_CST) == 0; }
static inline bool atomic_long_add_unless(atomic_long_t *a, long n, long u)
{
	long c = atomic_long_read(a);
	do { if (c == u) return false; } while (!__atomic_compare_exchange_n(&a->counter, &c, c + n, false, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED));
	return true;
}
static inline bool atomic_long_inc_not_zero(atomic_long_t *a) { return atomic_long_add_unless(a, 1, 0); }
static inline int atomic_inc_return(atomic_t *a) { return __atomic_add_fetch(&a->counter, 1, __ATOMIC_SEQ_CST); }
extern int warn_count;
extern bool warn_site[64];	/* one flag per WARN_ON_ONCE / WARN_ONCE site, reset by the test */
#define WARN_ON_ONCE(c) ({ bool *once_ = &warn_site[__COUNTER__]; bool c_ = !!(c); if (c_ && !*once_) { *once_ = true; warn_count++; } c_; })
#define WARN_ONCE(c, ...) ({ bool *once_ = &warn_site[__COUNTER__]; bool c_ = !!(c); if (c_ && !*once_) { *once_ = true; warn_count++; } c_; })
#define BUG_ON(c) do { if (c) abort(); } while (0)
#define pr_err(...) ((void)0)
#define pr_debug(...) ((void)0)
#define mem_dump_obj(p) ((void)(p))
#define lockdep_assert_held(l) ((void)(l))
/* RCU: read-side no-ops; callbacks queued and run by the test */
struct rcu_head { struct rcu_head *next; void (*func)(struct rcu_head *); };
typedef void (*rcu_callback_t)(struct rcu_head *);
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
#define rcu_read_lock_held() 1
void call_rcu_hurry(struct rcu_head *head, rcu_callback_t func);
bool rcu_run_one(void);		/* run one queued callback; false if none */
void rcu_run(void);
/* locks, wait queues */
typedef struct { int d; } spinlock_t;
typedef struct { int d; } wait_queue_head_t;
#define DEFINE_SPINLOCK(n) spinlock_t n
#define DECLARE_WAIT_QUEUE_HEAD(n) wait_queue_head_t n
#define spin_lock_irqsave(l, f) do { (void)(l); (f) = 0; } while (0)
#define spin_unlock_irqrestore(l, f) do { (void)(l); (void)(f); } while (0)
extern long wakes, waits;
#define wake_up_all(q) ((void)(q), wakes++)
#define wait_event_lock_irq(q, cond, lock) do { while (!(cond)) { waits++; if (!rcu_run_one()) abort(); } } while (0)
#define wait_event(q, cond) do { while (!(cond)) { waits++; if (!rcu_run_one()) abort(); } } while (0)
/* per-CPU */
#define NSHIM_CPUS 4
extern int shim_cpu;
#define raw_cpu_ptr(p) ((p) + shim_cpu)
#define per_cpu_ptr(p, cpu) ((p) + (cpu))
#define for_each_possible_cpu(i) for ((i) = 0; (i) < NSHIM_CPUS; (i)++)
#define this_cpu_add(x, v) (*raw_cpu_ptr(&(x)) += (v))
#define this_cpu_sub(x, v) (*raw_cpu_ptr(&(x)) -= (v))
#define this_cpu_inc(x) this_cpu_add(x, 1)
extern int alloc_fail_in;	/* fail the Nth next allocation; 0 = never */
extern long live_allocs;
static inline void *__alloc_percpu_gfp(size_t size, size_t align, gfp_t gfp)
{
	(void)gfp; if (alloc_fail_in && --alloc_fail_in == 0) return NULL;
	void *p = aligned_alloc(align < 16 ? 16 : align, ((size * NSHIM_CPUS + 15) / 16) * 16); memset(p, 0, size * NSHIM_CPUS); live_allocs++; return p;
}
static inline void free_percpu(void *p) { if (p) { live_allocs--; free(p); } }
static inline void *kzalloc(size_t sz, gfp_t gfp) { (void)gfp; if (alloc_fail_in && --alloc_fail_in == 0) return NULL; void *p = calloc(1, sz); live_allocs++; return p; }
static inline void kfree(void *p) { if (p) { live_allocs--; free(p); } }
#include "prefcount_body.h"
#endif
