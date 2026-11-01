/* kernel shim for the rhashtable differential: just enough of the kernel for lib/rhashtable.c, the real rhashtable.h / rhashtable-types.h /
 * jhash.h (reached through RHT_INC, an absolute include directory), and port/tree/lib/rhashtable_glue.c. Single-threaded by default; the
 * lock primitives are real (atomics / pthread) so the same shim also serves the threaded stress (main.c, -DSTRESS). */
#ifndef KSHIM_H
#define KSHIM_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>

typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef int8_t s8; typedef int16_t s16; typedef int32_t s32; typedef int64_t s64;
typedef unsigned int gfp_t;
typedef unsigned long ulong_;

#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define static_assert _Static_assert
#define __rcu
#define __force
#define __percpu
#define __init
#define __user
#define __kernel
#define __must_check
#define __acquires(x)
#define __releases(x)
#define __release(x)
#undef __always_inline
#define __always_inline inline __attribute__((always_inline))
#define fallthrough __attribute__((fallthrough))
#define get_unaligned(p) ({ __typeof__(*(p)) v_; memcpy(&v_, (p), sizeof(v_)); v_; })
#define ____cacheline_aligned_in_smp __attribute__((aligned(64)))
#define EXPORT_SYMBOL_GPL(x)
#define EXPORT_SYMBOL(x)
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define barrier() __asm__ __volatile__("" ::: "memory")
#define READ_ONCE(x) (*(const volatile __typeof__(x) *)&(x))
#define WRITE_ONCE(x, v) (*(volatile __typeof__(x) *)&(x) = (v))
#define smp_rmb() __atomic_thread_fence(__ATOMIC_ACQUIRE)
#define BIT(n) (1UL << (n))
#define _THIS_IP_ 0UL
#define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define max(a, b) ({ __typeof__(a) a_ = (a); __typeof__(b) b_ = (b); a_ > b_ ? a_ : b_; })
#define min(a, b) ({ __typeof__(a) a_ = (a); __typeof__(b) b_ = (b); a_ < b_ ? a_ : b_; })
#define max_t(t, a, b) ((t)(a) > (t)(b) ? (t)(a) : (t)(b))
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define struct_size(p, member, n) (sizeof(*(p)) + (size_t)(n) * sizeof((p)->member[0]))

/* BUG / WARN: counted, then abort for BUG */
extern int bug_count, warn_count;
#define BUG_ON(c) do { if (c) { fprintf(stderr, "BUG at %s:%d\n", __FILE__, __LINE__); bug_count++; abort(); } } while (0)
#define WARN_ON(c) ({ int c_ = !!(c); if (c_) warn_count++; c_; })

/* errors */
#define MAX_ERRNO 4095
#define EAGAIN_ EAGAIN
static inline void *ERR_PTR(long e) { return (void *)e; }
static inline long PTR_ERR(const void *p) { return (long)p; }
static inline bool IS_ERR(const void *p) { return (unsigned long)p >= (unsigned long)-MAX_ERRNO; }
static inline bool IS_ERR_OR_NULL(const void *p) { return !p || IS_ERR(p); }
static inline void *ERR_CAST(const void *p) { return (void *)p; }

/* log2 */
static inline unsigned long fls_long_(unsigned long x) { return x ? 64 - __builtin_clzl(x) : 0; }
#define ilog2(n) ((int)(fls_long_((unsigned long)(n)) - 1))
#define roundup_pow_of_two(n) ((unsigned long)(n) == 1 ? 1UL : 1UL << fls_long_((unsigned long)(n)-1))
#define rounddown_pow_of_two(n) (1UL << (fls_long_((unsigned long)(n)) - 1))

/* lists */
struct list_head { struct list_head *next, *prev; };
static inline void INIT_LIST_HEAD(struct list_head *l) { l->next = l; l->prev = l; }
static inline void list_add(struct list_head *n, struct list_head *h) { n->next = h->next; n->prev = h; h->next->prev = n; h->next = n; }
static inline void list_del(struct list_head *e) { e->prev->next = e->next; e->next->prev = e->prev; e->next = (void *)0x100; e->prev = (void *)0x122; }
#define list_for_each_entry(pos, head, member) \
	for (pos = container_of((head)->next, __typeof__(*pos), member); &pos->member != (head); pos = container_of(pos->member.next, __typeof__(*pos), member))

/* atomics */
typedef struct { int counter; } atomic_t;
static inline int atomic_read(const atomic_t *a) { return __atomic_load_n(&a->counter, __ATOMIC_RELAXED); }
static inline void atomic_set(atomic_t *a, int v) { __atomic_store_n(&a->counter, v, __ATOMIC_RELAXED); }
static inline void atomic_inc(atomic_t *a) { __atomic_add_fetch(&a->counter, 1, __ATOMIC_SEQ_CST); }
static inline void atomic_dec(atomic_t *a) { __atomic_sub_fetch(&a->counter, 1, __ATOMIC_SEQ_CST); }
#define cmpxchg(ptr, o, n) ({ __typeof__(*(ptr)) o_ = (o); __atomic_compare_exchange_n((ptr), &o_, (n), 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); o_; })

/* RCU */
struct rcu_head { struct rcu_head *next; void (*func)(struct rcu_head *); };
typedef void (*rcu_callback_t)(struct rcu_head *);
#define rcu_read_lock() rcu_read_lock_()
#define rcu_read_unlock() rcu_read_unlock_()
void rcu_read_lock_(void); void rcu_read_unlock_(void);
#define rcu_dereference(p) READ_ONCE(p)
#define rcu_dereference_all(p) READ_ONCE(p)
#define rcu_dereference_check(p, c) READ_ONCE(p)
#define rcu_dereference_all_check(p, c) READ_ONCE(p)
#define rcu_dereference_protected(p, c) READ_ONCE(p)
#define rcu_access_pointer(p) READ_ONCE(p)
#define rcu_assign_pointer(p, v) __atomic_store_n(&(p), (v), __ATOMIC_RELEASE)
#define RCU_INIT_POINTER(p, v) WRITE_ONCE(p, v)
static inline void rcu_head_init(struct rcu_head *rhp) { rhp->func = (rcu_callback_t)~0L; }
void call_rcu(struct rcu_head *head, rcu_callback_t func);
static inline bool rcu_head_after_call_rcu(struct rcu_head *rhp, rcu_callback_t f) { return READ_ONCE(rhp->func) == f; }

/* lockdep: nothing */
struct lockdep_map { int dummy_; };
struct lock_class_key { int dummy_; };
#define SINGLE_DEPTH_NESTING 1
#define lockdep_init_map(m, n, k, s) do { } while (0)
#define lock_map_acquire(m) do { } while (0)
#define lock_map_release(m) do { } while (0)
#define lock_acquire_exclusive(m, s, t, n, ip) do { } while (0)
#define lockdep_is_held(x) 1
#define debug_locks 1

/* locks */
struct mutex { pthread_mutex_t m; };
#define mutex_init(l) pthread_mutex_init(&(l)->m, NULL)
#define mutex_lock(l) pthread_mutex_lock(&(l)->m)
#define mutex_unlock(l) pthread_mutex_unlock(&(l)->m)
typedef struct { pthread_mutex_t m; } spinlock_t;
#define spin_lock_init(l) pthread_mutex_init(&(l)->m, NULL)
#define spin_lock(l) pthread_mutex_lock(&(l)->m)
#define spin_unlock(l) pthread_mutex_unlock(&(l)->m)
#define local_irq_save(f) do { (f) = 0; } while (0)
#define local_irq_restore(f) do { (void)(f); } while (0)
#define preempt_enable() do { } while (0)
static inline void bit_spin_lock(int bit, unsigned long *addr)
{
	while (__atomic_fetch_or(addr, 1UL << bit, __ATOMIC_ACQUIRE) & (1UL << bit))
		while (__atomic_load_n(addr, __ATOMIC_RELAXED) & (1UL << bit))
			sched_yield();
}
static inline void bit_spin_unlock(int bit, unsigned long *addr) { __atomic_fetch_and(addr, ~(1UL << bit), __ATOMIC_RELEASE); }
static inline int bit_spin_is_locked(int bit, unsigned long *addr) { return !!(__atomic_load_n(addr, __ATOMIC_RELAXED) & (1UL << bit)); }
static inline void cond_resched(void) { }

/* work */
struct work_struct { void (*func)(struct work_struct *); int pending; };
#define INIT_WORK(w, f) do { (w)->func = (f); (w)->pending = 0; } while (0)
#define schedule_work(w) schedule_work_(w)
#define cancel_work_sync(w) cancel_work_sync_(w)
bool schedule_work_(struct work_struct *w);
bool cancel_work_sync_(struct work_struct *w);

/* allocation */
#define GFP_KERNEL 0x0cc0u
#define GFP_ATOMIC 0x0020u
#define __GFP_ZERO 0x0100u
#define __GFP_NOWARN 0x0200u
#define __GFP_NOFAIL 0x8000u
#define __GFP_DIRECT_RECLAIM 0x0400u
#define NUMA_NO_NODE (-1)
static inline bool gfpflags_allow_blocking(gfp_t g) { return !!(g & __GFP_DIRECT_RECLAIM); }
struct alloc_tag;
#define alloc_hooks_tag(tag, x) (x)
#define alloc_hooks(x) (x)
#define alloc_tag_record(x) do { } while (0)
void *kmalloc_noprof(size_t size, gfp_t gfp);
void *kvmalloc_node_align_noprof(size_t size, size_t align, gfp_t gfp, int node);
void kfree(const void *p);
void kvfree(const void *p);

/* random, hashing */
u32 get_random_u32(void);
#define rol32(w, s) ((u32)(((w) << (s)) | ((w) >> ((-(s)) & 31))))
#define __get_unaligned_cpu32(p) ({ u32 v_; memcpy(&v_, (p), 4); v_; })
#define __pure

#define NULLS_MARKER(value) (1UL | (((long)value) << 1))

/* the real headers (rhashtable-types.h / rhashtable.h / jhash.h come through RHT_INC) */
#include "../../../../src/linux/include/linux/rhashtable-types.h"
#endif
