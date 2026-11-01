/* kernel shim for the sbitmap differential: just enough of the kernel for lib/sbitmap.c and sbitmap_glue.c to compile and run in userspace.
 * One thread (the "current CPU" is test-controlled); the PRNG, the wait-queue wake-up and seq_file are small stand-ins. */
#ifndef KSHIM_H
#define KSHIM_H
#include <errno.h>
#include <limits.h>
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
#define data_race(x) (x)
#define READ_ONCE(x) (*(volatile __typeof__(x) *)&(x))
#define WRITE_ONCE(x, v) (*(volatile __typeof__(x) *)&(x) = (v))
#define BITS_PER_LONG 64
#define BIT(n) (1UL << (n))
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define clamp_t(t, v, lo, hi) ((t)(v) < (t)(lo) ? (t)(lo) : (t)(v) > (t)(hi) ? (t)(hi) : (t)(v))
#define clamp_val(v, lo, hi) ({ __typeof__(v) v_ = (v); v_ < (lo) ? (lo) : v_ > (hi) ? (hi) : v_; })
#define ilog2(n) (63 - __builtin_clzl(n))
#define do_div(n, base) ({ unsigned int r_ = (n) % (base); (n) /= (base); r_; })
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef unsigned int gfp_t;
#define GFP_KERNEL 0x400u
#define NUMA_NO_NODE (-1)
#define TASK_NORMAL 3
#define __init

extern int warn_count;
extern bool warn_site[64];	/* one flag per WARN_ON_ONCE site, reset by the test at every re-init so each episode can warn again */
#define WARN_ON_ONCE(c) ({ bool *once_ = &warn_site[__COUNTER__]; bool c_ = !!(c); if (c_ && !*once_) { *once_ = true; warn_count++; } c_; })

/* lists, atomics, bit operations */
struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD_INIT(n) { &(n), &(n) }
static inline void INIT_LIST_HEAD(struct list_head *l) { l->next = l; l->prev = l; }
static inline bool list_empty(const struct list_head *h) { return h->next == h; }
static inline void list_del_init(struct list_head *e) { e->prev->next = e->next; e->next->prev = e->prev; INIT_LIST_HEAD(e); }
static inline void list_add(struct list_head *n, struct list_head *h) { n->next = h->next; n->prev = h; h->next->prev = n; h->next = n; }
static inline void list_add_tail(struct list_head *n, struct list_head *h) { n->next = h; n->prev = h->prev; h->prev->next = n; h->prev = n; }
typedef struct { int counter; } atomic_t;
typedef struct { long counter; } atomic_long_t;
static inline int atomic_read(const atomic_t *a) { return __atomic_load_n(&a->counter, __ATOMIC_RELAXED); }
static inline void atomic_set(atomic_t *a, int v) { __atomic_store_n(&a->counter, v, __ATOMIC_RELAXED); }
static inline void atomic_inc(atomic_t *a) { __atomic_fetch_add(&a->counter, 1, __ATOMIC_RELAXED); }
static inline void atomic_dec(atomic_t *a) { __atomic_fetch_sub(&a->counter, 1, __ATOMIC_RELAXED); }
static inline void atomic_add(int n, atomic_t *a) { __atomic_fetch_add(&a->counter, n, __ATOMIC_RELAXED); }
static inline int atomic_cmpxchg(atomic_t *a, int old, int new) { __atomic_compare_exchange_n(&a->counter, &old, new, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); return old; }
static inline bool atomic_try_cmpxchg(atomic_t *a, int *old, int new) { return __atomic_compare_exchange_n(&a->counter, old, new, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); }
static inline void atomic_long_andnot(long m, atomic_long_t *a) { __atomic_fetch_and(&a->counter, ~m, __ATOMIC_RELAXED); }
static inline bool atomic_long_try_cmpxchg(atomic_long_t *a, unsigned long *old, unsigned long new)
{
	return __atomic_compare_exchange_n((unsigned long *)&a->counter, old, new, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}
#define xchg(p, v) __atomic_exchange_n((p), (v), __ATOMIC_SEQ_CST)
#define smp_mb__before_atomic() __atomic_thread_fence(__ATOMIC_SEQ_CST)
#define smp_mb__after_atomic() __atomic_thread_fence(__ATOMIC_SEQ_CST)
#define smp_mb() __atomic_thread_fence(__ATOMIC_SEQ_CST)
static inline void set_bit(unsigned int nr, unsigned long *a) { __atomic_fetch_or(a, 1UL << nr, __ATOMIC_RELAXED); }
static inline void clear_bit(unsigned int nr, unsigned long *a) { __atomic_fetch_and(a, ~(1UL << nr), __ATOMIC_RELAXED); }
static inline int test_bit(unsigned int nr, const unsigned long *a) { return (*a >> nr) & 1; }
static inline int test_and_set_bit_lock(unsigned int nr, unsigned long *a) { return (__atomic_fetch_or(a, 1UL << nr, __ATOMIC_ACQUIRE) >> nr) & 1; }
static inline unsigned long find_next_zero_bit(const unsigned long *a, unsigned long size, unsigned long off)
{
	unsigned long v;
	if (off >= size) return size;
	v = ~*a & (~0UL << off);
	if (size < 64) v &= (1UL << size) - 1;
	return v ? (unsigned long)__builtin_ctzl(v) : size;
}
static inline unsigned long find_first_zero_bit(const unsigned long *a, unsigned long size) { return find_next_zero_bit(a, size, 0); }
static inline unsigned long find_next_bit(const unsigned long *a, unsigned long size, unsigned long off)
{
	unsigned long v;
	if (off >= size) return size;
	v = *a & (~0UL << off);
	if (size < 64) v &= (1UL << size) - 1;
	return v ? (unsigned long)__builtin_ctzl(v) : size;
}
static inline unsigned int bitmap_weight(const unsigned long *a, unsigned int nbits)
{
	return __builtin_popcountl(nbits >= 64 ? *a : *a & ((1UL << nbits) - 1));
}

/* locks (no-ops), CPUs, per-CPU, PRNG, allocation */
typedef struct { int d; } raw_spinlock_t;
#define raw_spin_lock_init(l) ((l)->d = 0)
#define raw_spin_lock_irqsave(l, f) do { (void)(l); (f) = 0; } while (0)
#define raw_spin_unlock_irqrestore(l, f) do { (void)(l); (void)(f); } while (0)
#define guard(name) _guard_##name
#define _guard_raw_spinlock_irqsave(l) ((void)(l))
#define NSHIM_CPUS 4
extern int shim_cpu;
#define raw_smp_processor_id() (shim_cpu)
#define for_each_possible_cpu(i) for ((i) = 0; (i) < NSHIM_CPUS; (i)++)
#define alloc_percpu_gfp(t, f) ((void)(f), (t *)calloc(NSHIM_CPUS, sizeof(t)))
#define free_percpu(p) free(p)
#define per_cpu_ptr(p, cpu) ((p) + (cpu))
#define raw_cpu_ptr(p) ((p) + shim_cpu)
#define get_cpu() (shim_cpu)
#define put_cpu() ((void)0)
#define BUILD_BUG_ON(c) _Static_assert(!(c), "BUILD_BUG_ON")
#define wake_up_nr(q, nr) __wake_up((q), TASK_NORMAL, (nr), NULL)
#define this_cpu_read(x) (*raw_cpu_ptr(&(x)))
#define this_cpu_write(x, v) (*raw_cpu_ptr(&(x)) = (v))
extern int alloc_fail_in;	/* fail the Nth next allocation; 0 = never */
static inline bool alloc_fails(void) { return alloc_fail_in && --alloc_fail_in == 0; }
#define kvzalloc_node(sz, f, n) (alloc_fails() ? NULL : calloc(1, (sz)))
#define kzalloc_node(sz, f, n) (alloc_fails() ? NULL : calloc(1, (sz)))
#define kvfree(p) free(p)
#define kfree(p) free(p)
extern u64 shim_rng;
static inline u32 get_random_u32_below(u32 n) { shim_rng = shim_rng * 6364136223846793005ULL + 1442695040888963407ULL; return (u32)(shim_rng >> 33) % n; }

/* wait queues: entries carry a function and an exclusive flag; __wake_up follows __wake_up_common() */
#define WQ_FLAG_EXCLUSIVE 0x01
struct wait_queue_entry;
typedef int (*wait_queue_func_t)(struct wait_queue_entry *, unsigned, int, void *);
struct wait_queue_entry { unsigned int flags; void *private; wait_queue_func_t func; struct list_head entry; };
typedef struct { int lock; struct list_head head; } wait_queue_head_t;
static inline void init_waitqueue_head(wait_queue_head_t *q) { q->lock = 0; INIT_LIST_HEAD(&q->head); }
static inline bool waitqueue_active(wait_queue_head_t *q) { return !list_empty(&q->head); }
static inline void add_wait_queue(wait_queue_head_t *q, struct wait_queue_entry *e) { e->flags &= ~WQ_FLAG_EXCLUSIVE; list_add(&e->entry, &q->head); }
static inline void prepare_to_wait_exclusive(wait_queue_head_t *q, struct wait_queue_entry *e, int st)
{
	(void)st; e->flags |= WQ_FLAG_EXCLUSIVE;
	if (list_empty(&e->entry)) list_add_tail(&e->entry, &q->head);
}
static inline void finish_wait(wait_queue_head_t *q, struct wait_queue_entry *e) { (void)q; if (!list_empty(&e->entry)) list_del_init(&e->entry); }
extern long wakeups_seen;
static inline int __wake_up(wait_queue_head_t *q, unsigned mode, int nr_exclusive, void *key)
{
	struct list_head *p = q->head.next, *next;
	int remaining = nr_exclusive;
	for (; p != &q->head; p = next) {
		struct wait_queue_entry *e = (struct wait_queue_entry *)((char *)p - offsetof(struct wait_queue_entry, entry));
		next = p->next;
		wakeups_seen++;
		if (e->func(e, mode, 0, key) && (e->flags & WQ_FLAG_EXCLUSIVE) && !--remaining) break;
	}
	return nr_exclusive - remaining;
}
#define wake_up(q) __wake_up((q), TASK_NORMAL, 1, NULL)

/* seq_file: a growing buffer */
struct seq_file { char *buf; size_t n, cap; };
static inline void seq_putc(struct seq_file *m, char c) { if (m->n + 2 > m->cap) { m->cap = m->cap * 2 + 64; m->buf = realloc(m->buf, m->cap); } m->buf[m->n++] = c; m->buf[m->n] = 0; }
static inline void seq_puts(struct seq_file *m, const char *s) { while (*s) seq_putc(m, *s++); }
#include <stdarg.h>
static inline void seq_printf(struct seq_file *m, const char *f, ...)
{
	char t[256]; va_list ap; va_start(ap, f); vsnprintf(t, sizeof(t), f, ap); va_end(ap); seq_puts(m, t);
}

#include "sbitmap_body.h"
#endif
