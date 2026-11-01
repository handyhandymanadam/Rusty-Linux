/* Userspace stand-ins for the kernel pieces lib/maple_tree.c and its glue use. */
#ifndef KSHIM_H
#define KSHIM_H
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef unsigned int gfp_t;
#define __rcu
#define __init
#define __must_hold(x)
#define __maybe_unused __attribute__((unused))
#define __always_inline inline __attribute__((always_inline))
#define noinline_for_stack __attribute__((noinline))
#define BITS_PER_LONG 64
#define CONFIG_64BIT 1
#define ULONG_MAX (~0UL)
#define U8_MAX 255
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))
#define READ_ONCE(x) (*(volatile __typeof__(x) *)&(x))
#define smp_wmb() __atomic_thread_fence(__ATOMIC_RELEASE)
#define smp_rmb() __atomic_thread_fence(__ATOMIC_ACQUIRE)
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define fallthrough __attribute__((__fallthrough__))
#define pr_err(...) do { } while (0)
#define pr_info(...) do { } while (0)
#define dump_stack() do { } while (0)
#define __ffs(x) ((unsigned long)__builtin_ctzl(x))
#define min(a, b) ({ __typeof__(a) _a = (a); __typeof__(b) _b = (b); _a < _b ? _a : _b; })
#define max(a, b) ({ __typeof__(a) _a = (a); __typeof__(b) _b = (b); _a > _b ? _a : _b; })
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define max_t(t, a, b) ((t)(a) > (t)(b) ? (t)(a) : (t)(b))
#define round_up(x, y) ((((x) - 1) | ((y) - 1)) + 1)
#define round_down(x, y) ((x) & ~((y) - 1))
#define struct_size(p, member, n) (sizeof(*(p)) + sizeof((p)->member[0]) * (n))
#define SINGLE_DEPTH_NESTING 1
/* events the harness compares between the arms */
extern int ev_warn;
void h_bug(void) __attribute__((noreturn));
#define BUG() h_bug()
#define BUG_ON(c) do { if (c) h_bug(); } while (0)
#define WARN_ON(c) ({ int _c = !!(c); if (_c) ev_warn++; _c; })
#define WARN_ON_ONCE(c) ({ int _c = !!(c); if (_c) ev_warn++; _c; })
/* gfp */
#define __GFP_DIRECT_RECLAIM 0x400u
#define GFP_KERNEL (0x3u | __GFP_DIRECT_RECLAIM)
#define GFP_NOWAIT 0x2u
#define gfpflags_allow_blocking(g) (!!((g) & __GFP_DIRECT_RECLAIM))
/* locks, RCU */
typedef struct { int lock; } spinlock_t;
#define __SPIN_LOCK_UNLOCKED(x) { 0 }
#define spin_lock(l) ((void)(l))
#define spin_unlock(l) ((void)(l))
#define spin_lock_nested(l, s) ((void)(l))
#define spin_lock_init(l) ((void)(l))
#define rcu_read_lock() do { } while (0)
#define rcu_read_unlock() do { } while (0)
#define rcu_assign_pointer(p, v) __atomic_store_n(&(p), (v), __ATOMIC_RELEASE)
struct rcu_head { struct rcu_head *next; void (*func)(struct rcu_head *); };
void h_call_rcu(struct rcu_head *head, void (*func)(struct rcu_head *));
#define call_rcu(h, f) h_call_rcu((h), (f))
void h_kfree_rcu(void *obj, struct rcu_head *head);
#define kfree_rcu(obj, member) h_kfree_rcu((obj), &(obj)->member)
/* slab */
struct kmem_cache; struct slab_sheaf;
struct kmem_cache_args { unsigned int align; unsigned int sheaf_capacity; };
#define SLAB_PANIC 1
struct kmem_cache *kmem_cache_create(const char *name, unsigned int size, struct kmem_cache_args *args, unsigned int flags);
void *kmem_cache_alloc(struct kmem_cache *c, gfp_t gfp);
void kmem_cache_free_bulk(struct kmem_cache *c, size_t n, void **p);
struct slab_sheaf *kmem_cache_prefill_sheaf(struct kmem_cache *c, gfp_t gfp, unsigned int size);
int kmem_cache_refill_sheaf(struct kmem_cache *c, gfp_t gfp, struct slab_sheaf **sheafp, unsigned int size);
void kmem_cache_return_sheaf(struct kmem_cache *c, gfp_t gfp, struct slab_sheaf *sheaf);
void *kmem_cache_alloc_from_sheaf(struct kmem_cache *c, gfp_t gfp, struct slab_sheaf *sheaf);
unsigned int kmem_cache_sheaf_size(struct slab_sheaf *sheaf);
void h_kfree(void *p);
#define kfree(p) h_kfree(p)
/* xarray bits maple_tree.c uses */
static inline bool xa_is_internal(const void *entry) { return ((unsigned long)entry & 3) == 2; }
static inline bool xa_is_node(const void *entry) { return xa_is_internal(entry) && (unsigned long)entry > 4096; }
static inline bool xa_is_value(const void *entry) { return (unsigned long)entry & 1; }
#define XA_ZERO_ENTRY ((void *)(((257UL) << 2) | 2))
#define XA_RETRY_ENTRY ((void *)(((256UL) << 2) | 2))
static inline bool xa_is_zero(const void *entry) { return entry == XA_ZERO_ENTRY; }
static inline bool xa_is_advanced(const void *entry) { return xa_is_internal(entry) && ((unsigned long)entry <= (unsigned long)XA_RETRY_ENTRY); }
static inline int xa_err(void *entry) { if (xa_is_internal(entry) && (unsigned long)entry >= (unsigned long)-4095L) return (long)entry >> 2; return 0; }
/* tracing: the calls are logged so the arms' sequences can be compared */
void h_trace(const char *kind, const char *fn, unsigned long a, void *v);
#define tracepoint_string(s) (s)
#define TP_FCT tracepoint_string(__func__)
#define trace_ma_op(fn, mas) h_trace("op", (fn), 0, 0)
#define trace_ma_read(fn, mas) h_trace("read", (fn), 0, 0)
#define trace_ma_write(fn, mas, piv, val) h_trace("write", (fn), (unsigned long)(piv), (void *)(val))
#define rcu_dereference_check(p, c) READ_ONCE(p)
#define rcu_dereference_protected(p, c) (p)
#define lockdep_is_held(l) 1
#define lock_is_held(l) 1
#define rcu_callback_map 0
#define noinline __attribute__((noinline))
#define EXPORT_SYMBOL(x)
#define EXPORT_SYMBOL_GPL(x)
#define static_assert _Static_assert
#endif
