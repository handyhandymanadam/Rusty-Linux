/* kernel shim for the stackdepot differential: just enough of the kernel for lib/stackdepot.c and stackdepot_glue.c to compile and run in
 * userspace.  One thread; allocation failure, NMI context and the RCU grace period are test-controlled. */
#ifndef KSHIM_H
#define KSHIM_H
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONFIG_STACKDEPOT 1
#define CONFIG_STACKDEPOT_MAX_FRAMES 64
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define POISON_POINTER_DELTA 0
#define STACK_DEPOT_POISON ((void *)(0xD390 + POISON_POINTER_DELTA))
#define static_assert _Static_assert
#define __init
#define __initdata
#define __read_mostly
#define __must_check
#define EXPORT_SYMBOL(x)
#define EXPORT_SYMBOL_GPL(x)
#define early_param(a, b)
#define late_initcall(f)
#define data_race(x) (x)
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define IS_ENABLED(x) (x)
#define CONFIG_STACKDEPOT_ALWAYS_INIT 0
#define ASSERT_EXCLUSIVE_WRITER(x) ((void)0)
#define ALIGN(x, a) (((x) + (a) - 1) & ~((__typeof__(x))(a) - 1))
#define flex_array_size(p, member, n) ((n) * sizeof((p)->member[0]))
#define REFCOUNT_SATURATED 0xC0000000u
#define READ_ONCE(x) (*(volatile __typeof__(x) *)&(x))
#define WRITE_ONCE(x, v) (*(volatile __typeof__(x) *)&(x) = (v))
#define pr_info(...) ((void)0)
#define pr_err(...) ((void)0)
#define GFP_KERNEL 0x400u
#define __GFP_NOWARN 0x2000u
#define GFP_ATOMIC 0x200u
#define GFP_NOWAIT 0x100u
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef unsigned int gfp_t;
typedef struct { int dummy; } raw_spinlock_t;
typedef struct { int dummy; } mutex_t;
struct seq_file; struct dentry; struct file; struct inode;

/* WARN sites: counted, with the first message kept for the transcript */
extern int warn_count;
#define WARN_ON(c) ({ bool c_ = !!(c); warn_count += c_; c_; })
#define WARN_ON_ONCE(c) ({ static bool once_; bool c_ = !!(c); if (c_ && !once_) { once_ = true; warn_count++; } c_; })
#define WARN_ONCE(c, ...) ({ static bool once_; bool c_ = !!(c); if (c_ && !once_) { once_ = true; warn_count++; } c_; })
#define WARN(c, ...) ({ bool c_ = !!(c); warn_count += c_; c_; })

/* list_head and the RCU variants (single thread: plain pointer stores) */
struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD(n) struct list_head n = { &n, &n }
static inline void INIT_LIST_HEAD(struct list_head *l) { l->next = l; l->prev = l; }
static inline void __list_add(struct list_head *n, struct list_head *p, struct list_head *x) { x->prev = n; n->next = x; n->prev = p; p->next = n; }
static inline void list_add_tail(struct list_head *n, struct list_head *h) { __list_add(n, h->prev, h); }
static inline void list_add_rcu(struct list_head *n, struct list_head *h) { __list_add(n, h, h->next); }
static inline void list_del(struct list_head *e) { e->prev->next = e->next; e->next->prev = e->prev; e->next = (void *)0x100; e->prev = (void *)0x122; }
static inline void list_del_rcu(struct list_head *e) { e->prev->next = e->next; e->next->prev = e->prev; e->prev = (void *)0x122; }
static inline bool list_empty(const struct list_head *h) { return h->next == h; }
#define list_entry(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define list_first_entry(p, t, m) list_entry((p)->next, t, m)
#define list_for_each_entry_rcu(pos, head, member) \
	for (pos = list_entry((head)->next, __typeof__(*pos), member); &pos->member != (head); pos = list_entry(pos->member.next, __typeof__(*pos), member))
#define list_for_each_entry(pos, head, member) list_for_each_entry_rcu(pos, head, member)

/* refcount_t: saturating at the top like the real one is not needed (no test reaches it), but zero handling matters */
typedef struct { int refs; } refcount_t;
static inline void refcount_set(refcount_t *r, int n) { r->refs = n; }
static inline unsigned int refcount_read(const refcount_t *r) { return r->refs; }
static inline bool refcount_inc_not_zero(refcount_t *r) { if (!r->refs) return false; r->refs++; return true; }
static inline bool refcount_dec_and_test(refcount_t *r) { return --r->refs == 0; }

/* locks, RCU: no-ops, except the grace period which the test drives */
#define DEFINE_RAW_SPINLOCK(n) raw_spinlock_t n
#define DEFINE_MUTEX(n) mutex_t n
#define raw_spin_lock_irqsave(l, f) do { (void)(l); (f) = 0; } while (0)
extern int trylock_fail_flag, sd_weak_hash;
#define raw_spin_trylock_irqsave(l, f) ((void)(l), (f) = 0, !trylock_fail_flag)
#define raw_spin_unlock_irqrestore(l, f) do { (void)(l); (void)(f); } while (0)
#define lockdep_assert_held(l) ((void)(l))
#define lockdep_assert_not_held(l) ((void)(l))
#define printk_deferred_enter() ((void)0)
#define printk_deferred_exit() ((void)0)
#define mutex_lock(m) ((void)(m))
#define mutex_unlock(m) ((void)(m))
#define rcu_read_lock_sched_notrace() ((void)0)
#define rcu_read_unlock_sched_notrace() ((void)0)
extern unsigned long rcu_gp_seq, rcu_gp_done;	/* a cookie is the sequence at the time; it is "done" once rcu_gp_done >= cookie */
static inline unsigned long get_state_synchronize_rcu(void) { return ++rcu_gp_seq; }
static inline bool poll_state_synchronize_rcu(unsigned long c) { return rcu_gp_done >= c; }
static inline void kmsan_unpoison_memory(void *p, size_t n) { (void)p; (void)n; }
extern int in_nmi_flag;
static inline bool in_nmi(void) { return in_nmi_flag; }
static inline bool gfpflags_allow_spinning(gfp_t g) { return !(g & 0x8000u); }
static inline gfp_t gfp_nested_mask(gfp_t g) { return g; }
static inline bool kasan_enabled(void) { return false; }

/* page allocator: fails on demand */
struct page { int d; };
extern int alloc_fail_in;	/* fail the Nth next allocation (1 = the next one); 0 = never */
extern long pages_live;
static inline struct page *alloc_pages(gfp_t g, unsigned int order)
{
	(void)g;
	if (alloc_fail_in && --alloc_fail_in == 0) return NULL;
	pages_live++;
	return aligned_alloc(PAGE_SIZE, PAGE_SIZE << order);
}
static inline void *page_address(struct page *p) { return p; }
static inline struct page *virt_to_page(void *p) { return p; }
static inline void free_pages(unsigned long a, unsigned int order) { (void)order; pages_live--; free((void *)a); }
static inline void free_pages_nolock(struct page *p, unsigned int order) { free_pages((unsigned long)p, order); }
static inline void *kvcalloc(size_t n, size_t sz, gfp_t g) { (void)g; return calloc(n, sz); }
static inline void kvfree(void *p) { free(p); }
static inline void *memblock_alloc(size_t sz, size_t al) { (void)al; return calloc(1, sz); }
static inline void memblock_free(void *p, size_t sz) { (void)sz; free(p); }
#define HASH_EARLY 1
static inline void *alloc_large_system_hash(const char *n, unsigned long sz, unsigned long ent, int scale, int flags, unsigned int *shift,
					    unsigned int *mask, unsigned long lo, unsigned long hi)
{
	(void)n; (void)scale; (void)flags; (void)shift; (void)lo; (void)hi;
	if (!ent) ent = 4096;
	*mask = ent - 1;
	return calloc(ent, sz);
}
static inline unsigned long nr_free_buffer_pages(void) { return 1UL << 20; }
static inline unsigned long roundup_pow_of_two(unsigned long n) { unsigned long r = 1; while (r < n) r <<= 1; return r; }
static inline int kstrtobool(const char *s, bool *r) { (void)s; (void)r; return 0; }
static inline int kstrtouint(const char *s, int b, unsigned int *r) { (void)s; (void)b; (void)r; return 0; }
static inline size_t array_size(size_t a, size_t b) { return a * b; }

/* hash: the real jhash2 (include/linux/jhash.h) */
static inline u32 rol32(u32 w, unsigned int s) { return (w << s) | (w >> (32 - s)); }
#define __jhash_mix(a, b, c) { a -= c; a ^= rol32(c, 4); c += b; b -= a; b ^= rol32(a, 6); a += c; c -= b; c ^= rol32(b, 8); b += a; a -= c; a ^= rol32(c, 16); c += b; b -= a; b ^= rol32(a, 19); a += c; c -= b; c ^= rol32(b, 4); b += a; }
#define __jhash_final(a, b, c) { c ^= b; c -= rol32(b, 14); a ^= c; a -= rol32(c, 11); b ^= a; b -= rol32(a, 25); c ^= b; c -= rol32(b, 16); a ^= c; a -= rol32(c, 4); b ^= a; b -= rol32(a, 14); c ^= b; c -= rol32(b, 24); }
#define JHASH_INITVAL 0xdeadbeef
static inline u32 jhash2(const u32 *k, u32 length, u32 initval)
{
	u32 a, b, c;
	a = b = c = JHASH_INITVAL + (length << 2) + initval;
	while (length > 3) { a += k[0]; b += k[1]; c += k[2]; __jhash_mix(a, b, c); length -= 3; k += 3; }
	switch (length) { case 3: c += k[2]; /* fallthrough */ case 2: b += k[1]; /* fallthrough */ case 1: a += k[0]; __jhash_final(a, b, c); /* fallthrough */ case 0: break; }
	return sd_weak_hash ? (c & 3) : c;
}
/* frames in the "irq stack" window are dropped: the test marks them with this value */
#define SD_IRQ_FRAME 0xDEAD0000UL
static inline unsigned int filter_irq_stacks(unsigned long *e, unsigned int n)
{
	unsigned int i;
	for (i = 0; i < n; i++) if (e[i] == SD_IRQ_FRAME) return i + 1;
	return n;
}
static inline void stack_trace_print(const unsigned long *e, unsigned int n, int sp) { (void)e; (void)n; (void)sp; }
static inline int stack_trace_snprint(char *b, size_t s, const unsigned long *e, unsigned int n, int sp) { (void)b; (void)s; (void)e; (void)sp; return n; }
static inline struct dentry *debugfs_create_dir(const char *n, struct dentry *p) { (void)n; (void)p; return NULL; }
#define debugfs_create_file(a, b, c, d, e) ((void)0)
#define seq_printf(...) ((void)0)
#define DEFINE_SHOW_ATTRIBUTE(n) static const int n##_fops = 0

#endif
