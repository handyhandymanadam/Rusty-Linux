/* shim for the cpu_rmap differential: the real struct cpu_rmap, plus a fake CPU topology (cpumasks are 64-bit words), kref, printk and the IRQ affinity-notifier API the glue part uses. */
#ifndef SH_CPU_RMAP_H
#define SH_CPU_RMAP_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <stdarg.h>
typedef uint64_t u64; typedef uint32_t u32; typedef uint16_t u16; typedef unsigned int gfp_t;
#define GFP_KERNEL 0
#define unlikely(x) __builtin_expect(!!(x), 0)
#define ALIGN(x, a) (((x) + (a) - 1) & ~((size_t)(a) - 1))
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define EXPORT_SYMBOL(x)
extern int warn_count; void klog(const char *fmt, ...);
#define pr_warn(fmt, ...) klog(fmt, ##__VA_ARGS__)

typedef struct { int refs; } refcount_t;
struct kref { refcount_t refcount; };
static inline void kref_init(struct kref *k) { k->refcount.refs = 1; }
static inline void kref_get(struct kref *k) { if (k->refcount.refs++ <= 0) warn_count += 1000; }
static inline int kref_put(struct kref *k, void (*release)(struct kref *)) { int o = --k->refcount.refs; if (o < 0) warn_count += 1000; if (o == 0) { release(k); return 1; } return 0; }

extern unsigned int nr_cpu_ids;
struct cpumask { u64 bits; };
typedef struct cpumask cpumask_t;
extern struct cpumask cpu_possible_mask_v, cpu_online_mask_v;
#define cpu_possible_mask (&cpu_possible_mask_v)
#define cpu_online_mask (&cpu_online_mask_v)
static inline unsigned int cpumask_next(int n, const struct cpumask *m) { for (unsigned i = n + 1; i < nr_cpu_ids; i++) if (m->bits >> i & 1) return i; return nr_cpu_ids; }
#define for_each_cpu(cpu, mask) for ((cpu) = -1; (cpu) = cpumask_next((cpu), (mask)), (cpu) < nr_cpu_ids;)
#define for_each_possible_cpu(cpu) for_each_cpu(cpu, cpu_possible_mask)
#define for_each_online_cpu(cpu) for_each_cpu(cpu, cpu_online_mask)
static inline void cpumask_set_cpu(unsigned cpu, struct cpumask *m) { m->bits |= 1ULL << cpu; }
static inline void cpumask_or(struct cpumask *d, const struct cpumask *a, const struct cpumask *b) { d->bits = a->bits | b->bits; }
/* off-stack cpumask_var_t: a pointer, allocation can fail */
typedef struct cpumask *cpumask_var_t;
bool zalloc_cpumask_var(cpumask_var_t *mask, gfp_t flags); void free_cpumask_var(cpumask_var_t mask);
const struct cpumask *topology_sibling_cpumask(int cpu); const struct cpumask *topology_core_cpumask(int cpu);
int cpu_to_node(int cpu); const struct cpumask *cpumask_of_node(int node);
void *kzalloc(size_t n, gfp_t g); void kfree(const void *p);

struct irq_affinity_notify {
	unsigned int irq;
	struct kref kref;
	void (*notify)(struct irq_affinity_notify *, const cpumask_t *mask);
	void (*release)(struct kref *ref);
};
int irq_set_affinity_notifier(unsigned int irq, struct irq_affinity_notify *notify);

struct cpu_rmap {
	struct kref refcount;
	u16 size;
	void **obj;
	struct { u16 index; u16 dist; } near[];
};
#define CPU_RMAP_DIST_INF 0xffff
struct cpu_rmap *alloc_cpu_rmap(unsigned int size, gfp_t flags);
void cpu_rmap_get(struct cpu_rmap *rmap);
int cpu_rmap_put(struct cpu_rmap *rmap);
int cpu_rmap_add(struct cpu_rmap *rmap, void *obj);
int cpu_rmap_update(struct cpu_rmap *rmap, u16 index, const cpumask_t *affinity);
void free_irq_cpu_rmap(struct cpu_rmap *rmap);
int irq_cpu_rmap_remove(struct cpu_rmap *rmap, int irq);
int irq_cpu_rmap_add(struct cpu_rmap *rmap, int irq);
#endif
