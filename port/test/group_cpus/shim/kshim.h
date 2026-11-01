/* kernel shim for the group_cpus differential: just enough of cpumask, nodemask, topology, slab and sort for lib/group_cpus.c */
#ifndef KSHIM_H
#define KSHIM_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define CONFIG_SMP 1
#define BITS_TO_LONGS(n) (((n) + 63) / 64)
#ifndef NR_CPUS
#define NR_CPUS 128
#endif
#ifndef MAXNODES
#define MAXNODES 64
#endif
#define MAX_NUMNODES MAXNODES
#define static_assert _Static_assert
#define __always_inline inline
#define EXPORT_SYMBOL_GPL(x)
#define GFP_KERNEL 0
#define ENOMEM 12
#define data_race(x) (x)
#define min(a, b) ((a) < (b) ? (a) : (b))
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define max_t(t, a, b) ((t)(a) > (t)(b) ? (t)(a) : (t)(b))
typedef unsigned gfp_t;

extern int warn_count;
#define WARN_ON_ONCE(cond) ({ static bool once_; bool c_ = !!(cond); if (c_ && !once_) { once_ = true; warn_count++; } c_; })

struct cpumask { unsigned long bits[BITS_TO_LONGS(NR_CPUS)]; };
extern unsigned int nr_cpu_ids, nr_node_ids;
#define nr_cpumask_bits nr_cpu_ids
static inline unsigned int cpumask_size(void) { return BITS_TO_LONGS(nr_cpumask_bits) * sizeof(long); }

static inline unsigned int find_next_(const unsigned long *b, unsigned int size, unsigned int start)
{
	for (unsigned int i = start; i < size; i++)
		if (b[i / 64] >> (i % 64) & 1)
			return i;
	return size;
}
static inline unsigned int cpumask_first(const struct cpumask *m) { return find_next_(m->bits, nr_cpumask_bits, 0); }
static inline unsigned int cpumask_next(int n, const struct cpumask *m) { return find_next_(m->bits, nr_cpumask_bits, n + 1); }
static inline void cpumask_set_cpu(int c, struct cpumask *m) { m->bits[c / 64] |= 1UL << (c % 64); }
static inline void cpumask_clear_cpu(int c, struct cpumask *m) { m->bits[c / 64] &= ~(1UL << (c % 64)); }
static inline bool cpumask_test_and_clear_cpu(int c, struct cpumask *m)
{
	bool was = m->bits[c / 64] >> (c % 64) & 1;
	cpumask_clear_cpu(c, m);
	return was;
}
static inline bool cpumask_and(struct cpumask *d, const struct cpumask *a, const struct cpumask *b)
{
	unsigned long any = 0;
	for (unsigned i = 0; i < BITS_TO_LONGS(nr_cpumask_bits); i++)
		any |= d->bits[i] = a->bits[i] & b->bits[i];
	return any != 0;
}
static inline void cpumask_or(struct cpumask *d, const struct cpumask *a, const struct cpumask *b)
{
	for (unsigned i = 0; i < BITS_TO_LONGS(nr_cpumask_bits); i++)
		d->bits[i] = a->bits[i] | b->bits[i];
}
static inline void cpumask_andnot(struct cpumask *d, const struct cpumask *a, const struct cpumask *b)
{
	for (unsigned i = 0; i < BITS_TO_LONGS(nr_cpumask_bits); i++)
		d->bits[i] = a->bits[i] & ~b->bits[i];
}
static inline void cpumask_copy(struct cpumask *d, const struct cpumask *s) { memcpy(d, s, cpumask_size()); }
static inline unsigned int cpumask_weight(const struct cpumask *m)
{
	unsigned w = 0;
	for (unsigned i = 0; i < nr_cpumask_bits; i++)
		w += m->bits[i / 64] >> (i % 64) & 1;
	return w;
}
static inline bool cpumask_empty(const struct cpumask *m) { return cpumask_first(m) >= nr_cpumask_bits; }
static inline bool cpumask_intersects(const struct cpumask *a, const struct cpumask *b)
{
	for (unsigned i = 0; i < BITS_TO_LONGS(nr_cpumask_bits); i++)
		if (a->bits[i] & b->bits[i])
			return true;
	return false;
}

extern struct cpumask g_possible, g_present, g_sibling[NR_CPUS];
extern int g_cpu_node[NR_CPUS];
#define cpu_possible_mask ((const struct cpumask *)&g_possible)
#define cpu_present_mask ((const struct cpumask *)&g_present)
#define topology_sibling_cpumask(cpu) (&g_sibling[cpu])
#define cpu_to_node(cpu) (g_cpu_node[cpu])
#define for_each_cpu(cpu, mask) for ((cpu) = -1; (cpu) = cpumask_next((cpu), (mask)), (cpu) < nr_cpu_ids;)
#define for_each_possible_cpu(cpu) for_each_cpu((cpu), cpu_possible_mask)

typedef struct { unsigned long bits[BITS_TO_LONGS(MAX_NUMNODES)]; } nodemask_t;
extern nodemask_t g_node_possible;
#define NODE_MASK_NONE ((nodemask_t){ { 0 } })
#define node_set(n, m) ((m).bits[(n) / 64] |= 1UL << ((n) % 64))
static inline int first_node_(const nodemask_t *m) { return find_next_(m->bits, MAX_NUMNODES, 0); }
static inline int next_node_(int n, const nodemask_t *m) { return find_next_(m->bits, MAX_NUMNODES, n + 1); }
#define for_each_node_mask(n, m) for ((n) = first_node_(&(m)); (n) < MAX_NUMNODES; (n) = next_node_((n), &(m)))
#define for_each_node(n) for_each_node_mask((n), g_node_possible)

#ifdef OFFSTACK
typedef struct cpumask *cpumask_var_t;
void *kzalloc(size_t, gfp_t);
static inline bool zalloc_cpumask_var(cpumask_var_t *m, gfp_t g) { return (*m = kzalloc(cpumask_size(), g)) != NULL; }
void kfree(const void *);
static inline void free_cpumask_var(cpumask_var_t m) { kfree(m); }
#else
typedef struct cpumask cpumask_var_t[1];
static inline bool zalloc_cpumask_var(cpumask_var_t *m, gfp_t g) { memset(*m, 0, cpumask_size()); return true; }
static inline void free_cpumask_var(cpumask_var_t m) { }
void kfree(const void *);
#endif
void *kcalloc(size_t, size_t, gfp_t);
void sort(void *base, size_t num, size_t size, int (*cmp)(const void *, const void *), void (*swap)(void *, void *, int));
#endif
