// SPDX-License-Identifier: GPL-2.0-only
/*
 * RUST PORT (lib/cpu_rmap.c, 6.18.49): alloc_cpu_rmap(), cpu_rmap_add() and the update algorithm (cpu_rmap_copy_neigh, the body of cpu_rmap_update) are in
 * cpu_rmap_rs.rs. This file keeps the exports as thunks (the MODVERSIONS fingerprint comes from the DWARF of the definition), cpu_rmap_update()'s mask allocation
 * (cpumask_var_t is an array or a pointer depending on CONFIG_CPUMASK_OFFSTACK), cpu_rmap_get()/put() with the kref release, the IRQ glue (struct irq_glue, the
 * affinity notifier) and the one-line wrappers for the cpumask iteration, topology masks, nr_cpu_ids and the allocator. Upstream's whole file is installed as
 * cpu_rmap_norust.c for CONFIG_RUST=n.
 */
/*
 * cpu_rmap.c: CPU affinity reverse-map support
 * Copyright 2011 Solarflare Communications Inc.
 */

#include <linux/cpu_rmap.h>
#include <linux/interrupt.h>
#include <linux/export.h>

/*
 * These functions maintain a mapping from CPUs to some ordered set of
 * objects with CPU affinities.  This can be seen as a reverse-map of
 * CPU affinity.  However, we do not assume that the object affinities
 * cover all CPUs in the system.  For those CPUs not directly covered
 * by object affinities, we attempt to find a nearest object based on
 * CPU topology.
 */

static_assert(offsetof(struct cpu_rmap, refcount) == 0 && offsetof(struct cpu_rmap, size) == 4 && offsetof(struct cpu_rmap, obj) == 8 && offsetof(struct cpu_rmap, near) == 16 &&
	      sizeof(__typeof__(((struct cpu_rmap *)0)->near[0])) == 4 && CPU_RMAP_DIST_INF == 0xffff);

struct cpu_rmap *rust_alloc_cpu_rmap(unsigned int size, gfp_t flags);
int rust_cpu_rmap_add(struct cpu_rmap *rmap, void *obj);
void rust_cpu_rmap_update(struct cpu_rmap *rmap, u16 index, const struct cpumask *affinity, struct cpumask *update_mask);
u32 rust_cr_nr_cpu_ids(void);
void *rust_cr_kzalloc(size_t size, gfp_t gfp);
void rust_cr_kref_init(struct cpu_rmap *rmap);
u32 rust_cr_next_possible(int n);
u32 rust_cr_next_online(int n);
u32 rust_cr_next(int n, const struct cpumask *mask);
void rust_cr_set_cpu(u32 cpu, struct cpumask *mask);
void rust_cr_or_node(struct cpumask *update_mask, u32 cpu);
const struct cpumask *rust_cr_sibling_mask(u32 cpu);
const struct cpumask *rust_cr_core_mask(u32 cpu);
const struct cpumask *rust_cr_node_mask(u32 cpu);

u32 rust_cr_nr_cpu_ids(void) { return nr_cpu_ids; }
void *rust_cr_kzalloc(size_t size, gfp_t gfp) { return kzalloc(size, gfp); }
void rust_cr_kref_init(struct cpu_rmap *rmap) { kref_init(&rmap->refcount); }
u32 rust_cr_next_possible(int n) { return cpumask_next(n, cpu_possible_mask); }
u32 rust_cr_next_online(int n) { return cpumask_next(n, cpu_online_mask); }
u32 rust_cr_next(int n, const struct cpumask *mask) { return cpumask_next(n, mask); }
void rust_cr_set_cpu(u32 cpu, struct cpumask *mask) { cpumask_set_cpu(cpu, mask); }
void rust_cr_or_node(struct cpumask *update_mask, u32 cpu) { cpumask_or(update_mask, update_mask, cpumask_of_node(cpu_to_node(cpu))); }
const struct cpumask *rust_cr_sibling_mask(u32 cpu) { return topology_sibling_cpumask(cpu); }
const struct cpumask *rust_cr_core_mask(u32 cpu) { return topology_core_cpumask(cpu); }
const struct cpumask *rust_cr_node_mask(u32 cpu) { return cpumask_of_node(cpu_to_node(cpu)); }

/**
 * alloc_cpu_rmap - allocate CPU affinity reverse-map
 * @size: Number of objects to be mapped
 * @flags: Allocation flags e.g. %GFP_KERNEL
 */
struct cpu_rmap *alloc_cpu_rmap(unsigned int size, gfp_t flags)
{
	return rust_alloc_cpu_rmap(size, flags);
}
EXPORT_SYMBOL(alloc_cpu_rmap);

/**
 * cpu_rmap_release - internal reclaiming helper called from kref_put
 * @ref: kref to struct cpu_rmap
 */
static void cpu_rmap_release(struct kref *ref)
{
	struct cpu_rmap *rmap = container_of(ref, struct cpu_rmap, refcount);
	kfree(rmap);
}

/**
 * cpu_rmap_get - internal helper to get new ref on a cpu_rmap
 * @rmap: reverse-map allocated with alloc_cpu_rmap()
 */
void cpu_rmap_get(struct cpu_rmap *rmap)
{
	kref_get(&rmap->refcount);
}

/**
 * cpu_rmap_put - release ref on a cpu_rmap
 * @rmap: reverse-map allocated with alloc_cpu_rmap()
 */
int cpu_rmap_put(struct cpu_rmap *rmap)
{
	return kref_put(&rmap->refcount, cpu_rmap_release);
}
EXPORT_SYMBOL(cpu_rmap_put);

/**
 * cpu_rmap_add - add object to a rmap
 * @rmap: CPU rmap allocated with alloc_cpu_rmap()
 * @obj: Object to add to rmap
 *
 * Return index of object or -ENOSPC if no free entry was found
 */
int cpu_rmap_add(struct cpu_rmap *rmap, void *obj)
{
	return rust_cpu_rmap_add(rmap, obj);
}
EXPORT_SYMBOL(cpu_rmap_add);

/**
 * cpu_rmap_update - update CPU rmap following a change of object affinity
 * @rmap: CPU rmap to update
 * @index: Index of object whose affinity changed
 * @affinity: New CPU affinity of object
 */
int cpu_rmap_update(struct cpu_rmap *rmap, u16 index,
		    const struct cpumask *affinity)
{
	cpumask_var_t update_mask;

	if (unlikely(!zalloc_cpumask_var(&update_mask, GFP_KERNEL)))
		return -ENOMEM;

	rust_cpu_rmap_update(rmap, index, affinity, update_mask);

	free_cpumask_var(update_mask);
	return 0;
}
EXPORT_SYMBOL(cpu_rmap_update);

/* Glue between IRQ affinity notifiers and CPU rmaps */

struct irq_glue {
	struct irq_affinity_notify notify;
	struct cpu_rmap *rmap;
	u16 index;
};

/**
 * free_irq_cpu_rmap - free a CPU affinity reverse-map used for IRQs
 * @rmap: Reverse-map allocated with alloc_irq_cpu_map(), or %NULL
 *
 * Must be called in process context, before freeing the IRQs.
 */
void free_irq_cpu_rmap(struct cpu_rmap *rmap)
{
	struct irq_glue *glue;
	u16 index;

	if (!rmap)
		return;

	for (index = 0; index < rmap->size; index++) {
		glue = rmap->obj[index];
		if (glue)
			irq_set_affinity_notifier(glue->notify.irq, NULL);
	}

	cpu_rmap_put(rmap);
}
EXPORT_SYMBOL(free_irq_cpu_rmap);

/**
 * irq_cpu_rmap_notify - callback for IRQ subsystem when IRQ affinity updated
 * @notify: struct irq_affinity_notify passed by irq/manage.c
 * @mask: cpu mask for new SMP affinity
 *
 * This is executed in workqueue context.
 */
static void
irq_cpu_rmap_notify(struct irq_affinity_notify *notify, const cpumask_t *mask)
{
	struct irq_glue *glue =
		container_of(notify, struct irq_glue, notify);
	int rc;

	rc = cpu_rmap_update(glue->rmap, glue->index, mask);
	if (rc)
		pr_warn("irq_cpu_rmap_notify: update failed: %d\n", rc);
}

/**
 * irq_cpu_rmap_release - reclaiming callback for IRQ subsystem
 * @ref: kref to struct irq_affinity_notify passed by irq/manage.c
 */
static void irq_cpu_rmap_release(struct kref *ref)
{
	struct irq_glue *glue =
		container_of(ref, struct irq_glue, notify.kref);

	glue->rmap->obj[glue->index] = NULL;
	cpu_rmap_put(glue->rmap);
	kfree(glue);
}

/**
 * irq_cpu_rmap_remove - remove an IRQ from a CPU affinity reverse-map
 * @rmap: The reverse-map
 * @irq: The IRQ number
 */
int irq_cpu_rmap_remove(struct cpu_rmap *rmap, int irq)
{
	return irq_set_affinity_notifier(irq, NULL);
}
EXPORT_SYMBOL(irq_cpu_rmap_remove);

/**
 * irq_cpu_rmap_add - add an IRQ to a CPU affinity reverse-map
 * @rmap: The reverse-map
 * @irq: The IRQ number
 *
 * This adds an IRQ affinity notifier that will update the reverse-map
 * automatically.
 *
 * Must be called in process context, after the IRQ is allocated but
 * before it is bound with request_irq().
 */
int irq_cpu_rmap_add(struct cpu_rmap *rmap, int irq)
{
	struct irq_glue *glue = kzalloc(sizeof(*glue), GFP_KERNEL);
	int rc;

	if (!glue)
		return -ENOMEM;
	glue->notify.notify = irq_cpu_rmap_notify;
	glue->notify.release = irq_cpu_rmap_release;
	glue->rmap = rmap;
	cpu_rmap_get(rmap);
	rc = cpu_rmap_add(rmap, glue);
	if (rc < 0)
		goto err_add;

	glue->index = rc;
	rc = irq_set_affinity_notifier(irq, &glue->notify);
	if (rc)
		goto err_set;

	return rc;

err_set:
	rmap->obj[glue->index] = NULL;
err_add:
	cpu_rmap_put(glue->rmap);
	kfree(glue);
	return rc;
}
EXPORT_SYMBOL(irq_cpu_rmap_add);
