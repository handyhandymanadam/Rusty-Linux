// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2016 Thomas Gleixner.
 * Copyright (C) 2016-2017 Christoph Hellwig.
 */
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/sort.h>
#include <linux/group_cpus.h>

#ifdef CONFIG_SMP

/*
 * RUST PORT (lib/group_cpus.c, 6.18.49): the grouping algorithm -- grp_spread_init_one(), get_nodes_in_cpumask(),
 * alloc_nodes_groups() and __group_cpus_evenly() -- is in group_cpus_rs.rs. This file keeps group_cpus_evenly() itself (the
 * scratch-mask and node-table allocation and its unwinding depend on CONFIG_CPUMASK_OFFSTACK, and the export's MODVERSIONS
 * fingerprint comes from the DWARF of its definition) and one-line wrappers for every accessor whose layout or definition varies
 * by configuration. WARN_ON_ONCE() sites live in the wrappers below, so a warning names this file, not group_cpus.c (recorded
 * divergence). Upstream's file is installed as group_cpus_norust.c for CONFIG_RUST=n.
 */
static_assert(MAX_NUMNODES <= 1024);

int rust___group_cpus_evenly(unsigned int startgrp, unsigned int numgrps, void *node_to_cpumask,
			     const struct cpumask *cpu_mask, struct cpumask *nmsk, struct cpumask *masks);

unsigned int rust_gc_nr_cpu_ids(void);
unsigned int rust_gc_nr_node_ids(void);
int rust_gc_max_numnodes(void);
size_t rust_gc_cpumask_stride(void);
int rust_gc_next_node(int n);
struct cpumask *rust_gc_node_mask(void *tbl, unsigned int n);
const struct cpumask *rust_gc_sibling_mask(int cpu);
unsigned int rust_gc_cpumask_first(const struct cpumask *m);
unsigned int rust_gc_cpumask_next(int n, const struct cpumask *m);
void rust_gc_cpumask_clear_cpu(int cpu, struct cpumask *m);
void rust_gc_cpumask_set_cpu(int cpu, struct cpumask *m);
bool rust_gc_cpumask_test_and_clear_cpu(int cpu, struct cpumask *m);
bool rust_gc_cpumask_and(struct cpumask *d, const struct cpumask *a, const struct cpumask *b);
void rust_gc_cpumask_or(struct cpumask *d, const struct cpumask *a, const struct cpumask *b);
unsigned int rust_gc_cpumask_weight(const struct cpumask *m);
bool rust_gc_cpumask_empty(const struct cpumask *m);
bool rust_gc_cpumask_intersects(const struct cpumask *a, const struct cpumask *b);
void rust_gc_warn_numgrps_zero(bool cond);
void rust_gc_warn_ngroups_gt_ncpus_alloc(bool cond);
void rust_gc_warn_ngroups_gt_ncpus_spread(bool cond);
void *rust_gc_kcalloc(size_t n, size_t size);
void rust_gc_kfree(void *p);

unsigned int rust_gc_nr_cpu_ids(void) { return nr_cpu_ids; }
unsigned int rust_gc_nr_node_ids(void) { return nr_node_ids; }
int rust_gc_max_numnodes(void) { return MAX_NUMNODES; }
size_t rust_gc_cpumask_stride(void) { return sizeof(struct cpumask); }
/* the smallest possible node after n (-1 to start), or MAX_NUMNODES: the for_each_node() macro itself */
int rust_gc_next_node(int n)
{
	int k;

	for_each_node(k)
		if (k > n)
			return k;
	return MAX_NUMNODES;
}
/* node_to_cpumask[n]: a pointer (CPUMASK_OFFSTACK) or an inline array (not), either way the mask's address */
struct cpumask *rust_gc_node_mask(void *tbl, unsigned int n) { cpumask_var_t *masks = tbl; return masks[n]; }
const struct cpumask *rust_gc_sibling_mask(int cpu) { return topology_sibling_cpumask(cpu); }
unsigned int rust_gc_cpumask_first(const struct cpumask *m) { return cpumask_first(m); }
unsigned int rust_gc_cpumask_next(int n, const struct cpumask *m) { return cpumask_next(n, m); }
void rust_gc_cpumask_clear_cpu(int cpu, struct cpumask *m) { cpumask_clear_cpu(cpu, m); }
void rust_gc_cpumask_set_cpu(int cpu, struct cpumask *m) { cpumask_set_cpu(cpu, m); }
bool rust_gc_cpumask_test_and_clear_cpu(int cpu, struct cpumask *m) { return cpumask_test_and_clear_cpu(cpu, m); }
bool rust_gc_cpumask_and(struct cpumask *d, const struct cpumask *a, const struct cpumask *b) { return cpumask_and(d, a, b); }
void rust_gc_cpumask_or(struct cpumask *d, const struct cpumask *a, const struct cpumask *b) { cpumask_or(d, a, b); }
unsigned int rust_gc_cpumask_weight(const struct cpumask *m) { return cpumask_weight(m); }
bool rust_gc_cpumask_empty(const struct cpumask *m) { return cpumask_empty(m); }
bool rust_gc_cpumask_intersects(const struct cpumask *a, const struct cpumask *b) { return cpumask_intersects(a, b); }
void rust_gc_warn_numgrps_zero(bool cond) { WARN_ON_ONCE(cond); }
void rust_gc_warn_ngroups_gt_ncpus_alloc(bool cond) { WARN_ON_ONCE(cond); }
void rust_gc_warn_ngroups_gt_ncpus_spread(bool cond) { WARN_ON_ONCE(cond); }
void *rust_gc_kcalloc(size_t n, size_t size) { return kcalloc(n, size, GFP_KERNEL); }
void rust_gc_kfree(void *p) { kfree(p); }

static cpumask_var_t *alloc_node_to_cpumask(void)
{
	cpumask_var_t *masks;
	int node;

	masks = kcalloc(nr_node_ids, sizeof(cpumask_var_t), GFP_KERNEL);
	if (!masks)
		return NULL;

	for (node = 0; node < nr_node_ids; node++) {
		if (!zalloc_cpumask_var(&masks[node], GFP_KERNEL))
			goto out_unwind;
	}

	return masks;

out_unwind:
	while (--node >= 0)
		free_cpumask_var(masks[node]);
	kfree(masks);
	return NULL;
}

static void free_node_to_cpumask(cpumask_var_t *masks)
{
	int node;

	for (node = 0; node < nr_node_ids; node++)
		free_cpumask_var(masks[node]);
	kfree(masks);
}

static void build_node_to_cpumask(cpumask_var_t *masks)
{
	int cpu;

	for_each_possible_cpu(cpu)
		cpumask_set_cpu(cpu, masks[cpu_to_node(cpu)]);
}

/**
 * group_cpus_evenly - Group all CPUs evenly per NUMA/CPU locality
 * @numgrps: number of groups
 * @nummasks: number of initialized cpumasks
 *
 * Return: cpumask array if successful, NULL otherwise. And each element
 * includes CPUs assigned to this group. nummasks contains the number
 * of initialized masks which can be less than numgrps.
 *
 * Try to put close CPUs from viewpoint of CPU and NUMA locality into
 * same group, and run two-stage grouping:
 *	1) allocate present CPUs on these groups evenly first
 *	2) allocate other possible CPUs on these groups evenly
 *
 * We guarantee in the resulted grouping that all CPUs are covered, and
 * no same CPU is assigned to multiple groups
 */
struct cpumask *group_cpus_evenly(unsigned int numgrps, unsigned int *nummasks)
{
	unsigned int curgrp = 0, nr_present = 0, nr_others = 0;
	cpumask_var_t *node_to_cpumask;
	cpumask_var_t nmsk, npresmsk;
	int ret = -ENOMEM;
	struct cpumask *masks = NULL;

	if (numgrps == 0)
		return NULL;

	if (!zalloc_cpumask_var(&nmsk, GFP_KERNEL))
		return NULL;

	if (!zalloc_cpumask_var(&npresmsk, GFP_KERNEL))
		goto fail_nmsk;

	node_to_cpumask = alloc_node_to_cpumask();
	if (!node_to_cpumask)
		goto fail_npresmsk;

	masks = kcalloc(numgrps, sizeof(*masks), GFP_KERNEL);
	if (!masks)
		goto fail_node_to_cpumask;

	build_node_to_cpumask(node_to_cpumask);

	/*
	 * Make a local cache of 'cpu_present_mask', so the two stages
	 * spread can observe consistent 'cpu_present_mask' without holding
	 * cpu hotplug lock, then we can reduce deadlock risk with cpu
	 * hotplug code.
	 *
	 * Here CPU hotplug may happen when reading `cpu_present_mask`, and
	 * we can live with the case because it only affects that hotplug
	 * CPU is handled in the 1st or 2nd stage, and either way is correct
	 * from API user viewpoint since 2-stage spread is sort of
	 * optimization.
	 */
	cpumask_copy(npresmsk, data_race(cpu_present_mask));

	/* grouping present CPUs first */
	ret = rust___group_cpus_evenly(curgrp, numgrps, node_to_cpumask,
				  npresmsk, nmsk, masks);
	if (ret < 0)
		goto fail_node_to_cpumask;
	nr_present = ret;

	/*
	 * Allocate non present CPUs starting from the next group to be
	 * handled. If the grouping of present CPUs already exhausted the
	 * group space, assign the non present CPUs to the already
	 * allocated out groups.
	 */
	if (nr_present >= numgrps)
		curgrp = 0;
	else
		curgrp = nr_present;
	cpumask_andnot(npresmsk, cpu_possible_mask, npresmsk);
	ret = rust___group_cpus_evenly(curgrp, numgrps, node_to_cpumask,
				  npresmsk, nmsk, masks);
	if (ret >= 0)
		nr_others = ret;

 fail_node_to_cpumask:
	free_node_to_cpumask(node_to_cpumask);

 fail_npresmsk:
	free_cpumask_var(npresmsk);

 fail_nmsk:
	free_cpumask_var(nmsk);
	if (ret < 0) {
		kfree(masks);
		return NULL;
	}
	*nummasks = min(nr_present + nr_others, numgrps);
	return masks;
}
#else /* CONFIG_SMP */
struct cpumask *group_cpus_evenly(unsigned int numgrps, unsigned int *nummasks)
{
	struct cpumask *masks;

	if (numgrps == 0)
		return NULL;

	masks = kcalloc(numgrps, sizeof(*masks), GFP_KERNEL);
	if (!masks)
		return NULL;

	/* assign all CPUs(cpu 0) to the 1st group only */
	cpumask_copy(&masks[0], cpu_possible_mask);
	*nummasks = 1;
	return masks;
}
#endif /* CONFIG_SMP */
EXPORT_SYMBOL_GPL(group_cpus_evenly);
