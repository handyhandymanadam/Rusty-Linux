// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2001 Momchil Velikov
 * Portions Copyright (C) 2001 Christoph Hellwig
 * Copyright (C) 2005 SGI, Christoph Lameter
 * Copyright (C) 2006 Nick Piggin
 * Copyright (C) 2012 Konstantin Khlebnikov
 * Copyright (C) 2016 Intel, Matthew Wilcox
 * Copyright (C) 2016 Intel, Ross Zwisler
 *
 * RUST PORT (lib/radix-tree.c, 6.18.49): the tree algorithms -- extend, shrink, create, insert, lookup, replace, tags, next_chunk, gang lookups, delete, idr_get_free,
 * idr_destroy -- are in radix_tree_rs.rs. This file keeps the node cache and the per-CPU preload (radix_tree_node_alloc(), __radix_tree_preload(), radix_tree_preload(),
 * radix_tree_maybe_preload(), idr_preload(), the constructor, the CPU-dead hook, radix_tree_init()), radix_tree_node_free() (call_rcu), the exports as thunks (the
 * MODVERSIONS fingerprint comes from the DWARF of the definition), and wrappers for the BUG_ON/WARN_ON_ONCE sites (the report now names this file -- recorded
 * divergence). Upstream's whole file is installed as radix-tree_norust.c for CONFIG_RUST=n.
 */

#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/bug.h>
#include <linux/cpu.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/idr.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kmemleak.h>
#include <linux/percpu.h>
#include <linux/preempt.h>		/* in_interrupt() */
#include <linux/radix-tree.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/xarray.h>

#include "radix-tree.h"

/*
 * Radix tree node cache.
 */
struct kmem_cache *radix_tree_node_cachep;

/*
 * The radix tree is variable-height, so an insert operation not only has
 * to build the branch to its corresponding item, it also has to build the
 * branch to existing items if the size has to be increased (by
 * radix_tree_extend).
 *
 * The worst case is a zero height tree with just a single item at index 0,
 * and then inserting an item at index ULONG_MAX. This requires 2 new branches
 * of RADIX_TREE_MAX_PATH size to be created, with only the root node shared.
 * Hence:
 */
#define RADIX_TREE_PRELOAD_SIZE (RADIX_TREE_MAX_PATH * 2 - 1)

/*
 * The IDR does not have to be as high as the radix tree since it uses
 * signed integers, not unsigned longs.
 */
#define IDR_INDEX_BITS		(8 /* CHAR_BIT */ * sizeof(int) - 1)
#define IDR_MAX_PATH		(DIV_ROUND_UP(IDR_INDEX_BITS, \
						RADIX_TREE_MAP_SHIFT))
#define IDR_PRELOAD_SIZE	(IDR_MAX_PATH * 2 - 1)

/*
 * Per-cpu pool of preloaded nodes
 */
DEFINE_PER_CPU(struct radix_tree_preload, radix_tree_preloads) = {
	.lock = INIT_LOCAL_LOCK(lock),
};
EXPORT_PER_CPU_SYMBOL_GPL(radix_tree_preloads);

/*
 * This assumes that the caller has performed appropriate preallocation, and
 * that the caller has pinned this thread of control to the current CPU.
 */
static struct radix_tree_node *
radix_tree_node_alloc(gfp_t gfp_mask, struct radix_tree_node *parent,
			struct radix_tree_root *root,
			unsigned int shift, unsigned int offset,
			unsigned int count, unsigned int nr_values)
{
	struct radix_tree_node *ret = NULL;

	/*
	 * Preload code isn't irq safe and it doesn't make sense to use
	 * preloading during an interrupt anyway as all the allocations have
	 * to be atomic. So just do normal allocation when in interrupt.
	 */
	if (!gfpflags_allow_blocking(gfp_mask) && !in_interrupt()) {
		struct radix_tree_preload *rtp;

		/*
		 * Even if the caller has preloaded, try to allocate from the
		 * cache first for the new node to get accounted to the memory
		 * cgroup.
		 */
		ret = kmem_cache_alloc(radix_tree_node_cachep,
				       gfp_mask | __GFP_NOWARN);
		if (ret)
			goto out;

		/*
		 * Provided the caller has preloaded here, we will always
		 * succeed in getting a node here (and never reach
		 * kmem_cache_alloc)
		 */
		rtp = this_cpu_ptr(&radix_tree_preloads);
		if (rtp->nr) {
			ret = rtp->nodes;
			rtp->nodes = ret->parent;
			rtp->nr--;
		}
		/*
		 * Update the allocation stack trace as this is more useful
		 * for debugging.
		 */
		kmemleak_update_trace(ret);
		goto out;
	}
	ret = kmem_cache_alloc(radix_tree_node_cachep, gfp_mask);
out:
	BUG_ON(radix_tree_is_internal_node(ret));
	if (ret) {
		ret->shift = shift;
		ret->offset = offset;
		ret->count = count;
		ret->nr_values = nr_values;
		ret->parent = parent;
		ret->array = root;
	}
	return ret;
}

void radix_tree_node_rcu_free(struct rcu_head *head)
{
	struct radix_tree_node *node =
			container_of(head, struct radix_tree_node, rcu_head);

	/*
	 * Must only free zeroed nodes into the slab.  We can be left with
	 * non-NULL entries by radix_tree_free_nodes, so clear the entries
	 * and tags here.
	 */
	memset(node->slots, 0, sizeof(node->slots));
	memset(node->tags, 0, sizeof(node->tags));
	INIT_LIST_HEAD(&node->private_list);

	kmem_cache_free(radix_tree_node_cachep, node);
}

static inline void
radix_tree_node_free(struct radix_tree_node *node)
{
	call_rcu(&node->rcu_head, radix_tree_node_rcu_free);
}

/*
 * Load up this CPU's radix_tree_node buffer with sufficient objects to
 * ensure that the addition of a single element in the tree cannot fail.  On
 * success, return zero, with preemption disabled.  On error, return -ENOMEM
 * with preemption not disabled.
 *
 * To make use of this facility, the radix tree must be initialised without
 * __GFP_DIRECT_RECLAIM being passed to INIT_RADIX_TREE().
 */
static __must_check int __radix_tree_preload(gfp_t gfp_mask, unsigned nr)
{
	struct radix_tree_preload *rtp;
	struct radix_tree_node *node;
	int ret = -ENOMEM;

	/*
	 * Nodes preloaded by one cgroup can be used by another cgroup, so
	 * they should never be accounted to any particular memory cgroup.
	 */
	gfp_mask &= ~__GFP_ACCOUNT;

	local_lock(&radix_tree_preloads.lock);
	rtp = this_cpu_ptr(&radix_tree_preloads);
	while (rtp->nr < nr) {
		local_unlock(&radix_tree_preloads.lock);
		node = kmem_cache_alloc(radix_tree_node_cachep, gfp_mask);
		if (node == NULL)
			goto out;
		local_lock(&radix_tree_preloads.lock);
		rtp = this_cpu_ptr(&radix_tree_preloads);
		if (rtp->nr < nr) {
			node->parent = rtp->nodes;
			rtp->nodes = node;
			rtp->nr++;
		} else {
			kmem_cache_free(radix_tree_node_cachep, node);
		}
	}
	ret = 0;
out:
	return ret;
}

/*
 * Load up this CPU's radix_tree_node buffer with sufficient objects to
 * ensure that the addition of a single element in the tree cannot fail.  On
 * success, return zero, with preemption disabled.  On error, return -ENOMEM
 * with preemption not disabled.
 *
 * To make use of this facility, the radix tree must be initialised without
 * __GFP_DIRECT_RECLAIM being passed to INIT_RADIX_TREE().
 */
int radix_tree_preload(gfp_t gfp_mask)
{
	/* Warn on non-sensical use... */
	WARN_ON_ONCE(!gfpflags_allow_blocking(gfp_mask));
	return __radix_tree_preload(gfp_mask, RADIX_TREE_PRELOAD_SIZE);
}
EXPORT_SYMBOL(radix_tree_preload);

/*
 * The same as above function, except we don't guarantee preloading happens.
 * We do it, if we decide it helps. On success, return zero with preemption
 * disabled. On error, return -ENOMEM with preemption not disabled.
 */
int radix_tree_maybe_preload(gfp_t gfp_mask)
{
	if (gfpflags_allow_blocking(gfp_mask))
		return __radix_tree_preload(gfp_mask, RADIX_TREE_PRELOAD_SIZE);
	/* Preloading doesn't help anything with this gfp mask, skip it */
	local_lock(&radix_tree_preloads.lock);
	return 0;
}
EXPORT_SYMBOL(radix_tree_maybe_preload);

/**
 * idr_preload - preload for idr_alloc()
 * @gfp_mask: allocation mask to use for preloading
 *
 * Preallocate memory to use for the next call to idr_alloc().  This function
 * returns with preemption disabled.  It will be enabled by idr_preload_end().
 */
void idr_preload(gfp_t gfp_mask)
{
	if (__radix_tree_preload(gfp_mask, IDR_PRELOAD_SIZE))
		local_lock(&radix_tree_preloads.lock);
}
EXPORT_SYMBOL(idr_preload);



static_assert(RADIX_TREE_MAP_SHIFT == 6 && RADIX_TREE_MAX_TAGS == 3 && RADIX_TREE_TAG_LONGS == 1 && RADIX_TREE_MAP_SIZE == 64);
static_assert(offsetof(struct radix_tree_node, shift) == 0 && offsetof(struct radix_tree_node, offset) == 1 && offsetof(struct radix_tree_node, count) == 2 &&
	      offsetof(struct radix_tree_node, nr_values) == 3 && offsetof(struct radix_tree_node, parent) == 8 && offsetof(struct radix_tree_node, array) == 16 &&
	      offsetof(struct radix_tree_node, slots) == 40 && offsetof(struct radix_tree_node, tags) == 40 + 8 * RADIX_TREE_MAP_SIZE &&
	      sizeof(struct radix_tree_node) == 40 + 8 * RADIX_TREE_MAP_SIZE + 8 * RADIX_TREE_MAX_TAGS);
static_assert(sizeof(struct radix_tree_iter) == 32 && offsetof(struct radix_tree_iter, index) == 0 && offsetof(struct radix_tree_iter, next_index) == 8 &&
	      offsetof(struct radix_tree_iter, tags) == 16 && offsetof(struct radix_tree_iter, node) == 24);
static_assert(IDR_FREE == 0 && ROOT_IS_IDR == 4);

extern const size_t rust_rt_off_flags, rust_rt_off_head;
extern const unsigned int rust_rt_root_tag_shift, rust_rt_root_gfp_bits;
const size_t rust_rt_off_flags = offsetof(struct radix_tree_root, xa_flags);
const size_t rust_rt_off_head = offsetof(struct radix_tree_root, xa_head);
const unsigned int rust_rt_root_tag_shift = ROOT_TAG_SHIFT;
const unsigned int rust_rt_root_gfp_bits = (__GFP_BITS_MASK & ~GFP_ZONEMASK);

int rust_radix_tree_insert(struct radix_tree_root *root, unsigned long index, void *item);
void *rust___radix_tree_lookup(const struct radix_tree_root *root, unsigned long index, struct radix_tree_node **nodep, void __rcu ***slotp);
void __rcu **rust_radix_tree_lookup_slot(const struct radix_tree_root *root, unsigned long index);
void *rust_radix_tree_lookup(const struct radix_tree_root *root, unsigned long index);
void rust___radix_tree_replace(struct radix_tree_root *root, struct radix_tree_node *node, void __rcu **slot, void *item);
void rust_radix_tree_replace_slot(struct radix_tree_root *root, void __rcu **slot, void *item);
void rust_radix_tree_iter_replace(struct radix_tree_root *root, const struct radix_tree_iter *iter, void __rcu **slot, void *item);
void *rust_radix_tree_tag_set(struct radix_tree_root *root, unsigned long index, unsigned int tag);
void *rust_radix_tree_tag_clear(struct radix_tree_root *root, unsigned long index, unsigned int tag);
void rust_radix_tree_iter_tag_clear(struct radix_tree_root *root, const struct radix_tree_iter *iter, unsigned int tag);
int rust_radix_tree_tag_get(const struct radix_tree_root *root, unsigned long index, unsigned int tag);
void __rcu **rust_radix_tree_iter_resume(void __rcu **slot, struct radix_tree_iter *iter);
void __rcu **rust_radix_tree_next_chunk(const struct radix_tree_root *root, struct radix_tree_iter *iter, unsigned flags);
unsigned int rust_radix_tree_gang_lookup(const struct radix_tree_root *root, void **results, unsigned long first_index, unsigned int max_items);
unsigned int rust_radix_tree_gang_lookup_tag(const struct radix_tree_root *root, void **results, unsigned long first_index, unsigned int max_items, unsigned int tag);
unsigned int rust_radix_tree_gang_lookup_tag_slot(const struct radix_tree_root *root, void __rcu ***results, unsigned long first_index, unsigned int max_items, unsigned int tag);
void rust_radix_tree_iter_delete(struct radix_tree_root *root, struct radix_tree_iter *iter, void __rcu **slot);
void *rust_radix_tree_delete_item(struct radix_tree_root *root, unsigned long index, void *item);
void *rust_radix_tree_delete(struct radix_tree_root *root, unsigned long index);
int rust_radix_tree_tagged(const struct radix_tree_root *root, unsigned int tag);
void __rcu **rust_idr_get_free(struct radix_tree_root *root, struct radix_tree_iter *iter, gfp_t gfp, unsigned long max);
void rust_idr_destroy(struct radix_tree_root *root);

struct radix_tree_node *rust_rt_node_alloc(gfp_t gfp, struct radix_tree_node *parent, struct radix_tree_root *root, unsigned int shift, unsigned int offset,
					   unsigned int count, unsigned int nr_values);
void rust_rt_node_free(struct radix_tree_node *node);
void rust_rt_bug(bool cond);
void rust_rt_warn_replace(bool cond);
void rust_rt_warn_private_list_shrink(struct radix_tree_node *node);
void rust_rt_warn_private_list_delete(struct radix_tree_node *node);
void rust_rt_warn_private_list_free(struct radix_tree_node *node);

struct radix_tree_node *rust_rt_node_alloc(gfp_t gfp, struct radix_tree_node *parent, struct radix_tree_root *root, unsigned int shift, unsigned int offset,
					   unsigned int count, unsigned int nr_values)
{
	return radix_tree_node_alloc(gfp, parent, root, shift, offset, count, nr_values);
}
void rust_rt_node_free(struct radix_tree_node *node) { radix_tree_node_free(node); }
void rust_rt_bug(bool cond) { BUG_ON(cond); }
void rust_rt_warn_replace(bool cond) { WARN_ON_ONCE(cond); }
void rust_rt_warn_private_list_shrink(struct radix_tree_node *node) { WARN_ON_ONCE(!list_empty(&node->private_list)); }
void rust_rt_warn_private_list_delete(struct radix_tree_node *node) { WARN_ON_ONCE(!list_empty(&node->private_list)); }
void rust_rt_warn_private_list_free(struct radix_tree_node *node) { WARN_ON_ONCE(!list_empty(&node->private_list)); }

int radix_tree_insert(struct radix_tree_root *root, unsigned long index, void *item)
{
	return rust_radix_tree_insert(root, index, item);
}
EXPORT_SYMBOL(radix_tree_insert);

void *__radix_tree_lookup(const struct radix_tree_root *root, unsigned long index, struct radix_tree_node **nodep, void __rcu ***slotp)
{
	return rust___radix_tree_lookup(root, index, nodep, slotp);
}

void __rcu **radix_tree_lookup_slot(const struct radix_tree_root *root, unsigned long index)
{
	return rust_radix_tree_lookup_slot(root, index);
}
EXPORT_SYMBOL(radix_tree_lookup_slot);

void *radix_tree_lookup(const struct radix_tree_root *root, unsigned long index)
{
	return rust_radix_tree_lookup(root, index);
}
EXPORT_SYMBOL(radix_tree_lookup);

void __radix_tree_replace(struct radix_tree_root *root, struct radix_tree_node *node, void __rcu **slot, void *item)
{
	rust___radix_tree_replace(root, node, slot, item);
}

void radix_tree_replace_slot(struct radix_tree_root *root, void __rcu **slot, void *item)
{
	rust_radix_tree_replace_slot(root, slot, item);
}
EXPORT_SYMBOL(radix_tree_replace_slot);

void radix_tree_iter_replace(struct radix_tree_root *root, const struct radix_tree_iter *iter, void __rcu **slot, void *item)
{
	rust_radix_tree_iter_replace(root, iter, slot, item);
}

void *radix_tree_tag_set(struct radix_tree_root *root, unsigned long index, unsigned int tag)
{
	return rust_radix_tree_tag_set(root, index, tag);
}
EXPORT_SYMBOL(radix_tree_tag_set);

void *radix_tree_tag_clear(struct radix_tree_root *root, unsigned long index, unsigned int tag)
{
	return rust_radix_tree_tag_clear(root, index, tag);
}
EXPORT_SYMBOL(radix_tree_tag_clear);

void radix_tree_iter_tag_clear(struct radix_tree_root *root, const struct radix_tree_iter *iter, unsigned int tag)
{
	rust_radix_tree_iter_tag_clear(root, iter, tag);
}

int radix_tree_tag_get(const struct radix_tree_root *root, unsigned long index, unsigned int tag)
{
	return rust_radix_tree_tag_get(root, index, tag);
}
EXPORT_SYMBOL(radix_tree_tag_get);

void __rcu **radix_tree_iter_resume(void __rcu **slot, struct radix_tree_iter *iter)
{
	return rust_radix_tree_iter_resume(slot, iter);
}
EXPORT_SYMBOL(radix_tree_iter_resume);

void __rcu **radix_tree_next_chunk(const struct radix_tree_root *root, struct radix_tree_iter *iter, unsigned flags)
{
	return rust_radix_tree_next_chunk(root, iter, flags);
}
EXPORT_SYMBOL(radix_tree_next_chunk);

unsigned int radix_tree_gang_lookup(const struct radix_tree_root *root, void **results, unsigned long first_index, unsigned int max_items)
{
	return rust_radix_tree_gang_lookup(root, results, first_index, max_items);
}
EXPORT_SYMBOL(radix_tree_gang_lookup);

unsigned int radix_tree_gang_lookup_tag(const struct radix_tree_root *root, void **results, unsigned long first_index, unsigned int max_items, unsigned int tag)
{
	return rust_radix_tree_gang_lookup_tag(root, results, first_index, max_items, tag);
}
EXPORT_SYMBOL(radix_tree_gang_lookup_tag);

unsigned int radix_tree_gang_lookup_tag_slot(const struct radix_tree_root *root, void __rcu ***results, unsigned long first_index, unsigned int max_items,
					     unsigned int tag)
{
	return rust_radix_tree_gang_lookup_tag_slot(root, results, first_index, max_items, tag);
}
EXPORT_SYMBOL(radix_tree_gang_lookup_tag_slot);

void radix_tree_iter_delete(struct radix_tree_root *root, struct radix_tree_iter *iter, void __rcu **slot)
{
	rust_radix_tree_iter_delete(root, iter, slot);
}
EXPORT_SYMBOL(radix_tree_iter_delete);

void *radix_tree_delete_item(struct radix_tree_root *root, unsigned long index, void *item)
{
	return rust_radix_tree_delete_item(root, index, item);
}
EXPORT_SYMBOL(radix_tree_delete_item);

void *radix_tree_delete(struct radix_tree_root *root, unsigned long index)
{
	return rust_radix_tree_delete(root, index);
}
EXPORT_SYMBOL(radix_tree_delete);

int radix_tree_tagged(const struct radix_tree_root *root, unsigned int tag)
{
	return rust_radix_tree_tagged(root, tag);
}
EXPORT_SYMBOL(radix_tree_tagged);

void __rcu **idr_get_free(struct radix_tree_root *root, struct radix_tree_iter *iter, gfp_t gfp, unsigned long max)
{
	return rust_idr_get_free(root, iter, gfp, max);
}

void idr_destroy(struct idr *idr)
{
	rust_idr_destroy(&idr->idr_rt);
}
EXPORT_SYMBOL(idr_destroy);

static void
radix_tree_node_ctor(void *arg)
{
	struct radix_tree_node *node = arg;

	memset(node, 0, sizeof(*node));
	INIT_LIST_HEAD(&node->private_list);
}

static int radix_tree_cpu_dead(unsigned int cpu)
{
	struct radix_tree_preload *rtp;
	struct radix_tree_node *node;

	/* Free per-cpu pool of preloaded nodes */
	rtp = &per_cpu(radix_tree_preloads, cpu);
	while (rtp->nr) {
		node = rtp->nodes;
		rtp->nodes = node->parent;
		kmem_cache_free(radix_tree_node_cachep, node);
		rtp->nr--;
	}
	return 0;
}

void __init radix_tree_init(void)
{
	int ret;

	BUILD_BUG_ON(RADIX_TREE_MAX_TAGS + __GFP_BITS_SHIFT > 32);
	BUILD_BUG_ON(ROOT_IS_IDR & ~GFP_ZONEMASK);
	BUILD_BUG_ON(XA_CHUNK_SIZE > 255);
	radix_tree_node_cachep = kmem_cache_create("radix_tree_node",
			sizeof(struct radix_tree_node), 0,
			SLAB_PANIC | SLAB_RECLAIM_ACCOUNT,
			radix_tree_node_ctor);
	ret = cpuhp_setup_state_nocalls(CPUHP_RADIX_DEAD, "lib/radix:dead",
					NULL, radix_tree_cpu_dead);
	WARN_ON(ret < 0);
}
