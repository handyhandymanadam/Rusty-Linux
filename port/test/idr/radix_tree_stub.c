/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Real allocator backing lib/radix-tree.h's radix_tree_node_cachep /
 * kmem_cache_alloc_lru / radix_tree_node_rcu_free, shared by BOTH arms
 * of the differential (the C reference via normal linkage, and the Rust
 * probe via matching extern "C" declarations) -- one real allocator, not
 * two, so a node one arm allocates and the other frees (never happens
 * here since each arm owns its own tree, but the two arms' nodes must
 * still look identical in memory shape) behaves the same way.
 *
 * The real kernel's radix_tree_node_ctor() runs `memset(node, 0,
 * sizeof(*node))` + INIT_LIST_HEAD() -- but ONLY the first time a slab
 * object is carved out. Every subsequent reuse instead relies on
 * radix_tree_node_rcu_free()'s own "Must only free zeroed nodes into
 * the slab" memset before the object goes back to the slab freelist
 * (lib/radix-tree.c). A plain malloc()-backed stub that only called
 * INIT_LIST_HEAD() would leave slots[]/marks[] as glibc's leftover
 * heap bytes from a PRIOR free() in this same process -- which
 * satisfied xa_is_sibling() on garbage often enough to walk
 * xas_descend()'s sibling-chase loop into a real infinite cycle the
 * first time this harness ran a second xarray after destroying a
 * first one. calloc() reproduces the "always zeroed" guarantee
 * directly, which is simpler than reproducing zero-on-free to match a
 * real allocator this harness never actually exercises the reuse path
 * of anyway (malloc/free, not a slab freelist).
 */
#include <linux/list.h>
#include <linux/xarray.h>
#include <stddef.h>
#include <stdlib.h>

struct kmem_cache {
	int unused;
};

static struct kmem_cache real_radix_tree_node_cachep;
struct kmem_cache *radix_tree_node_cachep = &real_radix_tree_node_cachep;

void *kmem_cache_alloc_lru(struct kmem_cache *cachep, struct list_lru *lru,
		gfp_t gfp)
{
	struct xa_node *node;
	extern long fail_node;

	if (fail_node < 0 || (fail_node > 0 && --fail_node == 0))
		return NULL;
	node = calloc(1, sizeof(struct xa_node));

	(void)cachep;
	(void)lru;
	(void)gfp;
	if (!node)
		return NULL;
	INIT_LIST_HEAD(&node->private_list);
	return node;
}

void radix_tree_node_rcu_free(struct rcu_head *head)
{
	struct xa_node *node = (struct xa_node *)
		((char *)head - offsetof(struct xa_node, rcu_head));

	free(node);
}

/* The real kernel's counterparts live in port/tree/lib/xarray.c, kept in
 * C there only because kmem_cache_alloc_lru() is an allocation-profiling
 * macro with no linkable symbol (logs/allocation.md) -- a restriction
 * that does not exist in this userspace harness, where the function
 * above already is a real, callable, un-macroed body. Same real names
 * and signatures so xarray_rs.rs's extern "C" declarations are identical
 * in both contexts; __GFP_ACCOUNT's actual value does not matter here
 * (this stub's allocator ignores gfp entirely), only that `account`
 * being nonzero does not crash. */
struct xa_node *rust_xa_node_alloc_nowait(struct list_lru *lru, int account)
{
	(void)account;
	return kmem_cache_alloc_lru(radix_tree_node_cachep, lru, GFP_NOWAIT);
}

struct xa_node *rust_xa_node_alloc(struct list_lru *lru, gfp_t gfp, int account)
{
	(void)account;
	return kmem_cache_alloc_lru(radix_tree_node_cachep, lru, gfp);
}

int rust_gfp_allows_blocking(gfp_t gfp)
{
	return gfpflags_allow_blocking(gfp);
}
