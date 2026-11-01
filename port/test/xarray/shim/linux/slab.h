/* SPDX-License-Identifier: GPL-2.0-only */
/* radix_tree_node_cachep / kmem_cache_alloc_lru's REAL bodies live in
 * radix_tree_stub.c (a real allocator, not a mock: it has to actually
 * hand out and reclaim struct xa_node storage for the differential to
 * mean anything), matching this file's declaration to lib/radix-tree.h. */
#ifndef _SHIM_XARRAY_LINUX_SLAB_H
#define _SHIM_XARRAY_LINUX_SLAB_H
#include <linux/types.h>

struct list_lru;
struct kmem_cache;

void *kmem_cache_alloc_lru(struct kmem_cache *cachep, struct list_lru *lru,
		gfp_t gfp);

#endif
