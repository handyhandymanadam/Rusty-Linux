// SPDX-License-Identifier: GPL-2.0+
/*
 * Maple Tree implementation -- the entry file of the Rust port.
 * Copyright (c) 2018-2022 Oracle Corporation
 * Authors: Liam R. Howlett <Liam.Howlett@oracle.com>
 *	    Matthew Wilcox <willy@infradead.org>
 * Copyright (c) 2023 ByteDance
 * Author: Peng Zhang <zhangpeng.00@bytedance.com>
 *
 * RUST PORT (lib/maple_tree.c, 6.18.49): the whole algorithm is in maple_tree_rs.rs. This file keeps (1) every public entry point as a
 * thunk -- the MODVERSIONS fingerprints come from the DWARF of the definition -- (2) the operations that must stay C: the slab calls
 * (kmem_cache_*, sheaves, kfree_rcu, call_rcu), the spinlock / RCU read-side calls (inline and configuration-dependent), the BUG() /
 * WARN() sites (one helper per kind: the bug-table entry now names this file, once -- recorded divergence), the tracepoints, the
 * node cache and maple_tree_init(), and (3) static_asserts of every layout and constant the Rust mirrors. struct maple_tree itself is
 * not mirrored: where ma_flags and ma_root sit depends on the lock size, so the offsets are handed over as constants. Upstream's file
 * is installed as maple_tree_norust.c for CONFIG_RUST=n and for CONFIG_DEBUG_MAPLE_TREE (the dump / validate code is not ported).
 */

#include <linux/maple_tree.h>
#include <linux/xarray.h>
#include <linux/types.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/limits.h>
#include <asm/barrier.h>

#define CREATE_TRACE_POINTS
#include <trace/events/maple_tree.h>

#define ma_parent_ptr(x) ((struct maple_pnode *)(x))

static struct kmem_cache *maple_node_cache;

/* The layouts and constants maple_tree_rs.rs assumes, checked here against the real headers at every build. */
static_assert(sizeof(struct maple_node) == 256);
static_assert(offsetof(struct maple_node, parent) == 0 && offsetof(struct maple_node, slot) == 8);
static_assert(offsetof(struct maple_node, mr64.pivot) == 8 && offsetof(struct maple_node, mr64.slot) == 128 &&
	      offsetof(struct maple_node, mr64.meta) == 248);
static_assert(offsetof(struct maple_node, ma64.pivot) == 8 && offsetof(struct maple_node, ma64.slot) == 80 &&
	      offsetof(struct maple_node, ma64.gap) == 160 && offsetof(struct maple_node, ma64.meta) == 240);
static_assert(offsetof(struct maple_node, rcu) == 8 && offsetof(struct maple_node, piv_parent) == 24 &&
	      offsetof(struct maple_node, parent_slot) == 32 && offsetof(struct maple_node, type) == 36 &&
	      offsetof(struct maple_node, slot_len) == 40 && offsetof(struct maple_node, ma_flags) == 44);
static_assert(offsetof(struct maple_metadata, end) == 0 && offsetof(struct maple_metadata, gap) == 1);
static_assert(sizeof(struct rcu_head) == 16);
static_assert(sizeof(struct ma_state) == 88 && offsetof(struct ma_state, tree) == 0 && offsetof(struct ma_state, index) == 8 &&
	      offsetof(struct ma_state, last) == 16 && offsetof(struct ma_state, node) == 24 && offsetof(struct ma_state, min) == 32 &&
	      offsetof(struct ma_state, max) == 40 && offsetof(struct ma_state, sheaf) == 48 && offsetof(struct ma_state, alloc) == 56 &&
	      offsetof(struct ma_state, node_request) == 64 && offsetof(struct ma_state, status) == 72 &&
	      offsetof(struct ma_state, depth) == 76 && offsetof(struct ma_state, offset) == 77 &&
	      offsetof(struct ma_state, mas_flags) == 78 && offsetof(struct ma_state, end) == 79 &&
	      offsetof(struct ma_state, store_type) == 80);
static_assert(sizeof(enum maple_status) == 4 && sizeof(enum store_type) == 4 && sizeof(enum maple_type) == 4);
static_assert(MAPLE_NODE_SLOTS == 31 && MAPLE_RANGE64_SLOTS == 16 && MAPLE_ARANGE64_SLOTS == 10 && MAPLE_ALLOC_SLOTS == 30 &&
	      MAPLE_NODE_MASK == 255 && MAPLE_RESERVED_RANGE == 4096 && MAPLE_HEIGHT_MAX == 31 && MAPLE_NODE_TYPE_MASK == 0x0f &&
	      MAPLE_NODE_TYPE_SHIFT == 3);
static_assert(MT_FLAGS_ALLOC_RANGE == 1 && MT_FLAGS_USE_RCU == 2 && MT_FLAGS_HEIGHT_OFFSET == 2 && MT_FLAGS_HEIGHT_MASK == 0x7c &&
	      MT_FLAGS_LOCK_MASK == 0x300 && MT_FLAGS_LOCK_EXTERN == 0x300 && MT_FLAGS_ALLOC_WRAPPED == 0x800);
static_assert(maple_dense == 0 && maple_leaf_64 == 1 && maple_range_64 == 2 && maple_arange_64 == 3);
static_assert(wr_invalid == 0 && wr_new_root == 1 && wr_store_root == 2 && wr_exact_fit == 3 && wr_spanning_store == 4 &&
	      wr_split_store == 5 && wr_rebalance == 6 && wr_append == 7 && wr_node_store == 8 && wr_slot_store == 9);
static_assert(ma_active == 0 && ma_start == 1 && ma_root == 2 && ma_none == 3 && ma_pause == 4 && ma_overflow == 5 &&
	      ma_underflow == 6 && ma_error == 7);

/* Constants handed to the Rust. */
extern const size_t rust_mt_flags_off, rust_mt_root_off;
extern const gfp_t rust_gfp_nowait, rust_gfp_kernel;
const size_t rust_mt_flags_off = offsetof(struct maple_tree, ma_flags);
const size_t rust_mt_root_off = offsetof(struct maple_tree, ma_root);
const gfp_t rust_gfp_nowait = GFP_NOWAIT;
const gfp_t rust_gfp_kernel = GFP_KERNEL;

/* lib/maple_tree_rs.rs */
void rust_mt_free_walk(struct maple_node *node);
int rust_mas_alloc_cyclic(struct ma_state *mas, unsigned long *startp, void *entry, unsigned long range_lo, unsigned long range_hi, unsigned long *next, gfp_t gfp);
void *rust_mas_walk(struct ma_state *mas);
int rust_mas_empty_area(struct ma_state *mas, unsigned long min, unsigned long max, unsigned long size);
int rust_mas_empty_area_rev(struct ma_state *mas, unsigned long min, unsigned long max, unsigned long size);
void *rust_mas_store(struct ma_state *mas, void *entry);
int rust_mas_store_gfp(struct ma_state *mas, void *entry, gfp_t gfp);
void rust_mas_store_prealloc(struct ma_state *mas, void *entry);
int rust_mas_preallocate(struct ma_state *mas, void *entry, gfp_t gfp);
void rust_mas_destroy(struct ma_state *mas);
void *rust_mas_next(struct ma_state *mas, unsigned long max);
void *rust_mas_next_range(struct ma_state *mas, unsigned long max);
void *rust_mt_next(struct maple_tree *mt, unsigned long index, unsigned long max);
void *rust_mas_prev(struct ma_state *mas, unsigned long min);
void *rust_mas_prev_range(struct ma_state *mas, unsigned long min);
void *rust_mt_prev(struct maple_tree *mt, unsigned long index, unsigned long min);
void rust_mas_pause(struct ma_state *mas);
void *rust_mas_find(struct ma_state *mas, unsigned long max);
void *rust_mas_find_range(struct ma_state *mas, unsigned long max);
void *rust_mas_find_rev(struct ma_state *mas, unsigned long min);
void *rust_mas_find_range_rev(struct ma_state *mas, unsigned long min);
void *rust_mas_erase(struct ma_state *mas);
void *rust_mtree_load(struct maple_tree *mt, unsigned long index);
int rust_mtree_store_range(struct maple_tree *mt, unsigned long index, unsigned long last, void *entry, gfp_t gfp);
int rust_mtree_store(struct maple_tree *mt, unsigned long index, void *entry, gfp_t gfp);
int rust_mtree_insert_range(struct maple_tree *mt, unsigned long first, unsigned long last, void *entry, gfp_t gfp);
int rust_mtree_insert(struct maple_tree *mt, unsigned long index, void *entry, gfp_t gfp);
int rust_mtree_alloc_range(struct maple_tree *mt, unsigned long *startp, void *entry, unsigned long size, unsigned long min, unsigned long max, gfp_t gfp);
int rust_mtree_alloc_cyclic(struct maple_tree *mt, unsigned long *startp, void *entry, unsigned long range_lo, unsigned long range_hi, unsigned long *next, gfp_t gfp);
int rust_mtree_alloc_rrange(struct maple_tree *mt, unsigned long *startp, void *entry, unsigned long size, unsigned long min, unsigned long max, gfp_t gfp);
void *rust_mtree_erase(struct maple_tree *mt, unsigned long index);
int rust___mt_dup(struct maple_tree *mt, struct maple_tree *new, gfp_t gfp);
int rust_mtree_dup(struct maple_tree *mt, struct maple_tree *new, gfp_t gfp);
void rust___mt_destroy(struct maple_tree *mt);
void rust_mtree_destroy(struct maple_tree *mt);
void *rust_mt_find(struct maple_tree *mt, unsigned long *index, unsigned long max);
void *rust_mt_find_after(struct maple_tree *mt, unsigned long *index, unsigned long max);
bool rust_mas_nomem(struct ma_state *mas, gfp_t gfp);

/* helpers the Rust calls: slab and RCU */
struct maple_node *rust_mt_alloc_one(gfp_t gfp);
void rust_mt_free_bulk(size_t size, void **nodes);
void rust_mt_return_sheaf(struct slab_sheaf *sheaf);
struct slab_sheaf *rust_mt_get_sheaf(gfp_t gfp, int count);
int rust_mt_refill_sheaf(gfp_t gfp, struct slab_sheaf **sheaf, unsigned int size);
struct maple_node *rust_mt_alloc_from_sheaf(struct slab_sheaf *sheaf);
unsigned int rust_mt_sheaf_size(struct slab_sheaf *sheaf);
void rust_mt_kfree(void *p);
void rust_mt_free_rcu(struct maple_node *node);
void rust_mt_call_rcu_free_walk(struct maple_node *node);
/* BUG / WARN / trace */
void rust_mt_bug(void);
bool rust_mt_warn(bool cond);
bool rust_mt_warn_once(bool cond);
void rust_mt_trace_ma_op(const char *func, struct ma_state *mas);
void rust_mt_trace_ma_read(const char *func, struct ma_state *mas);
void rust_mt_trace_ma_write(const char *func, struct ma_state *mas, unsigned long piv, void *val);
/* locks */
void rust_mtree_lock(struct maple_tree *mt);
void rust_mtree_lock_nested(struct maple_tree *mt);
void rust_mtree_unlock(struct maple_tree *mt);
void rust_rcu_read_lock(void);
void rust_rcu_read_unlock(void);
bool rust_gfp_allow_blocking(gfp_t gfp);

struct maple_node *rust_mt_alloc_one(gfp_t gfp)
{
	return kmem_cache_alloc(maple_node_cache, gfp);
}

void rust_mt_free_bulk(size_t size, void **nodes)
{
	kmem_cache_free_bulk(maple_node_cache, size, nodes);
}

void rust_mt_return_sheaf(struct slab_sheaf *sheaf)
{
	kmem_cache_return_sheaf(maple_node_cache, GFP_NOWAIT, sheaf);
}

struct slab_sheaf *rust_mt_get_sheaf(gfp_t gfp, int count)
{
	return kmem_cache_prefill_sheaf(maple_node_cache, gfp, count);
}

int rust_mt_refill_sheaf(gfp_t gfp, struct slab_sheaf **sheaf, unsigned int size)
{
	return kmem_cache_refill_sheaf(maple_node_cache, gfp, sheaf, size);
}

struct maple_node *rust_mt_alloc_from_sheaf(struct slab_sheaf *sheaf)
{
	return kmem_cache_alloc_from_sheaf(maple_node_cache, GFP_NOWAIT, sheaf);
}

unsigned int rust_mt_sheaf_size(struct slab_sheaf *sheaf)
{
	return kmem_cache_sheaf_size(sheaf);
}

void rust_mt_kfree(void *p)
{
	kfree(p);
}

/*
 * ma_free_rcu() - Use rcu callback to free a maple node
 * @node: The node to free
 *
 * The maple tree uses the parent pointer to indicate this node is no longer in
 * use and will be freed.
 */
void rust_mt_free_rcu(struct maple_node *node)
{
	WARN_ON(node->parent != ma_parent_ptr(node));
	kfree_rcu(node, rcu);
}

/*
 * mt_free_walk() - Walk & free a tree in the RCU callback context
 * @head: The RCU head that's within the node.
 */
static void mt_free_walk(struct rcu_head *head)
{
	rust_mt_free_walk(container_of(head, struct maple_node, rcu));
}

void rust_mt_call_rcu_free_walk(struct maple_node *node)
{
	call_rcu(&node->rcu, mt_free_walk);
}

void rust_mt_bug(void)
{
	BUG();
}

bool rust_mt_warn(bool cond)
{
	return WARN_ON(cond);
}

bool rust_mt_warn_once(bool cond)
{
	return WARN_ON_ONCE(cond);
}

void rust_mt_trace_ma_op(const char *func, struct ma_state *mas)
{
	trace_ma_op(func, mas);
}

void rust_mt_trace_ma_read(const char *func, struct ma_state *mas)
{
	trace_ma_read(func, mas);
}

void rust_mt_trace_ma_write(const char *func, struct ma_state *mas, unsigned long piv, void *val)
{
	trace_ma_write(func, mas, piv, val);
}

void rust_mtree_lock(struct maple_tree *mt)
{
	mtree_lock(mt);
}

void rust_mtree_lock_nested(struct maple_tree *mt)
{
	spin_lock_nested(&mt->ma_lock, SINGLE_DEPTH_NESTING);
}

void rust_mtree_unlock(struct maple_tree *mt)
{
	mtree_unlock(mt);
}

void rust_rcu_read_lock(void)
{
	rcu_read_lock();
}

void rust_rcu_read_unlock(void)
{
	rcu_read_unlock();
}

bool rust_gfp_allow_blocking(gfp_t gfp)
{
	return gfpflags_allow_blocking(gfp);
}

void __init maple_tree_init(void)
{
	struct kmem_cache_args args = {
		.align  = sizeof(struct maple_node),
		.sheaf_capacity = 32,
	};

	maple_node_cache = kmem_cache_create("maple_node",
			sizeof(struct maple_node), &args,
			SLAB_PANIC);
}

/* The public interface (thunks). */

int mas_alloc_cyclic(struct ma_state *mas, unsigned long *startp, void *entry, unsigned long range_lo, unsigned long range_hi, unsigned long *next, gfp_t gfp)
{
	return rust_mas_alloc_cyclic(mas, startp, entry, range_lo, range_hi, next, gfp);
}
EXPORT_SYMBOL(mas_alloc_cyclic);

void *mas_walk(struct ma_state *mas)
{
	return rust_mas_walk(mas);
}
EXPORT_SYMBOL_GPL(mas_walk);

int mas_empty_area(struct ma_state *mas, unsigned long min, unsigned long max, unsigned long size)
{
	return rust_mas_empty_area(mas, min, max, size);
}
EXPORT_SYMBOL_GPL(mas_empty_area);

int mas_empty_area_rev(struct ma_state *mas, unsigned long min, unsigned long max, unsigned long size)
{
	return rust_mas_empty_area_rev(mas, min, max, size);
}
EXPORT_SYMBOL_GPL(mas_empty_area_rev);

void *mas_store(struct ma_state *mas, void *entry)
{
	return rust_mas_store(mas, entry);
}
EXPORT_SYMBOL_GPL(mas_store);

int mas_store_gfp(struct ma_state *mas, void *entry, gfp_t gfp)
{
	return rust_mas_store_gfp(mas, entry, gfp);
}
EXPORT_SYMBOL_GPL(mas_store_gfp);

void mas_store_prealloc(struct ma_state *mas, void *entry)
{
	rust_mas_store_prealloc(mas, entry);
}
EXPORT_SYMBOL_GPL(mas_store_prealloc);

int mas_preallocate(struct ma_state *mas, void *entry, gfp_t gfp)
{
	return rust_mas_preallocate(mas, entry, gfp);
}
EXPORT_SYMBOL_GPL(mas_preallocate);

void mas_destroy(struct ma_state *mas)
{
	rust_mas_destroy(mas);
}
EXPORT_SYMBOL_GPL(mas_destroy);

void *mas_next(struct ma_state *mas, unsigned long max)
{
	return rust_mas_next(mas, max);
}
EXPORT_SYMBOL_GPL(mas_next);

void *mas_next_range(struct ma_state *mas, unsigned long max)
{
	return rust_mas_next_range(mas, max);
}
EXPORT_SYMBOL_GPL(mas_next_range);

void *mt_next(struct maple_tree *mt, unsigned long index, unsigned long max)
{
	return rust_mt_next(mt, index, max);
}
EXPORT_SYMBOL_GPL(mt_next);

void *mas_prev(struct ma_state *mas, unsigned long min)
{
	return rust_mas_prev(mas, min);
}
EXPORT_SYMBOL_GPL(mas_prev);

void *mas_prev_range(struct ma_state *mas, unsigned long min)
{
	return rust_mas_prev_range(mas, min);
}
EXPORT_SYMBOL_GPL(mas_prev_range);

void *mt_prev(struct maple_tree *mt, unsigned long index, unsigned long min)
{
	return rust_mt_prev(mt, index, min);
}
EXPORT_SYMBOL_GPL(mt_prev);

void mas_pause(struct ma_state *mas)
{
	rust_mas_pause(mas);
}
EXPORT_SYMBOL_GPL(mas_pause);

void *mas_find(struct ma_state *mas, unsigned long max)
{
	return rust_mas_find(mas, max);
}
EXPORT_SYMBOL_GPL(mas_find);

void *mas_find_range(struct ma_state *mas, unsigned long max)
{
	return rust_mas_find_range(mas, max);
}
EXPORT_SYMBOL_GPL(mas_find_range);

void *mas_find_rev(struct ma_state *mas, unsigned long min)
{
	return rust_mas_find_rev(mas, min);
}
EXPORT_SYMBOL_GPL(mas_find_rev);

void *mas_find_range_rev(struct ma_state *mas, unsigned long min)
{
	return rust_mas_find_range_rev(mas, min);
}
EXPORT_SYMBOL_GPL(mas_find_range_rev);

void *mas_erase(struct ma_state *mas)
{
	return rust_mas_erase(mas);
}
EXPORT_SYMBOL_GPL(mas_erase);

void *mtree_load(struct maple_tree *mt, unsigned long index)
{
	return rust_mtree_load(mt, index);
}
EXPORT_SYMBOL(mtree_load);

int mtree_store_range(struct maple_tree *mt, unsigned long index, unsigned long last, void *entry, gfp_t gfp)
{
	return rust_mtree_store_range(mt, index, last, entry, gfp);
}
EXPORT_SYMBOL(mtree_store_range);

int mtree_store(struct maple_tree *mt, unsigned long index, void *entry, gfp_t gfp)
{
	return rust_mtree_store(mt, index, entry, gfp);
}
EXPORT_SYMBOL(mtree_store);

int mtree_insert_range(struct maple_tree *mt, unsigned long first, unsigned long last, void *entry, gfp_t gfp)
{
	return rust_mtree_insert_range(mt, first, last, entry, gfp);
}
EXPORT_SYMBOL(mtree_insert_range);

int mtree_insert(struct maple_tree *mt, unsigned long index, void *entry, gfp_t gfp)
{
	return rust_mtree_insert(mt, index, entry, gfp);
}
EXPORT_SYMBOL(mtree_insert);

int mtree_alloc_range(struct maple_tree *mt, unsigned long *startp, void *entry, unsigned long size, unsigned long min, unsigned long max, gfp_t gfp)
{
	return rust_mtree_alloc_range(mt, startp, entry, size, min, max, gfp);
}
EXPORT_SYMBOL(mtree_alloc_range);

int mtree_alloc_cyclic(struct maple_tree *mt, unsigned long *startp, void *entry, unsigned long range_lo, unsigned long range_hi, unsigned long *next, gfp_t gfp)
{
	return rust_mtree_alloc_cyclic(mt, startp, entry, range_lo, range_hi, next, gfp);
}
EXPORT_SYMBOL(mtree_alloc_cyclic);

int mtree_alloc_rrange(struct maple_tree *mt, unsigned long *startp, void *entry, unsigned long size, unsigned long min, unsigned long max, gfp_t gfp)
{
	return rust_mtree_alloc_rrange(mt, startp, entry, size, min, max, gfp);
}
EXPORT_SYMBOL(mtree_alloc_rrange);

void *mtree_erase(struct maple_tree *mt, unsigned long index)
{
	return rust_mtree_erase(mt, index);
}
EXPORT_SYMBOL(mtree_erase);

int __mt_dup(struct maple_tree *mt, struct maple_tree *new, gfp_t gfp)
{
	return rust___mt_dup(mt, new, gfp);
}
EXPORT_SYMBOL(__mt_dup);

int mtree_dup(struct maple_tree *mt, struct maple_tree *new, gfp_t gfp)
{
	return rust_mtree_dup(mt, new, gfp);
}
EXPORT_SYMBOL(mtree_dup);

void __mt_destroy(struct maple_tree *mt)
{
	rust___mt_destroy(mt);
}
EXPORT_SYMBOL_GPL(__mt_destroy);

void mtree_destroy(struct maple_tree *mt)
{
	rust_mtree_destroy(mt);
}
EXPORT_SYMBOL(mtree_destroy);

void *mt_find(struct maple_tree *mt, unsigned long *index, unsigned long max)
{
	return rust_mt_find(mt, index, max);
}
EXPORT_SYMBOL(mt_find);

void *mt_find_after(struct maple_tree *mt, unsigned long *index, unsigned long max)
{
	return rust_mt_find_after(mt, index, max);
}
EXPORT_SYMBOL(mt_find_after);

bool mas_nomem(struct ma_state *mas, gfp_t gfp)
{
	return rust_mas_nomem(mas, gfp);
}
