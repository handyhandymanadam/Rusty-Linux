// SPDX-License-Identifier: GPL-2.0+
/*
 * PORTED TO RUST. WHAT IS LEFT OF THIS FILE, AND WHY
 *
 * Every exported entry point (all 41 EXPORT_SYMBOL[_GPL]s) is in
 * lib/xarray_rs.rs. What stays here is the one call to
 * kmem_cache_alloc_lru() -- since 6.10's allocation profiling it is
 * `#define kmem_cache_alloc_lru(...) alloc_hooks(kmem_cache_alloc_lru_noprof(__VA_ARGS__))`
 * (include/linux/slab.h), a macro over a static inline with no linkable
 * symbol. This is the standing exception logs/allocation.md documents
 * for kmalloc/vmalloc; kmem_cache_alloc_lru is the same shape and is
 * added to that file's table.
 *
 * radix_tree_node_cachep and radix_tree_node_rcu_free are real,
 * pre-existing symbols from lib/radix-tree.c (untouched, not part of
 * this port), and call_rcu() is a real EXPORT_SYMBOL_GPL
 * (kernel/rcu/tree.c) -- neither needed a C-side wrapper, so
 * lib/xarray_rs.rs calls them directly via extern "C".
 */

#include <linux/slab.h>
#include <linux/xarray.h>

#include "radix-tree.h"

/* config-full's -Wmissing-prototypes is fatal (-Werror); these symbols'
 * only caller (Rust, via FFI) gives the compiler nothing else to infer a
 * prototype from. Same shape as lib/generic-radix-tree.c's
 * rust_genradix_alloc_node().
 *
 * Two entry points, matching the two shapes xarray.c's own call sites
 * come in: xas_alloc() hardcodes GFP_NOWAIT itself (it allocates while
 * holding the lock) and only conditionally ORs in __GFP_ACCOUNT;
 * xas_nomem()/__xas_nomem()/xas_try_split() forward a caller-supplied
 * gfp_t and ALSO conditionally OR in __GFP_ACCOUNT; xas_split_alloc()
 * forwards a caller-supplied gfp_t with no ORing at all (call
 * rust_xa_node_alloc() with account=0, which is a no-op OR). Neither
 * GFP_NOWAIT's nor __GFP_ACCOUNT's actual bit values are ever needed on
 * the Rust side -- xa->xa_flags & XA_FLAGS_ACCOUNT (a plain literal 32,
 * not bit-position-derived) is evaluated in Rust and passed down as a
 * plain 0/1. */
struct xa_node *rust_xa_node_alloc_nowait(struct list_lru *lru, int account);
struct xa_node *rust_xa_node_alloc(struct list_lru *lru, gfp_t gfp, int account);

struct xa_node *rust_xa_node_alloc_nowait(struct list_lru *lru, int account)
{
	gfp_t gfp = GFP_NOWAIT;

	if (account)
		gfp |= __GFP_ACCOUNT;
	return kmem_cache_alloc_lru(radix_tree_node_cachep, lru, gfp);
}

struct xa_node *rust_xa_node_alloc(struct list_lru *lru, gfp_t gfp, int account)
{
	if (account)
		gfp |= __GFP_ACCOUNT;
	return kmem_cache_alloc_lru(radix_tree_node_cachep, lru, gfp);
}

/*
 * gfpflags_allow_blocking() (include/linux/gfp.h) is also a
 * `static inline` -- no linkable symbol -- and its `__GFP_DIRECT_RECLAIM`
 * bit, like `__GFP_ACCOUNT`, comes from the same bit-position-counter
 * macro chain (include/linux/gfp_types.h), not a plain literal. Same
 * reasoning as rust_xa_node_alloc(): the bit test stays in C so a future
 * kernel bump that reshuffles that chain cannot silently desync a
 * hand-copied value on the Rust side.
 */
int rust_gfp_allows_blocking(gfp_t gfp);

/* __GFP_BITS_SHIFT (= ___GFP_LAST_BIT) depends on the configuration (24 in config-full; more with LOCKDEP, KASAN_HW_TAGS, ...) and XA_FLAGS_MARK() puts
 * the mark bits above it. The Rust side used to hard-code 8, so a C-initialised array (xa_init_flags(XA_FLAGS_ALLOC): every IDA) had its free mark
 * in a bit Rust never looked at. Found 2026-10-26 by the lib/idr port's libtest (first ida_alloc_range() returned 1024). */
extern const unsigned int rust_xa_gfp_bits_shift;
const unsigned int rust_xa_gfp_bits_shift = __GFP_BITS_SHIFT;

int rust_gfp_allows_blocking(gfp_t gfp)
{
	return gfpflags_allow_blocking(gfp);
}
