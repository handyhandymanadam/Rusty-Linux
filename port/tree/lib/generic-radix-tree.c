// SPDX-License-Identifier: GPL-2.0
/*
 * PORTED TO RUST. WHAT IS LEFT OF THIS FILE, AND WHY
 *
 * Every exported entry point (__genradix_ptr, __genradix_ptr_alloc,
 * __genradix_iter_peek, __genradix_iter_peek_prev, __genradix_prealloc,
 * __genradix_free) is in lib/generic-radix-tree_rs.rs. What stays here is
 * node allocation and freeing -- kzalloc()/kfree() -- because kzalloc()
 * (since 6.10's allocation profiling) is `alloc_hooks(kzalloc_noprof(...))`,
 * a macro over a static inline with no linkable symbol. logs/allocation.md
 * documents this as a standing, undesigned exception across this project:
 * an allocating/freeing pair stays together in C rather than being split
 * across the language boundary. kfree() alone IS a real EXPORT_SYMBOL and
 * could be called from Rust, but its allocating half cannot, so both stay
 * here for the same reason lib/xz/xz_dec_bcj.c's create/free pair does.
 */

#include <linux/generic-radix-tree.h>
#include <linux/slab.h>

/* config-full's -Wmissing-prototypes is fatal (-Werror); neither symbol's
 * only caller (Rust, via FFI) gives the compiler anything else to infer a
 * prototype from. Same shape as lib/crypto/blake2s.c's
 * blake2s_compress_dispatch(). */
struct genradix_node *rust_genradix_alloc_node(gfp_t gfp_mask);
void rust_genradix_free_node(struct genradix_node *node);

struct genradix_node *rust_genradix_alloc_node(gfp_t gfp_mask)
{
	return kzalloc(GENRADIX_NODE_SIZE, gfp_mask);
}

void rust_genradix_free_node(struct genradix_node *node)
{
	kfree(node);
}
