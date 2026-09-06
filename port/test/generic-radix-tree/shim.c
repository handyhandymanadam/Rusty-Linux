/* SPDX-License-Identifier: GPL-2.0-only */
/* rust_genradix_alloc_node()/rust_genradix_free_node() for the Rust arm --
 * see port/tree/lib/generic-radix-tree.c's real (in-kernel) versions of
 * these. Both arms ultimately allocate/free the same way (calloc/free) as
 * shim/linux/generic-radix-tree.h's genradix_alloc_node()/free_node() do
 * for the C arm, so the two are compared on tree logic, not allocation. */
#include <stdlib.h>
#include <stdint.h>

struct genradix_node;

struct genradix_node *rust_genradix_alloc_node(unsigned int gfp_mask)
{
	(void)gfp_mask;
	return calloc(1, 512);
}

void rust_genradix_free_node(struct genradix_node *node)
{
	free(node);
}
