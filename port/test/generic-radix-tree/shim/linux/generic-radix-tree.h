#pragma once
/* Minimal reproduction of include/linux/generic-radix-tree.h: the macros,
 * types and inline helpers lib/generic-radix-tree.c itself references
 * directly. Both arms (pristine C and Rust) are checked against the SAME
 * shim, so what's compared is the two ports' logic, not this header. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

typedef unsigned int gfp_t;

/* ilog2(), include/linux/log2.h's runtime (__ilog2_u64 = fls64(n) - 1) arm:
 * well-defined (-1) at n == 0, unlike a raw clz. See
 * lib/generic_radix_tree_rs.rs's own doc comment on why this matters. */
static inline int ilog2(unsigned long n)
{
	return n == 0 ? -1 : 63 - __builtin_clzl(n);
}

#define GENRADIX_NODE_SHIFT 9
#define GENRADIX_NODE_SIZE (1U << GENRADIX_NODE_SHIFT)
#define GENRADIX_ARY (GENRADIX_NODE_SIZE / sizeof(struct genradix_node *))
#define GENRADIX_ARY_SHIFT ilog2(GENRADIX_ARY)

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define GENRADIX_MAX_DEPTH \
	DIV_ROUND_UP(64 - GENRADIX_NODE_SHIFT, GENRADIX_ARY_SHIFT)

#define __round_mask(x, y) ((__typeof__(x))((y) - 1))
#define round_down(x, y) ((x) & ~__round_mask(x, y))

static inline unsigned long roundup_pow_of_two(unsigned long n)
{
	if (n <= 1)
		return 1;
	return 1UL << (64 - __builtin_clzl(n - 1));
}

#define GENRADIX_DEPTH_MASK \
	((unsigned long)(roundup_pow_of_two(GENRADIX_MAX_DEPTH + 1) - 1))

static inline int genradix_depth_shift(unsigned depth)
{
	return GENRADIX_NODE_SHIFT + GENRADIX_ARY_SHIFT * depth;
}

static inline size_t genradix_depth_size(unsigned depth)
{
	return 1UL << genradix_depth_shift(depth);
}

struct genradix_root;

static inline unsigned genradix_root_to_depth(struct genradix_root *r)
{
	return (unsigned long)r & GENRADIX_DEPTH_MASK;
}

static inline struct genradix_node *genradix_root_to_node(struct genradix_root *r)
{
	return (void *)((unsigned long)r & ~GENRADIX_DEPTH_MASK);
}

struct __genradix {
	struct genradix_root *root;
};

struct genradix_node {
	union {
		struct genradix_node *children[GENRADIX_ARY];
		uint8_t data[GENRADIX_NODE_SIZE];
	};
};

/* kzalloc()/kfree(), shimmed -- see shim.c. Real upstream calls kzalloc()
 * directly; this project's retained C thunk calls these renamed wrappers
 * instead (see lib/generic-radix-tree.c's own comment), so the harness
 * provides both names, doing the same thing, for the two arms. */
static inline struct genradix_node *genradix_alloc_node(gfp_t gfp_mask)
{
	(void)gfp_mask;
	return calloc(1, GENRADIX_NODE_SIZE);
}

static inline void genradix_free_node(struct genradix_node *node)
{
	free(node);
}

struct genradix_iter {
	size_t offset;
	size_t pos;
};

static inline void *__genradix_ptr_inlined(struct __genradix *radix, size_t offset)
{
	struct genradix_root *r = READ_ONCE(radix->root);
	struct genradix_node *n = genradix_root_to_node(r);
	unsigned level = genradix_root_to_depth(r);
	unsigned shift = genradix_depth_shift(level);

	if (ilog2(offset) >= genradix_depth_shift(level))
		return NULL;

	while (n && shift > GENRADIX_NODE_SHIFT) {
		shift -= GENRADIX_ARY_SHIFT;
		n = n->children[offset >> shift];
		offset &= (1UL << shift) - 1;
	}

	return n ? &n->data[offset] : NULL;
}

void *__genradix_ptr(struct __genradix *, size_t);
void *__genradix_ptr_alloc(struct __genradix *, size_t,
			   struct genradix_node **, gfp_t);
void *__genradix_iter_peek(struct genradix_iter *, struct __genradix *, size_t);
void *__genradix_iter_peek_prev(struct genradix_iter *, struct __genradix *,
				size_t, size_t);
int __genradix_prealloc(struct __genradix *, size_t, gfp_t);
void __genradix_free(struct __genradix *);
