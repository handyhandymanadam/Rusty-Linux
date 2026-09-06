/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * port/test/generic-radix-tree/drv.c -- differential for
 * lib/generic-radix-tree.c.
 *
 * SCOPE: single-threaded. This proves the tree-walking/allocation LOGIC
 * agrees between the two ports on every input tried. It does not, and
 * cannot, exercise the concurrent-CAS-race paths (a losing
 * cmpxchg_release()) -- both arms only ever see uncontended compare-
 * exchanges here, same as any single-threaded run of either implementation
 * would. That is a real, stated limit of this harness, not a silent one.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct genradix { void *root; };
struct genradix_iter { size_t offset, pos; };

/* ---- C arm (renamed) ---- */
void *c___genradix_ptr(struct genradix *radix, size_t offset);
void *c___genradix_ptr_alloc(struct genradix *radix, size_t offset,
			     void **preallocated, unsigned int gfp_mask);
void *c___genradix_iter_peek(struct genradix_iter *iter, struct genradix *radix,
			     size_t objs_per_page);
int c___genradix_prealloc(struct genradix *radix, size_t size, unsigned int gfp_mask);
void c___genradix_free(struct genradix *radix);

/* ---- Rust arm ---- */
void *__genradix_ptr(struct genradix *radix, size_t offset);
void *__genradix_ptr_alloc(struct genradix *radix, size_t offset,
			   void **preallocated, unsigned int gfp_mask);
void *__genradix_iter_peek(struct genradix_iter *iter, struct genradix *radix,
			   size_t objs_per_page);
int __genradix_prealloc(struct genradix *radix, size_t size, unsigned int gfp_mask);
void __genradix_free(struct genradix *radix);

static unsigned long cases, mism;
static int poison;

static void bad(const char *what, unsigned long ctx)
{
	if (mism < 20)
		printf("MISMATCH %-16s ctx=%lu\n", what, ctx);
	mism++;
}

#define OBJ_SIZE 8
#define NODE_SIZE 512

static void run_one(unsigned n_offsets, unsigned seed)
{
	struct genradix c = { 0 };
	struct genradix r = { 0 };
	unsigned s = seed;

	size_t *offsets = malloc(n_offsets * sizeof(*offsets));
	for (unsigned i = 0; i < n_offsets; i++) {
		s = s * 1103515245u + 12345u;
		/* Byte offsets, 8-aligned, spread across several tree
		 * levels' worth of address space (a few hundred MB). */
		offsets[i] = ((size_t)(s % (200u * 1024 * 1024 / OBJ_SIZE))) * OBJ_SIZE;
	}

	/* Allocate every offset in both arms, write a distinct pattern. */
	for (unsigned i = 0; i < n_offsets; i++) {
		uint64_t *pc = c___genradix_ptr_alloc(&c, offsets[i], NULL, 0);
		uint64_t *pr = __genradix_ptr_alloc(&r, offsets[i], NULL, 0);
		cases++;
		if (!pc || !pr) {
			bad("alloc-null", offsets[i]);
			continue;
		}
		uint64_t pattern = 0x1000000000000000ULL | (i + 1);
		*pc = pattern;
		*pr = pattern;
	}

	if (poison && n_offsets > 0) {
		/* Corrupt the Rust tree's view of one already-written entry
		 * by writing through a second alloc call at the same offset
		 * -- proving the harness can disagree. */
		uint64_t *pr = __genradix_ptr_alloc(&r, offsets[0], NULL, 0);
		if (pr)
			*pr ^= 0xff;
	}

	/* Re-fetch every offset via __genradix_ptr and compare contents. */
	for (unsigned i = 0; i < n_offsets; i++) {
		uint64_t *pc = c___genradix_ptr(&c, offsets[i]);
		uint64_t *pr = __genradix_ptr(&r, offsets[i]);
		cases++;
		if (!pc || !pr) {
			bad("ptr-null", offsets[i]);
			continue;
		}
		if (*pc != *pr)
			bad("content-mismatch", offsets[i]);
	}

	/* An offset never allocated must read back zeroed (kzalloc-style),
	 * identically in both arms, at a location distinct from every
	 * allocated one. */
	{
		size_t far = (size_t)512 * 1024 * 1024 + 8;
		uint64_t *pc = c___genradix_ptr(&c, far);
		uint64_t *pr = __genradix_ptr(&r, far);
		cases++;
		if ((pc == NULL) != (pr == NULL))
			bad("absent-disagree", far);
	}

	/* Iterate the whole tree in order; the sequence of non-null
	 * positions visited must match between arms. */
	{
		struct genradix_iter ic = {0}, ir = {0};
		size_t objs_per_page = NODE_SIZE / OBJ_SIZE;
		for (;;) {
			void *vc = c___genradix_iter_peek(&ic, &c, objs_per_page);
			void *vr = __genradix_iter_peek(&ir, &r, objs_per_page);
			cases++;
			if ((vc == NULL) != (vr == NULL)) {
				bad("iter-disagree", ic.pos);
				break;
			}
			if (!vc)
				break;
			if (ic.pos != ir.pos || *(uint64_t *)vc != *(uint64_t *)vr)
				bad("iter-mismatch", ic.pos);
			ic.offset += OBJ_SIZE;
			ir.offset += OBJ_SIZE;
			ic.pos++;
			ir.pos++;
		}
	}

	c___genradix_free(&c);
	__genradix_free(&r);
	free(offsets);
}

int main(void)
{
	if (getenv("GENRADIX_PROVE_CAN_FAIL"))
		poison = 1;

	for (unsigned n = 0; n <= 64; n += 4)
		for (unsigned trial = 0; trial < 8; trial++)
			run_one(n, n * 2654435761u + trial + 1);

	/* A prealloc/free smoke test, both arms. */
	{
		struct genradix c = {0}, r = {0};
		int rc = c___genradix_prealloc(&c, 4096, 0);
		int rr = __genradix_prealloc(&r, 4096, 0);
		cases++;
		if (rc != rr)
			bad("prealloc-disagree", 0);
		c___genradix_free(&c);
		__genradix_free(&r);
	}

	if (mism) {
		fprintf(stderr, "%lu/%lu cases MISMATCHED\n", mism, cases);
		return 1;
	}
	printf("%lu cases, 0 mismatches\n", cases);
	return 0;
}
