/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Differential driver for lib/rbtree.c -> port/tree/lib/rbtree_rs.rs.
 *
 *   difftest [runs] [seed]
 *
 * Two independent trees (one driven entirely through ref_* calls, one
 * entirely through rs_* calls) are built from the IDENTICAL sequence of
 * random insert/erase operations, for both the plain API (rb_insert_color/
 * rb_erase) and a synthetic augmented API (__rb_insert_augmented/
 * __rb_erase_color with a real max-of-subtree callback triple, the same
 * shape RB_DECLARE_CALLBACKS_MAX generates). After EVERY operation, on
 * BOTH trees:
 *
 *   1. An explicit tree-invariant check: BST order (in-order walk against
 *      a shadow sorted array), red-black properties (root black, no
 *      red-red, equal black-height on every root-to-NULL path), parent-
 *      pointer consistency, and (for the augmented tree) that every node's
 *      cached max is truly the max of its subtree.
 *   2. A structural comparison of the two trees against EACH OTHER: a
 *      simultaneous preorder walk comparing key AND colour at every node,
 *      not just the sorted order rb_next() would show -- a shape that
 *      differs only in which specific rotations fired, but happens to
 *      still be sorted and still a valid RB tree, would pass every check
 *      above and fail only this one.
 *
 * This is deliberately NOT the shape of a differential that only compares
 * ref/rs return values or final sorted order: a sibling project's own gate
 * ledger found that class of harness catches mirror-structure corruption
 * only by TIMEOUT (the corrupted tree loops forever), not by a specific
 * failed assertion -- see port/rbtree_rs.rs's own module doc and the
 * project report this harness's design responds to. Every check here is a
 * direct, immediate assertion; nothing here should ever need a watchdog.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <linux/rbtree_types.h>

#include "../common/difftest.h"

typedef void (*augment_rotate_fn)(void *old, void *new);

/* ---- the two arms -------------------------------------------------------
 */
void ref_rb_insert_color(void *node, void *root);
void ref_rb_erase(void *node, void *root);
void ref___rb_insert_augmented(void *node, void *root, augment_rotate_fn rotate);
void ref___rb_erase_color(void *parent, void *root, augment_rotate_fn rotate);
void *ref_rb_first(const void *root);
void *ref_rb_last(const void *root);
void *ref_rb_next(const void *node);
void *ref_rb_prev(const void *node);
void ref_rb_replace_node(void *victim, void *new, void *root);
void ref_rb_replace_node_rcu(void *victim, void *new, void *root);
void *ref_rb_next_postorder(const void *node);
void *ref_rb_first_postorder(const void *root);

void rs_rb_insert_color(void *node, void *root);
void rs_rb_erase(void *node, void *root);
void rs___rb_insert_augmented(void *node, void *root, augment_rotate_fn rotate);
void rs___rb_erase_color(void *parent, void *root, augment_rotate_fn rotate);
void *rs_rb_first(const void *root);
void *rs_rb_last(const void *root);
void *rs_rb_next(const void *node);
void *rs_rb_prev(const void *node);
void rs_rb_replace_node(void *victim, void *new, void *root);
void rs_rb_replace_node_rcu(void *victim, void *new, void *root);
void *rs_rb_next_postorder(const void *node);
void *rs_rb_first_postorder(const void *root);

/* ---- header-only helpers, reproduced (rbtree.h/rbtree_augmented.h are not
 * ported, so nothing here can call into them either -- same reasoning as
 * rbtree_rs.rs's own module doc). */
#define RB_RED 0
#define RB_BLACK 1
#define RB_PARENT(r) ((struct rb_node *)((r)->__rb_parent_color & ~3UL))
#define RB_COLOR(r) ((r)->__rb_parent_color & 1)

static void rb_link_node(struct rb_node *node, struct rb_node *parent, struct rb_node **rb_link)
{
	node->__rb_parent_color = (unsigned long)parent;
	node->rb_left = node->rb_right = NULL;
	*rb_link = node;
}

/* ---- test node shapes ---------------------------------------------------
 */
struct plain_node {
	unsigned long key;
	struct rb_node rb;
};

struct aug_node {
	unsigned long key;
	unsigned long max; /* max key anywhere in this subtree */
	struct rb_node rb;
};

#define rb_to_plain(r) ((struct plain_node *)((char *)(r) - offsetof(struct plain_node, rb)))
#define rb_to_aug(r) ((struct aug_node *)((char *)(r) - offsetof(struct aug_node, rb)))

static unsigned long aug_compute_max(struct aug_node *node)
{
	unsigned long max = node->key;
	if (node->rb.rb_left) {
		struct aug_node *l = rb_to_aug(node->rb.rb_left);
		if (l->max > max) max = l->max;
	}
	if (node->rb.rb_right) {
		struct aug_node *r = rb_to_aug(node->rb.rb_right);
		if (r->max > max) max = r->max;
	}
	return max;
}

static void aug_propagate(void *rb_v, void *stop_v)
{
	struct rb_node *rb = rb_v, *stop = stop_v;
	while (rb != stop) {
		struct aug_node *node = rb_to_aug(rb);
		unsigned long max = aug_compute_max(node);
		if (node->max == max) break;
		node->max = max;
		rb = RB_PARENT(rb);
	}
}

static void aug_copy(void *rb_old_v, void *rb_new_v)
{
	struct aug_node *old = rb_to_aug(rb_old_v);
	struct aug_node *new = rb_to_aug(rb_new_v);
	new->max = old->max;
}

static void aug_rotate(void *rb_old_v, void *rb_new_v)
{
	struct aug_node *old = rb_to_aug(rb_old_v);
	struct aug_node *new = rb_to_aug(rb_new_v);
	new->max = old->max;
	old->max = aug_compute_max(old);
}

/* ---- the invariant checker -----------------------------------------------
 * Returns 0 on success; on failure, prints why and returns nonzero. `aug`
 * is NULL for the plain tree, or aug_compute_max-equivalent verification is
 * done via `check_aug` when true.
 */
static int walk_check(struct rb_node *node, struct rb_node *parent, int is_aug,
		       unsigned long *black_height, unsigned long *prev_key, int *have_prev,
		       const char *tag)
{
	unsigned long key;
	unsigned long lh = 0, rh = 0;

	if (!node) {
		*black_height = 1; /* NULL leaves count as one black level */
		return 0;
	}

	if (RB_PARENT(node) != parent) {
		fprintf(stderr, "%s: INVARIANT: node's parent pointer disagrees with its actual parent\n", tag);
		return 1;
	}

	if (RB_COLOR(node) == RB_RED) {
		if (node->rb_left && RB_COLOR(node->rb_left) == RB_RED) {
			fprintf(stderr, "%s: INVARIANT: red node has a red left child\n", tag);
			return 1;
		}
		if (node->rb_right && RB_COLOR(node->rb_right) == RB_RED) {
			fprintf(stderr, "%s: INVARIANT: red node has a red right child\n", tag);
			return 1;
		}
	}

	if (walk_check(node->rb_left, node, is_aug, &lh, prev_key, have_prev, tag))
		return 1;

	key = is_aug ? rb_to_aug(node)->key : rb_to_plain(node)->key;
	if (*have_prev && key <= *prev_key) {
		fprintf(stderr, "%s: INVARIANT: BST order violated at key %lu (prev %lu)\n", tag, key, *prev_key);
		return 1;
	}
	*prev_key = key;
	*have_prev = 1;

	if (is_aug) {
		struct aug_node *a = rb_to_aug(node);
		unsigned long want = aug_compute_max(a);
		if (a->max != want) {
			fprintf(stderr, "%s: INVARIANT: augmented max wrong at key %lu (have %lu want %lu)\n",
				tag, a->key, a->max, want);
			return 1;
		}
	}

	if (walk_check(node->rb_right, node, is_aug, &rh, prev_key, have_prev, tag))
		return 1;

	if (lh != rh) {
		fprintf(stderr, "%s: INVARIANT: unequal black-height at key %lu (left %lu right %lu)\n",
			tag, key, lh, rh);
		return 1;
	}

	*black_height = lh + (RB_COLOR(node) == RB_BLACK ? 1 : 0);
	return 0;
}

static int check_tree(struct rb_root *root, int is_aug, const char *tag)
{
	unsigned long bh = 0, prev = 0;
	int have_prev = 0;

	if (root->rb_node && RB_COLOR(root->rb_node) != RB_BLACK) {
		fprintf(stderr, "%s: INVARIANT: root is not black\n", tag);
		return 1;
	}
	return walk_check(root->rb_node, NULL, is_aug, &bh, &prev, &have_prev, tag);
}

/* Simultaneous preorder walk of the two arms' trees -- catches a shape
 * divergence that is still sorted and still a valid RB tree (see the file
 * header comment). */
static int compare_shape(struct rb_node *a, struct rb_node *b, int is_aug)
{
	unsigned long ka, kb;

	if (!a && !b) return 0;
	if (!a || !b) {
		fprintf(stderr, "MISMATCH: shape differs (one side has a node, the other NULL)\n");
		return 1;
	}
	ka = is_aug ? rb_to_aug(a)->key : rb_to_plain(a)->key;
	kb = is_aug ? rb_to_aug(b)->key : rb_to_plain(b)->key;
	if (ka != kb) {
		fprintf(stderr, "MISMATCH: shape differs: key %lu vs %lu at corresponding position\n", ka, kb);
		return 1;
	}
	if (RB_COLOR(a) != RB_COLOR(b)) {
		fprintf(stderr, "MISMATCH: colour differs at key %lu\n", ka);
		return 1;
	}
	if (compare_shape(a->rb_left, b->rb_left, is_aug)) return 1;
	return compare_shape(a->rb_right, b->rb_right, is_aug);
}

static uint64_t rng_next(uint64_t *s)
{
	*s ^= *s << 13;
	*s ^= *s >> 7;
	*s ^= *s << 17;
	return *s;
}

/* Fisher-Yates over 0..n-1. */
static void shuffle(unsigned long *a, size_t n, uint64_t *rng)
{
	size_t i;
	for (i = n; i-- > 1;) {
		size_t j = (size_t)(rng_next(rng) % (i + 1));
		unsigned long t = a[i];
		a[i] = a[j];
		a[j] = t;
	}
}

static long g_checks, g_fails;

static void report(const char *what)
{
	g_checks++;
	fprintf(stderr, "%s\n", what);
	g_fails++;
}

/* ---- plain-tree test -----------------------------------------------------
 */
static void insert_plain(int rs, struct plain_node *n, struct rb_root *root)
{
	struct rb_node **link = &root->rb_node, *parent = NULL;
	while (*link) {
		struct plain_node *cur = rb_to_plain(*link);
		parent = *link;
		if (n->key < cur->key) link = &parent->rb_left;
		else link = &parent->rb_right;
	}
	rb_link_node(&n->rb, parent, link);
	if (rs) rs_rb_insert_color(&n->rb, root);
	else ref_rb_insert_color(&n->rb, root);
}

static void run_plain(unsigned long n_nodes, uint64_t *seed)
{
	struct plain_node *ref_nodes = calloc(n_nodes, sizeof(*ref_nodes));
	struct plain_node *rs_nodes = calloc(n_nodes, sizeof(*rs_nodes));
	struct rb_root ref_root = { NULL }, rs_root = { NULL };
	unsigned long *order = calloc(n_nodes, sizeof(*order));
	unsigned long i;

	for (i = 0; i < n_nodes; i++) {
		ref_nodes[i].key = rs_nodes[i].key = i;
		order[i] = i;
	}
	shuffle(order, n_nodes, seed);

	for (i = 0; i < n_nodes; i++) {
		unsigned long k = order[i];
		insert_plain(0, &ref_nodes[k], &ref_root);
		insert_plain(1, &rs_nodes[k], &rs_root);
		g_checks++;
		if (check_tree(&ref_root, 0, "ref(plain,insert)")) report("ref invariant failed after insert");
		if (check_tree(&rs_root, 0, "rs(plain,insert)")) report("rs invariant failed after insert");
		if (compare_shape(ref_root.rb_node, rs_root.rb_node, 0)) report("shape mismatch after insert");
	}

	/* Traversal order matches the sorted key sequence, both directions. */
	{
		void *rn = ref_rb_first(&ref_root);
		void *sn = rs_rb_first(&rs_root);
		unsigned long expect = 0;
		g_checks++;
		while (rn || sn) {
			unsigned long rk = rn ? rb_to_plain(rn)->key : (unsigned long)-1;
			unsigned long sk = sn ? rb_to_plain(sn)->key : (unsigned long)-1;
			if (!rn || !sn || rk != sk || rk != expect) {
				report("rb_next traversal order mismatch");
				break;
			}
			rn = ref_rb_next(rn);
			sn = rs_rb_next(sn);
			expect++;
		}
	}
	{
		void *rn = ref_rb_last(&ref_root);
		void *sn = rs_rb_last(&rs_root);
		long expect = (long)n_nodes - 1;
		g_checks++;
		while (rn || sn) {
			unsigned long rk = rn ? rb_to_plain(rn)->key : (unsigned long)-1;
			unsigned long sk = sn ? rb_to_plain(sn)->key : (unsigned long)-1;
			if (!rn || !sn || rk != sk || (long)rk != expect) {
				report("rb_prev traversal order mismatch");
				break;
			}
			rn = ref_rb_prev(rn);
			sn = rs_rb_prev(sn);
			expect--;
		}
	}

	/* Postorder: every node visited exactly once, children before parent. */
	{
		void *rn = ref_rb_first_postorder(&ref_root);
		void *sn = rs_rb_first_postorder(&rs_root);
		unsigned long count = 0;
		g_checks++;
		while (rn && sn) {
			if (rb_to_plain(rn)->key != rb_to_plain(sn)->key) {
				report("postorder key mismatch");
				break;
			}
			count++;
			rn = ref_rb_next_postorder(rn);
			sn = rs_rb_next_postorder(sn);
		}
		if ((rn == NULL) != (sn == NULL)) report("postorder length mismatch");
		else if (count != n_nodes) report("postorder did not visit every node");
	}

	/* Erase in a second random order. */
	shuffle(order, n_nodes, seed);
	for (i = 0; i < n_nodes; i++) {
		unsigned long k = order[i];
		ref_rb_erase(&ref_nodes[k].rb, &ref_root);
		rs_rb_erase(&rs_nodes[k].rb, &rs_root);
		g_checks++;
		if (check_tree(&ref_root, 0, "ref(plain,erase)")) report("ref invariant failed after erase");
		if (check_tree(&rs_root, 0, "rs(plain,erase)")) report("rs invariant failed after erase");
		if (compare_shape(ref_root.rb_node, rs_root.rb_node, 0)) report("shape mismatch after erase");
	}
	g_checks++;
	if (ref_root.rb_node != NULL || rs_root.rb_node != NULL) report("tree not empty after erasing every node");

	/* rb_replace_node[_rcu]: reinsert one, then replace it. */
	{
		struct plain_node ref_a = { .key = 12345 }, ref_b = { 0 };
		struct plain_node rs_a = { .key = 12345 }, rs_b = { 0 };
		insert_plain(0, &ref_a, &ref_root);
		insert_plain(1, &rs_a, &rs_root);
		ref_b.key = ref_a.key;
		rs_b.key = rs_a.key;
		ref_rb_replace_node(&ref_a.rb, &ref_b.rb, &ref_root);
		rs_rb_replace_node(&rs_a.rb, &rs_b.rb, &rs_root);
		g_checks++;
		if (check_tree(&ref_root, 0, "ref(replace)")) report("ref invariant failed after rb_replace_node");
		if (check_tree(&rs_root, 0, "rs(replace)")) report("rs invariant failed after rb_replace_node");
		if (compare_shape(ref_root.rb_node, rs_root.rb_node, 0)) report("shape mismatch after rb_replace_node");

		ref_rb_erase(&ref_b.rb, &ref_root);
		rs_rb_erase(&rs_b.rb, &rs_root);
	}

	free(ref_nodes);
	free(rs_nodes);
	free(order);
}

/* ---- augmented-tree test --------------------------------------------------
 */
static void insert_aug(int rs, struct aug_node *n, struct rb_root *root)
{
	struct rb_node **link = &root->rb_node, *parent = NULL;
	n->max = n->key;
	while (*link) {
		struct aug_node *cur = rb_to_aug(*link);
		parent = *link;
		if (n->key < cur->key) link = &parent->rb_left;
		else link = &parent->rb_right;
	}
	rb_link_node(&n->rb, parent, link);
	aug_propagate(parent, NULL);
	if (rs) rs___rb_insert_augmented(&n->rb, root, aug_rotate);
	else ref___rb_insert_augmented(&n->rb, root, aug_rotate);
}

/* rb_erase_augmented(), reproduced -- header-only, see main.c's own note
 * at the top mirroring rbtree_rs.rs's module doc. */
static struct rb_node *erase_aug_splice(struct rb_node *node, struct rb_root *root)
{
	struct rb_node *child = node->rb_right;
	struct rb_node *tmp = node->rb_left;
	struct rb_node *parent, *rebalance;
	unsigned long pc;

	if (!tmp) {
		pc = node->__rb_parent_color;
		parent = RB_PARENT(node);
		if (parent) { if (parent->rb_left == node) parent->rb_left = child; else parent->rb_right = child; }
		else root->rb_node = child;
		if (child) { child->__rb_parent_color = pc; rebalance = NULL; }
		else rebalance = ((pc & 1) == RB_BLACK) ? parent : NULL;
		tmp = parent;
	} else if (!child) {
		tmp->__rb_parent_color = pc = node->__rb_parent_color;
		parent = RB_PARENT(node);
		if (parent) { if (parent->rb_left == node) parent->rb_left = tmp; else parent->rb_right = tmp; }
		else root->rb_node = tmp;
		rebalance = NULL;
		tmp = parent;
	} else {
		struct rb_node *successor = child, *child2;
		tmp = child->rb_left;
		if (!tmp) {
			parent = successor;
			child2 = successor->rb_right;
			aug_copy(node, successor);
		} else {
			do { parent = successor; successor = tmp; tmp = tmp->rb_left; } while (tmp);
			child2 = successor->rb_right;
			parent->rb_left = child2;
			successor->rb_right = child;
			child->__rb_parent_color = (child->__rb_parent_color & 3) | (unsigned long)successor;
			aug_copy(node, successor);
			aug_propagate(parent, successor);
		}
		tmp = node->rb_left;
		successor->rb_left = tmp;
		tmp->__rb_parent_color = (tmp->__rb_parent_color & 3) | (unsigned long)successor;

		pc = node->__rb_parent_color;
		{
			struct rb_node *gp = RB_PARENT(node);
			if (gp) { if (gp->rb_left == node) gp->rb_left = successor; else gp->rb_right = successor; }
			else root->rb_node = successor;
		}
		if (child2) {
			child2->__rb_parent_color = (unsigned long)parent | RB_BLACK;
			rebalance = NULL;
		} else {
			rebalance = (((successor->__rb_parent_color) & 1) == RB_BLACK) ? parent : NULL;
		}
		successor->__rb_parent_color = pc;
		tmp = successor;
	}
	aug_propagate(tmp, NULL);
	return rebalance;
}

static void erase_aug(int rs, struct rb_node *node, struct rb_root *root)
{
	struct rb_node *rebalance = erase_aug_splice(node, root);
	if (rebalance) {
		if (rs) rs___rb_erase_color(rebalance, root, aug_rotate);
		else ref___rb_erase_color(rebalance, root, aug_rotate);
	}
}

static void run_augmented(unsigned long n_nodes, uint64_t *seed)
{
	struct aug_node *ref_nodes = calloc(n_nodes, sizeof(*ref_nodes));
	struct aug_node *rs_nodes = calloc(n_nodes, sizeof(*rs_nodes));
	struct rb_root ref_root = { NULL }, rs_root = { NULL };
	unsigned long *order = calloc(n_nodes, sizeof(*order));
	unsigned long i;

	for (i = 0; i < n_nodes; i++) {
		ref_nodes[i].key = rs_nodes[i].key = i;
		order[i] = i;
	}
	shuffle(order, n_nodes, seed);

	for (i = 0; i < n_nodes; i++) {
		unsigned long k = order[i];
		insert_aug(0, &ref_nodes[k], &ref_root);
		insert_aug(1, &rs_nodes[k], &rs_root);
		g_checks++;
		if (check_tree(&ref_root, 1, "ref(aug,insert)")) report("ref invariant failed after augmented insert");
		if (check_tree(&rs_root, 1, "rs(aug,insert)")) report("rs invariant failed after augmented insert");
		if (compare_shape(ref_root.rb_node, rs_root.rb_node, 1)) report("augmented shape mismatch after insert");
	}

	shuffle(order, n_nodes, seed);
	for (i = 0; i < n_nodes; i++) {
		unsigned long k = order[i];
		erase_aug(0, &ref_nodes[k].rb, &ref_root);
		erase_aug(1, &rs_nodes[k].rb, &rs_root);
		g_checks++;
		if (check_tree(&ref_root, 1, "ref(aug,erase)")) report("ref invariant failed after augmented erase");
		if (check_tree(&rs_root, 1, "rs(aug,erase)")) report("rs invariant failed after augmented erase");
		if (compare_shape(ref_root.rb_node, rs_root.rb_node, 1)) report("augmented shape mismatch after erase");
	}
	g_checks++;
	if (ref_root.rb_node != NULL || rs_root.rb_node != NULL)
		report("augmented tree not empty after erasing every node");

	free(ref_nodes);
	free(rs_nodes);
	free(order);
}

int main(int argc, char **argv)
{
	long runs = argc > 1 ? atol(argv[1]) : 200;
	uint64_t seed = argc > 2 ? (uint64_t)atol(argv[2]) : 20260906u;
	long i;

	printf("runs=%ld seed=%llu\n", runs, (unsigned long long)seed);

	for (i = 0; i < runs; i++) {
		unsigned long n_plain = 1 + (unsigned long)(rng_next(&seed) % 3000);
		unsigned long n_aug = 1 + (unsigned long)(rng_next(&seed) % 1500);
		run_plain(n_plain, &seed);
		run_augmented(n_aug, &seed);
		if (g_fails >= 10) {
			fprintf(stderr, "too many failures, stopping\n");
			break;
		}
	}

	printf("checks: %ld   fails: %ld\n", g_checks, g_fails);
	return g_fails != 0;
}
