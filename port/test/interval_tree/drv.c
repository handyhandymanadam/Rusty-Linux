// SPDX-License-Identifier: GPL-2.0-only
/*
 * port/test/interval_tree/drv.c -- the userspace differential for
 * lib/interval_tree.c.
 *
 * WHAT IS COMPARED, AND WHY IT IS MORE THAN THE RETURN VALUES
 *
 * An interval tree is an augmented rbtree: every node carries
 * `__subtree_last`, the largest `last` in its subtree, and every insert,
 * every erase and every rotation has to keep that value true. A port can
 * get the augmentation subtly wrong and still answer most queries
 * correctly, because a stale `__subtree_last` that is too LARGE only costs
 * a wasted descent -- it never changes an answer. It is a defect that
 * appears as a wrong answer only when a later erase happens to consult it.
 *
 * So the differential does not compare answers. After EVERY operation it
 * compares the whole tree: for each node, its parent, both children, its
 * red/black colour, its interval and its `__subtree_last`, with every
 * pointer translated to an array index so the two arms' addresses are
 * comparable. Plus `rb_leftmost`. That is logs/floor.md's xxh64 lesson --
 * "wherever a port writes a caller-owned struct, compare the WHOLE struct"
 * -- applied to a structure rather than a scalar.
 *
 * AND THREE THINGS THAT ARE NOT A COMPARISON AT ALL
 *
 * logs/floor.md RULE T2, and Ousterhout behind it: two arms built from the
 * same C cannot detect a fault in what they share. `INTERVAL_TREE_DEFINE`
 * is one macro instantiated twice here, so a defect inside it would be
 * invisible to any amount of arm-versus-arm agreement. Three stages
 * therefore check properties rather than equality, and each is derived
 * independently of both arms:
 *
 *   1. `check_invariants()` recomputes `__subtree_last` by plain recursion
 *      and requires it to equal what the tree stores, checks the BST
 *      ordering on `start`, and checks the four red-black properties.
 *      Nothing in it consults interval_tree code.
 *   2. `stage_query()` derives the expected match list by walking the tree
 *      in order with `rb_first()`/`rb_next()` -- unported lib/rbtree.c --
 *      and filtering on the intersection predicate written out longhand.
 *      A wrong augmentation that makes `iter_first`/`iter_next` SKIP a
 *      node is caught here even if both arms skip it.
 *   3. `expected_spans()` computes the expected hole/used spans from a
 *      plain coverage bitmap over a small universe, with no tree at all.
 *
 * THE ONE COUPLING THEY DO HAVE, found by adversarial review 2026-09-05 and
 * written down rather than removed: all three read the tree THE ARMS BUILT.
 * So a shared insert defect that silently dropped a node would be invisible
 * to oracles 2 and 3 -- they would faithfully derive the expected answer for
 * a tree that is already wrong. What stands behind them is
 * `check_invariants()`'s `count != expect_count`, which compares the number
 * of nodes actually linked against the number this file inserted, and is the
 * only check here that does not read the tree to decide what the tree should
 * say.
 *
 * THE ARMS SHARE lib/rbtree.c, DELIBERATELY. `__rb_insert_augmented()`,
 * `__rb_erase_color()` and `rb_next()` are real, exported, unported kernel
 * functions -- measured, not assumed: `nm -g` on the compiled oracle
 * leaves exactly those three undefined. Both arms call the same copy, the
 * way both call the same `simple_strtoull` in port/test/cmdline/. What is
 * being compared is the two interval trees over one rbtree, which is what
 * the kernel ships.
 */

#include <linux/interval_tree.h>
#include <linux/rbtree.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --------------------------------------------------------------------- */
/* The two arms.                                                          */
/* --------------------------------------------------------------------- */

/* The Rust arm defines the real names; <linux/interval_tree.h> declares
 * them above. The C arm is the same pristine file compiled with every
 * symbol it defines renamed c_*, so both can be linked into one binary --
 * see run.sh's REN[] array. */
void c_interval_tree_insert(struct interval_tree_node *node,
			    struct rb_root_cached *root);
void c_interval_tree_remove(struct interval_tree_node *node,
			    struct rb_root_cached *root);
struct interval_tree_node *c_interval_tree_iter_first(struct rb_root_cached *root,
						      unsigned long start,
						      unsigned long last);
struct interval_tree_node *c_interval_tree_iter_next(struct interval_tree_node *node,
						     unsigned long start,
						     unsigned long last);
#ifdef CONFIG_INTERVAL_TREE_SPAN_ITER
void c_interval_tree_span_iter_first(struct interval_tree_span_iter *iter,
				     struct rb_root_cached *itree,
				     unsigned long first_index,
				     unsigned long last_index);
void c_interval_tree_span_iter_next(struct interval_tree_span_iter *iter);
void c_interval_tree_span_iter_advance(struct interval_tree_span_iter *iter,
				       struct rb_root_cached *itree,
				       unsigned long new_index);
#endif

struct itops {
	const char *name;
	void (*insert)(struct interval_tree_node *, struct rb_root_cached *);
	void (*remove)(struct interval_tree_node *, struct rb_root_cached *);
	struct interval_tree_node *(*first)(struct rb_root_cached *,
					    unsigned long, unsigned long);
	struct interval_tree_node *(*next)(struct interval_tree_node *,
					   unsigned long, unsigned long);
#ifdef CONFIG_INTERVAL_TREE_SPAN_ITER
	void (*span_first)(struct interval_tree_span_iter *,
			   struct rb_root_cached *, unsigned long, unsigned long);
	void (*span_next)(struct interval_tree_span_iter *);
	void (*span_advance)(struct interval_tree_span_iter *,
			     struct rb_root_cached *, unsigned long);
#endif
};

static const struct itops OPS_C = {
	.name = "ref",
	.insert = c_interval_tree_insert,
	.remove = c_interval_tree_remove,
	.first = c_interval_tree_iter_first,
	.next = c_interval_tree_iter_next,
#ifdef CONFIG_INTERVAL_TREE_SPAN_ITER
	.span_first = c_interval_tree_span_iter_first,
	.span_next = c_interval_tree_span_iter_next,
	.span_advance = c_interval_tree_span_iter_advance,
#endif
};

static const struct itops OPS_RS = {
	.name = "rs",
	.insert = interval_tree_insert,
	.remove = interval_tree_remove,
	.first = interval_tree_iter_first,
	.next = interval_tree_iter_next,
#ifdef CONFIG_INTERVAL_TREE_SPAN_ITER
	.span_first = interval_tree_span_iter_first,
	.span_next = interval_tree_span_iter_next,
	.span_advance = interval_tree_span_iter_advance,
#endif
};

/* --------------------------------------------------------------------- */
/* Bookkeeping.                                                           */
/* --------------------------------------------------------------------- */

#define MAXN 512

struct arm {
	const struct itops *ops;
	struct rb_root_cached root;
	struct interval_tree_node node[MAXN];
	unsigned char linked[MAXN];
};

static struct arm A_REF, A_RS;

static unsigned long mismatches;
static unsigned long checks;
static unsigned long ops_applied;

/* Per-stage accounting. notes/STATUS.md standing guard 9: "read the case count --
 * whatever number says work happened -- and ask whether it is plausible."
 * A single total cannot say that a stage ran at all. */
static unsigned long stage_checks_at_start;
static unsigned long stage_ops_at_start;

static void stage_begin(const char *label)
{
	stage_checks_at_start = checks;
	stage_ops_at_start = ops_applied;
	printf("  %-18s ", label);
	fflush(stdout);
}

static void stage_end(void)
{
	printf("ops %-8lu comparisons %-9lu %s\n",
	       ops_applied - stage_ops_at_start,
	       checks - stage_checks_at_start,
	       mismatches ? "*** MISMATCH ***" : "ok");
}

static int prove_can_fail;

/* The leading newline is load-bearing, not cosmetic. stage_begin() prints a
 * label with no newline, so without it the FIRST failure of a stage lands at
 * column 21 and run.sh's prove-can-fail gate -- which greps for a
 * line-anchored MISMATCH -- reads a log that HAS one and reports that it does
 * not. Found by adversarial review, 2026-09-05, demonstrated on a real
 * sabotage log rather than argued. Same reason for the INVARIANT: lines. */
#define FAIL(fmt, ...)							\
	do {								\
		if (mismatches++ < 20)					\
			printf("\nMISMATCH: " fmt "\n", ##__VA_ARGS__);	\
	} while (0)

/* --------------------------------------------------------------------- */
/* RNG -- xorshift64*, so a seed reproduces a run exactly.                */
/* --------------------------------------------------------------------- */

static unsigned long long rng_state = 0x2545F4914F6CDD1DULL;

static unsigned long long rnd(void)
{
	unsigned long long x = rng_state;

	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	rng_state = x;
	return x * 0x2545F4914F6CDD1DULL;
}

static unsigned long rnd_below(unsigned long n)
{
	return (unsigned long)(rnd() % n);
}

/* --------------------------------------------------------------------- */
/* Structural snapshot: the whole tree, with pointers as indices.         */
/* --------------------------------------------------------------------- */

struct snapent {
	int idx, parent, left, right, black;
	unsigned long start, last, subtree_last;
};

struct snap {
	int n;
	int leftmost;
	struct snapent e[MAXN];
};

static int idx_of(const struct arm *a, const struct rb_node *rb)
{
	const struct interval_tree_node *n;

	if (!rb)
		return -1;
	n = rb_entry(rb, struct interval_tree_node, rb);
	return (int)(n - a->node);
}

static void snapshot(const struct arm *a, struct snap *s)
{
	struct rb_node *rb;

	s->n = 0;
	s->leftmost = idx_of(a, a->root.rb_leftmost);

	for (rb = rb_first(&a->root.rb_root); rb; rb = rb_next(rb)) {
		struct interval_tree_node *n =
			rb_entry(rb, struct interval_tree_node, rb);
		struct snapent *e = &s->e[s->n++];

		e->idx = idx_of(a, rb);
		e->parent = idx_of(a, rb_parent(rb));
		e->left = idx_of(a, rb->rb_left);
		e->right = idx_of(a, rb->rb_right);
		/* rb_color() lives in <linux/rbtree_augmented.h>, which this
		 * file does not include -- reproduce the one bit here rather
		 * than pull the whole augmented header into the driver. */
		e->black = (int)(rb->__rb_parent_color & 1);
		e->start = n->start;
		e->last = n->last;
		e->subtree_last = n->__subtree_last;
	}
}

static void compare_snap(const char *where, unsigned long iter)
{
	struct snap sc, sr;
	int i;

	snapshot(&A_REF, &sc);
	snapshot(&A_RS, &sr);
	checks++;

	if (sc.n != sr.n) {
		FAIL("%s iter %lu: node count ref=%d rs=%d", where, iter,
		     sc.n, sr.n);
		return;
	}
	if (sc.leftmost != sr.leftmost) {
		FAIL("%s iter %lu: rb_leftmost ref=%d rs=%d", where, iter,
		     sc.leftmost, sr.leftmost);
		return;
	}
	for (i = 0; i < sc.n; i++) {
		const struct snapent *c = &sc.e[i], *r = &sr.e[i];

		if (c->idx != r->idx || c->parent != r->parent ||
		    c->left != r->left || c->right != r->right ||
		    c->black != r->black || c->start != r->start ||
		    c->last != r->last || c->subtree_last != r->subtree_last) {
			FAIL("%s iter %lu: in-order slot %d differs\n"
			     "    ref idx=%d parent=%d l=%d r=%d %s [%lu,%lu] subtree_last=%lu\n"
			     "    rs  idx=%d parent=%d l=%d r=%d %s [%lu,%lu] subtree_last=%lu",
			     where, iter, i,
			     c->idx, c->parent, c->left, c->right,
			     c->black ? "B" : "R", c->start, c->last,
			     c->subtree_last,
			     r->idx, r->parent, r->left, r->right,
			     r->black ? "B" : "R", r->start, r->last,
			     r->subtree_last);
			return;
		}
	}
}

/* --------------------------------------------------------------------- */
/* The independent invariant checker. Consults no interval_tree code.     */
/* --------------------------------------------------------------------- */

struct inv {
	const char *arm;
	const char *where;
	unsigned long iter;
	int bad;
};

/* Returns the black-height of the subtree, and -1 on any violation.
 * `lo`/`hi` bound the BST key (`start`) for this subtree. */
static int check_subtree(struct inv *v, struct rb_node *rb,
			 unsigned long lo, unsigned long hi,
			 unsigned long *subtree_max, int *count)
{
	struct interval_tree_node *n;
	unsigned long max;
	int bh_l, bh_r;
	unsigned long ml = 0, mr = 0;
	int black;

	if (!rb) {
		*subtree_max = 0;
		return 1;			/* NULL leaves are black */
	}

	n = rb_entry(rb, struct interval_tree_node, rb);
	(*count)++;
	black = (int)(rb->__rb_parent_color & 1);

	if (n->start < lo || n->start > hi) {
		printf("\nINVARIANT: %s %s iter %lu: BST order broken at node "
		       "start=%lu, allowed [%lu,%lu]\n",
		       v->arm, v->where, v->iter, n->start, lo, hi);
		v->bad = 1;
		return -1;
	}
	if (n->start > n->last) {
		printf("\nINVARIANT: %s %s iter %lu: node has start=%lu > last=%lu\n",
		       v->arm, v->where, v->iter, n->start, n->last);
		v->bad = 1;
		return -1;
	}

	/* Property 4: both children of a red node are black. */
	if (!black) {
		if ((rb->rb_left &&
		     !(rb->rb_left->__rb_parent_color & 1)) ||
		    (rb->rb_right &&
		     !(rb->rb_right->__rb_parent_color & 1))) {
			printf("\nINVARIANT: %s %s iter %lu: red node with a red "
			       "child at start=%lu\n",
			       v->arm, v->where, v->iter, n->start);
			v->bad = 1;
			return -1;
		}
	}

	/* Parent links must agree with child links. */
	if (rb->rb_left && rb_parent(rb->rb_left) != rb) {
		printf("\nINVARIANT: %s %s iter %lu: left child's parent link is "
		       "wrong at start=%lu\n",
		       v->arm, v->where, v->iter, n->start);
		v->bad = 1;
		return -1;
	}
	if (rb->rb_right && rb_parent(rb->rb_right) != rb) {
		printf("\nINVARIANT: %s %s iter %lu: right child's parent link is "
		       "wrong at start=%lu\n",
		       v->arm, v->where, v->iter, n->start);
		v->bad = 1;
		return -1;
	}

	bh_l = check_subtree(v, rb->rb_left, lo, n->start, &ml, count);
	if (bh_l < 0)
		return -1;
	bh_r = check_subtree(v, rb->rb_right, n->start, hi, &mr, count);
	if (bh_r < 0)
		return -1;

	/* Property 5: equal black-height on every path. */
	if (bh_l != bh_r) {
		printf("\nINVARIANT: %s %s iter %lu: black height %d vs %d at "
		       "start=%lu\n",
		       v->arm, v->where, v->iter, bh_l, bh_r, n->start);
		v->bad = 1;
		return -1;
	}

	/* THE AUGMENTATION. Recomputed from scratch, not from the stored
	 * value: max(this node's last, both children's real subtree max). */
	max = n->last;
	if (rb->rb_left && ml > max)
		max = ml;
	if (rb->rb_right && mr > max)
		max = mr;
	if (n->__subtree_last != max) {
		printf("\nINVARIANT: %s %s iter %lu: __subtree_last=%lu but the "
		       "subtree's real max last is %lu (node [%lu,%lu])\n",
		       v->arm, v->where, v->iter, n->__subtree_last, max,
		       n->start, n->last);
		v->bad = 1;
		return -1;
	}

	*subtree_max = max;
	return bh_l + (black ? 1 : 0);
}

static void check_invariants(struct arm *a, const char *where,
			     unsigned long iter, int expect_count)
{
	struct inv v = { a->ops->name, where, iter, 0 };
	unsigned long max = 0;
	int count = 0;
	struct rb_node *root = a->root.rb_root.rb_node;

	checks++;

	/* Property 2: the root is black. */
	if (root && !(root->__rb_parent_color & 1)) {
		printf("\nINVARIANT: %s %s iter %lu: root is red\n",
		       v.arm, where, iter);
		v.bad = 1;
	}
	if (root && rb_parent(root)) {
		printf("\nINVARIANT: %s %s iter %lu: root has a parent\n",
		       v.arm, where, iter);
		v.bad = 1;
	}

	check_subtree(&v, root, 0, ~0UL, &max, &count);

	if (count != expect_count) {
		printf("\nINVARIANT: %s %s iter %lu: tree holds %d nodes, %d were "
		       "inserted\n", v.arm, where, iter, count, expect_count);
		v.bad = 1;
	}
	if (a->root.rb_leftmost != rb_first(&a->root.rb_root)) {
		printf("\nINVARIANT: %s %s iter %lu: rb_leftmost is not rb_first\n",
		       v.arm, where, iter);
		v.bad = 1;
	}
	if (v.bad)
		mismatches++;
}

/* --------------------------------------------------------------------- */
/* Stage 1 -- insert/remove, whole-tree comparison after every operation. */
/* --------------------------------------------------------------------- */

static void reset_arms(void)
{
	memset(&A_REF, 0, sizeof(A_REF));
	memset(&A_RS, 0, sizeof(A_RS));
	A_REF.ops = &OPS_C;
	A_RS.ops = &OPS_RS;
	A_REF.root.rb_root.rb_node = NULL;
	A_REF.root.rb_leftmost = NULL;
	A_RS.root.rb_root.rb_node = NULL;
	A_RS.root.rb_leftmost = NULL;
}

/* Fill both arms' node arrays with the same intervals. `universe` is the
 * index space; a small one makes overlaps and last+1==start adjacency the
 * common case rather than a rarity, which is what the span iterator's
 * consolidation logic actually turns on. */
static void fill_nodes(int n, unsigned long universe, int extremes)
{
	int i;

	for (i = 0; i < n; i++) {
		unsigned long s, l;

		if (extremes && (i % 8) == 0) {
			/* Deliberate boundary values: the C's `- 1` and
			 * `+ 1` sites live here, and so does the ULONG_MAX
			 * wrap the port spells `wrapping_add`. */
			switch ((i / 8) % 5) {
			case 0: s = 0;              l = 0;              break;
			case 1: s = 0;              l = ~0UL;           break;
			case 2: s = ~0UL;           l = ~0UL;           break;
			case 3: s = ~0UL - 1;       l = ~0UL;           break;
			default: s = rnd_below(universe);
				 l = s;                              break;
			}
		} else {
			s = rnd_below(universe);
			l = s + rnd_below(universe / 8 + 1);
			if (l < s)
				l = s;
		}

		A_REF.node[i].start = s;
		A_REF.node[i].last = l;
		A_RS.node[i].start = s;
		A_RS.node[i].last = l;

		if (prove_can_fail && i == 0) {
			/* THE ARRANGEMENT PROVES ITSELF. One node's interval
			 * is one larger in the Rust arm only, so the two
			 * trees must disagree. run.sh refuses to believe a
			 * clean run unless the poisoned one fails. */
			A_RS.node[i].last = l + 1 > l ? l + 1 : l;
			if (A_RS.node[i].last == A_REF.node[i].last)
				A_RS.node[i].start =
					A_RS.node[i].start ? A_RS.node[i].start - 1 : 1;
		}
	}
}

static void apply_op(struct arm *a, int which, int idx)
{
	if (which)
		a->ops->insert(&a->node[idx], &a->root);
	else
		a->ops->remove(&a->node[idx], &a->root);
}

static void stage_structure(int n, unsigned long universe, unsigned long iters,
			    int extremes, const char *label)
{
	unsigned long i;
	int live = 0;

	reset_arms();
	fill_nodes(n, universe, extremes);

	for (i = 0; i < iters; i++) {
		int idx = (int)rnd_below((unsigned long)n);
		int want_insert;

		/* Bias toward filling the tree, then toward churn. */
		if (live == 0)
			want_insert = 1;
		else if (live == n)
			want_insert = 0;
		else
			want_insert = (rnd_below(100) < 55);

		/* Find a node in the right state, cheaply. */
		while (A_REF.linked[idx] == want_insert)
			idx = (idx + 1) % n;

		apply_op(&A_REF, want_insert, idx);
		apply_op(&A_RS, want_insert, idx);
		A_REF.linked[idx] = (unsigned char)want_insert;
		A_RS.linked[idx] = (unsigned char)want_insert;
		live += want_insert ? 1 : -1;
		ops_applied++;

		compare_snap(label, i);
		check_invariants(&A_REF, label, i, live);
		check_invariants(&A_RS, label, i, live);

		if (mismatches)
			return;
	}
}

/* --------------------------------------------------------------------- */
/* Stage 2 -- queries, against each other AND against an independent walk. */
/* --------------------------------------------------------------------- */

#define MAXMATCH (MAXN + 4)

static int collect_matches(struct arm *a, unsigned long qs, unsigned long ql,
			   int *out)
{
	struct interval_tree_node *n;
	int k = 0;

	for (n = a->ops->first(&a->root, qs, ql); n;
	     n = a->ops->next(n, qs, ql)) {
		if (k >= MAXMATCH)
			return -1;	/* runaway iteration */
		out[k++] = (int)(n - a->node);
	}
	return k;
}

/* The independent oracle: in-order over lib/rbtree.c's own walk, filtered
 * by the intersection predicate written out longhand. No interval_tree
 * code is consulted, so a wrong augmentation that makes BOTH arms skip a
 * node is still caught. */
static int expected_matches(struct arm *a, unsigned long qs, unsigned long ql,
			    int *out)
{
	struct rb_node *rb;
	int k = 0;

	for (rb = rb_first(&a->root.rb_root); rb; rb = rb_next(rb)) {
		struct interval_tree_node *n =
			rb_entry(rb, struct interval_tree_node, rb);

		if (n->start <= ql && qs <= n->last) {
			if (k >= MAXMATCH)
				return -1;
			out[k++] = (int)(n - a->node);
		}
	}
	return k;
}

static void stage_query(int n, unsigned long universe, unsigned long iters,
			const char *label)
{
	unsigned long i;
	int live = 0;
	int mc[MAXMATCH], mr[MAXMATCH], me[MAXMATCH];

	reset_arms();
	fill_nodes(n, universe, 1);

	/* Populate about two thirds of the nodes. */
	for (i = 0; i < (unsigned long)n; i++) {
		if (rnd_below(3) == 0)
			continue;
		apply_op(&A_REF, 1, (int)i);
		apply_op(&A_RS, 1, (int)i);
		A_REF.linked[i] = A_RS.linked[i] = 1;
		live++;
		ops_applied++;
	}
	compare_snap(label, 0);

	for (i = 0; i < iters; i++) {
		unsigned long qs, ql;
		int kc, kr, ke, j;

		qs = rnd_below(universe + 2);
		ql = qs + rnd_below(universe / 4 + 2);
		if ((i & 63) == 0) {			/* whole-space query */
			qs = 0;
			ql = ~0UL;
		} else if ((i & 63) == 1) {		/* single index */
			ql = qs;
		}
		if (ql < qs)
			ql = qs;

		kc = collect_matches(&A_REF, qs, ql, mc);
		kr = collect_matches(&A_RS, qs, ql, mr);
		ke = expected_matches(&A_REF, qs, ql, me);
		checks++;

		if (kc < 0 || kr < 0 || ke < 0) {
			FAIL("%s iter %lu: iteration did not terminate "
			     "(ref=%d rs=%d oracle=%d) for [%lu,%lu]",
			     label, i, kc, kr, ke, qs, ql);
			return;
		}
		if (kc != kr) {
			FAIL("%s iter %lu: [%lu,%lu] match count ref=%d rs=%d",
			     label, i, qs, ql, kc, kr);
			return;
		}
		for (j = 0; j < kc; j++) {
			if (mc[j] != mr[j]) {
				FAIL("%s iter %lu: [%lu,%lu] match %d "
				     "ref=%d rs=%d", label, i, qs, ql, j,
				     mc[j], mr[j]);
				return;
			}
		}
		/* The independent arm. A disagreement here means the C and the
		 * Rust are wrong TOGETHER -- see this file's header. */
		if (kc != ke) {
			FAIL("%s iter %lu: [%lu,%lu] BOTH ARMS disagree with "
			     "the in-order oracle: arms=%d oracle=%d",
			     label, i, qs, ql, kc, ke);
			return;
		}
		for (j = 0; j < ke; j++) {
			if (mc[j] != me[j]) {
				FAIL("%s iter %lu: [%lu,%lu] BOTH ARMS disagree "
				     "with the in-order oracle at match %d: "
				     "arms=%d oracle=%d",
				     label, i, qs, ql, j, mc[j], me[j]);
				return;
			}
		}

		/* Churn one node so the tree is not static across queries. */
		if ((i & 7) == 7) {
			int idx = (int)rnd_below((unsigned long)n);
			int want = !A_REF.linked[idx];

			apply_op(&A_REF, want, idx);
			apply_op(&A_RS, want, idx);
			A_REF.linked[idx] = A_RS.linked[idx] = (unsigned char)want;
			live += want ? 1 : -1;
			ops_applied++;
			compare_snap(label, i);
			check_invariants(&A_REF, label, i, live);
			check_invariants(&A_RS, label, i, live);
		}
		if (mismatches)
			return;
	}
}

/* --------------------------------------------------------------------- */
/* Stage 3 -- the span iterator.                                          */
/* --------------------------------------------------------------------- */

#ifdef CONFIG_INTERVAL_TREE_SPAN_ITER

#define MAXSPAN (2 * MAXN + 8)

static void check_iter_state(struct arm *a, struct interval_tree_span_iter *it);

struct spanrec {
	int is_hole;
	unsigned long start, last;
	int node0, node1;
	unsigned long first_index, last_index;
};

static int collect_spans(struct arm *a, unsigned long fi, unsigned long li,
			 struct spanrec *out)
{
	struct interval_tree_span_iter it;
	int k = 0;

	memset(&it, 0, sizeof(it));
	for (a->ops->span_first(&it, &a->root, fi, li);
	     !interval_tree_span_iter_done(&it);
	     a->ops->span_next(&it)) {
		check_iter_state(a, &it);
		if (k >= MAXSPAN)
			return -1;
		out[k].is_hole = it.is_hole;
		out[k].start = it.start_hole;	/* the union, either name */
		out[k].last = it.last_hole;
		out[k].node0 = idx_of(a, it.nodes[0] ? &it.nodes[0]->rb : NULL);
		out[k].node1 = idx_of(a, it.nodes[1] ? &it.nodes[1]->rb : NULL);
		out[k].first_index = it.first_index;
		out[k].last_index = it.last_index;
		k++;
	}
	return k;
}

static int span_differs(const struct spanrec *x, const struct spanrec *y)
{
	return x->is_hole != y->is_hole || x->start != y->start ||
	       x->last != y->last || x->node0 != y->node0 ||
	       x->node1 != y->node1 || x->first_index != y->first_index ||
	       x->last_index != y->last_index;
}

/* The independent span oracle: a coverage bitmap over a small universe,
 * with no tree involved at all. The C's contract, restated from
 * <linux/interval_tree.h>: alternating hole/used spans that between them
 * cover [fi,li] exactly, greedy, starting with whichever fi falls in. */
#define SPAN_UNIVERSE 384

static int expected_spans(struct arm *a, unsigned long fi, unsigned long li,
			  struct spanrec *out)
{
	static unsigned char cover[SPAN_UNIVERSE];
	struct rb_node *rb;
	unsigned long i;
	int k = 0;

	/* REFUSE rather than read past the bitmap. Every caller today passes a
	 * window inside [0, SPAN_UNIVERSE), but that is a property of the
	 * callers and not of this function -- raising a stage's `universe`
	 * above SPAN_UNIVERSE made it index cover[427] of a 384-byte array.
	 * Found by adversarial review, 2026-09-05. A silent out-of-bounds read
	 * in the ORACLE is the lib/lz4 shape: the harness is then wrong about
	 * the answer and blames the port. */
	if (fi >= SPAN_UNIVERSE || li >= SPAN_UNIVERSE || li < fi)
		return -1;

	memset(cover, 0, sizeof(cover));
	for (rb = rb_first(&a->root.rb_root); rb; rb = rb_next(rb)) {
		struct interval_tree_node *n =
			rb_entry(rb, struct interval_tree_node, rb);
		unsigned long s = n->start, l = n->last;

		if (s >= SPAN_UNIVERSE)
			continue;
		if (l >= SPAN_UNIVERSE)
			l = SPAN_UNIVERSE - 1;
		for (i = s; i <= l; i++)
			cover[i] = 1;
	}

	i = fi;
	while (i <= li) {
		unsigned long run = i;
		int hole = !cover[i];

		while (run + 1 <= li && (!cover[run + 1]) == hole)
			run++;
		if (k >= MAXSPAN)
			return -1;
		out[k].is_hole = hole;
		out[k].start = i;
		out[k].last = run;
		k++;
		if (run == li)
			break;
		i = run + 1;
	}
	return k;
}

static void stage_span(int n, unsigned long universe, unsigned long iters,
		       const char *label)
{
	static struct spanrec sc[MAXSPAN], sr[MAXSPAN], se[MAXSPAN];
	unsigned long i;
	int live = 0;

	reset_arms();
	fill_nodes(n, universe, 0);

	for (i = 0; i < (unsigned long)n; i++) {
		if (rnd_below(4) == 0)
			continue;
		apply_op(&A_REF, 1, (int)i);
		apply_op(&A_RS, 1, (int)i);
		A_REF.linked[i] = A_RS.linked[i] = 1;
		live++;
		ops_applied++;
	}
	compare_snap(label, 0);

	for (i = 0; i < iters; i++) {
		unsigned long fi, li;
		int kc, kr, ke, j;

		fi = rnd_below(universe) % SPAN_UNIVERSE;
		li = fi + rnd_below(universe);
		if (li >= SPAN_UNIVERSE)
			li = SPAN_UNIVERSE - 1;
		if (li < fi)
			li = fi;

		kc = collect_spans(&A_REF, fi, li, sc);
		kr = collect_spans(&A_RS, fi, li, sr);
		checks++;

		if (kc < 0 || kr < 0) {
			FAIL("%s iter %lu: span iteration did not terminate "
			     "for [%lu,%lu] (ref=%d rs=%d)",
			     label, i, fi, li, kc, kr);
			return;
		}
		if (kc != kr) {
			FAIL("%s iter %lu: [%lu,%lu] span count ref=%d rs=%d",
			     label, i, fi, li, kc, kr);
			return;
		}
		for (j = 0; j < kc; j++) {
			if (span_differs(&sc[j], &sr[j])) {
				FAIL("%s iter %lu: [%lu,%lu] span %d differs\n"
				     "    ref is_hole=%d [%lu,%lu] nodes=(%d,%d) window=[%lu,%lu]\n"
				     "    rs  is_hole=%d [%lu,%lu] nodes=(%d,%d) window=[%lu,%lu]",
				     label, i, fi, li, j,
				     sc[j].is_hole, sc[j].start, sc[j].last,
				     sc[j].node0, sc[j].node1,
				     sc[j].first_index, sc[j].last_index,
				     sr[j].is_hole, sr[j].start, sr[j].last,
				     sr[j].node0, sr[j].node1,
				     sr[j].first_index, sr[j].last_index);
				return;
			}
		}

		/* The independent arm. */
		ke = expected_spans(&A_REF, fi, li, se);
		if (ke < 0) {
			FAIL("%s iter %lu: span oracle overflowed", label, i);
			return;
		}
		if (kc != ke) {
			FAIL("%s iter %lu: [%lu,%lu] BOTH ARMS disagree with "
			     "the coverage oracle: arms=%d oracle=%d",
			     label, i, fi, li, kc, ke);
			return;
		}
		for (j = 0; j < ke; j++) {
			if (sc[j].is_hole != se[j].is_hole ||
			    sc[j].start != se[j].start ||
			    sc[j].last != se[j].last) {
				FAIL("%s iter %lu: [%lu,%lu] BOTH ARMS disagree "
				     "with the coverage oracle at span %d\n"
				     "    arms   is_hole=%d [%lu,%lu]\n"
				     "    oracle is_hole=%d [%lu,%lu]",
				     label, i, fi, li, j,
				     sc[j].is_hole, sc[j].start, sc[j].last,
				     se[j].is_hole, se[j].start, se[j].last);
				return;
			}
		}

		if ((i & 15) == 15) {
			int idx = (int)rnd_below((unsigned long)n);
			int want = !A_REF.linked[idx];

			apply_op(&A_REF, want, idx);
			apply_op(&A_RS, want, idx);
			A_REF.linked[idx] = A_RS.linked[idx] = (unsigned char)want;
			live += want ? 1 : -1;
			ops_applied++;
			compare_snap(label, i);
			check_invariants(&A_REF, label, i, live);
			check_invariants(&A_RS, label, i, live);
		}
		if (mismatches)
			return;
	}
}

/* --------------------------------------------------------------------- */
/* Stage 4 -- span_iter_advance.                                          */
/* --------------------------------------------------------------------- */

/* THE ONE BRANCH THE CORPUS CANNOT REACH, AND WHY THAT IS A PROPERTY OF THE
 * CODE RATHER THAN A GAP IN THE CORPUS.
 *
 * `gcov` on the oracle puts every line and every branch of
 * lib/interval_tree.c at executed, and 83 of 84 at taken-at-least-once. The
 * one that never flips is the second half of
 * `if (!iter->nodes[0] && !iter->nodes[1])` in
 * interval_tree_span_iter_next(): `&&` short-circuits, so evaluating
 * `!nodes[1]` at all requires `nodes[0] == NULL` on entry, and reaching that
 * arm with `nodes[1] != NULL` requires the state (NULL, non-NULL).
 *
 * That state is unreachable by construction: interval_tree_span_iter_next_gap()
 * always writes a non-NULL nodes[0], and every site that clears nodes[0]
 * clears nodes[1] in the same breath or has already found it NULL. Rather
 * than assert that from reading the source -- the project has been wrong
 * doing exactly that -- it is MEASURED: every observation of either arm's
 * iterator passes through here, and (NULL, non-NULL) has never been seen.
 *
 * Same shape as inftrees.c:290-293 in logs/hooks.md: recorded with its
 * reasoning so nobody adds a sabotage for it and reports it uncaught.
 */
static unsigned long iter_states_observed;

static void check_iter_state(struct arm *a, struct interval_tree_span_iter *it)
{
	iter_states_observed++;
	if (!it->nodes[0] && it->nodes[1]) {
		FAIL("%s: span iterator reached nodes[0]=NULL with "
		     "nodes[1]=%d, a state this file records as unreachable",
		     a->ops->name, idx_of(a, &it->nodes[1]->rb));
	}
}

static void snap_iter(struct arm *a, struct interval_tree_span_iter *it,
		      struct spanrec *r)
{
	check_iter_state(a, it);
	r->is_hole = it->is_hole;
	r->start = it->start_hole;
	r->last = it->last_hole;
	r->node0 = idx_of(a, it->nodes[0] ? &it->nodes[0]->rb : NULL);
	r->node1 = idx_of(a, it->nodes[1] ? &it->nodes[1]->rb : NULL);
	r->first_index = it->first_index;
	r->last_index = it->last_index;
}

static void stage_advance(int n, unsigned long universe, unsigned long iters,
			  const char *label)
{
	unsigned long i;

	reset_arms();
	fill_nodes(n, universe, 0);
	for (i = 0; i < (unsigned long)n; i++) {
		if (rnd_below(4) == 0)
			continue;
		apply_op(&A_REF, 1, (int)i);
		apply_op(&A_RS, 1, (int)i);
		A_REF.linked[i] = A_RS.linked[i] = 1;
		ops_applied++;
	}
	compare_snap(label, 0);

	for (i = 0; i < iters; i++) {
		struct interval_tree_span_iter ic, ir;
		struct spanrec rc, rr;
		unsigned long fi, li, at;
		int step, steps;

		fi = rnd_below(universe) % SPAN_UNIVERSE;
		li = fi + rnd_below(universe);
		if (li >= SPAN_UNIVERSE)
			li = SPAN_UNIVERSE - 1;
		if (li < fi)
			li = fi;

		memset(&ic, 0, sizeof(ic));
		memset(&ir, 0, sizeof(ir));
		A_REF.ops->span_first(&ic, &A_REF.root, fi, li);
		A_RS.ops->span_first(&ir, &A_RS.root, fi, li);

		at = fi;
		steps = 1 + (int)rnd_below(8);
		for (step = 0; step < steps; step++) {
			at += rnd_below(universe / 8 + 2);
			A_REF.ops->span_advance(&ic, &A_REF.root, at);
			A_RS.ops->span_advance(&ir, &A_RS.root, at);
			snap_iter(&A_REF, &ic, &rc);
			snap_iter(&A_RS, &ir, &rr);
			checks++;

			if (span_differs(&rc, &rr)) {
				FAIL("%s iter %lu step %d: advance to %lu in "
				     "[%lu,%lu] differs\n"
				     "    ref is_hole=%d [%lu,%lu] nodes=(%d,%d) window=[%lu,%lu]\n"
				     "    rs  is_hole=%d [%lu,%lu] nodes=(%d,%d) window=[%lu,%lu]",
				     label, i, step, at, fi, li,
				     rc.is_hole, rc.start, rc.last,
				     rc.node0, rc.node1,
				     rc.first_index, rc.last_index,
				     rr.is_hole, rr.start, rr.last,
				     rr.node0, rr.node1,
				     rr.first_index, rr.last_index);
				return;
			}

			/* The independent property, from the header's own
			 * words: "The returned used/hole is updated to start
			 * at new_index. This is faster than calling
			 * interval_tree_span_iter_first()." So for a forward
			 * advance the REPORTED span must be what a fresh
			 * _first() at that index reports. Shares no code path
			 * with _advance, so it catches a shortcut both arms
			 * take wrongly. */
			if (!interval_tree_span_iter_done(&ic)) {
				struct interval_tree_span_iter fresh;
				struct spanrec rf;

				memset(&fresh, 0, sizeof(fresh));
				A_REF.ops->span_first(&fresh, &A_REF.root, at, li);
				snap_iter(&A_REF, &fresh, &rf);
				if (rf.is_hole != rc.is_hole ||
				    rf.start != rc.start ||
				    rf.last != rc.last) {
					FAIL("%s iter %lu step %d: advance to "
					     "%lu in [%lu,%lu] reports a span "
					     "a fresh _first() does not\n"
					     "    advance is_hole=%d [%lu,%lu]\n"
					     "    _first  is_hole=%d [%lu,%lu]",
					     label, i, step, at, fi, li,
					     rc.is_hole, rc.start, rc.last,
					     rf.is_hole, rf.start, rf.last);
					return;
				}
			} else {
				break;
			}
		}
		if (mismatches)
			return;
	}
}
#endif /* CONFIG_INTERVAL_TREE_SPAN_ITER */

/* --------------------------------------------------------------------- */

/* --------------------------------------------------------------------- */
/* Stage 5 -- the cases random input does not reach.                       */
/*                                                                         */
/* logs/hooks.md, from the inftrees work: "Random inputs test the middle    */
/* of a condition. A boundary has to be built." `gcov` on the oracle,       */
/* 2026-09-05, put exactly four branches of lib/interval_tree.c at          */
/* never-taken after the random stages, and every one of them is an early   */
/* return that a populated tree and a forward-only iteration cannot reach:  */
/* the empty-tree exit in iter_first, the already-done exit in             */
/* span_iter_advance, and the two arms of advance's containment test. This  */
/* stage builds them.                                                       */
/* --------------------------------------------------------------------- */

static void directed_query(unsigned long qs, unsigned long ql, const char *what)
{
	int mc[MAXMATCH], mr[MAXMATCH], me[MAXMATCH];
	int kc, kr, ke, j;

	kc = collect_matches(&A_REF, qs, ql, mc);
	kr = collect_matches(&A_RS, qs, ql, mr);
	ke = expected_matches(&A_REF, qs, ql, me);
	checks++;

	if (kc != kr) {
		FAIL("directed/%s: [%lu,%lu] match count ref=%d rs=%d",
		     what, qs, ql, kc, kr);
		return;
	}
	for (j = 0; j < kc; j++)
		if (mc[j] != mr[j]) {
			FAIL("directed/%s: [%lu,%lu] match %d ref=%d rs=%d",
			     what, qs, ql, j, mc[j], mr[j]);
			return;
		}
	if (kc != ke) {
		FAIL("directed/%s: [%lu,%lu] BOTH ARMS disagree with the "
		     "in-order oracle: arms=%d oracle=%d", what, qs, ql, kc, ke);
	}
}

static void stage_directed(void)
{
	unsigned long i;

	/* --- the empty tree. iter_first's `!root->rb_root.rb_node` exit. --- */
	reset_arms();
	fill_nodes(4, 64, 0);
	directed_query(0, ~0UL, "empty/whole-space");
	directed_query(7, 7, "empty/point");
	compare_snap("directed/empty", 0);
	check_invariants(&A_REF, "directed/empty", 0, 0);
	check_invariants(&A_RS, "directed/empty", 0, 0);

#ifdef CONFIG_INTERVAL_TREE_SPAN_ITER
	{
		static struct spanrec sc[MAXSPAN], sr[MAXSPAN], se[MAXSPAN];
		struct interval_tree_span_iter ic, ir;
		struct spanrec rc, rr;
		int kc, kr, ke, j;

		/* An empty tree is one whole hole. */
		kc = collect_spans(&A_REF, 3, 20, sc);
		kr = collect_spans(&A_RS, 3, 20, sr);
		ke = expected_spans(&A_REF, 3, 20, se);
		checks++;
		if (kc != kr || kc != ke || kc != 1 ||
		    sc[0].is_hole != 1 || sc[0].start != 3 || sc[0].last != 20)
			FAIL("directed/span-empty: ref=%d rs=%d oracle=%d",
			     kc, kr, ke);
		for (j = 0; j < kc && j < kr; j++)
			if (span_differs(&sc[j], &sr[j]))
				FAIL("directed/span-empty: span %d differs", j);

		/* --- advance past last_index, then advance again.
		 * The first sets is_hole = -1; the second must take
		 * span_iter_advance's `if (iter->is_hole == -1) return;`
		 * exit, which no forward walk reaches because the loop
		 * stops at done. --- */
		memset(&ic, 0, sizeof(ic));
		memset(&ir, 0, sizeof(ir));
		A_REF.ops->span_first(&ic, &A_REF.root, 0, 10);
		A_RS.ops->span_first(&ir, &A_RS.root, 0, 10);
		A_REF.ops->span_advance(&ic, &A_REF.root, 11);
		A_RS.ops->span_advance(&ir, &A_RS.root, 11);
		snap_iter(&A_REF, &ic, &rc);
		snap_iter(&A_RS, &ir, &rr);
		checks++;
		if (span_differs(&rc, &rr) || rc.is_hole != -1)
			FAIL("directed/advance-past-end: ref is_hole=%d "
			     "rs is_hole=%d", rc.is_hole, rr.is_hole);

		A_REF.ops->span_advance(&ic, &A_REF.root, 5);
		A_RS.ops->span_advance(&ir, &A_RS.root, 5);
		snap_iter(&A_REF, &ic, &rc);
		snap_iter(&A_RS, &ir, &rr);
		checks++;
		if (span_differs(&rc, &rr) || rc.is_hole != -1)
			FAIL("directed/advance-after-done: ref is_hole=%d "
			     "rs is_hole=%d", rc.is_hole, rr.is_hole);
	}
#endif

	/* --- one node, and every query that touches its boundaries. --- */
	reset_arms();
	fill_nodes(4, 64, 0);
	A_REF.node[0].start = A_RS.node[0].start = 100;
	A_REF.node[0].last = A_RS.node[0].last = 200;
	if (prove_can_fail)
		A_RS.node[0].last = 201;
	apply_op(&A_REF, 1, 0);
	apply_op(&A_RS, 1, 0);
	A_REF.linked[0] = A_RS.linked[0] = 1;
	ops_applied++;
	compare_snap("directed/one", 0);
	directed_query(0, 99, "one/before");
	directed_query(0, 100, "one/touch-start");
	directed_query(200, 400, "one/touch-last");
	directed_query(201, 400, "one/after");
	directed_query(100, 200, "one/exact");
	directed_query(150, 150, "one/inside-point");

	/* --- adjacency: [a,b] and [b+1,c] are ONE used span, but [a,b] and
	 * [b+2,c] are two with a one-index hole between them. That
	 * `nodes[0]->last + 1 == cur->start` disjunct is the whole of the
	 * span iterator's consolidation rule and a random corpus over a wide
	 * universe almost never lands on it. --- */
	reset_arms();
	fill_nodes(8, 64, 0);
	for (i = 0; i < 6; i++) {
		unsigned long s = 10 + i * 6, l = s + 4;	/* [10,14][16,20]... */

		A_REF.node[i].start = A_RS.node[i].start = s;
		A_REF.node[i].last = A_RS.node[i].last = l;
	}
	/* Make the first two exactly adjacent: [10,14] then [15,19]. */
	A_REF.node[1].start = A_RS.node[1].start = 15;
	A_REF.node[1].last = A_RS.node[1].last = 19;
	if (prove_can_fail)
		A_RS.node[1].last = 20;
	for (i = 0; i < 6; i++) {
		apply_op(&A_REF, 1, (int)i);
		apply_op(&A_RS, 1, (int)i);
		A_REF.linked[i] = A_RS.linked[i] = 1;
		ops_applied++;
	}
	compare_snap("directed/adjacent", 0);
	check_invariants(&A_REF, "directed/adjacent", 0, 6);
	check_invariants(&A_RS, "directed/adjacent", 0, 6);
	directed_query(0, ~0UL, "adjacent/all");

#ifdef CONFIG_INTERVAL_TREE_SPAN_ITER
	{
		static struct spanrec sc[MAXSPAN], sr[MAXSPAN], se[MAXSPAN];
		struct interval_tree_span_iter ic, ir;
		struct spanrec rc, rr;
		int kc, kr, ke, j;
		unsigned long at;

		kc = collect_spans(&A_REF, 0, 60, sc);
		kr = collect_spans(&A_RS, 0, 60, sr);
		ke = expected_spans(&A_REF, 0, 60, se);
		checks++;
		if (kc != kr || kc != ke)
			FAIL("directed/span-adjacent: ref=%d rs=%d oracle=%d",
			     kc, kr, ke);
		for (j = 0; j < kc && j < kr; j++)
			if (span_differs(&sc[j], &sr[j]))
				FAIL("directed/span-adjacent: span %d differs", j);
		for (j = 0; j < kc && j < ke; j++)
			if (sc[j].is_hole != se[j].is_hole ||
			    sc[j].start != se[j].start ||
			    sc[j].last != se[j].last)
				FAIL("directed/span-adjacent: BOTH ARMS "
				     "disagree with the coverage oracle at "
				     "span %d: arms is_hole=%d [%lu,%lu] "
				     "oracle is_hole=%d [%lu,%lu]",
				     j, sc[j].is_hole, sc[j].start, sc[j].last,
				     se[j].is_hole, se[j].start, se[j].last);

		/* --- advance BACKWARD. Both arms of the containment test in
		 * span_iter_advance, including the one a forward-only walk
		 * never takes, and the site the port spells `wrapping_add`. */
		memset(&ic, 0, sizeof(ic));
		memset(&ir, 0, sizeof(ir));
		A_REF.ops->span_first(&ic, &A_REF.root, 0, 60);
		A_RS.ops->span_first(&ir, &A_RS.root, 0, 60);
		for (at = 60; at > 0; at--) {
			A_REF.ops->span_advance(&ic, &A_REF.root, at);
			A_RS.ops->span_advance(&ir, &A_RS.root, at);
			snap_iter(&A_REF, &ic, &rc);
			snap_iter(&A_RS, &ir, &rr);
			checks++;
			if (span_differs(&rc, &rr)) {
				FAIL("directed/advance-backward to %lu:\n"
				     "    ref is_hole=%d [%lu,%lu] nodes=(%d,%d)\n"
				     "    rs  is_hole=%d [%lu,%lu] nodes=(%d,%d)",
				     at, rc.is_hole, rc.start, rc.last,
				     rc.node0, rc.node1,
				     rr.is_hole, rr.start, rr.last,
				     rr.node0, rr.node1);
				return;
			}
		}
	}
#endif

	/* --- ULONG_MAX. The C's unsigned arithmetic wraps here and the port
	 * has to wrap with it; a used span ending at ULONG_MAX is what makes
	 * span_iter_advance's `last_hole + 1` reachable at all. --- */
	reset_arms();
	fill_nodes(4, 64, 0);
	A_REF.node[0].start = A_RS.node[0].start = 0;
	A_REF.node[0].last = A_RS.node[0].last = ~0UL;
	A_REF.node[1].start = A_RS.node[1].start = ~0UL;
	A_REF.node[1].last = A_RS.node[1].last = ~0UL;
	A_REF.node[2].start = A_RS.node[2].start = ~0UL - 1;
	A_REF.node[2].last = A_RS.node[2].last = ~0UL;
	if (prove_can_fail)
		A_RS.node[2].start = ~0UL;
	for (i = 0; i < 3; i++) {
		apply_op(&A_REF, 1, (int)i);
		apply_op(&A_RS, 1, (int)i);
		A_REF.linked[i] = A_RS.linked[i] = 1;
		ops_applied++;
		compare_snap("directed/ulong-max", i);
		check_invariants(&A_REF, "directed/ulong-max", i, (int)i + 1);
		check_invariants(&A_RS, "directed/ulong-max", i, (int)i + 1);
	}
	directed_query(~0UL, ~0UL, "ulong-max/top");
	directed_query(0, 0, "ulong-max/bottom");
	directed_query(~0UL - 1, ~0UL, "ulong-max/pair");

#ifdef CONFIG_INTERVAL_TREE_SPAN_ITER
	{
		struct interval_tree_span_iter ic, ir;
		struct spanrec rc, rr;

		/* A used span that reaches ULONG_MAX, then an advance BELOW
		 * its start -- the one site in the port spelled
		 * `wrapping_add`, because the C computes `ULONG_MAX + 1`. */
		memset(&ic, 0, sizeof(ic));
		memset(&ir, 0, sizeof(ir));
		A_REF.ops->span_first(&ic, &A_REF.root, 10, ~0UL);
		A_RS.ops->span_first(&ir, &A_RS.root, 10, ~0UL);
		snap_iter(&A_REF, &ic, &rc);
		snap_iter(&A_RS, &ir, &rr);
		checks++;
		if (span_differs(&rc, &rr))
			FAIL("directed/span-ulong-max: first differs "
			     "(ref is_hole=%d [%lu,%lu], rs is_hole=%d [%lu,%lu])",
			     rc.is_hole, rc.start, rc.last,
			     rr.is_hole, rr.start, rr.last);

		A_REF.ops->span_advance(&ic, &A_REF.root, 0);
		A_RS.ops->span_advance(&ir, &A_RS.root, 0);
		snap_iter(&A_REF, &ic, &rc);
		snap_iter(&A_RS, &ir, &rr);
		checks++;
		if (span_differs(&rc, &rr))
			FAIL("directed/span-wrap: advance to 0 from a span "
			     "ending at ULONG_MAX differs\n"
			     "    ref is_hole=%d [%lu,%lu]\n"
			     "    rs  is_hole=%d [%lu,%lu]",
			     rc.is_hole, rc.start, rc.last,
			     rr.is_hole, rr.start, rr.last);
	}
#endif
}

/* --------------------------------------------------------------------- */
/* Stage 0 -- the part is inspected against the blueprint.                 */
/*                                                                         */
/* logs/floor.md RAISE 6 checks mirrored struct geometry against the built  */
/* kernel's DWARF. That needs a kernel; this needs neither, and it runs     */
/* first, because every `.cast()` in the port and every comparison in this  */
/* file is void if the two layouts differ. `rs_geometry()` is appended to   */
/* the probe by run.sh -- see its comment for why it has to live inside     */
/* the crate.                                                              */
/* --------------------------------------------------------------------- */

#define GEOM_N 22
void rs_geometry(unsigned long *out);

static void geom_check(const char *what, unsigned long got, unsigned long want)
{
	checks++;
	if (got != want) {
		printf("\nGEOMETRY: %s: rust=%lu c=%lu\n", what, got, want);
		mismatches++;
	}
}

static void stage_geometry(void)
{
	unsigned long g[GEOM_N];
	unsigned int i;

	for (i = 0; i < GEOM_N; i++)
		g[i] = ~0UL;
	rs_geometry(g);

	geom_check("sizeof(interval_tree_node)", g[0],
		   sizeof(struct interval_tree_node));
	geom_check("alignof(interval_tree_node)", g[1],
		   __alignof__(struct interval_tree_node));
	geom_check("interval_tree_node.rb", g[2],
		   offsetof(struct interval_tree_node, rb));
	geom_check("interval_tree_node.start", g[3],
		   offsetof(struct interval_tree_node, start));
	geom_check("interval_tree_node.last", g[4],
		   offsetof(struct interval_tree_node, last));
	geom_check("interval_tree_node.__subtree_last", g[5],
		   offsetof(struct interval_tree_node, __subtree_last));

	geom_check("sizeof(rb_node)", g[6], sizeof(struct rb_node));
	geom_check("rb_node.__rb_parent_color", g[7],
		   offsetof(struct rb_node, __rb_parent_color));
	geom_check("rb_node.rb_right", g[8],
		   offsetof(struct rb_node, rb_right));
	geom_check("rb_node.rb_left", g[9],
		   offsetof(struct rb_node, rb_left));

	geom_check("sizeof(rb_root)", g[10], sizeof(struct rb_root));
	geom_check("sizeof(rb_root_cached)", g[11],
		   sizeof(struct rb_root_cached));
	geom_check("rb_root_cached.rb_root", g[12],
		   offsetof(struct rb_root_cached, rb_root));
	geom_check("rb_root_cached.rb_leftmost", g[13],
		   offsetof(struct rb_root_cached, rb_leftmost));

#ifdef CONFIG_INTERVAL_TREE_SPAN_ITER
	geom_check("sizeof(interval_tree_span_iter)", g[14],
		   sizeof(struct interval_tree_span_iter));
	geom_check("alignof(interval_tree_span_iter)", g[15],
		   __alignof__(struct interval_tree_span_iter));
	geom_check("span_iter.nodes", g[16],
		   offsetof(struct interval_tree_span_iter, nodes));
	geom_check("span_iter.first_index", g[17],
		   offsetof(struct interval_tree_span_iter, first_index));
	geom_check("span_iter.last_index", g[18],
		   offsetof(struct interval_tree_span_iter, last_index));
	geom_check("span_iter.start_hole", g[19],
		   offsetof(struct interval_tree_span_iter, start_hole));
	geom_check("span_iter.last_hole", g[20],
		   offsetof(struct interval_tree_span_iter, last_hole));
	geom_check("span_iter.is_hole", g[21],
		   offsetof(struct interval_tree_span_iter, is_hole));

	/* The two anonymous unions alias by name in the C and are reproduced
	 * as named unions in the Rust. Assert the aliasing itself, since it
	 * is what interval_tree_span_iter_advance() reads on. */
	geom_check("span_iter.start_used aliases start_hole",
		   offsetof(struct interval_tree_span_iter, start_used),
		   offsetof(struct interval_tree_span_iter, start_hole));
	geom_check("span_iter.last_used aliases last_hole",
		   offsetof(struct interval_tree_span_iter, last_used),
		   offsetof(struct interval_tree_span_iter, last_hole));
#endif
}

static unsigned long envnum(const char *name, unsigned long dflt)
{
	const char *v = getenv(name);

	return v ? strtoul(v, NULL, 0) : dflt;
}

int main(void)
{
	unsigned long scale = envnum("INTERVAL_TREE_SCALE", 1);
	unsigned long seed = envnum("INTERVAL_TREE_SEED", 0);

	/* Line-buffered even when stdout is a file. A sabotaged port crashes,
	 * and a fully-buffered stdout would swallow the MISMATCH line that had
	 * already been printed -- which run.sh's prove-can-fail gate reads as
	 * "the harness cannot disagree". Losing the report is the same defect
	 * as never producing it. */
	setvbuf(stdout, NULL, _IOLBF, 0);

	prove_can_fail = getenv("INTERVAL_TREE_PROVE_CAN_FAIL") != NULL;
	if (seed)
		rng_state = seed;

	printf("interval_tree differential\n");
	printf("  span iterator : %s\n",
#ifdef CONFIG_INTERVAL_TREE_SPAN_ITER
	       "CONFIG_INTERVAL_TREE_SPAN_ITER=y"
#else
	       "not compiled (CONFIG_INTERVAL_TREE_SPAN_ITER unset)"
#endif
	       );
	printf("  sizeof(struct interval_tree_node)      = %zu\n",
	       sizeof(struct interval_tree_node));
#ifdef CONFIG_INTERVAL_TREE_SPAN_ITER
	printf("  sizeof(struct interval_tree_span_iter) = %zu\n",
	       sizeof(struct interval_tree_span_iter));
#endif
	printf("  seed = 0x%llx  scale = %lu\n", rng_state, scale);

	stage_geometry();
	if (mismatches) {
		printf("  the two layouts differ; every later stage would be "
		       "comparing nothing. Stopping.\n");
		return 1;
	}

	/* Small trees, heavy churn: this is where erase case 2 and case 3
	 * and the leftmost-cache update actually get exercised. */
#define STAGE(label, call)						\
	do { stage_begin(label); call; stage_end(); } while (0)

	STAGE("structure/tiny",  stage_structure(8,   64,   4000 * scale, 1, "structure/tiny"));
	STAGE("structure/small", stage_structure(40,  256,  6000 * scale, 1, "structure/small"));
	STAGE("structure/wide",  stage_structure(200, 4096, 6000 * scale, 0, "structure/wide"));
	STAGE("structure/dense", stage_structure(64,  8,    4000 * scale, 0, "structure/dense"));

	STAGE("query/small",     stage_query(64,  256,  8000 * scale, "query/small"));
	STAGE("query/wide",      stage_query(300, 4096, 8000 * scale, "query/wide"));

#ifdef CONFIG_INTERVAL_TREE_SPAN_ITER
	STAGE("span/sparse",     stage_span(48,  SPAN_UNIVERSE, 3000 * scale, "span/sparse"));
	STAGE("span/dense",      stage_span(160, SPAN_UNIVERSE, 3000 * scale, "span/dense"));
	STAGE("advance",         stage_advance(96, SPAN_UNIVERSE, 3000 * scale, "advance"));
#endif

	STAGE("directed",        stage_directed());

#ifdef CONFIG_INTERVAL_TREE_SPAN_ITER
	printf("  span iterator states observed : %lu, none of them "
	       "(nodes[0]=NULL, nodes[1]!=NULL)\n", iter_states_observed);
#endif
	printf("  operations applied : %lu\n", ops_applied);
	printf("  comparisons        : %lu\n", checks);
	printf("  mismatches         : %lu\n", mismatches);
	return mismatches ? 1 : 0;
}
