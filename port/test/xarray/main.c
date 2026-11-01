/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Differential test for lib/xarray.c -> port/tree/lib/xarray_rs.rs.
 *
 * Two xarray pairs, driven by the SAME random operation stream:
 *   xa_ref / xa_rs   -- plain xarray, general store/erase/cmpxchg/
 *                        insert/store_range/marks/find fuzzing.
 *   xa_ref_alloc / xa_rs_alloc -- XA_FLAGS_ALLOC, for __xa_alloc /
 *                        __xa_alloc_cyclic and the FREE_MARK oracle.
 *
 * Entries are xa_mk_value() integers so results can be compared by
 * VALUE across the two arms (raw pointers would never match -- each
 * arm allocates its own nodes independently).
 */
#include <linux/xarray.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <signal.h>
#include <unistd.h>
#include <execinfo.h>

/* A real tree cycle (garbage sibling chain) hangs xas_descend()'s inner
 * while loop with no other symptom -- found once, via this watchdog,
 * when a stub allocator bug (see radix_tree_stub.c) left stale heap
 * bytes in a reused node's slots[]. Kept as permanent infrastructure:
 * a hang here tells you nothing on its own, a backtrace does. */
static void on_alarm(int sig)
{
	void *bt[64];
	int n = backtrace(bt, 64);
	(void)sig;
	fprintf(stderr, "\n=== WATCHDOG FIRED, BACKTRACE ===\n");
	backtrace_symbols_fd(bt, n, 2);
	_exit(3);
}

/* ---- ref_* (pristine C, renamed) ---- */
extern void *ref_xas_load(struct xa_state *);
extern void ref_xas_destroy(struct xa_state *);
extern bool ref_xas_nomem(struct xa_state *, gfp_t);
extern void *ref_xas_store(struct xa_state *, void *);
extern bool ref_xas_get_mark(const struct xa_state *, xa_mark_t);
extern void ref_xas_set_mark(const struct xa_state *, xa_mark_t);
extern void ref_xas_clear_mark(const struct xa_state *, xa_mark_t);
extern void ref_xas_init_marks(const struct xa_state *);
extern void ref_xas_split_alloc(struct xa_state *, void *, unsigned int, gfp_t);
extern void ref_xas_split(struct xa_state *, void *, unsigned int);
extern unsigned int ref_xas_try_split_min_order(unsigned int);
extern void ref_xas_try_split(struct xa_state *, void *, unsigned int);
extern int ref_xas_get_order(struct xa_state *);
extern void *ref_xas_find(struct xa_state *, unsigned long);
extern void *ref_xas_find_marked(struct xa_state *, unsigned long, xa_mark_t);

extern void *ref_xa_load(struct xarray *, unsigned long);
extern void *ref___xa_erase(struct xarray *, unsigned long);
extern void *ref_xa_erase(struct xarray *, unsigned long);
extern void *ref___xa_store(struct xarray *, unsigned long, void *, gfp_t);
extern void *ref_xa_store(struct xarray *, unsigned long, void *, gfp_t);
extern void *ref___xa_cmpxchg(struct xarray *, unsigned long, void *, void *, gfp_t);
extern int ref___xa_insert(struct xarray *, unsigned long, void *, gfp_t);
extern void *ref_xa_store_range(struct xarray *, unsigned long, unsigned long, void *, gfp_t);
extern int ref_xa_get_order(struct xarray *, unsigned long);
extern void ref___xa_set_mark(struct xarray *, unsigned long, xa_mark_t);
extern void ref___xa_clear_mark(struct xarray *, unsigned long, xa_mark_t);
extern bool ref_xa_get_mark(struct xarray *, unsigned long, xa_mark_t);
extern void *ref_xa_find(struct xarray *, unsigned long *, unsigned long, xa_mark_t);
extern void *ref_xa_find_after(struct xarray *, unsigned long *, unsigned long, xa_mark_t);
extern unsigned int ref_xa_extract(struct xarray *, void **, unsigned long, unsigned long, unsigned int, xa_mark_t);
extern void ref_xa_destroy(struct xarray *);
extern int ref___xa_alloc(struct xarray *, u32 *, void *, struct xa_limit, gfp_t);
extern int ref___xa_alloc_cyclic(struct xarray *, u32 *, void *, struct xa_limit, u32 *, gfp_t);

/* ---- rs_* (the Rust port, via probe.rs) ---- */
extern void *rs_xas_load(struct xa_state *);
extern void rs_xas_destroy(struct xa_state *);
extern bool rs_xas_nomem(struct xa_state *, gfp_t);
extern void *rs_xas_store(struct xa_state *, void *);
extern bool rs_xas_get_mark(const struct xa_state *, xa_mark_t);
extern void rs_xas_set_mark(const struct xa_state *, xa_mark_t);
extern void rs_xas_clear_mark(const struct xa_state *, xa_mark_t);
extern void rs_xas_init_marks(const struct xa_state *);
extern void rs_xas_split_alloc(struct xa_state *, void *, unsigned int, gfp_t);
extern void rs_xas_split(struct xa_state *, void *, unsigned int);
extern unsigned int rs_xas_try_split_min_order(unsigned int);
extern void rs_xas_try_split(struct xa_state *, void *, unsigned int);
extern int rs_xas_get_order(struct xa_state *);
extern void *rs_xas_find(struct xa_state *, unsigned long);
extern void *rs_xas_find_marked(struct xa_state *, unsigned long, xa_mark_t);

extern void *rs_xa_load(struct xarray *, unsigned long);
extern void *rs___xa_erase(struct xarray *, unsigned long);
extern void *rs_xa_erase(struct xarray *, unsigned long);
extern void *rs___xa_store(struct xarray *, unsigned long, void *, gfp_t);
extern void *rs_xa_store(struct xarray *, unsigned long, void *, gfp_t);
extern void *rs___xa_cmpxchg(struct xarray *, unsigned long, void *, void *, gfp_t);
extern int rs___xa_insert(struct xarray *, unsigned long, void *, gfp_t);
extern void *rs_xa_store_range(struct xarray *, unsigned long, unsigned long, void *, gfp_t);
extern int rs_xa_get_order(struct xarray *, unsigned long);
extern void rs___xa_set_mark(struct xarray *, unsigned long, xa_mark_t);
extern void rs___xa_clear_mark(struct xarray *, unsigned long, xa_mark_t);
extern bool rs_xa_get_mark(struct xarray *, unsigned long, xa_mark_t);
extern void *rs_xa_find(struct xarray *, unsigned long *, unsigned long, xa_mark_t);
extern void *rs_xa_find_after(struct xarray *, unsigned long *, unsigned long, xa_mark_t);
extern unsigned int rs_xa_extract(struct xarray *, void **, unsigned long, unsigned long, unsigned int, xa_mark_t);
extern void rs_xa_destroy(struct xarray *);
extern int rs___xa_alloc(struct xarray *, u32 *, void *, struct xa_limit, gfp_t);
extern int rs___xa_alloc_cyclic(struct xarray *, u32 *, void *, struct xa_limit, u32 *, gfp_t);

static unsigned int g_seed;
static unsigned int failures;
static unsigned int checks;
#define MAX_FAILURES 10

static unsigned long xrand(unsigned long n)
{
	g_seed = g_seed * 1103515245u + 12345u;
	unsigned long r = (g_seed >> 8);
	g_seed = g_seed * 1103515245u + 12345u;
	r = (r << 24) ^ (g_seed >> 8);
	return n ? (r % n) : 0;
}

#define CHECK(cond, fmt, ...) do { \
	checks++; \
	if (!(cond)) { \
		failures++; \
		fprintf(stderr, "MISMATCH (seed %u): " fmt "\n", g_seed, ##__VA_ARGS__); \
		if (failures >= MAX_FAILURES) { \
			fprintf(stderr, "too many failures, aborting\n"); \
			exit(1); \
		} \
	} \
} while (0)

/* Both a NULL pointer and an xa_is_err() pointer compare by their
 * "meaning" (NULL, or the errno), never by raw address -- separate
 * allocations mean addresses never match even when both arms are
 * correct. Value entries compare by their decoded integer. */
static int entries_equal(void *a, void *b)
{
	if (xa_is_err(a) || xa_is_err(b))
		return xa_err(a) == xa_err(b);
	if (a == NULL || b == NULL)
		return a == b;
	if (xa_is_value(a) != xa_is_value(b))
		return 0;
	if (xa_is_value(a))
		return xa_to_value(a) == xa_to_value(b);
	/* Only value entries are ever stored by this harness. */
	return a == b;
}

/* ---- structural self-check: recompute count/nr_values from a raw
 * walk, independent of what the node's own fields claim. ---- */

/* node_get_mark() itself is `static` inside lib/xarray.c -- not
 * reachable from here. Reimplemented directly against the real,
 * pahole-verified `struct xa_node.marks` bitmap layout. */
static int node_get_mark(struct xa_node *node, unsigned int offset, xa_mark_t mark)
{
	unsigned long *bits = node->marks[(__force unsigned int)mark];
	return (bits[offset / (8 * sizeof(unsigned long))] >>
		(offset % (8 * sizeof(unsigned long)))) & 1UL;
}

static int check_node_structure(struct xarray *xa, struct xa_node *node, const char *arm)
{
	unsigned int real_count = 0, real_values = 0;
	unsigned int i;
	int ok = 1;

	for (i = 0; i < XA_CHUNK_SIZE; i++) {
		void *entry = xa_entry_locked(xa, node, i);

		if (!entry)
			continue;
		real_count++;
		if (xa_is_value(entry))
			real_values++;
		else if (xa_is_sibling(entry)) {
			/* A sibling's value-ness follows the canonical
			 * slot it points back to -- which can itself be
			 * ANOTHER sibling (a chain, not always one hop;
			 * xas_descend()'s own resolution loops for exactly
			 * this reason). Follow it the same way. */
			void *chead = entry;
			unsigned int hops = 0;

			while (xa_is_sibling(chead) && hops++ < XA_CHUNK_SIZE) {
				unsigned long canon = xa_to_sibling(chead);
				chead = xa_entry_locked(xa, node, canon);
			}
			if (xa_is_value(chead))
				real_values++;
		} else if (xa_is_node(entry)) {
			if (!check_node_structure(xa, xa_to_node(entry), arm))
				ok = 0;
		}
	}

	CHECK(real_count == node->count,
	      "%s: node %p count=%u recomputed=%u", arm, (void *)node,
	      node->count, real_count);
	CHECK(real_values == node->nr_values,
	      "%s: node %p nr_values=%u recomputed=%u", arm, (void *)node,
	      node->nr_values, real_values);
	return ok;
}

static void check_structure(struct xarray *xa, const char *arm)
{
	void *head = xa_head(xa);

	if (xa_is_node(head))
		check_node_structure(xa, xa_to_node(head), arm);
}

/* ---- mark oracle: recompute "should this bit be set" independently
 * of the stored bitmap, per the approved plan's two-oracle design. ---- */

/* Normal marks: OR over live descendants, EXCLUDING sibling slots (a
 * multi-slot entry's mark lives only on its canonical/first slot --
 * xas_squash_marks() clears it from every sibling). */
static int node_mark_should_be_set(struct xarray *xa, struct xa_node *node,
				    unsigned int offset, xa_mark_t mark)
{
	void *entry = xa_entry_locked(xa, node, offset);

	if (!entry)
		return 0;
	if (xa_is_sibling(entry))
		return 0; /* never independently marked; canon carries it */
	if (xa_is_node(entry)) {
		struct xa_node *child = xa_to_node(entry);
		unsigned int i;

		for (i = 0; i < XA_CHUNK_SIZE; i++) {
			void *centry = xa_entry_locked(xa, child, i);
			if (!centry || xa_is_sibling(centry))
				continue;
			if (node_get_mark(child, i, mark))
				return 1;
		}
		return 0;
	}
	/* A leaf's own mark bit is ground truth at the leaf level --
	 * checked at the level ABOVE by node_get_mark on the child. */
	return node_get_mark(node, offset, mark);
}

/* FREE_MARK: inverted leaf predicate (set means EMPTY, not occupied). */
static int node_free_mark_should_be_set(struct xarray *xa, struct xa_node *node,
					 unsigned int offset)
{
	void *entry = xa_entry_locked(xa, node, offset);

	if (xa_is_node(entry)) {
		struct xa_node *child = xa_to_node(entry);
		unsigned int i;

		for (i = 0; i < XA_CHUNK_SIZE; i++)
			if (node_get_mark(child, i, XA_FREE_MARK))
				return 1;
		return 0;
	}
	if (xa_is_sibling(entry))
		return 0;
	return entry == NULL; /* empty slot -> free */
}

static void check_marks_node(struct xarray *xa, struct xa_node *node,
			      xa_mark_t mark, const char *arm)
{
	unsigned int i;

	for (i = 0; i < XA_CHUNK_SIZE; i++) {
		void *entry = xa_entry_locked(xa, node, i);
		int want, got = node_get_mark(node, i, mark);

		if (mark == XA_FREE_MARK && (xa->xa_flags & XA_FLAGS_TRACK_FREE))
			want = node_free_mark_should_be_set(xa, node, i);
		else
			want = node_mark_should_be_set(xa, node, i, mark);

		CHECK(want == got,
		      "%s: node %p offset %u mark %u want=%d got=%d",
		      arm, (void *)node, i, (unsigned)mark, want, got);

		if (xa_is_node(entry))
			check_marks_node(xa, xa_to_node(entry), mark, arm);
	}
}

static void check_marks(struct xarray *xa, const char *arm)
{
	void *head = xa_head(xa);
	xa_mark_t m;

	if (!xa_is_node(head))
		return;
	for (m = XA_MARK_0; m <= XA_MARK_2; m++)
		check_marks_node(xa, xa_to_node(head), (xa_mark_t)m, arm);
}

/* ---- cross-arm comparison: same (index, value) sequence ---- */
static void compare_present(struct xarray *xa_ref, struct xarray *xa_rs,
			     unsigned long max, const char *label)
{
	unsigned long idx_ref = 0, idx_rs = 0;
	void *e_ref, *e_rs;

	e_ref = ref_xa_find(xa_ref, &idx_ref, max, XA_PRESENT);
	e_rs = rs_xa_find(xa_rs, &idx_rs, max, XA_PRESENT);
	for (;;) {
		if (!e_ref && !e_rs)
			break;
		CHECK(!!e_ref == !!e_rs,
		      "%s: presence mismatch at idx_ref=%lu idx_rs=%lu",
		      label, idx_ref, idx_rs);
		if (!e_ref || !e_rs)
			break;
		CHECK(idx_ref == idx_rs, "%s: index mismatch %lu vs %lu",
		      label, idx_ref, idx_rs);
		CHECK(entries_equal(e_ref, e_rs),
		      "%s: value mismatch at %lu", label, idx_ref);

		e_ref = ref_xa_find_after(xa_ref, &idx_ref, max, XA_PRESENT);
		e_rs = rs_xa_find_after(xa_rs, &idx_rs, max, XA_PRESENT);
	}
}

static void full_invariant_check(struct xarray *xa_ref, struct xarray *xa_rs,
				  unsigned long max, const char *label)
{
	compare_present(xa_ref, xa_rs, max, label);
	check_structure(xa_ref, "ref");
	check_structure(xa_rs, "rs");
	check_marks(xa_ref, "ref");
	check_marks(xa_rs, "rs");
}

/* ---- fuzz loop ---- */
enum op {
	OP_STORE, OP_ERASE, OP_CMPXCHG, OP_INSERT, OP_STORE_RANGE,
	OP_SET_MARK, OP_CLEAR_MARK, OP_NR,
};

static void run_plain(unsigned long n_ops, unsigned long index_space)
{
	struct xarray xa_ref, xa_rs;

	xa_init_flags(&xa_ref, 0);
	xa_init_flags(&xa_rs, 0);

	for (unsigned long i = 0; i < n_ops; i++) {
		enum op op = xrand(OP_NR);
		unsigned long idx = xrand(index_space);

		if (getenv("XA_TRACE")) { fprintf(stderr, "OP i=%lu op=%d idx=%lu\n", i, op, idx); fflush(stderr); }
		switch (op) {
		case OP_STORE: {
			void *v = xa_mk_value(xrand(1000));
			void *r1 = ref_xa_store(&xa_ref, idx, v, GFP_KERNEL);
			void *r2 = rs_xa_store(&xa_rs, idx, v, GFP_KERNEL);
			CHECK(entries_equal(r1, r2), "xa_store(%lu) old", idx);
			break;
		}
		case OP_ERASE: {
			void *r1 = ref_xa_erase(&xa_ref, idx);
			void *r2 = rs_xa_erase(&xa_rs, idx);
			CHECK(entries_equal(r1, r2), "xa_erase(%lu)", idx);
			break;
		}
		case OP_CMPXCHG: {
			void *old = xrand(2) ? NULL : xa_mk_value(xrand(1000));
			void *v = xa_mk_value(xrand(1000));
			void *r1 = ref___xa_cmpxchg(&xa_ref, idx, old, v, GFP_KERNEL);
			void *r2 = rs___xa_cmpxchg(&xa_rs, idx, old, v, GFP_KERNEL);
			CHECK(entries_equal(r1, r2), "xa_cmpxchg(%lu)", idx);
			break;
		}
		case OP_INSERT: {
			void *v = xa_mk_value(xrand(1000));
			if (getenv("XA_TRACE")) { fprintf(stderr, "  insert idx=%lu v=%p\n", idx, v); fflush(stderr); }
			int r1 = ref___xa_insert(&xa_ref, idx, v, GFP_KERNEL);
			int r2 = rs___xa_insert(&xa_rs, idx, v, GFP_KERNEL);
			CHECK(r1 == r2, "xa_insert(%lu) ret %d vs %d", idx, r1, r2);
			break;
		}
		case OP_STORE_RANGE: {
			unsigned long first = idx;
			unsigned long span = 1 + xrand(8);
			unsigned long last = first + span;
			void *v = xa_mk_value(xrand(1000));
			void *r1 = ref_xa_store_range(&xa_ref, first, last, v, GFP_KERNEL);
			void *r2 = rs_xa_store_range(&xa_rs, first, last, v, GFP_KERNEL);
			CHECK(entries_equal(r1, r2), "xa_store_range(%lu,%lu)", first, last);
			break;
		}
		case OP_SET_MARK: {
			xa_mark_t m = (xa_mark_t)xrand(3);
			ref___xa_set_mark(&xa_ref, idx, m);
			rs___xa_set_mark(&xa_rs, idx, m);
			break;
		}
		case OP_CLEAR_MARK: {
			xa_mark_t m = (xa_mark_t)xrand(3);
			if (getenv("XA_TRACE")) { fprintf(stderr, "  clear_mark idx=%lu m=%u\n", idx, (unsigned)m); fflush(stderr); }
			ref___xa_clear_mark(&xa_ref, idx, m);
			rs___xa_clear_mark(&xa_rs, idx, m);
			break;
		}
		default:
			break;
		}

		if (i % 200 == 0 || getenv("XA_TRACE"))
			full_invariant_check(&xa_ref, &xa_rs, index_space + 16, "plain");
	}

	full_invariant_check(&xa_ref, &xa_rs, index_space + 16, "plain-final");
	ref_xa_destroy(&xa_ref);
	rs_xa_destroy(&xa_rs);
}

/* Dedicated split coverage: store a multi-order entry, then split it
 * back down via a raw xas cursor on both arms. */
static void run_split(void)
{
	struct xarray xa_ref, xa_rs;
	unsigned int order;

	xa_init_flags(&xa_ref, 0);
	xa_init_flags(&xa_rs, 0);

	for (order = 1; order <= 6; order++) {
		unsigned long index = 0;
		void *v = xa_mk_value(42 + order);
		void *v2 = xa_mk_value(99 + order);

		{
			XA_STATE_ORDER(xas, &xa_ref, index, order);
			do {
				xas_lock(&xas);
				ref_xas_store(&xas, v);
				xas_unlock(&xas);
			} while (ref_xas_nomem(&xas, GFP_KERNEL));
		}
		{
			XA_STATE_ORDER(xas, &xa_rs, index, order);
			do {
				xas_lock(&xas);
				rs_xas_store(&xas, v);
				xas_unlock(&xas);
			} while (rs_xas_nomem(&xas, GFP_KERNEL));
		}

		CHECK(entries_equal(ref_xa_load(&xa_ref, index), rs_xa_load(&xa_rs, index)),
		      "split setup order %u", order);

		/* Split down to order-1: xas_set_order() gives the xa_state
		 * the NEW (post-split) granularity; xas_split_alloc()/
		 * xas_split() take the OLD order being split as their own
		 * argument. Same sequence real callers use (e.g.
		 * mm/huge_memory.c's split paths). */
		unsigned int new_order = order - 1;
		{
			XA_STATE(xas, &xa_ref, index);
			xas_set_order(&xas, index, new_order);
			ref_xas_split_alloc(&xas, v2, order, GFP_KERNEL);
			xas_lock(&xas);
			ref_xas_load(&xas);
			ref_xas_split(&xas, v2, order);
			xas_unlock(&xas);
		}
		{
			XA_STATE(xas, &xa_rs, index);
			xas_set_order(&xas, index, new_order);
			rs_xas_split_alloc(&xas, v2, order, GFP_KERNEL);
			xas_lock(&xas);
			rs_xas_load(&xas);
			rs_xas_split(&xas, v2, order);
			xas_unlock(&xas);
		}

		for (unsigned long i = 0; i <= (1UL << order); i++) {
			void *r1 = ref_xa_load(&xa_ref, i);
			void *r2 = rs_xa_load(&xa_rs, i);
			CHECK(entries_equal(r1, r2), "post-split order %u idx %lu", order, i);
		}

		ref_xa_destroy(&xa_ref);
		rs_xa_destroy(&xa_rs);
	}
}

static void run_alloc(unsigned long n_ops)
{
	struct xarray xa_ref, xa_rs;
	struct xa_limit limit = XA_LIMIT(0, 1000);

	xa_init_flags(&xa_ref, XA_FLAGS_ALLOC);
	xa_init_flags(&xa_rs, XA_FLAGS_ALLOC);

	for (unsigned long i = 0; i < n_ops; i++) {
		void *v = xa_mk_value(xrand(1000));
		u32 id_ref = 0xffffffff, id_rs = 0xffffffff;
		int r1 = ref___xa_alloc(&xa_ref, &id_ref, v, limit, GFP_KERNEL);
		int r2 = rs___xa_alloc(&xa_rs, &id_rs, v, limit, GFP_KERNEL);

		CHECK(r1 == r2, "xa_alloc ret %d vs %d", r1, r2);
		if (r1 == 0 && r2 == 0)
			CHECK(id_ref == id_rs, "xa_alloc id %u vs %u", id_ref, id_rs);

		if (xrand(4) == 0 && id_ref != 0xffffffff) {
			ref_xa_erase(&xa_ref, id_ref);
			rs_xa_erase(&xa_rs, id_rs);
		}

		if (i % 100 == 0)
			full_invariant_check(&xa_ref, &xa_rs, 1100, "alloc");
	}

	full_invariant_check(&xa_ref, &xa_rs, 1100, "alloc-final");
	ref_xa_destroy(&xa_ref);
	rs_xa_destroy(&xa_rs);
}

/* __xa_alloc_cyclic() had NO coverage at all until a reborrow-sweep
 * pass found a real bug in it directly by inspection (a `&mut Xarray`
 * held live across the function's own second __xa_alloc() call) --
 * this is what should have caught it first. A small limit (0-7) and
 * many ops per round make wraparound (ret==1, WRAPPED-flag clearing)
 * common rather than incidental. */
static void run_alloc_cyclic(unsigned long n_ops)
{
	struct xarray xa_ref, xa_rs;
	struct xa_limit limit = XA_LIMIT(0, 7);
	u32 next_ref = 0, next_rs = 0;

	xa_init_flags(&xa_ref, XA_FLAGS_ALLOC);
	xa_init_flags(&xa_rs, XA_FLAGS_ALLOC);

	for (unsigned long i = 0; i < n_ops; i++) {
		void *v = xa_mk_value(xrand(1000));
		u32 id_ref = 0xffffffff, id_rs = 0xffffffff;
		int r1 = ref___xa_alloc_cyclic(&xa_ref, &id_ref, v, limit, &next_ref, GFP_KERNEL);
		int r2 = rs___xa_alloc_cyclic(&xa_rs, &id_rs, v, limit, &next_rs, GFP_KERNEL);

		CHECK(r1 == r2, "xa_alloc_cyclic ret %d vs %d", r1, r2);
		if (r1 >= 0 && r2 >= 0) {
			CHECK(id_ref == id_rs, "xa_alloc_cyclic id %u vs %u", id_ref, id_rs);
			CHECK(next_ref == next_rs, "xa_alloc_cyclic next %u vs %u", next_ref, next_rs);
		}

		if (xrand(3) == 0 && id_ref != 0xffffffff) {
			ref_xa_erase(&xa_ref, id_ref);
			rs_xa_erase(&xa_rs, id_rs);
		}

		if (i % 50 == 0)
			full_invariant_check(&xa_ref, &xa_rs, 16, "alloc_cyclic");
	}

	full_invariant_check(&xa_ref, &xa_rs, 16, "alloc_cyclic-final");
	ref_xa_destroy(&xa_ref);
	rs_xa_destroy(&xa_rs);
}

/* Mirrors CONFIG_TEST_XARRAY's check_xas_erase(): fill a contiguous,
 * growing index range then walk+erase it with xas_find(), on both
 * arms. Reproduces the exact shape that found xas_move_index()'s `~
 * XA_CHUNK_MASK << shift` operator-precedence bug for real -- C's
 * unary `~` binds tighter than `<<`, so `(~XA_CHUNK_MASK) << shift` is
 * NOT `~(XA_CHUNK_MASK << shift)`; the two coincide at shift==0, which
 * is why run_plain()'s shallow, random-op trees never hit it. Needs a
 * tree deep enough that xas_find() crosses a node boundary at
 * shift>0, which needs a contiguous run past one node's span -- run_
 * plain()'s largest index_space (512) only reaches that by chance,
 * never through a guaranteed cross-boundary walk. */
static void run_erase_walk(unsigned int max_i)
{
	struct xarray xa_ref, xa_rs;

	xa_init_flags(&xa_ref, 0);
	xa_init_flags(&xa_rs, 0);

	for (unsigned int i = 0; i < max_i; i++) {
		for (unsigned long j = i; j < 2UL * i + 17; j++) {
			void *v = xa_mk_value(j);
			{
				XA_STATE(xas, &xa_ref, j);
				do {
					xas_lock(&xas);
					ref_xas_store(&xas, v);
					xas_unlock(&xas);
				} while (ref_xas_nomem(&xas, GFP_KERNEL));
			}
			{
				XA_STATE(xas, &xa_rs, j);
				do {
					xas_lock(&xas);
					rs_xas_store(&xas, v);
					xas_unlock(&xas);
				} while (rs_xas_nomem(&xas, GFP_KERNEL));
			}
		}

		{
			XA_STATE(xas_ref_s, &xa_ref, 0);
			XA_STATE(xas_rs_s, &xa_rs, 0);
			unsigned long j = i;
			void *e_ref = ref_xas_find(&xas_ref_s, ULONG_MAX);
			void *e_rs = rs_xas_find(&xas_rs_s, ULONG_MAX);
			while (e_ref || e_rs) {
				CHECK(entries_equal(e_ref, e_rs),
				      "erase_walk(i=%u) entry at j=%lu", i, j);
				ref_xas_store(&xas_ref_s, NULL);
				rs_xas_store(&xas_rs_s, NULL);
				j++;
				e_ref = ref_xas_find(&xas_ref_s, ULONG_MAX);
				e_rs = rs_xas_find(&xas_rs_s, ULONG_MAX);
			}
		}

		full_invariant_check(&xa_ref, &xa_rs, 2UL * i + 32, "erase_walk");
	}

	ref_xa_destroy(&xa_ref);
	rs_xa_destroy(&xa_rs);
}

/* xas_set_range()'s `((first+sibs+1)<<shift)-1` (CONFIG_XARRAY_MULTI-
 * only) has the same intentional-wraparound shape as max_index()/
 * xas_max(), reachable via xa_store_range() with a large enough span
 * that its own convergence loop grows shift into the ~58-66 range.
 * Found for real via a targeted scratch repro (main.c's own corpus
 * never drives xa_store_range() anywhere near this magnitude --
 * run_plain()'s OP_STORE_RANGE case caps span at 9). Deliberately
 * stops short of (first=0, last=ULONG_MAX) exactly: that exact input
 * makes xas_size() itself evaluate to 0 (16 << 60 doesn't fit in 64
 * bits, wraps to 0 in BOTH the C and this port identically), so
 * xa_store_range()'s own `first += xas_size(&xas)` never advances --
 * a real infinite loop in the pristine C too, not a divergence, and
 * not something any real caller does (no real xa_store_range() caller
 * spans anywhere near the full 64-bit index space). */
static void run_extreme_range(void)
{
	struct xarray xa_ref, xa_rs;

	xa_init_flags(&xa_ref, 0);
	xa_init_flags(&xa_rs, 0);

	unsigned long spans[] = { 1000000000000UL, ULONG_MAX - 1000, ULONG_MAX - 1 };
	for (unsigned int i = 0; i < sizeof(spans) / sizeof(spans[0]); i++) {
		void *v = xa_mk_value(i);
		void *r1 = ref_xa_store_range(&xa_ref, 0, spans[i], v, GFP_KERNEL);
		void *r2 = rs_xa_store_range(&xa_rs, 0, spans[i], v, GFP_KERNEL);
		CHECK(entries_equal(r1, r2), "extreme_range(0,%lu)", spans[i]);
		full_invariant_check(&xa_ref, &xa_rs, spans[i] > 4096 ? 4096 : spans[i] + 16, "extreme_range");
		ref_xa_destroy(&xa_ref);
		rs_xa_destroy(&xa_rs);
		xa_init_flags(&xa_ref, 0);
		xa_init_flags(&xa_rs, 0);
	}

	ref_xa_destroy(&xa_ref);
	rs_xa_destroy(&xa_rs);
}

/* Dedicated coverage for tree growth to the top of the address space.
 * run_plain()'s index_space never exceeds ~528, so no ordinary
 * differential round ever grows a node's shift far enough that
 * XA_CHUNK_SIZE << shift itself overflows -- exactly the case
 * xas_max()/max_index()'s "- 1" relies on wrapping (0 - 1 == the C's
 * ULONG_MAX "covers everything" sentinel) rather than panicking.
 * Found for real by CONFIG_TEST_XARRAY's check_xa_shrink(), which
 * stores at index 0 then ULONG_MAX; reproduced here with the same
 * shape. */
static void run_extreme(void)
{
	struct xarray xa_ref, xa_rs;

	xa_init_flags(&xa_ref, 0);
	xa_init_flags(&xa_rs, 0);

	void *v0 = xa_mk_value(0);
	void *v1 = xa_mk_value(1);
	CHECK(entries_equal(ref_xa_store(&xa_ref, 0, v0, GFP_KERNEL),
			     rs_xa_store(&xa_rs, 0, v0, GFP_KERNEL)),
	      "extreme: store(0)");
	CHECK(entries_equal(ref_xa_store(&xa_ref, ULONG_MAX, v1, GFP_KERNEL),
			     rs_xa_store(&xa_rs, ULONG_MAX, v1, GFP_KERNEL)),
	      "extreme: store(ULONG_MAX)");
	CHECK(entries_equal(ref_xa_load(&xa_ref, ULONG_MAX), rs_xa_load(&xa_rs, ULONG_MAX)),
	      "extreme: load(ULONG_MAX)");
	CHECK(entries_equal(ref_xa_load(&xa_ref, 0), rs_xa_load(&xa_rs, 0)),
	      "extreme: load(0)");
	full_invariant_check(&xa_ref, &xa_rs, 16, "extreme");

	ref_xa_erase(&xa_ref, ULONG_MAX);
	rs_xa_erase(&xa_rs, ULONG_MAX);
	ref_xa_erase(&xa_ref, 0);
	rs_xa_erase(&xa_rs, 0);
	full_invariant_check(&xa_ref, &xa_rs, 16, "extreme-final");

	ref_xa_destroy(&xa_ref);
	rs_xa_destroy(&xa_rs);
}

/* __xa_alloc_cyclic()'s `*next = *id + 1` relies on well-defined u32
 * wraparound when *id == UINT_MAX -- run_alloc_cyclic()'s small limit
 * (0-7) never reaches anywhere near there through ordinary
 * incrementing. Forces it directly, matching CONFIG_TEST_XARRAY's own
 * check_xa_alloc()'s explicit `next = UINT_MAX` wrap-around check,
 * which found this for real: a plain `*id + 1` panicked under this
 * kernel's overflow-checks instead of wrapping to 0. */
static void run_alloc_cyclic_wrap(void)
{
	struct xarray xa_ref, xa_rs;
	struct xa_limit limit = XA_LIMIT(0, UINT_MAX);
	u32 next_ref = UINT_MAX - 1, next_rs = UINT_MAX - 1;

	xa_init_flags(&xa_ref, XA_FLAGS_ALLOC);
	xa_init_flags(&xa_rs, XA_FLAGS_ALLOC);

	for (int i = 0; i < 4; i++) {
		void *v = xa_mk_value(i);
		u32 id_ref = 0xffffffff, id_rs = 0xffffffff;
		int r1 = ref___xa_alloc_cyclic(&xa_ref, &id_ref, v, limit, &next_ref, GFP_KERNEL);
		int r2 = rs___xa_alloc_cyclic(&xa_rs, &id_rs, v, limit, &next_rs, GFP_KERNEL);

		CHECK(r1 == r2, "alloc_cyclic_wrap ret %d vs %d", r1, r2);
		CHECK(id_ref == id_rs, "alloc_cyclic_wrap id %u vs %u", id_ref, id_rs);
		CHECK(next_ref == next_rs, "alloc_cyclic_wrap next %u vs %u", next_ref, next_rs);
	}

	full_invariant_check(&xa_ref, &xa_rs, 8, "alloc_cyclic_wrap");
	ref_xa_destroy(&xa_ref);
	rs_xa_destroy(&xa_rs);
}

int main(int argc, char **argv)
{
	unsigned long runs = argc > 1 ? strtoul(argv[1], NULL, 10) : 200;
	g_seed = argc > 2 ? (unsigned int)strtoul(argv[2], NULL, 10) : 20260906;

	signal(SIGALRM, on_alarm);
	alarm(30 + (unsigned int)(runs / 20));

	printf("xarray differential: %lu ops/round, seed %u, XA_CHUNK_SIZE=%d\n",
	       runs, g_seed, (int)XA_CHUNK_SIZE);

	run_plain(runs, 64);
	run_plain(runs, 512);
	run_extreme();
	run_erase_walk(60);
	run_split();
	run_alloc(runs / 4 + 10);
	run_alloc_cyclic(runs / 2 + 20);
	run_alloc_cyclic_wrap();
	run_extreme_range();

	printf("%u checks, %u mismatches\n", checks, failures);
	return failures ? 1 : 0;
}
