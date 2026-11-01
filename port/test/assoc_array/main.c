/* SPDX-License-Identifier: GPL-2.0 */
/* lib/assoc_array.c: pristine C (c_*) vs the CONFIG_RUST=y code (assoc_array_rs.rs, with assoc_array_glue.c's helpers).
 * Each arm runs the SAME random sequence of operations on its own array and writes a transcript; the transcripts are compared line by
 * line. Operations: insert (new key, replacement, cancelled, insert_set_object), delete (hit, miss, cancelled), clear, gc with a keep
 * predicate, find, iterate (also stopped early), destroy at the end. Keys are three 64-bit chunks from clustered families so that
 * shortcuts, node splits and collapses all happen. After EVERY operation the transcript has: the kind of edit returned, the find
 * result, the iterate order, the sequence of allocation sizes, a structural dump of the tree (node and shortcut shapes, parent slots,
 * per-branch leaf counts, back pointers, shortcut index keys) and nr_leaves_on_tree; at each RCU grace period, the ids of the objects
 * freed, in order. Allocation failures are injected (the Nth allocation of an operation fails) to take every "enomem" path. At the end
 * the array is destroyed and every allocation must have been freed.
 * usage: main SHARD ; AA_N ; AA_PROVE_CAN_FAIL=1 */
#include "kshim.h"
#include <stdarg.h>
#include <linux/assoc_array_priv.h>

/* ---- allocator, RCU, BUG ---- */
static int alloc_fail_at = -1, alloc_n, live;
static unsigned long alloc_log[1 << 16]; static int alloc_log_n;
static struct rcu_head *rcu_q[1 << 14]; static int rcu_n;
void h_bug(void) { fprintf(stderr, "BUG() hit\n"); abort(); }
static void *do_alloc(size_t n, int zero)
{
	if (alloc_n++ == alloc_fail_at) { if (alloc_log_n < (1 << 16)) alloc_log[alloc_log_n++] = ~0UL; return NULL; }
	if (alloc_log_n < (1 << 16)) alloc_log[alloc_log_n++] = n;
	live++;
	void *p = zero ? calloc(1, n) : malloc(n);
	if (!zero) memset(p, 0xA5, n);
	return p;
}
void *h_zalloc(size_t n) { return do_alloc(n, 1); }
void *h_malloc(size_t n) { return do_alloc(n, 0); }
void h_free(void *p) { if (p) { live--; free(p); } }
void h_call_rcu(struct rcu_head *head, void (*func)(struct rcu_head *)) { head->func = func; rcu_q[rcu_n++] = head; }
static void rcu_run(void) { for (int i = 0; i < rcu_n; i++) rcu_q[i]->func(rcu_q[i]); rcu_n = 0; }

/* ---- objects and ops ---- */
#define NCH 3
struct obj { u64 key[NCH + 1]; int id; int ref; };   /* ref: one per tree that holds it; gc's iterator takes one for the new tree */
static unsigned long get_key_chunk(const void *k, int level) { return ((const u64 *)k)[level / 64]; }
static unsigned long get_object_key_chunk(const void *o, int level) { return ((const struct obj *)o)->key[level / 64]; }
static bool compare_object(const void *o, const void *k) { return !memcmp(((const struct obj *)o)->key, k, NCH * 8); }
static int diff_objects(const void *o, const void *k)
{
	const u64 *a = ((const struct obj *)o)->key, *b = k;
	for (int i = 0; i < NCH; i++) if (a[i] != b[i]) return i * 64 + __builtin_ctzl(a[i] ^ b[i]);
	return -1;
}
static int freed[1 << 14]; static int freed_n;
static void free_object(void *o) { struct obj *ob = o; if (--ob->ref == 0) { if (freed_n < (1 << 14)) freed[freed_n++] = ob->id; free(o); } }
static const struct assoc_array_ops ops = { get_key_chunk, get_object_key_chunk, compare_object, diff_objects, free_object };

#define D(r, n, a) r c_##n a; r n a;
D(int, assoc_array_iterate, (const struct assoc_array *, int (*)(const void *, void *), void *))
D(void *, assoc_array_find, (const struct assoc_array *, const struct assoc_array_ops *, const void *))
D(void, assoc_array_destroy, (struct assoc_array *, const struct assoc_array_ops *))
D(struct assoc_array_edit *, assoc_array_insert, (struct assoc_array *, const struct assoc_array_ops *, const void *, void *))
D(void, assoc_array_insert_set_object, (struct assoc_array_edit *, void *))
D(struct assoc_array_edit *, assoc_array_delete, (struct assoc_array *, const struct assoc_array_ops *, const void *))
D(struct assoc_array_edit *, assoc_array_clear, (struct assoc_array *, const struct assoc_array_ops *))
D(void, assoc_array_apply_edit, (struct assoc_array_edit *))
D(void, assoc_array_cancel_edit, (struct assoc_array_edit *))
D(int, assoc_array_gc, (struct assoc_array *, const struct assoc_array_ops *, bool (*)(void *, void *), void *))
#define CALL(rs, f, ...) ((rs) ? f(__VA_ARGS__) : c_##f(__VA_ARGS__))

static int poison; static unsigned long long fails, checks, st_steps, st_enomem, st_short, st_gcnomem, st_repl, st_nodes_deep;
static unsigned long long count_str(const char *h, const char *n) { unsigned long long c = 0; for (const char *p = h; (p = strstr(p, n)); p += strlen(n)) c++; return c; }
#define FAIL(...) do { if (fails++ < 10) fprintf(stderr, __VA_ARGS__); } while (0)
static uint64_t mix(uint64_t z) { z += 0x9e3779b97f4a7c15ULL; z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL; z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL; return z ^ (z >> 31); }
static uint64_t rs_state;
static unsigned R(void) { return (unsigned)mix(rs_state += 1); }

/* ---- transcript ---- */
struct tx { char *p; size_t n, cap; };
static void tp(struct tx *t, const char *fmt, ...)
{
	va_list ap;
	if (t->n + 4096 > t->cap) { t->cap *= 2; t->p = realloc(t->p, t->cap); }
	va_start(ap, fmt); t->n += vsnprintf(t->p + t->n, 4096, fmt, ap); va_end(ap);
}
static void dump(struct tx *b, struct assoc_array_ptr *p, struct assoc_array_ptr *parent)
{
	if (!p) { tp(b, "-"); return; }
	if (assoc_array_ptr_is_leaf(p)) { tp(b, "L%d", ((struct obj *)assoc_array_ptr_to_leaf(p))->id); return; }
	if (assoc_array_ptr_is_shortcut(p)) {
		struct assoc_array_shortcut *s = assoc_array_ptr_to_shortcut(p);
		int keylen = round_up(s->skip_to_level, 64) / 64;
		tp(b, "S(ps%d,skip%d,%s,k", s->parent_slot, s->skip_to_level, s->back_pointer == parent ? "ok" : "BADBACK");
		for (int i = 0; i < keylen; i++) tp(b, ":%lx", s->index_key[i]);
		tp(b, ",");
		dump(b, s->next_node, p);
		tp(b, ")");
		return;
	}
	struct assoc_array_node *n = assoc_array_ptr_to_node(p);
	tp(b, "N(ps%d,nl%lu,%s[", n->parent_slot, n->nr_leaves_on_branch, n->back_pointer == parent ? "ok" : "BADBACK");
	for (int i = 0; i < ASSOC_ARRAY_FAN_OUT; i++) { dump(b, n->slots[i], p); if (i != ASSOC_ARRAY_FAN_OUT - 1) tp(b, ","); }
	tp(b, "])");
}
/* gc's out-of-memory cleanup walks the half-built copy; if a shortcut was duplicated before the failure its next_node still points into
 * the OLD tree and destroy_subtree()'s BUG_ON fires in the C itself (found by this harness, kept faithfully in the port, see
 * logs/hooks.md): so no allocation failure is injected into gc while the tree holds a shortcut. */
static int has_shortcut(struct assoc_array_ptr *p)
{
	if (!p || assoc_array_ptr_is_leaf(p)) return 0;
	if (assoc_array_ptr_is_shortcut(p)) return 1;
	struct assoc_array_node *n = assoc_array_ptr_to_node(p);
	for (int i = 0; i < ASSOC_ARRAY_FAN_OUT; i++) if (has_shortcut(n->slots[i])) return 1;
	return 0;
}
static int iter_cb(const void *o, void *d) { int **q = d; *(*q)++ = ((const struct obj *)o)->id; return 0; }
static int iter_stop_cb(const void *o, void *d) { int *cnt = d; return --(*cnt) <= 0 ? 7 : 0; }
static bool keep_cb(void *o, void *d) { if (((struct obj *)o)->id % (long)d == 0) return false; ((struct obj *)o)->ref++; return true; }

static u64 case_base[NCH]; static int case_cluster;
static void new_case_keys(void)
{
	/* every key of a case = base with a few bits flipped at or above `cluster`: the lower bits are shared, so shortcuts form */
	for (int i = 0; i < NCH; i++) case_base[i] = ((uint64_t)R() << 32) | R();
	int mode = R() % 4;
	case_cluster = mode == 0 ? 0 : mode == 1 ? 8 + R() % 60 : mode == 2 ? 64 + R() % 100 : 100 + R() % 90;
}
static void make_key(u64 *k)
{
	memcpy(k, case_base, sizeof case_base);
	int flips = 1 + R() % 4;
	for (int j = 0; j < flips; j++) {
		int span = NCH * 64 - case_cluster;
		int bit = case_cluster + (R() % 3 == 0 ? (int)(R() % span) : (int)((R() % 24) * 4 % span + R() % 2));
		if (bit >= NCH * 64) bit = NCH * 64 - 1;
		k[bit / 64] ^= 1ULL << (bit % 64);
	}
	k[NCH] = 0;
}
static struct obj *new_obj(const u64 *k, int id) { struct obj *o = calloc(1, sizeof *o); memcpy(o->key, k, sizeof o->key); o->id = id; o->ref = 1; return o; }
static void finish_edit(int rs, struct assoc_array_edit *e, int how)
{
	if (!e || IS_ERR(e)) return;
	if (how) CALL(rs, assoc_array_cancel_edit, e); else CALL(rs, assoc_array_apply_edit, e);
}
static void flush_rcu(struct tx *t)
{
	freed_n = 0; rcu_run();
	tp(t, " freed:");
	for (int i = 0; i < freed_n; i++) tp(t, "%d,", freed[i]);
}

/* one arm: returns the transcript */
static char *run_arm(int rs, uint64_t seed, int nsteps, int poison_step)
{
	struct tx t = { malloc(1 << 20), 0, 1 << 20 };
	struct assoc_array arr = { NULL, 0 };
	int nid = 1;
	rs_state = seed;
	new_case_keys();
	alloc_n = 0; alloc_fail_at = -1; alloc_log_n = 0; freed_n = 0; live = 0; rcu_n = 0;
	for (int step = 0; step < nsteps; step++) {
		int op = R() % 100, fail = (R() % 12 == 0) ? (int)(1 + R() % 6) : -1, how = R() % 10 == 0, setobj = R() % 8 == 0;
		long keep_mod = 2 + R() % 3;
		int stop_after = 1 + R() % 5;
		u64 key[NCH + 1]; make_key(key);
		int ptrclass = 0, found = -2, rc = 0, itn = 0, itl[4096];
		if (op >= 84 && op < 92 && has_shortcut(arr.root)) fail = -1;
		alloc_n = 0; alloc_log_n = 0; alloc_fail_at = fail;
		tp(&t, "%d op%d", step, op);
		if (op < 45) {            /* insert */
			struct obj *o = new_obj(key, nid), *o2 = setobj ? new_obj(key, nid + 1000) : NULL;
			struct assoc_array_edit *e = CALL(rs, assoc_array_insert, &arr, &ops, key, o);
			ptrclass = IS_ERR(e) ? 2 : e ? 1 : 0;
			if (!IS_ERR(e) && e) {
				if (o2) CALL(rs, assoc_array_insert_set_object, e, o2);
				finish_edit(rs, e, how);
				if (how) { free(o); free(o2); } else if (o2) free(o);   /* the leaf is o2 when set; o is then unused */
			} else { free(o); free(o2); }
		} else if (op < 70) {     /* delete */
			struct assoc_array_edit *e = CALL(rs, assoc_array_delete, &arr, &ops, key);
			ptrclass = IS_ERR(e) ? 2 : e ? 1 : 0;
			finish_edit(rs, e, how);
		} else if (op < 78) {     /* find */
			void *o = CALL(rs, assoc_array_find, &arr, &ops, key);
			found = o ? ((struct obj *)o)->id : -1;
		} else if (op < 84) {     /* iterate */
			int *q = itl, cnt = stop_after;
			rc = CALL(rs, assoc_array_iterate, &arr, iter_cb, &q);
			itn = q - itl;
			rc += 100 * CALL(rs, assoc_array_iterate, &arr, iter_stop_cb, &cnt);
		} else if (op < 92) {     /* gc */
			rc = CALL(rs, assoc_array_gc, &arr, &ops, keep_cb, (void *)keep_mod);
		} else if (op < 95) {     /* clear */
			struct assoc_array_edit *e = CALL(rs, assoc_array_clear, &arr, &ops);
			ptrclass = IS_ERR(e) ? 2 : e ? 1 : 0;
			finish_edit(rs, e, how);
		}
		alloc_fail_at = -1;
		tp(&t, " class%d find%d rc%d it%d:", ptrclass, found, rc, itn);
		for (int i = 0; i < itn; i++) tp(&t, "%d,", itl[i]);
		tp(&t, " alloc:");
		for (int i = 0; i < alloc_log_n; i++) tp(&t, "%ld,", (long)alloc_log[i]);
		if (op >= 95 || R() % 4 == 0) flush_rcu(&t);
		if (poison_step == step) tp(&t, " POISON");
		tp(&t, " n=%lu ", arr.nr_leaves_on_tree);
		dump(&t, arr.root, NULL);
		tp(&t, "\n");
		nid++;
	}
	flush_rcu(&t);
	CALL(rs, assoc_array_destroy, &arr, &ops);
	tp(&t, "\ndestroyed, live allocations %d\n", live);
	return t.p;
}

int main(int argc, char **argv)
{
	unsigned shard = argc > 1 ? atoi(argv[1]) : 0;
	poison = getenv("AA_PROVE_CAN_FAIL") != 0;
	long long n = getenv("AA_N") ? atoll(getenv("AA_N")) : 2000;
	rs_state = 0x7654321ULL * (shard + 1);
	for (long long it = 0; it < n; it++) {
		uint64_t seed = mix(rs_state += 7);
		int nsteps = 20 + (int)(seed % 140);
		char *a = run_arm(0, seed, nsteps, -1), *b = run_arm(1, seed, nsteps, poison && it == 3 ? 5 : -1);
		checks++;
		st_steps += count_str(a, "\n"); st_enomem += count_str(a, " class2"); st_short += count_str(a, "S("); st_gcnomem += count_str(a, " rc-12"); st_repl += count_str(a, " freed:1") + count_str(a, " freed:2"); st_nodes_deep += count_str(a, "skip1");
		if (strcmp(a, b)) {
			const char *pa = a, *pb = b;
			int line = 0;
			while (*pa && *pb) {
				const char *ea = strchr(pa, '\n'), *eb = strchr(pb, '\n');
				if (!ea || !eb || ea - pa != eb - pb || memcmp(pa, pb, ea - pa)) {
					FAIL("MISMATCH shard %u case %lld line %d\n  C   : %.600s\n  Rust: %.600s\n", shard, it, line, pa, pb);
					break;
				}
				pa = ea + 1; pb = eb + 1; line++;
			}
		}
		free(a); free(b);
	}
	if (getenv("AA_STATS")) printf("steps %llu, insert/delete/clear ENOMEM %llu, gc ENOMEM %llu, shortcut occurrences %llu (skip1xx: %llu), step lines with frees %llu\n", st_steps, st_enomem, st_gcnomem, st_short, st_nodes_deep, st_repl);
	printf("shard %u: %llu cases, %llu failures\n", shard, checks, fails);
	return fails != 0;
}
