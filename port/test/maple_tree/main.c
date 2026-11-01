/* SPDX-License-Identifier: GPL-2.0 */
/* lib/maple_tree.c: pristine C (c_*) vs the CONFIG_RUST=y code (maple_tree_rs.rs behind maple_tree_glue.c's thunks and helpers).
 * Each arm runs the SAME random sequence of operations and writes a transcript; the transcripts are compared line by line. Operations:
 * mtree_store_range / insert_range / erase / load, mt_find / mt_next / mt_prev, mtree_alloc_range / alloc_rrange / alloc_cyclic (on
 * allocation trees), the advanced API (mas_walk, mas_find*, mas_next / prev, mas_store_gfp, mas_erase, mas_empty_area*, mas_preallocate +
 * mas_store_prealloc), mtree_dup, RCU mode on and off, grace periods, tree destruction. After EVERY operation the transcript has: the
 * return value(s), the WARN count, the sequence of tracepoint calls, the sequence of allocation sizes, and a structural dump of the whole
 * tree (every node: type, parent encoding, pivots, slots, gaps, metadata) -- the node layout itself is part of the ABI. Allocation
 * failures are injected (the Nth allocation of an operation fails) to take every -ENOMEM path. At the end every tree is destroyed and
 * every allocation must be freed.
 * usage: main SHARD ; MT_N ; MT_PROVE_CAN_FAIL=1 */
#include "kshim.h"
#include <stdarg.h>
#include <linux/maple_tree.h>

/* ---- allocator, RCU, BUG, tracing ---- */
int ev_warn;
static int alloc_fail_at = -1, alloc_sticky, alloc_n, live;
static int should_fail(void) { int n = alloc_n++; return alloc_fail_at >= 0 && (n == alloc_fail_at || (alloc_sticky && n > alloc_fail_at)); }
static unsigned long alloc_log[1 << 16]; static int alloc_log_n;
static char trace_log[1 << 16]; static size_t trace_n;
void h_bug(void) { fprintf(stderr, "BUG() hit\n"); abort(); }
void h_trace(const char *kind, const char *fn, unsigned long a, void *v)
{
	if (!strncmp(fn, "c_", 2)) fn += 2;   /* the reference arm's exports are renamed c_<name> */
	if (trace_n < sizeof trace_log - 200) trace_n += snprintf(trace_log + trace_n, 200, "%s:%s:%lx:%lx;", kind, fn, a, (unsigned long)v);
}
#define TRK (1 << 22)
static void *trk[TRK]; static int trk_step[TRK]; static const char *trk_who[TRK]; static void *freedtab[TRK]; static int freed_step[TRK]; static const char *freed_who[TRK];
extern int cur_step, cur_arm, cur_cb_step;
static void *watch; static void trk_add(void *p) { if (watch == p) fprintf(stderr, "WATCH alloc %p step %d arm %d\n", p, cur_step, cur_arm); unsigned h = ((unsigned long)p >> 8) % TRK; while (trk[h]) h = (h + 1) % TRK; trk[h] = p; trk_step[h] = cur_step; }
static void trk_del(void *p, const char *who)
{
	if (watch == p) fprintf(stderr, "WATCH free %p by %s step %d arm %d\n", p, who, cur_step, cur_arm);
	unsigned h = ((unsigned long)p >> 8) % TRK;
	for (int i = 0; i < TRK; i++, h = (h + 1) % TRK) { if (trk[h] == p) { trk[h] = (void *)1; unsigned f = ((unsigned long)p >> 8) % TRK; while (freedtab[f] && freedtab[f] != p) f = (f + 1) % TRK; freedtab[f] = p; freed_step[f] = cur_step; freed_who[f] = who; return; } if (!trk[h]) break; }
	{ unsigned f = ((unsigned long)p >> 8) % TRK; while (freedtab[f] && freedtab[f] != p) f = (f + 1) % TRK; if (freedtab[f] == p) fprintf(stderr, "previously freed by %s at step %d\n", freed_who[f], freed_step[f]); }
	fprintf(stderr, "FREE OF NON-LIVE %p by %s at arm%d step %d (callback queued at step %d)\n", p, who, cur_arm, cur_step, cur_cb_step); abort();
}
static void log_alloc(size_t n) { if (alloc_log_n < (1 << 16)) alloc_log[alloc_log_n++] = n; }
static void *a256(void) { void *p = aligned_alloc(256, 256); memset(p, 0xA5, 256); trk_add(p); return p; }
struct kmem_cache { int dummy; };
static struct kmem_cache the_cache;
struct kmem_cache *kmem_cache_create(const char *name, unsigned int size, struct kmem_cache_args *args, unsigned int flags) { return &the_cache; }
void *kmem_cache_alloc(struct kmem_cache *c, gfp_t gfp)
{
	if (should_fail()) { log_alloc(~0UL); return NULL; }
	log_alloc(256); live++; return a256();
}
void kmem_cache_free_bulk(struct kmem_cache *c, size_t n, void **p) { for (size_t i = 0; i < n; i++) { live--; trk_del(p[i], "free_bulk"); free(p[i]); } }
struct slab_sheaf { unsigned int size; unsigned int cap; void *objects[64]; };
struct slab_sheaf *kmem_cache_prefill_sheaf(struct kmem_cache *c, gfp_t gfp, unsigned int size)
{
	if (should_fail()) { log_alloc(~0UL); return NULL; }
	log_alloc(1000 + size);
	struct slab_sheaf *s = calloc(1, sizeof *s);
	for (unsigned i = 0; i < size; i++) { s->objects[i] = a256(); live++; }
	s->size = size; s->cap = size; return s;
}
int kmem_cache_refill_sheaf(struct kmem_cache *c, gfp_t gfp, struct slab_sheaf **sp, unsigned int size)
{
	struct slab_sheaf *s = *sp;
	if (should_fail()) { log_alloc(~0UL); return -ENOMEM; }
	log_alloc(2000 + size);
	for (unsigned i = s->size; i < size; i++) { s->objects[i] = a256(); live++; }
	if (size > s->size) s->size = size;
	return 0;
}
void kmem_cache_return_sheaf(struct kmem_cache *c, gfp_t gfp, struct slab_sheaf *s)
{
	for (unsigned i = 0; i < s->size; i++) { live--; trk_del(s->objects[i], "return_sheaf"); free(s->objects[i]); }
	free(s);
}
void *kmem_cache_alloc_from_sheaf(struct kmem_cache *c, gfp_t gfp, struct slab_sheaf *s) { if (!s->size) h_bug(); return s->objects[--s->size]; }
unsigned int kmem_cache_sheaf_size(struct slab_sheaf *s) { return s->size; }
void h_kfree(void *p) { if (p) { live--; trk_del(p, "kfree"); free(p); } }
static struct rcu_head *rcu_q[1 << 16]; static void *rcu_obj[1 << 16]; static int rcu_n; static int rcu_step[1 << 16]; int cur_cb_step = -1; static unsigned char rcu_snap[1 << 16][256]; static int cur_cb_idx = -1;
void h_call_rcu(struct rcu_head *head, void (*func)(struct rcu_head *)) { head->func = func; rcu_obj[rcu_n] = NULL; rcu_step[rcu_n] = cur_step; memcpy(rcu_snap[rcu_n], (char *)head - 8, 256); rcu_q[rcu_n++] = head; }
int cur_step, cur_arm;
void h_kfree_rcu(void *obj, struct rcu_head *head)
{
	for (int i = 0; i < rcu_n; i++) if (rcu_obj[i] == obj) { fprintf(stderr, "DOUBLE QUEUED node %p arm%d step %d\n", obj, cur_arm, cur_step); abort(); }
	head->func = NULL; rcu_obj[rcu_n] = obj; rcu_q[rcu_n++] = head;
}
static void rcu_run(void)
{
	for (int i = 0; i < rcu_n; i++) { cur_cb_step = rcu_step[i]; cur_cb_idx = i; if (rcu_q[i]->func) { if (getenv("MT_VERBOSE") && memcmp(rcu_snap[i] + 24, (char *)rcu_q[i] - 8 + 24, 232)) { fprintf(stderr, "dead node %p modified between call_rcu (step %d) and its callback (step %d):", (char *)rcu_q[i] - 8, rcu_step[i], cur_step); for (int o = 24; o < 256; o++) if (rcu_snap[i][o] != ((unsigned char *)rcu_q[i])[o - 8]) fprintf(stderr, " +%d", o); fprintf(stderr, "\n"); } rcu_q[i]->func(rcu_q[i]); } else { live--; trk_del(rcu_obj[i], "kfree_rcu"); free(rcu_obj[i]); } }
	rcu_n = 0;
}

/* the two arms */
#define D(r, n, a) r c_##n a; r n a;
D(void *, mas_walk, (struct ma_state *)) D(int, mas_empty_area, (struct ma_state *, unsigned long, unsigned long, unsigned long))
D(int, mas_empty_area_rev, (struct ma_state *, unsigned long, unsigned long, unsigned long)) D(void *, mas_store, (struct ma_state *, void *))
D(int, mas_store_gfp, (struct ma_state *, void *, gfp_t)) D(void, mas_store_prealloc, (struct ma_state *, void *))
D(int, mas_preallocate, (struct ma_state *, void *, gfp_t)) D(void, mas_destroy, (struct ma_state *))
D(void *, mas_next, (struct ma_state *, unsigned long)) D(void *, mas_next_range, (struct ma_state *, unsigned long))
D(void *, mt_next, (struct maple_tree *, unsigned long, unsigned long)) D(void *, mas_prev, (struct ma_state *, unsigned long))
D(void *, mas_prev_range, (struct ma_state *, unsigned long)) D(void *, mt_prev, (struct maple_tree *, unsigned long, unsigned long))
D(void, mas_pause, (struct ma_state *)) D(void *, mas_find, (struct ma_state *, unsigned long)) D(void *, mas_find_range, (struct ma_state *, unsigned long))
D(void *, mas_find_rev, (struct ma_state *, unsigned long)) D(void *, mas_find_range_rev, (struct ma_state *, unsigned long))
D(void *, mas_erase, (struct ma_state *)) D(bool, mas_nomem, (struct ma_state *, gfp_t))
D(void *, mtree_load, (struct maple_tree *, unsigned long))
D(int, mtree_store_range, (struct maple_tree *, unsigned long, unsigned long, void *, gfp_t))
D(int, mtree_store, (struct maple_tree *, unsigned long, void *, gfp_t))
D(int, mtree_insert_range, (struct maple_tree *, unsigned long, unsigned long, void *, gfp_t))
D(int, mtree_insert, (struct maple_tree *, unsigned long, void *, gfp_t))
D(int, mtree_alloc_range, (struct maple_tree *, unsigned long *, void *, unsigned long, unsigned long, unsigned long, gfp_t))
D(int, mtree_alloc_rrange, (struct maple_tree *, unsigned long *, void *, unsigned long, unsigned long, unsigned long, gfp_t))
D(int, mtree_alloc_cyclic, (struct maple_tree *, unsigned long *, void *, unsigned long, unsigned long, unsigned long *, gfp_t))
D(int, mas_alloc_cyclic, (struct ma_state *, unsigned long *, void *, unsigned long, unsigned long, unsigned long *, gfp_t))
D(void *, mtree_erase, (struct maple_tree *, unsigned long)) D(int, __mt_dup, (struct maple_tree *, struct maple_tree *, gfp_t))
D(int, mtree_dup, (struct maple_tree *, struct maple_tree *, gfp_t)) D(void, __mt_destroy, (struct maple_tree *))
D(void, mtree_destroy, (struct maple_tree *)) D(void *, mt_find, (struct maple_tree *, unsigned long *, unsigned long))
D(void *, mt_find_after, (struct maple_tree *, unsigned long *, unsigned long)) D(void, maple_tree_init, (void))
#define CALL(rs, f, ...) ((rs) ? f(__VA_ARGS__) : c_##f(__VA_ARGS__))

static int poison; static unsigned long long fails, checks;
static unsigned long long st[16];
static unsigned long long count_str(const char *h, const char *n) { unsigned long long c = 0; for (const char *p = h; (p = strstr(p, n)); p += strlen(n)) c++; return c; }
#define FAIL(...) do { if (fails++ < 10) fprintf(stderr, __VA_ARGS__); } while (0)
static uint64_t mix(uint64_t z) { z += 0x9e3779b97f4a7c15ULL; z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL; z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL; return z ^ (z >> 31); }
static uint64_t rs_state;
static unsigned R(void) { return (unsigned)mix(rs_state += 1); }
static uint64_t R64(void) { return mix(rs_state += 1); }

/* ---- transcript ---- */
struct tx { char *p; size_t n, cap; };
static void tp(struct tx *t, const char *fmt, ...)
{
	va_list ap;
	if (t->n + 8192 > t->cap) { t->cap *= 2; t->p = realloc(t->p, t->cap); }
	va_start(ap, fmt); t->n += vsnprintf(t->p + t->n, 8192, fmt, ap); va_end(ap);
}
/* node access (same offsets as the kernel header) */
static unsigned char dm_end(struct maple_node *n, int t, unsigned long *pivots, unsigned long max)
{
	static const unsigned char mp[4] = { 0, 15, 15, 9 };
	if (!pivots) return 0;
	if (t == maple_arange_64) return n->ma64.meta.end;
	unsigned char off = mp[t] - 1;
	if (!pivots[off]) return n->mr64.meta.end;
	if (pivots[off] == max) return off;
	return mp[t];
}
static void dump_node(struct tx *b, void *enode, unsigned long min, unsigned long max, void *parent_node)
{
	static const unsigned char mp[4] = { 0, 15, 15, 9 };
	struct maple_node *n = (struct maple_node *)((unsigned long)enode & ~255UL);
	int t = ((unsigned long)enode >> 3) & 0xf;
	unsigned long *pivots = t == maple_arange_64 ? n->ma64.pivot : n->mr64.pivot;
	void **slots = t == maple_arange_64 ? (void **)n->ma64.slot : (void **)n->mr64.slot;
	unsigned char end = dm_end(n, t, pivots, max);
	unsigned long par = (unsigned long)n->parent;
	tp(b, "N%d(par%lx,%s,end%d", t, par & 0xff, (parent_node == NULL || (void *)(par & ~255UL) == parent_node || (par & 1)) ? "ok" : "BADPARENT", end);
	if (t == maple_arange_64) tp(b, ",mg%d", n->ma64.meta.gap);
	tp(b, ",[");
	for (int i = 0; i <= end && i < (t == maple_arange_64 ? 10 : 16); i++) {
		unsigned long pmin = i ? pivots[i - 1] + 1 : min;
		unsigned long pmax = i >= mp[t] ? max : pivots[i];
		tp(b, "%s%lx/", i ? "," : "", pmax);
		if (t == maple_arange_64) tp(b, "g%lx/", n->ma64.gap[i]);
		if (t >= maple_range_64) dump_node(b, slots[i], pmin, pmax, n);
		else tp(b, "%lx", (unsigned long)slots[i]);
	}
	tp(b, "])");
}
static void dump_tree(struct tx *b, struct maple_tree *mt)
{
	void *root = mt->ma_root;
	tp(b, " F%x R", mt->ma_flags);
	if (xa_is_node(root)) dump_node(b, (void *)((unsigned long)root & ~2UL), 0, ULONG_MAX, NULL);
	else tp(b, "%lx", (unsigned long)root);
}

static void *val(unsigned long id) { return (void *)((id << 1) | 1); }
#define NT 3
struct arm_state { struct maple_tree t[NT]; struct ma_state mas; };

static void new_tree(struct maple_tree *mt, int kind)
{
	memset(mt, 0, sizeof *mt);
	mt_init_flags(mt, kind == 1 ? MT_FLAGS_ALLOC_RANGE : 0);
}

static unsigned long rnd_index(int mode)
{
	switch (mode) {
	case 0: return R() % 64;
	case 1: return R() % 4096;
	case 2: return (uint64_t)R() * 17;
	case 3: return ULONG_MAX - R() % 256;
	default: return R64();
	}
}

static char *run_arm(int rs, uint64_t seed, int nsteps, int poison_step)
{
	int mega = nsteps > 15000;
	int dump_every = mega ? 1000 : nsteps > 5000 ? 200 : nsteps > 1000 ? 10 : 1;
	struct tx t = { malloc(1 << 20), 0, 1 << 20 };
	struct arm_state A;
	struct maple_tree *mt = &A.t[0];
	int kind, nid = 1, mode;
	unsigned long next_id = 0;
	rs_state = seed;
	memset(trk, 0, sizeof trk); memset(freedtab, 0, sizeof freedtab);
	alloc_n = 0; alloc_fail_at = -1; alloc_log_n = 0; trace_n = 0; trace_log[0] = 0; ev_warn = 0; live = 0; rcu_n = 0;
	kind = R() % 3 == 0;            /* 1 = allocation-range tree */
	mode = R() % 5;
	new_tree(&A.t[0], kind); new_tree(&A.t[1], kind); new_tree(&A.t[2], kind);
	for (int step = 0; step < nsteps; step++) {
		int op = R() % 100, fail = (R() % 6 == 0) ? (int)(R() % 3 == 0 ? R() % 40 : R() % 4) : -1, sticky = R() % 2, which = R() % 2;
		alloc_sticky = sticky;
		unsigned long i1 = rnd_index(mode), len = R() % 8 == 0 ? R() % 5000 : R() % 20, i2 = i1 + len;
		if (i2 < i1) i2 = ULONG_MAX;
		unsigned long idv = nid++;
		void *entry = R() % 5 == 0 ? NULL : val(idv);
		if (mega) { which = 0; if (op >= 60 && op < 90) op = op % 30; mode = 2 + (step / 4000) % 3; }   /* store-heavy, one big tree */
		int ret = 0; void *rp = NULL; unsigned long ul = 0;
		mt = &A.t[which];
		alloc_n = 0; alloc_log_n = 0; trace_n = 0; trace_log[0] = 0; ev_warn = 0; alloc_fail_at = fail;
		cur_step = step; cur_arm = rs;
		if (getenv("MT_VERBOSE")) { fprintf(stderr, "arm%d step %d/%d op%d which%d fail%d sticky%d mega%d\n", rs, step, nsteps, op, which, fail, sticky, mega); }
		tp(&t, "%d op%d w%d", step, op, which);
		if (op < 30) {          /* store_range */
			ret = CALL(rs, mtree_store_range, mt, i1, i2, entry, GFP_KERNEL);
		} else if (op < 40) {   /* insert_range */
			ret = CALL(rs, mtree_insert_range, mt, i1, i2, entry ? entry : val(idv), GFP_KERNEL);
		} else if (op < 48) {   /* erase */
			rp = CALL(rs, mtree_erase, mt, i1);
		} else if (op < 54) {   /* load */
			rp = CALL(rs, mtree_load, mt, i1);
		} else if (op < 58) {   /* find / next / prev */
			unsigned long idx = i1;
			switch (R() % 4) {
			case 0: rp = CALL(rs, mt_find, mt, &idx, ULONG_MAX); ul = idx; break;
			case 1: rp = CALL(rs, mt_find_after, mt, &idx, i2); ul = idx; break;
			case 2: rp = CALL(rs, mt_next, mt, i1, ULONG_MAX); break;
			default: rp = CALL(rs, mt_prev, mt, i1, 0); break;
			}
		} else if (op < 66) {   /* allocation interface */
			if (kind == 1) {
				unsigned long start = 0, size = 1 + R() % 40, lo = R() % 100, hi = lo + R() % 20000;
				switch (R() % 3) {
				case 0: ret = CALL(rs, mtree_alloc_range, mt, &start, val(idv), size, lo, hi, GFP_KERNEL); break;
				case 1: ret = CALL(rs, mtree_alloc_rrange, mt, &start, val(idv), size, lo, hi, GFP_KERNEL); break;
				default: ret = CALL(rs, mtree_alloc_cyclic, mt, &start, val(idv), lo, hi, &next_id, GFP_KERNEL); break;
				}
				ul = start;
			}
		} else if (op < 90) {   /* advanced API */
			MA_STATE(mas, mt, i1, i1);
			int sub = R() % 18;
			switch (sub) {
			case 0: rp = CALL(rs, mas_walk, &mas); ul = mas.index ^ (mas.last << 1) ^ ((unsigned long)mas.offset << 40) ^ ((unsigned long)mas.end << 48) ^ (mas.min * 3) ^ (mas.max * 5) ^ ((unsigned long)mas.status << 56); break;
			case 1: { unsigned n = 1 + R() % 6; mas_set(&mas, i1); rp = CALL(rs, mas_find, &mas, ULONG_MAX); while (--n) { void *e = CALL(rs, mas_find, &mas, ULONG_MAX); if (!e) break; ul += (unsigned long)e; } ul ^= mas.index + mas.last; break; }
			case 2: { unsigned n = 1 + R() % 6; mas_set(&mas, i1); rp = CALL(rs, mas_find_rev, &mas, 0); while (--n) { void *e = CALL(rs, mas_find_rev, &mas, 0); if (!e) break; ul += (unsigned long)e; } ul ^= mas.index + mas.last; break; }
			case 3: { unsigned n = 1 + R() % 6; mas_set(&mas, i1); rp = CALL(rs, mas_find_range, &mas, ULONG_MAX); while (--n) { void *e = CALL(rs, mas_next_range, &mas, ULONG_MAX); ul += (unsigned long)e ^ mas.index ^ mas.last; if (mas.status != ma_active && mas.status != ma_root) break; } break; }
			case 4: { unsigned n = 1 + R() % 6; mas_set(&mas, i1); rp = CALL(rs, mas_find_range_rev, &mas, 0); while (--n) { void *e = CALL(rs, mas_prev_range, &mas, 0); ul += (unsigned long)e ^ mas.index ^ mas.last; if (mas.status != ma_active && mas.status != ma_root) break; } break; }
			case 5: { rp = CALL(rs, mas_walk, &mas); void *e = CALL(rs, mas_next, &mas, ULONG_MAX); void *f = CALL(rs, mas_prev, &mas, 0); ul = (unsigned long)e ^ ((unsigned long)f << 1) ^ mas.index ^ mas.last; break; }
			case 6: mas_set_range(&mas, i1, i2); ret = CALL(rs, mas_store_gfp, &mas, entry, GFP_KERNEL); ul = mas.index ^ mas.last; break;
			case 7: mas_set(&mas, i1); rp = CALL(rs, mas_erase, &mas); ul = mas.index ^ mas.last; break;
			case 8: if (kind == 1) { mas_set(&mas, 0); { unsigned long a_ = R() % 50, b_ = R() % 30000 + 100, c_ = 1 + R() % 30; ret = CALL(rs, mas_empty_area, &mas, a_, b_, c_); } ul = mas.index ^ mas.last; } break;
			case 9: if (kind == 1) { mas_set(&mas, 0); { unsigned long a_ = R() % 50, b_ = R() % 30000 + 100, c_ = 1 + R() % 30; ret = CALL(rs, mas_empty_area_rev, &mas, a_, b_, c_); } ul = mas.index ^ mas.last; } break;
			case 10: mas_set_range(&mas, i1, i2); ret = CALL(rs, mas_preallocate, &mas, entry, GFP_KERNEL); if (!ret) { alloc_fail_at = -1; CALL(rs, mas_store_prealloc, &mas, entry); } else CALL(rs, mas_destroy, &mas); ul = mas.index ^ mas.last; break;
			case 12: { if (R() % 4 == 0) i1 = 0; unsigned long lim = R() % 4 == 0 ? i1 + R() % 3 : R() % 2 ? i2 : i1 + R() % 300; unsigned n = 1 + R() % 8; mas_set(&mas, i1); rp = CALL(rs, mas_find, &mas, lim); ul = mas.index ^ mas.last ^ mas.status;
				while (--n) { void *e = R() % 2 ? CALL(rs, mas_next, &mas, lim) : CALL(rs, mas_next_range, &mas, lim); ul = ul * 31 + ((unsigned long)e ^ mas.index ^ mas.last ^ mas.status); if (R() % 6 == 0) { CALL(rs, mas_pause, &mas); } } { void *e = CALL(rs, mas_next, &mas, mas.last); ul = ul * 31 + ((unsigned long)e ^ mas.index ^ mas.last ^ mas.status); e = CALL(rs, mas_next_range, &mas, mas.index); ul = ul * 31 + ((unsigned long)e ^ mas.index ^ mas.last ^ mas.status); } break; }
			case 13: { if (R() % 8 == 0) i1 = ULONG_MAX; unsigned long lim = R() % 4 == 0 ? i1 - R() % 3 : R() % 2 ? i2 : (i1 > 300 ? i1 - R() % 300 : R() % 3); unsigned n = 1 + R() % 8; mas_set(&mas, i1); rp = CALL(rs, mas_find_rev, &mas, lim); ul = mas.index ^ mas.last ^ mas.status;
				while (--n) { void *e = R() % 2 ? CALL(rs, mas_prev, &mas, lim) : CALL(rs, mas_prev_range, &mas, lim); ul = ul * 31 + ((unsigned long)e ^ mas.index ^ mas.last ^ mas.status); } { void *e = CALL(rs, mas_prev, &mas, mas.index); ul = ul * 31 + ((unsigned long)e ^ mas.index ^ mas.last ^ mas.status); e = CALL(rs, mas_prev_range, &mas, mas.last); ul = ul * 31 + ((unsigned long)e ^ mas.index ^ mas.last ^ mas.status); } break; }
			case 14: if (kind == 1) { unsigned long lo = R() % 3 ? 0 : R() % 200, hi = lo + R() % 30000 + 20; mas_set(&mas, lo + R() % (hi - lo + 1)); rp = CALL(rs, mas_walk, &mas); tp(&t, "[pre o%u e%u mn%lx mx%lx i%lx l%lx s%d] ", mas.offset, mas.end, mas.min, mas.max, mas.index, mas.last, mas.status); { unsigned long c_ = 1 + R() % 30; ret = CALL(rs, mas_empty_area, &mas, lo, hi, c_); } ul = mas.index ^ mas.last ^ mas.status ^ ((unsigned long)mas.offset << 40) ^ ((unsigned long)mas.end << 50); } break;
			case 15: if (kind == 1) { unsigned long lo = R() % 3 ? 0 : R() % 200, hi = lo + R() % 30000 + 20; mas_set(&mas, lo + R() % (hi - lo + 1)); rp = CALL(rs, mas_walk, &mas); tp(&t, "[pre o%u e%u mn%lx mx%lx i%lx l%lx s%d] ", mas.offset, mas.end, mas.min, mas.max, mas.index, mas.last, mas.status); { unsigned long c_ = 1 + R() % 30; ret = CALL(rs, mas_empty_area_rev, &mas, lo, hi, c_); } ul = mas.index ^ mas.last ^ mas.status ^ ((unsigned long)mas.offset << 40) ^ ((unsigned long)mas.end << 50); } break;
			case 16: { unsigned n = 1 + R() % 6; rp = CALL(rs, mas_walk, &mas); ul = mas.index ^ mas.last;   /* limits at the walked node's own bounds */
				while (n--) { unsigned long lim = R() % 3 == 0 ? mas.max : R() % 2 ? mas.last : mas.max - R() % 2; void *e = R() % 2 ? CALL(rs, mas_next, &mas, lim) : CALL(rs, mas_next_range, &mas, lim); ul = ul * 31 + ((unsigned long)e ^ mas.index ^ mas.last ^ mas.status); if (mas.status != ma_active && mas.status != ma_root) break; } break; }
			case 17: { unsigned n = 1 + R() % 6; rp = CALL(rs, mas_walk, &mas); ul = mas.index ^ mas.last;
				while (n--) { unsigned long lim = R() % 3 == 0 ? mas.min : R() % 2 ? mas.index : mas.min + R() % 2; void *e = R() % 2 ? CALL(rs, mas_prev, &mas, lim) : CALL(rs, mas_prev_range, &mas, lim); ul = ul * 31 + ((unsigned long)e ^ mas.index ^ mas.last ^ mas.status); if (mas.status != ma_active && mas.status != ma_root) break; } break; }
			default: { mas_set(&mas, i1); rp = CALL(rs, mas_walk, &mas); CALL(rs, mas_pause, &mas); void *e = CALL(rs, mas_find, &mas, ULONG_MAX); ul = (unsigned long)e ^ mas.index; break; }
			}
			CALL(rs, mas_destroy, &mas);
		} else if (op < 93) {   /* dup */
			struct maple_tree *dst = &A.t[(which + 1) % NT];
			struct maple_tree *dst2 = dst;
			(void)dst2;
			if (!dst->ma_root) {
				dst->ma_flags = mt->ma_flags & ~MT_FLAGS_HEIGHT_MASK;
				if (R() % 2) { alloc_fail_at = R() % 60; alloc_sticky = R() % 2; alloc_n = 0; } ret = CALL(rs, mtree_dup, mt, dst, GFP_KERNEL);
			}
		} else if (op < 95) {   /* rcu mode */
			if (R() % 2) mt_set_in_rcu(mt); else mt_clear_in_rcu(mt);
		} else if (op < 98) {   /* destroy */
			CALL(rs, mtree_destroy, mt);
			if (R() % 2) { new_tree(mt, kind); }
			if (R() % 3 == 0) { CALL(rs, mtree_store_range, mt, 0, R() % 3 == 0 ? 0 : R() % 5, val(idv), GFP_KERNEL); }
		} else {                /* grace period */
			rcu_run();
		}
		alloc_fail_at = -1;
		tp(&t, " i1=%lx i2=%lx ret%d rp%lx ul%lx warn%d tr:%s al:", i1, i2, ret, (unsigned long)rp, ul, ev_warn, trace_log);
		for (int i = 0; i < alloc_log_n; i++) tp(&t, "%ld,", (long)alloc_log[i]);
		if (poison_step == step) tp(&t, " POISON");
		tp(&t, " |");
		if (step % dump_every == 0 || step == nsteps - 1) for (int w = 0; w < NT; w++) { dump_tree(&t, &A.t[w]); tp(&t, ";"); }
		tp(&t, "\n");
		if (R() % 5 == 0) rcu_run();
	}
	rcu_run();
	for (int w = 0; w < NT; w++) if (A.t[w].ma_root) for (int k = 0; k < 48; k++) {   /* duplicate under a failure at every allocation index, sticky and single */
		struct maple_tree d; memset(&d, 0, sizeof d); d.ma_flags = A.t[w].ma_flags & ~MT_FLAGS_HEIGHT_MASK; d.ma_root = NULL;
		alloc_n = 0; alloc_log_n = 0; trace_n = 0; trace_log[0] = 0; alloc_fail_at = k / 2; alloc_sticky = k % 2; cur_step = nsteps + k;
		int r = CALL(rs, mtree_dup, &A.t[w], &d, GFP_KERNEL);
		alloc_fail_at = -1;
		tp(&t, "dupfail w%d k%d ret%d root%d live%d al%d |", w, k, r, d.ma_root != NULL, live, alloc_log_n);
		if (!r) { dump_tree(&t, &d); tp(&t, ";"); CALL(rs, mtree_destroy, &d); tp(&t, "\n"); if (k % 2 == 0) break; } else tp(&t, "\n");
		rcu_run();
	}
	for (int w = 0; w < NT; w++) CALL(rs, mtree_destroy, &A.t[w]);
	rcu_run();
	tp(&t, "\ndestroyed, live allocations %d\n", live);
	return t.p;
}

int main(int argc, char **argv)
{
	if (getenv("MT_WATCH")) watch = (void *)strtoul(getenv("MT_WATCH"), 0, 16);
	unsigned shard = argc > 1 ? atoi(argv[1]) : 0;
	poison = getenv("MT_PROVE_CAN_FAIL") != 0;
	long long n = getenv("MT_N") ? atoll(getenv("MT_N")) : 400;
	rs_state = 0x7654321ULL * (shard + 1);
	c_maple_tree_init(); maple_tree_init();
	for (long long it = 0; it < n; it++) {
		uint64_t seed = mix(rs_state += 7);
		int nsteps = (it % 25 == 24) ? 20000 + (int)(seed % 4000) : (it % 25 == 12) ? 8000 + (int)(seed % 3000) : (it % 6 == 5) ? 1200 + (int)(seed % 1500) : 30 + (int)(seed % 200);
		char *a = run_arm(0, seed, nsteps, -1), *b = run_arm(1, seed, nsteps, poison && it == 3 ? 5 : -1);
		checks++;
		st[0] += count_str(a, "\n"); st[1] += count_str(a, "mas_split"); st[2] += count_str(a, "mas_rebalance"); st[3] += count_str(a, "mas_wr_spanning_store"); st[4] += count_str(a, "mas_wr_node_store"); st[5] += count_str(a, "mas_wr_slot_store"); st[6] += count_str(a, "mas_wr_append"); st[7] += count_str(a, " ret-12"); st[8] += count_str(a, "N3("); st[9] += count_str(a, "N1("); st[10] += count_str(a, "N2("); st[11] += count_str(a, " F10 ") + count_str(a, " F11 ") + count_str(a, " F14 ") + count_str(a, " F15 ") + count_str(a, " F18 ") + count_str(a, " F19 "); st[12] += count_str(a, "mas_wr_bnode");
		if (strcmp(a, b)) {
			const char *pa = a, *pb = b; int line = 0;
			while (*pa && *pb) {
				const char *ea = strchr(pa, '\n'), *eb = strchr(pb, '\n');
				if (!ea || !eb || ea - pa != eb - pb || memcmp(pa, pb, ea - pa)) {
					FAIL("MISMATCH shard %u case %lld line %d\n  C   : %.1500s\n  Rust: %.1500s\n", shard, it, line, pa, pb);
					break;
				}
				pa = ea + 1; pb = eb + 1; line++;
			}
		}
		free(a); free(b);
	}
	if (getenv("MT_STATS")) printf("steps %llu, split %llu, rebalance %llu, spanning %llu, node_store %llu, slot_store %llu, append %llu, enomem %llu, arange-node dumps %llu, leaf dumps %llu, range dumps %llu, height>=4 dumps %llu, bnode %llu\n", st[0], st[1], st[2], st[3], st[4], st[5], st[6], st[7], st[8], st[9], st[10], st[11], st[12]);
	printf("shard %u: %llu cases, %llu failures\n", shard, checks, fails);
	return fails != 0;
}
