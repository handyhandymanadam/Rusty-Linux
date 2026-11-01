/* port/test/rhashtable/main.c -- differential driver for lib/rhashtable.c.
 * The same file is linked against the pristine C (ref) and against rhashtable_glue.c + rhashtable_rs.rs; each prints one digest per
 * case and the two outputs must be identical. Everything observable is folded into the digest: the result of every operation, the
 * walker's output (including -EAGAIN rewinds), the table size / nest / nelems after each step, every allocation the code makes (size and
 * gfp, and whether the shim failed it), the order the bucket chains hold the objects in, and the order free_and_destroy releases them.
 * Allocation failures are injected (non-blocking big allocations fail, so the nested-table path runs; random failures; every Nth).
 * Single-threaded: the lock primitives are real but nothing contends. The concurrent check is libstress (in the kernel).
 *   t <shard>      env RHT_N = cases per shard (default 120), RHT_PROVE=1 (Rust build only) poisons one result. */
#include <linux/rhashtable.h>
#include <linux/jhash.h>

int bug_count, warn_count;

/* ------------------------------------------------------------------ the shim runtime */
static u64 rng_state = 88172645463325252ULL;
static u32 rnd(void)
{
	rng_state ^= rng_state << 13; rng_state ^= rng_state >> 7; rng_state ^= rng_state << 17;
	return (u32)(rng_state >> 16);
}
static u32 rndn(u32 n) { return n ? rnd() % n : 0; }

static u64 dig = 0xcbf29ce484222325ULL;
static void mix(u64 v)
{
	for (int i = 0; i < 8; i++) { dig ^= (v >> (i * 8)) & 0xff; dig *= 0x100000001b3ULL; }
}

/* allocation registry + failure injection */
struct live { const void *p; size_t size; };
static struct live *live_tab; static size_t live_cap, live_n;
static size_t fail_big_nonblock;   /* non-blocking allocations of at least this many bytes fail (0 = off) */
static u32 fail_rand;              /* fail 1 in fail_rand allocations (0 = off) */
static u32 fail_every;             /* fail every Nth allocation (0 = off) */
static u64 alloc_n;
static int bad_free, nest_depth;

static void live_add(const void *p, size_t size)
{
	size_t h = ((uintptr_t)p >> 4) % live_cap;
	while (live_tab[h].p && live_tab[h].p != (void *)1) h = (h + 1) % live_cap;
	live_tab[h].p = p; live_tab[h].size = size; live_n++;
}
static bool live_del(const void *p)
{
	size_t h = ((uintptr_t)p >> 4) % live_cap;
	for (size_t i = 0; i < live_cap && live_tab[h].p; i++, h = (h + 1) % live_cap)
		if (live_tab[h].p == p) { live_tab[h].p = (void *)1; live_n--; return true; }
	return false;
}
static void live_reset(void)
{
	free(live_tab); live_cap = 1 << 18; live_tab = calloc(live_cap, sizeof(*live_tab)); live_n = 0;
}

static void *do_alloc(size_t size, gfp_t gfp, bool vm)
{
	alloc_n++;
	bool fail = false;
	if (!(gfp & __GFP_NOFAIL)) {
		if (fail_big_nonblock && !gfpflags_allow_blocking(gfp) && size >= fail_big_nonblock) fail = true;
		if (fail_rand && rndn(fail_rand) == 0) fail = true;
		if (fail_every && alloc_n % fail_every == 0) fail = true;
	}
	mix(size); mix(gfp); mix(!fail); mix(vm);
	if (fail) return NULL;
	void *p = (gfp & __GFP_ZERO) ? calloc(1, size ? size : 1) : malloc(size ? size : 1);
	if (!(gfp & __GFP_ZERO)) memset(p, 0xa5, size);
	live_add(p, size);
	return p;
}
void *kmalloc_noprof(size_t size, gfp_t gfp) { return do_alloc(size, gfp, false); }
void *kvmalloc_node_align_noprof(size_t size, size_t align, gfp_t gfp, int node) { (void)align; (void)node; return do_alloc(size, gfp, true); }
void kfree(const void *p)
{
	if (!p) return;
	if (!live_del(p)) { fprintf(stderr, "BAD FREE %p\n", p); bad_free++; return; }
	free((void *)p);
}
void kvfree(const void *p) { kfree(p); }
u32 get_random_u32(void) { return rnd() ^ 0x5bd1e995; }

/* RCU: callbacks queue until the driver drains them */
static struct rcu_head *rcu_q[1 << 16]; static unsigned rcu_nq;
void rcu_read_lock_(void) { nest_depth++; }
void rcu_read_unlock_(void) { nest_depth--; }
void call_rcu(struct rcu_head *head, rcu_callback_t func)
{
	head->func = func;
	if (rcu_nq == sizeof(rcu_q) / sizeof(rcu_q[0])) { fprintf(stderr, "rcu queue full\n"); abort(); }
	rcu_q[rcu_nq++] = head;
}
static void rcu_drain(void)
{
	/* callbacks run in order; a callback may not queue another; nothing is freed while a reader is inside rcu_read_lock() (a started walker) */
	if (nest_depth > 0) return;
	unsigned n = rcu_nq; rcu_nq = 0;
	mix(0x2c00 + n);
	for (unsigned i = 0; i < n; i++) { rcu_callback_t f = rcu_q[i]->func; f(rcu_q[i]); }
}
bool schedule_work_(struct work_struct *w) { bool was = w->pending; w->pending = 1; return !was; }
bool cancel_work_sync_(struct work_struct *w) { bool was = w->pending; w->pending = 0; return was; }

/* ------------------------------------------------------------------ test objects and parameter sets */
struct tobj {
	u32 key[3];
	u32 id;
	struct rhash_head node;
	struct rhlist_head lnode;
};
#define POOL 5000
static struct tobj pool[POOL];
static bool in_ht[POOL];
static unsigned ids_live;

static u32 obj_hash_k0(const void *data, u32 len, u32 seed)   /* obj_hashfn: only key[0], folded to 8 values so chains get long */
{
	const struct tobj *o = data;
	(void)len;
	return jhash_1word((o->key[0] & 7) * 0x9e3779b1u, seed);
}
static u32 key_hash_k0(const void *key, u32 len, u32 seed)    /* hashfn for the key side of P_D: must agree with obj_hash_k0 */
{
	const u32 *k = key;
	(void)len;
	return jhash_1word((k[0] & 7) * 0x9e3779b1u, seed);
}
static int obj_cmp_k0(struct rhashtable_compare_arg *arg, const void *obj)
{
	const u32 *k = arg->key; const struct tobj *o = obj;
	return o->key[0] != k[0];
}

#define PARAMS_P(name, klen, shrink, hfn, ohfn, ocmp, hoff) \
	static const struct rhashtable_params name = { .head_offset = hoff, .key_offset = offsetof(struct tobj, key), .key_len = klen, \
		.automatic_shrinking = shrink, .hashfn = hfn, .obj_hashfn = ohfn, .obj_cmpfn = ocmp }
PARAMS_P(P_A, 4, false, NULL, NULL, NULL, offsetof(struct tobj, node));
PARAMS_P(P_B, 12, true, NULL, NULL, NULL, offsetof(struct tobj, node));
PARAMS_P(P_C, 5, true, NULL, NULL, NULL, offsetof(struct tobj, node));
PARAMS_P(P_D, 4, true, key_hash_k0, obj_hash_k0, obj_cmp_k0, offsetof(struct tobj, node));
PARAMS_P(L_A, 4, true, NULL, NULL, NULL, offsetof(struct tobj, lnode));
PARAMS_P(L_B, 12, false, NULL, NULL, NULL, offsetof(struct tobj, lnode));

/* ------------------------------------------------------------------ per-case configuration */
struct cfg {
	u32 nops, keys, work_pct[3], drain_pct, walk_pct, remove_pct[3];
	u16 nelem_hint, min_size; u32 max_size;
	bool destroy_nofn, noins[3];
	u32 bound[2], pool, work_below;
};

static void settle(struct rhashtable *h)       /* run the deferred work until it stops asking for itself again (bounded) */
{
	for (int i = 0; i < 64 && h->run_work.pending; i++) {
		h->run_work.pending = 0;
		h->run_work.func(&h->run_work);
		rcu_drain();
	}
}

static void snapshot(struct rhashtable *h, bool rhl)
{
	struct bucket_table *t = rht_dereference_rcu(h->tbl, h);
	mix(atomic_read(&h->nelems)); mix(h->max_elems); mix(h->key_len);
	for (; t; t = rht_dereference_rcu(t->future_tbl, h)) {
		mix(t->size); mix(t->nest); mix(t->hash_rnd);
		for (unsigned i = 0; i < t->size; i++) {
			struct rhash_lock_head __rcu *const *bkt = rht_bucket(t, i);
			struct rhash_head *p;
			mix(0xb0b0);
			for (p = rht_ptr_rcu(bkt); !rht_is_a_nulls(p); p = rcu_dereference_all(p->next)) {
				struct tobj *o = rht_obj(h, p);
				mix(o->id);
				if (rhl) {
					struct rhlist_head *l;
					for (l = container_of(p, struct rhlist_head, rhead)->next; l; l = rcu_dereference(l->next))
						mix(container_of(l, struct tobj, lnode)->id);
				}
			}
		}
	}
}

/* the walker: one iterator driven by random steps */
struct walkst { struct rhashtable_iter it; int state; /* 0 none, 1 entered/stopped, 2 started */ };
static void walk_step(struct rhashtable *h, struct walkst *w, bool rhl)
{
	void *r;
	switch (w->state) {
	case 0: rhashtable_walk_enter(h, &w->it); w->state = 1; mix(0x10); break;
	case 1: mix(0x11 + rhashtable_walk_start_check(&w->it)); w->state = 2; break;
	case 2:
		switch (rndn(5)) {
		case 0: case 1: case 2:
			r = rhashtable_walk_next(&w->it);
			mix(IS_ERR(r) ? (u64)PTR_ERR(r) : r ? ((struct tobj *)r)->id : 0xdead);
			break;
		case 3:
			r = rhashtable_walk_peek(&w->it);
			mix(IS_ERR(r) ? (u64)PTR_ERR(r) : r ? ((struct tobj *)r)->id + 0x100000 : 0xdead);
			break;
		case 4: rhashtable_walk_stop(&w->it); w->state = 1; mix(0x12); break;
		}
		break;
	}
	(void)rhl;
}
static void walk_finish(struct walkst *w)
{
	if (w->state == 2) rhashtable_walk_stop(&w->it);
	if (w->state >= 1) rhashtable_walk_exit(&w->it);
	w->state = 0;
}

static u64 freed_n;
static void free_fn(void *ptr, void *arg) { mix(((struct tobj *)ptr)->id + (u64)(uintptr_t)arg); freed_n++; }

#ifdef ARM_RS
static int prove_poison;
#endif

/* The driver, once per parameter set (the header's inline functions take the params as a compile-time constant). */
#define DRIVER(NAME, PARAMS, RHL, LKINS) \
static void drive_##NAME(const struct cfg *c) \
{ \
	struct rhltable hlt; struct rhashtable ht; \
	struct rhashtable *h = (RHL) ? &hlt.ht : &ht; \
	struct rhashtable_params rp = PARAMS; \
	struct walkst w = { .state = 0 }; \
	rp.nelem_hint = c->nelem_hint; rp.min_size = c->min_size; rp.max_size = c->max_size; \
	int err = (RHL) ? rhltable_init(&hlt, &rp) : rhashtable_init(&ht, &rp); \
	mix(err); if (err) return; \
	memset(in_ht, 0, sizeof(in_ht)); \
	for (unsigned i = 0; i < POOL; i++) { pool[i].id = i + 1; pool[i].key[0] = 0; pool[i].key[1] = 0; pool[i].key[2] = 0; } \
	for (u32 op = 0; op < c->nops; op++) { \
		unsigned ph = op < c->bound[0] ? 0 : op < c->bound[1] ? 1 : 2; unsigned i = rndn(c->pool); struct tobj *o = &pool[i]; u32 r = rndn(100); \
		if (r < c->walk_pct) { walk_step(h, &w, RHL); } \
		else if (!in_ht[i] && !c->noins[ph]) { \
			o->key[0] = rndn(c->keys); o->key[1] = o->key[0] * 7; o->key[2] = 0; \
			int rc; \
			if (RHL) rc = rhltable_insert(&hlt, &o->lnode, PARAMS); \
			else if (!(LKINS) && (rnd() & 1)) { \
				void *ex = rhashtable_lookup_get_insert_key(&ht, o->key, &o->node, PARAMS); \
				rc = IS_ERR(ex) ? (int)PTR_ERR(ex) : ex ? -EEXIST : 0; \
			} else if (!(LKINS) || (rnd() & 1)) rc = rhashtable_insert_fast(&ht, &o->node, PARAMS); \
			else rc = rhashtable_lookup_insert_fast(&ht, &o->node, PARAMS); \
			mix(0x20 + rc); if (!rc) in_ht[i] = true; \
		} else if (in_ht[i] && r < c->walk_pct + c->remove_pct[ph]) { \
			int rc = (RHL) ? rhltable_remove(&hlt, &o->lnode, PARAMS) : rhashtable_remove_fast(&ht, &o->node, PARAMS); \
			mix(0x30 + rc); if (!rc) in_ht[i] = false; \
		} else { \
			u32 k[3] = { o->key[0], o->key[1], 0 }; u64 got = 0; \
			if (!in_ht[i]) { k[0] = rndn(c->keys); k[1] = k[0] * 7; } \
			if (RHL) { \
				struct rhlist_head *l, *p; \
				rcu_read_lock(); \
				l = rhltable_lookup(&hlt, k, PARAMS); \
				for (p = l; p; p = rcu_dereference(p->next)) got = got * 31 + container_of(p, struct tobj, lnode)->id; \
				rcu_read_unlock(); \
			} else { \
				struct tobj *f; \
				rcu_read_lock(); f = rhashtable_lookup_fast(&ht, k, PARAMS); got = f ? f->id : 0; rcu_read_unlock(); \
			} \
			PROVE_HOOK \
			mix(0x40 + got); \
		} \
		if (rndn(100) < c->work_pct[ph] && (!c->work_below || (u32)atomic_read(&h->nelems) < c->work_below)) { if (h->run_work.pending) { h->run_work.pending = 0; h->run_work.func(&h->run_work); } } \
		if (rndn(100) < c->drain_pct) rcu_drain(); \
		if ((op & 63) == 0) { mix(atomic_read(&h->nelems)); { struct bucket_table *t = rht_dereference_rcu(h->tbl, h); mix(t->size); mix(t->nest); mix(!!t->future_tbl); } } \
		if (nest_depth != (w.state == 2)) { fprintf(stderr, "RCU nest %d\n", nest_depth); nest_depth = w.state == 2; bug_count++; } \
	} \
	if (rnd() & 1) { settle(h); rcu_drain(); } \
	walk_finish(&w); \
	snapshot(h, RHL); \
	if (c->destroy_nofn) { rhashtable_destroy(h); } else { freed_n = 0; rhashtable_free_and_destroy(h, free_fn, (void *)0x1000); mix(freed_n); } \
	rcu_drain(); \
}

#ifdef ARM_RS
#define PROVE_HOOK if (getenv("RHT_PROVE") && !prove_poison++) got ^= 1;
#else
#define PROVE_HOOK
#endif

DRIVER(A, P_A, false, 1)
DRIVER(B, P_B, false, 1)
DRIVER(C, P_C, false, 1)
DRIVER(D, P_D, false, 0)
DRIVER(LA, L_A, true, 0)
DRIVER(LB, L_B, true, 0)

/* Nested tables of every depth, built by hand: the real code only makes one when a non-blocking allocation of a big table fails, and the
 * deeper levels need a table of 2^19+ buckets. A bucket table is made the way nested_bucket_table_alloc() makes it, the exported
 * rht_bucket_nested_insert() / __rht_bucket_nested() / rht_bucket_nested() are driven over random hashes, buckets are filled with marker
 * chains, and rhashtable_free_and_destroy() walks and frees the whole thing. */
static void nested_case(unsigned lg)
{
	struct rhashtable ht;
	struct rhashtable_params rp = P_A;
	size_t nb = (size_t)1 << lg;
	int e = rhashtable_init(&ht, &rp); mix(e);
	struct bucket_table *old = rht_dereference_rcu(ht.tbl, &ht);
	struct bucket_table *t = kmalloc_noprof(sizeof(*t) + sizeof(t->buckets[0]), GFP_KERNEL | __GFP_ZERO);
	unsigned shift = PAGE_SHIFT - 3;
	void *top = kmalloc_noprof(PAGE_SIZE, GFP_KERNEL | __GFP_ZERO);
	t->size = nb; t->nest = (ilog2(nb) - 1) % shift + 1; INIT_LIST_HEAD(&t->walkers);
	*(void **)&t->buckets[0] = top;
	mix(t->nest);
	static struct tobj objs[300];
	unsigned nobj = 0;
	for (unsigned i = 0; i < 300; i++) {
		unsigned hash = rnd() & (nb - 1);
		struct rhash_lock_head __rcu **b = rht_bucket_nested_insert(&ht, t, hash);
		mix(b != NULL);
		if (!b) continue;
		struct rhash_lock_head __rcu **b2 = __rht_bucket_nested(t, hash);
		mix(b == b2);
		if (*(void **)b == NULL && nobj < 300) {                    /* first fill: a one-entry chain, nulls-terminated like the real ones */
			struct tobj *o = &objs[nobj++]; o->id = 100000 + nobj;
			o->node.next = (struct rhash_head *)(NULLS_MARKER(0) | 0);
			*(void **)b = &o->node;
		}
	}
	for (unsigned i = 0; i < 400; i++) {
		unsigned hash = rnd() & (nb - 1);
		struct rhash_lock_head __rcu *const *b = rht_bucket_nested(t, hash);
		struct rhash_head *p = rht_ptr_rcu(b);
		mix(rht_is_a_nulls(p) ? 0 : ((struct tobj *)rht_obj(&ht, p))->id);
		mix(__rht_bucket_nested(t, hash) != NULL);
	}
	/* hand the table to the table: free_and_destroy releases the registered original first, then ours */
	rcu_assign_pointer(ht.tbl, t);
	rhashtable_free_and_destroy(&ht, lg <= 20 ? free_fn : NULL, (void *)0x2000);
	mix(freed_n);
	kvfree(old);
	rcu_drain();
}

/* init error paths (no table is built) */
static void init_errors(void)
{
	struct rhashtable ht;
	struct rhashtable_params bad1 = { .head_offset = 0, .key_len = 0 };
	struct rhashtable_params bad2 = { .key_len = 4, .obj_hashfn = obj_hash_k0 };
	struct rhashtable_params bad3 = { .key_len = 0, .obj_hashfn = obj_hash_k0, .obj_cmpfn = obj_cmp_k0 };
	mix(rhashtable_init(&ht, &bad1)); mix(rhashtable_init(&ht, &bad2));
	int e = rhashtable_init(&ht, &bad3); mix(e); if (!e) rhashtable_destroy(&ht);
	rcu_drain();
}

int main(int argc, char **argv)
{
	unsigned shard = argc > 1 ? (unsigned)atoi(argv[1]) : 0;
	unsigned ncase = getenv("RHT_N") ? (unsigned)atoi(getenv("RHT_N")) : 120;
	int bad_cases = 0;
	for (unsigned n = 0; n < ncase; n++) {
		rng_state = 0x9e3779b97f4a7c15ULL * (shard * 100000u + n + 1); for (int i = 0; i < 8; i++) rnd();
		dig = 0xcbf29ce484222325ULL; alloc_n = 0; bug_count = 0; bad_free = 0; nest_depth = 0; rcu_nq = 0;
		live_reset();
		struct cfg c;
		unsigned kind = n % 6;
		if (n % 4 == 3) kind = (unsigned[]){ 1, 2, 4 }[rndn(3)];   /* the "lag" cases need a hash that spreads and automatic shrinking */
		c.nops = 200 + rndn(3500);
		c.keys = (u32[]){ 4, 40, 400, 5000, 100000 }[rndn(5)];
		for (int ph = 0; ph < 3; ph++) c.work_pct[ph] = (u32[]){ 0, 0, 2, 10, 60, 100 }[rndn(6)];
		c.drain_pct = (u32[]){ 1, 10, 50, 100 }[rndn(4)];
		c.walk_pct = (u32[]){ 0, 5, 20, 40 }[rndn(4)];
		for (int ph = 0; ph < 3; ph++) c.remove_pct[ph] = (u32[]){ 5, 20, 45, 70, 90 }[rndn(5)];
		c.nelem_hint = rndn(3) ? 0 : (u16)rndn(3000);
		c.min_size = rndn(3) ? 0 : (u16)(1 + rndn(300));
		c.max_size = rndn(4) ? 0 : rndn(2) ? (1 + rndn(5000)) : ((1u << (2 + rndn(11))) + rndn(3) - 1);   /* 2^k-1, 2^k, 2^k+1 as well */
		c.destroy_nofn = rndn(4) == 0;
		c.pool = POOL; c.noins[0] = c.noins[1] = c.noins[2] = false; c.work_below = 0;
		if (rndn(3) == 0) { c.nops += 2500; c.remove_pct[0] = 5; c.walk_pct = (c.walk_pct > 5) ? 5 : c.walk_pct; }   /* a long growing phase */
		c.bound[0] = c.nops / 3; c.bound[1] = c.nops / 3 * 2;
		fail_big_nonblock = fail_rand = fail_every = 0;
		if (n % 4 == 3) {
			/* "lag": the worker grows the table to 512 buckets, stops, the inserts outrun it so the atomic growth to 1024 buckets fails and a
			 * 1-level nested table becomes the future table, then the table empties and the worker runs only once it is small (shrink on a
			 * table whose last table is nested, which is how rehash_one() meets a nested target) */
			c.nops = 2200; c.bound[0] = 350; c.bound[1] = 1000; c.pool = 1400; c.keys = 100000; c.nelem_hint = c.min_size = 0; c.max_size = 0;
			c.work_pct[0] = 100; c.work_pct[1] = 0; c.work_pct[2] = 100; c.work_below = 0;
			c.remove_pct[0] = 0; c.remove_pct[1] = 0; c.remove_pct[2] = 100; c.noins[2] = true; c.walk_pct = rndn(2) ? 0 : 5;
			if (rndn(2)) c.work_below = 290;
		}
		switch (rndn(6)) {
		case 0: fail_big_nonblock = 4097; break;
		case 1: fail_big_nonblock = 1024; break;
		case 2: fail_rand = 8 + rndn(40); break;
		case 3: fail_every = 3 + rndn(7); break;
		default: break;
		}
		if (n % 4 == 3) fail_big_nonblock = 4097;
		if (n == 0) init_errors();
		if (n < 8 && shard == 0) { static const unsigned lgs[] = { 10, 13, 18, 19, 20, 21, 22, 11 }; size_t fb = fail_big_nonblock; u32 fr = fail_rand, fe = fail_every; fail_big_nonblock = fail_rand = fail_every = 0; freed_n = 0; nested_case(lgs[n]); fail_big_nonblock = fb; fail_rand = fr; fail_every = fe; }
		mix(kind); mix(c.nops); mix(fail_big_nonblock); mix(fail_rand); mix(fail_every);
		switch (kind) {
		case 0: drive_A(&c); break;
		case 1: drive_B(&c); break;
		case 2: drive_C(&c); break;
		case 3: drive_D(&c); break;
		case 4: drive_LA(&c); break;
		case 5: drive_LB(&c); break;
		}
		mix(live_n);
		int bad = bug_count + bad_free + (live_n != 0);
		if (live_n) fprintf(stderr, "LEAK case %u: %zu allocations live\n", n, live_n);
		bad_cases += bad != 0;
		printf("%u.%u %016llx\n", shard, n, (unsigned long long)dig);
	}
	return bad_cases != 0;
}
