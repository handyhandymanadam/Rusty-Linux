/* radix tree differential: the same op stream drives pristine lib/radix-tree.c (ARM_REF) or radix-tree_glue.c over radix_tree_rs.rs (ARM_RS); plus the IDR half of pristine
 * lib/idr.c on top of each. Two radix trees (one with tags, GFP_NOWAIT roots exercise the preload path) and one IDR. Ops: insert / lookup / lookup_slot / delete / delete_item /
 * replace_slot / tag_set / tag_clear / tag_get / tagged / gang lookups (plain, tagged, tagged slots) / an iteration that deletes, replaces and clears tags / idr_alloc_u32 /
 * idr_alloc_cyclic / idr_remove / idr_find / idr_replace / idr_get_next / idr_for_each / idr_destroy / preload, with node-allocation failures injected. After every op the raw
 * tree structure (every node: shift, offset, count, nr_values, tag words, entries) is printed.  usage: t SHARD (env RT_N, RT_PROVE=1) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/bug.h>
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/bitops.h>
#include <linux/bitmap.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/xarray.h>

long fail_node, nodes_live, local_lock_depth; int warn_count;
#undef BUG_ON
#undef WARN_ON_ONCE
#define BUG_ON(c) do { if (c) { printf("BUG_ON(%s) line %d\n", #c, __LINE__); fflush(stdout); abort(); } } while (0)
#define WARN_ON_ONCE(c) ({ int __r = !!(c); if (__r) warn_count++; __r; })
#ifndef ERR_PTR
#define ERR_PTR(e) ((void *)(long)(e))
#define PTR_ERR(p) ((long)(p))
#define IS_ERR(p) ((unsigned long)(p) >= (unsigned long)-4095)
#endif
#ifndef container_of
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#endif
#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define __must_check

/* call_rcu(): queue; grace() runs the callbacks (a node freed by delete_node stays readable until then, like a reader holding it) */
static struct rcu_head *rcu_q[100000]; static int rcu_n;
void call_rcu(struct rcu_head *head, void (*func)(struct rcu_head *head)) { head->func = func; rcu_q[rcu_n++] = head; }
static void grace(void) { while (rcu_n) { struct rcu_head *h = rcu_q[--rcu_n]; h->func(h); } }

#include <linux/radix-tree.h>
#include <linux/idr.h>
#include SRC
#include IDRSRC

static unsigned long long rs_;
static unsigned rnd(unsigned n) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return n ? (unsigned)(rs_ >> 40) % n : 0; }
static unsigned long rnd_index(void)
{
	switch (rnd(12)) {
	case 0: return 0;
	case 1: return 63 + rnd(3);
	case 2: return 4095 + rnd(3);
	case 3: return 262143 + rnd(3);
	case 4: return ULONG_MAX - rnd(70);
	case 5: return (1UL << 40) + rnd(200);
	case 6: return (1UL << (6 * (1 + rnd(9)))) - 1 + rnd(3);
	case 7: case 8: return rnd(5000);
	default: return rnd(300);
	}
}
static void *mk_item(unsigned long v) { return rnd(4) ? (void *)(((v & 0xffffff) + 1) << 3) : xa_mk_value(v & 0xffff); }

static RADIX_TREE(tree0, GFP_KERNEL);
static RADIX_TREE(tree1, GFP_NOWAIT);
static RADIX_TREE(tree2, GFP_KERNEL);
static struct idr idr = { .idr_rt = RADIX_TREE_INIT(idr, IDR_RT_MARKER), .idr_base = 0, .idr_next = 0 };

static void dump_node(struct radix_tree_node *n, int depth)
{
	int i;
	printf("%*s[N shift=%u off=%u count=%u nv=%u tags=%lx.%lx.%lx]", depth, "", n->shift, n->offset, n->count, n->nr_values, n->tags[0][0], n->tags[1][0], n->tags[2][0]);
	for (i = 0; i < RADIX_TREE_MAP_SIZE; i++) {
		void *e = n->slots[i];
		if (!e) continue;
		if (xa_is_node(e)) { printf(" %d:node", i); }
		else if (e == XA_RETRY_ENTRY) printf(" %d:retry", i);
		else printf(" %d:%lx", i, (unsigned long)e);
	}
	printf("\n");
	for (i = 0; i < RADIX_TREE_MAP_SIZE; i++) {
		void *e = n->slots[i];
		if (e && xa_is_node(e) && n->shift) { struct radix_tree_node *c = (void *)((unsigned long)e & ~2UL); if (c->parent != n) printf("%*sBAD PARENT\n", depth, ""); dump_node(c, depth + 2); }
	}
}
static void dump_root(const char *name, struct radix_tree_root *r)
{
	void *h = r->xa_head;
	printf("  T %s flags=%x head=", name, (unsigned)r->xa_flags >> ROOT_TAG_SHIFT);
	if (xa_is_node(h)) { printf("node\n"); dump_node((void *)((unsigned long)h & ~2UL), 4); } else printf("%lx\n", (unsigned long)h);
}
static void state(void)
{
	dump_root("t0", &tree0); dump_root("t1", &tree1); dump_root("t2", &tree2); dump_root("idr", &idr.idr_rt);
	printf("  S warn=%d live=%ld lock=%ld idr_next=%u\n", warn_count, nodes_live, local_lock_depth, idr.idr_next);
}

static int idr_cb(int id, void *p, void *data) { long *sum = data; *sum += id * 7 + (long)((unsigned long)p & 0xff); return (id > 3000 && rnd(2)) ? 5 : 0; }

int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0; long n = getenv("RT_N") ? atol(getenv("RT_N")) : 2500; int prove = getenv("RT_PROVE") != NULL;
	unsigned long keys[2][512]; int nk[2] = {0, 0};
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1) + 12345;
	for (long s = 0; s < n; s++) {
		unsigned op = rnd(100); int t = rnd(2); struct radix_tree_root *r = t ? &tree1 : &tree0; unsigned long idx = (nk[t] && rnd(3)) ? keys[t][rnd(nk[t])] : rnd_index(); int err;
		if (!rnd(7)) fail_node = rnd(2) ? 1 + rnd(4) : -1;
		if (op < 22) {
			void *it = mk_item(idx ^ s); int pre = 0;
			if (t == 1 && rnd(2)) pre = radix_tree_preload(GFP_KERNEL) == 0;
			if (t == 1 && !pre && rnd(2)) pre = radix_tree_maybe_preload(GFP_NOWAIT) == 0;
			err = radix_tree_insert(r, idx, it);
			if (pre) local_unlock(&radix_tree_preloads.lock);
			printf("%ld insert t%d %lu %lx -> %d\n", s, t, idx, (unsigned long)it, err);
			if (!err && nk[t] < 512) keys[t][nk[t]++] = idx;
		} else if (op < 30) {
			void *e = radix_tree_lookup(r, idx); void **sl = radix_tree_lookup_slot(r, idx);
			printf("%ld lookup t%d %lu -> %lx slot=%d\n", s, t, idx, (unsigned long)e, sl ? (*sl == e) : -1);
		} else if (op < 38) {
			void *e = (rnd(2)) ? radix_tree_delete(r, idx) : radix_tree_delete_item(r, idx, rnd(2) ? radix_tree_lookup(r, idx) : mk_item(5));
			printf("%ld delete t%d %lu -> %lx\n", s, t, idx, (unsigned long)e);
		} else if (op < 44) {
			void **sl = radix_tree_lookup_slot(r, idx);
			if (sl && !xa_is_value(*sl)) { void *it = (void *)(((idx ^ s) + 1) << 3); radix_tree_replace_slot(r, sl, it); printf("%ld replace t%d %lu %lx\n", s, t, idx, (unsigned long)it); }
			else printf("%ld skip\n", s);
		} else if (op < 52) {
			unsigned tag = rnd(3);
			if (radix_tree_lookup(r, idx)) { void *e = radix_tree_tag_set(r, idx, tag); printf("%ld tag_set t%d %lu %u -> %lx\n", s, t, idx, tag, (unsigned long)e); } else printf("%ld skip\n", s);
		} else if (op < 58) {
			unsigned tag = rnd(3); void *e = radix_tree_tag_clear(r, idx, tag);
			printf("%ld tag_clear t%d %lu %u -> %lx\n", s, t, idx, tag, (unsigned long)e);
		} else if (op < 62) {
			unsigned tag = rnd(3);
			printf("%ld tag_get t%d %lu %u -> %d tagged=%d\n", s, t, idx, tag, radix_tree_tag_get(r, idx, tag), radix_tree_tagged(r, tag));
		} else if (op < 70) {
			void *res[40]; void **sl[40]; unsigned mx = rnd(45), c, i, tag = rnd(3); int k = rnd(3);
			if (mx > 40) mx = 40;
			c = k == 0 ? radix_tree_gang_lookup(r, res, idx, mx) : k == 1 ? radix_tree_gang_lookup_tag(r, res, idx, mx, tag) : radix_tree_gang_lookup_tag_slot(r, (void ***)sl, idx, mx, tag);
			printf("%ld gang%d t%d %lu %u -> %u:", s, k, t, idx, mx, c);
			for (i = 0; i < c; i++) printf(" %lx", k == 2 ? (unsigned long)*sl[i] : (unsigned long)res[i]);
			printf("\n");
		} else if (op < 76) {
			struct radix_tree_iter iter; void **slot; int cnt = 0; unsigned tag = rnd(3); int mode = rnd(4), tagged = rnd(2);
			if (tagged) { radix_tree_for_each_tagged(slot, r, &iter, idx, tag) { unsigned long v = (unsigned long)rcu_dereference_raw(*slot); if (radix_tree_is_internal_node((void *)v)) { slot = radix_tree_iter_retry(&iter); continue; }
					printf(" i%lu", iter.index);
					if (mode == 0) radix_tree_iter_tag_clear(r, &iter, tag);
					else if (mode == 1 && !xa_is_value((void *)v)) radix_tree_iter_replace(r, &iter, slot, (void *)(v + 8));
					else if (mode == 2) { radix_tree_iter_delete(r, &iter, slot); slot = radix_tree_iter_resume(slot, &iter); }
					if (++cnt >= 6) break; } }
			else { radix_tree_for_each_slot(slot, r, &iter, idx) { unsigned long v = (unsigned long)rcu_dereference_raw(*slot); if (!v) continue; if (radix_tree_is_internal_node((void *)v)) { slot = radix_tree_iter_retry(&iter); continue; }
					printf(" i%lu", iter.index);
					if (mode == 0) radix_tree_iter_tag_clear(r, &iter, tag);
					else if (mode == 1 && !xa_is_value((void *)v)) radix_tree_iter_replace(r, &iter, slot, (void *)(v + 8));
					else if (mode == 2) radix_tree_iter_delete(r, &iter, slot);
					if (++cnt >= 6) break; } }
			printf("\n%ld iter t%d %lu tagged=%d mode=%d visited=%d\n", s, t, idx, tagged, mode, cnt);
		} else if (op < 90) {
			switch (rnd(9)) {
			case 0: case 1: { u32 id = rnd(4) ? rnd(300) : rnd_index(); unsigned long max = rnd(3) ? INT_MAX : (rnd(3) ? id + rnd(500) : id + rnd(2)); void *p = rnd(5) ? mk_item(id) : NULL; unsigned base = idr.idr_base; err = idr_alloc_u32(&idr, p, &id, max, rnd(2) ? GFP_KERNEL : GFP_NOWAIT); printf("%ld idr_alloc_u32 max=%lu -> %d id=%u\n", s, max, err, id); (void)base; break; }
			case 2: { int start = rnd(2) ? 0 : rnd(100), end = rnd(2) ? 0 : start + 1 + rnd(200); void *p = mk_item(s); int id = idr_alloc_cyclic(&idr, p, start, end, GFP_KERNEL); printf("%ld idr_alloc_cyclic %d %d -> %d\n", s, start, end, id); break; }
			case 3: { unsigned long id = rnd(3) ? rnd(400) : rnd_index(); void *p = idr_remove(&idr, id); printf("%ld idr_remove %lu -> %lx\n", s, id, (unsigned long)p); break; }
			case 4: { unsigned long id = rnd(400); void *p = idr_find(&idr, id); printf("%ld idr_find %lu -> %lx\n", s, id, (unsigned long)p); break; }
			case 5: { unsigned long id = rnd(400); void *p = idr_replace(&idr, mk_item(id + 77), id); printf("%ld idr_replace %lu -> %lx\n", s, id, (unsigned long)p); break; }
			case 6: { int id = rnd(400); void *p = idr_get_next(&idr, &id); printf("%ld idr_get_next -> %lx id=%d\n", s, (unsigned long)p, id); break; }
			case 7: { int id = 0, cnt = 0; void *p; if (rnd(3)) break; while ((p = idr_get_next(&idr, &id)) || id < 70) { if (!p) { if (idr_find(&idr, id) == NULL && idr_replace(&idr, NULL, id) == NULL) { } } idr_remove(&idr, id); cnt++; id++; if (id > 5000) break; } printf("%ld idr_removeall %d\n", s, cnt); break; }
			default: { long sum = 0; int rc = idr_for_each(&idr, idr_cb, &sum); printf("%ld idr_for_each -> %d sum=%ld\n", s, rc, sum); break; }
			}
		} else if (op < 91) {
			if (rnd(3) == 0) { idr_destroy(&idr); idr.idr_next = 0; printf("%ld idr_destroy\n", s); }
			else { int i, c = 0; unsigned tg = rnd(3); for (i = 0; i < nk[t]; i++) if (rnd(2) && radix_tree_lookup(r, keys[t][i])) { radix_tree_tag_set(r, keys[t][i], tg); c++; } printf("%ld tagmany t%d %u -> %d\n", s, t, tg, c); }
		} else if (op < 95) {
			/* grow-shrink cycle on tree2 (always empty between cycles): low entries plus a far one at a random height (value or pointer at the bottom), random tags, then delete
			 * far-first or low-first, or leave a low entry behind so the tree shrinks to the root */
			unsigned lv = 1 + rnd(5); unsigned long far = 1UL << (6 * lv); void *lo = rnd(2) ? xa_mk_value(rnd(1000)) : mk_item(s); int tg = rnd(4), keep = rnd(3) == 0; unsigned k;
			err = radix_tree_insert(&tree2, 0, lo); err += radix_tree_insert(&tree2, far + rnd(3), mk_item(s + 1));
			for (k = 0; k < rnd(4); k++) radix_tree_insert(&tree2, 1 + rnd(2) * 64 + k, mk_item(s + 2 + k));
			if (tg == 1) { radix_tree_tag_set(&tree2, 0, rnd(3)); } else if (tg == 2 && radix_tree_lookup(&tree2, far)) { radix_tree_tag_set(&tree2, far, rnd(3)); }
			{ void *res[16]; int c = radix_tree_gang_lookup_tag(&tree2, res, 0, 16, rnd(3)); printf("%ld cycle tags=%d\n", s, c); dump_root("t2-full", &tree2); }
			if (rnd(3) == 0) { struct radix_tree_iter it; void **sl; printf("%ld iterdrain:", s); radix_tree_for_each_slot(sl, &tree2, &it, rnd(2) ? 0 : 1) { if (radix_tree_is_internal_node(*sl)) { sl = radix_tree_iter_retry(&it); continue; } printf(" %lu", it.index); radix_tree_iter_delete(&tree2, &it, sl); } printf("\n"); }
			if (rnd(2)) { radix_tree_delete(&tree2, far); radix_tree_delete(&tree2, far + 1); radix_tree_delete(&tree2, far + 2); if (!keep) radix_tree_delete(&tree2, 0); } else { if (!keep) radix_tree_delete(&tree2, 0); radix_tree_delete(&tree2, far); radix_tree_delete(&tree2, far + 1); radix_tree_delete(&tree2, far + 2); }
			for (k = 0; k < 130; k++) if (keep) { if (k) radix_tree_delete(&tree2, k); } else radix_tree_delete(&tree2, k);
			dump_root("t2-after-low", &tree2);
			if (keep) radix_tree_delete(&tree2, 0);
			printf("%ld cycle-end lv=%u -> %d\n", s, lv, err);
			if (rnd(3) == 0) {		/* a single entry in the root: tags on it, then gone */
				void *res[4]; unsigned tg2 = rnd(3); radix_tree_insert(&tree2, 0, mk_item(s)); if (rnd(2)) radix_tree_tag_set(&tree2, 0, tg2);
				printf("%ld single tagged=%d get=%d gang=%u clear=%lx\n", s, radix_tree_tagged(&tree2, tg2), radix_tree_tag_get(&tree2, 0, tg2), radix_tree_gang_lookup_tag(&tree2, res, 0, 4, tg2), (unsigned long)radix_tree_tag_clear(&tree2, 0, tg2));
				dump_root("t2-single", &tree2); radix_tree_delete(&tree2, 0);
			}
		} else if (op < 98) {
			/* IDR burst: fill consecutive ids (several nodes, then levels), then maybe remove a random subset or all of them */
			unsigned k = rnd(4) ? 20 + rnd(300) : (rnd(2) ? 64 : 4096), i; int first = -1, lastid = -1;
			for (i = 0; i < k; i++) { int id = idr_alloc(&idr, mk_item(i), (k >= 64 && (k & 63) == 0) ? 0 : (rnd(8) ? 0 : rnd(100)), (k >= 64 && (k & 63) == 0) ? 0 : (rnd(4) ? 0 : 400 + rnd(100)), GFP_KERNEL); if (id < 0) { lastid = id; break; } if (first < 0) first = id; lastid = id; }
			if (rnd(2)) { int id = 0, cnt = 0; void *p; while ((p = idr_get_next(&idr, &id))) { if (rnd(4) || id > 1) { if (rnd(3)) { idr_remove(&idr, id); cnt++; } } id++; } printf("%ld idr_burst-remove %d\n", s, cnt); }
			else printf("%ld idr_burst first=%d last=%d\n", s, first, lastid);
			if (rnd(3) == 0) { dump_root("idr-full", &idr.idr_rt); idr_destroy(&idr); idr.idr_next = 0; printf("%ld idr_burst-destroy\n", s); }
		} else {
			grace(); printf("%ld grace\n", s);
		}
		fail_node = 0;
		if (prove && s == 20) printf("  POISON\n");
		state();
	}
	grace();
	printf("final live=%ld\n", nodes_live);
	return 0;
}
