/* SELinux hashtab / symtab differential: the pristine hashtab.c and symtab.c (ARM_REF) against hashtab_rs.rs and symtab_rs.rs with the glue's wrappers (ARM_RS). Three int-keyed hash tables (driven through
 * the header's inline hashtab_insert / hashtab_search with test hash and compare functions) and three symbol tables take random operations: init with every size hint, insert, search, map with
 * a callback that stops after a few entries, duplicate through copy / destroy callbacks that fail on demand, destroy; allocation failures injected. Every result and the chains of the touched
 * tables are printed.   usage: t SHARD (env EB_N, EB_PROVE) */
#include "refshim.h"
#include "hashtab.h"
#include "symtab.h"
struct kmem_cache *hashtab_node_cachep; long fail_in, live, resched_count;
#include SRCFILE_H
#include SRCFILE_S
static unsigned long long rs_;
static unsigned long long rnd64(void) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return (rs_ >> 11) ^ (rs_ << 53); }
static unsigned rnd(unsigned n) { return n ? (unsigned)(rnd64() % n) : 0; }
static u32 ihash(const void *key) { return (u32)(uintptr_t)key * 2654435761u >> 7; }
static int icmp(const void *a, const void *b) { uintptr_t x = (uintptr_t)a, y = (uintptr_t)b; return x < y ? -1 : x > y; }
static const struct hashtab_key_params ikp = { .hash = ihash, .cmp = icmp };
#define K 3
static struct hashtab ht[K]; static struct symtab st[K];
static const char *names[] = { "a", "b", "ab", "ba", "object_r", "file", "dir", "lnk_file", "sock_file", "process", "read", "write", "getattr", "", "A", "z", "foo.bar", "foo.baz", "\xe9t\xe9", "\xff" };
static char dyn[16][8];
static void dumpht(int i)
{
	u32 s; struct hashtab_node *n;
	printf("  ht[%d] size=%u nel=%u", i, ht[i].size, ht[i].nel);
	for (s = 0; s < ht[i].size; s++) if (ht[i].htable[s]) { printf(" %u:", s); for (n = ht[i].htable[s]; n; n = n->next) printf("%lu/%lu,", (unsigned long)(uintptr_t)n->key, (unsigned long)(uintptr_t)n->datum); }
	printf("\n");
}
static void dumpst(int i)
{
	u32 s; struct hashtab_node *n;
	printf("  st[%d] size=%u nel=%u nprim=%u", i, st[i].table.size, st[i].table.nel, st[i].nprim);
	for (s = 0; s < st[i].table.size; s++) if (st[i].table.htable[s]) { printf(" %u:", s); for (n = st[i].table.htable[s]; n; n = n->next) printf("%s=%lu,", (char *)n->key, (unsigned long)(uintptr_t)n->datum); }
	printf("\n");
}
static int mapcount;
static int apply(void *k, void *d, void *args) { printf("    apply %lu %lu\n", (unsigned long)(uintptr_t)k, (unsigned long)(uintptr_t)d); return mapcount-- == 0 ? (rnd(2) ? 7 : 1) : 0; }
static int copycount;
static int copyf(struct hashtab_node *nw, const struct hashtab_node *o, void *args) { if (copycount-- == 0) return -5; nw->key = o->key; nw->datum = (void *)((uintptr_t)o->datum + 1000); return 0; }
static int destroyf(void *k, void *d, void *args) { printf("    destroy %lu %lu\n", (unsigned long)(uintptr_t)k, (unsigned long)(uintptr_t)d); return 0; }
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0, prove = getenv("EB_PROVE") != NULL; long n = getenv("EB_N") ? atol(getenv("EB_N")) : 80000, it, pc = 0; int i, j, rc, q;
	struct kmem_cache c; hashtab_node_cachep = &c;
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (q = 0; q < 16; q++) snprintf(dyn[q], 8, "%c%c%d", 'a' + rnd(3), 'a' + rnd(3), q % 3);
	for (i = 0; i < K; i++) { memset(&ht[i], 0, sizeof ht[i]); memset(&st[i], 0, sizeof st[i]); }
	for (it = 0; it < n; it++) {
		int op = rnd(100); static const u32 hints[] = { 0, 1, 2, 3, 4, 5, 7, 8, 9, 16, 100, 1000, 0x7fffffffu, 0x80000000u, 0x80000001u, 0xffffffffu, 5000000 };
		i = rnd(K); j = rnd(K); fail_in = rnd(12) == 0 ? 1 + rnd(3) : 0;
		if (op < 5) { u32 h = hints[rnd(17)]; if (ht[i].htable) hashtab_destroy(&ht[i]); memset(&ht[i], 0xab, sizeof ht[i]); rc = hashtab_init(&ht[i], h); printf("%ld hinit %d %u -> %d\n", it, i, h, rc); dumpht(i); }
		else if (op < 10) { u32 h = hints[rnd(17)]; if (st[i].table.htable) hashtab_destroy(&st[i].table); memset(&st[i], 0xab, sizeof st[i]); st[i].nprim = 77; rc = symtab_init(&st[i], h); printf("%ld sinit %d %u -> %d\n", it, i, h, rc); dumpst(i); }
		else if (op < 35) {
			uintptr_t k = 1 + rnd(40); if (!ht[i].size && rnd(2)) { if (ht[i].htable) hashtab_destroy(&ht[i]); hashtab_init(&ht[i], 1 + rnd(12)); }
			if (rnd(40) == 0) { u32 save = ht[i].nel; ht[i].nel = U32_MAX; rc = hashtab_insert(&ht[i], (void *)k, (void *)(k * 3), ikp); ht[i].nel = save; printf("%ld hinsert-full -> %d\n", it, rc); }
			rc = hashtab_insert(&ht[i], (void *)k, (void *)(k * 3), ikp); printf("%ld hinsert %d %lu -> %d\n", it, i, (unsigned long)k, rc); if (!rc || rc == -ENOMEM) dumpht(i);
		} else if (op < 45) {
			uintptr_t k = 1 + rnd(40); if (rnd(10) < 6 && ht[i].size) { u32 s0 = rnd(ht[i].size), t; for (t = 0; t < ht[i].size; t++) if (ht[i].htable[(s0 + t) % ht[i].size]) { k = (uintptr_t)ht[i].htable[(s0 + t) % ht[i].size]->key; break; } } void *r = hashtab_search(&ht[i], (void *)k, ikp); if (prove && pc++ == 3) r = (void *)((uintptr_t)r + 1);
			printf("%ld hsearch %d %lu -> %lu\n", it, i, (unsigned long)k, (unsigned long)(uintptr_t)r);
		} else if (op < 60) {
			const char *nm = rnd(4) ? names[rnd(20)] : dyn[rnd(16)];
			if (!st[i].table.size && rnd(2)) { if (st[i].table.htable) hashtab_destroy(&st[i].table); symtab_init(&st[i], 1 + rnd(12)); }
			if (rnd(40) == 0) { u32 save = st[i].table.nel; st[i].table.nel = U32_MAX; rc = symtab_insert(&st[i], (char *)nm, (void *)7); st[i].table.nel = save; printf("%ld sinsert-full -> %d\n", it, rc); }
			rc = symtab_insert(&st[i], (char *)nm, (void *)(uintptr_t)(10 + rnd(90))); printf("%ld sinsert %d \"%s\" -> %d resched=%ld\n", it, i, nm, rc, resched_count); if (!rc || rc == -ENOMEM) dumpst(i);
		} else if (op < 72) {
			const char *nm = rnd(4) ? names[rnd(20)] : dyn[rnd(16)];
			if (rnd(10) < 6 && st[i].table.size) { u32 s0 = rnd(st[i].table.size), t; for (t = 0; t < st[i].table.size; t++) if (st[i].table.htable[(s0 + t) % st[i].table.size]) { nm = (char *)st[i].table.htable[(s0 + t) % st[i].table.size]->key; break; } }
			void *r = symtab_search(&st[i], nm); printf("%ld ssearch %d \"%s\" -> %lu\n", it, i, nm, (unsigned long)(uintptr_t)r);
		} else if (op < 78) { mapcount = rnd(4) == 0 ? rnd(4) : 100000; if (ht[i].htable || !ht[i].size) { rc = hashtab_map(&ht[i], apply, NULL); printf("%ld map %d -> %d\n", it, i, rc); } }
		else if (op < 86) {
			if (i != j && (ht[i].htable || !ht[i].size)) {
				copycount = rnd(3) == 0 ? rnd(5) : 100000; if (ht[j].htable) hashtab_destroy(&ht[j]); memset(&ht[j], 0xab, sizeof ht[j]);
				rc = hashtab_duplicate(&ht[j], &ht[i], copyf, destroyf, NULL); printf("%ld dup %d %d -> %d\n", it, j, i, rc); dumpht(j);
			}
		} else if (op < 92) { if (ht[i].htable) { hashtab_destroy(&ht[i]); printf("%ld hdestroy %d htable=%d\n", it, i, ht[i].htable != NULL); memset(&ht[i], 0, sizeof ht[i]); } }
		else { if (st[i].table.htable) { hashtab_destroy(&st[i].table); printf("%ld sdestroy %d\n", it, i); memset(&st[i], 0, sizeof st[i]); } }
		fail_in = 0;
	}
	for (i = 0; i < K; i++) { if (ht[i].htable) hashtab_destroy(&ht[i]); if (st[i].table.htable) hashtab_destroy(&st[i].table); }
	printf("live at the end: %ld\n", live);
	return 0;
}
