/* SELinux avtab differential: the pristine table functions (ARM_REF) against avtab_rs.rs with the glue's wrappers (ARM_RS). A pool of three tables takes random operations: alloc with every
 * size class, non-unique insert of keys from a small domain (so chains, ordering and equal keys happen), search and search-next, destroy, alloc_dup, write into buffers of every size,
 * read of what was written (mutated or truncated), and crafted streams in the old (< version 20) and new formats that reach every error message, through avtab_read and through
 * avtab_read_item with a callback that records and sometimes fails; allocation failures injected. Every result and the whole contents of the touched tables are printed.   usage: t SHARD */
#include "refshim.h"
#include "avtab.h"
#include "policydb.h"
struct kmem_cache *avtab_node_cachep, *avtab_xperms_cachep; long fail_in, live_nodes, allocs;
#include SRCFILE
static unsigned long long rs_;
static unsigned long long rnd64(void) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return (rs_ >> 11) ^ (rs_ << 53); }
static unsigned rnd(unsigned n) { return n ? (unsigned)(rnd64() % n) : 0; }
#define K 3
static struct avtab pool[K];
static struct policydb pols[8], *curpol = &pols[0];
#define pol (*curpol)
static void scrubinit(int i) { avtab_destroy(&pool[i]); pool[i].htable = (struct avtab_node **)0x10; pool[i].nel = 0xdead; pool[i].nslot = 0xbeef; pool[i].mask = 0x1234; avtab_init(&pool[i]); }
static unsigned char lastbuf[1 << 16]; static size_t lastlen;
static void dump(int i)
{
	u32 s; struct avtab_node *n;
	printf("  [%d] nel=%u nslot=%u mask=%u", i, pool[i].nel, pool[i].nslot, pool[i].mask);
	for (s = 0; s < pool[i].nslot; s++) for (n = pool[i].htable[s]; n; n = n->next) {
		printf(" (%u:%u,%u,%u,%x", s, n->key.source_type, n->key.target_type, n->key.target_class, n->key.specified);
		if (n->key.specified & AVTAB_XPERMS) { int q; printf(" x%u/%u", n->datum.u.xperms->specified, n->datum.u.xperms->driver); for (q = 0; q < 8; q++) printf(".%x", n->datum.u.xperms->perms.p[q]); }
		else printf(" %x", n->datum.u.data);
		printf(")");
	}
	printf("\n");
}
static u16 pickspec(void)
{
	static const u16 sp[] = { AVTAB_ALLOWED, AVTAB_AUDITALLOW, AVTAB_AUDITDENY, AVTAB_TRANSITION, AVTAB_MEMBER, AVTAB_CHANGE, AVTAB_XPERMS_ALLOWED, AVTAB_XPERMS_AUDITALLOW, AVTAB_XPERMS_DONTAUDIT };
	u16 v = sp[rnd(9)];
	if (rnd(5) == 0) v |= AVTAB_ENABLED;
	if (rnd(30) == 0) v |= sp[rnd(9)];
	return v;
}
static void pickkey(struct avtab_key *k)
{
	k->source_type = rnd(30) == 0 ? rnd(65536) : 1 + rnd(5); k->target_type = rnd(30) == 0 ? rnd(65536) : 1 + rnd(5); k->target_class = rnd(30) == 0 ? rnd(65536) : 1 + rnd(3); k->specified = pickspec();
}
static void pickdatum(const struct avtab_key *k, struct avtab_datum *d, struct avtab_extended_perms *x)
{
	int q;
	if (k->specified & AVTAB_XPERMS) { x->specified = rnd(5); x->driver = rnd(256); for (q = 0; q < 8; q++) x->perms.p[q] = rnd(3) ? 0 : (u32)rnd64(); d->u.xperms = x; }
	else { d->u.data = (u32)rnd64() >> rnd(32); }
}
static void put32(unsigned char *p, u32 v) { memcpy(p, &v, 4); }
static void put16(unsigned char *p, u16 v) { memcpy(p, &v, 2); }
static int cbcount;
static int cb(struct avtab *a, const struct avtab_key *k, const struct avtab_datum *d, void *p)
{
	printf("    cb %u,%u,%u,%x ", k->source_type, k->target_type, k->target_class, k->specified);
	if (k->specified & AVTAB_XPERMS) { int q; printf("x%u/%u", d->u.xperms->specified, d->u.xperms->driver); for (q = 0; q < 8; q++) printf(".%x", d->u.xperms->perms.p[q]); } else printf("%x", d->u.data);
	printf("\n");
	if (cbcount-- == 0) return rnd(2) ? -ENOMEM : -EEXIST;
	return 0;
}
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0, prove = getenv("EB_PROVE") != NULL; long n = getenv("EB_N") ? atol(getenv("EB_N")) : 60000, it, pc = 0; int i, j, rc;
	struct kmem_cache c1, c2; avtab_node_cachep = &c1; avtab_xperms_cachep = &c2;
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (i = 0; i < K; i++) avtab_init(&pool[i]);
	for (it = 0; it < n; it++) {
		int op = rnd(100);
		static const unsigned vers[] = { 5, 19, 20, 29, 30, 33, 34, 35 };
		i = rnd(K); j = rnd(K); curpol = &pols[rnd(8)];
		pol.policyvers = vers[rnd(8)]; pol.ntypes = rnd(2) ? 6 : 65535; pol.nclasses = rnd(2) ? 4 : 65535;
		fail_in = rnd(10) == 0 ? 1 + rnd(4) : 0;
		if (op < 6) {
			static const u32 nr[] = { 0, 1, 2, 3, 4, 5, 7, 8, 9, 16, 31, 100, 1000, 131071, 131072, 200000, 0xffffffffu };
			u32 r = nr[rnd(17)]; if (r > 140000 && rnd(3)) r = 8;
			avtab_destroy(&pool[i]); rc = avtab_alloc(&pool[i], r); printf("%ld alloc %d %u -> %d\n", it, i, r, rc); dump(i);
		} else if (op < 40) {
			struct avtab_key k; struct avtab_datum d; struct avtab_extended_perms x; struct avtab_node *nn;
			if (!pool[i].nslot) { rc = avtab_alloc(&pool[i], rnd(3) ? 1 + rnd(40) : 1000); }
			pickkey(&k); pickdatum(&k, &d, &x);
			if (rnd(20) == 0) { u32 save = pool[i].nel; pool[i].nel = U32_MAX; nn = avtab_insert_nonunique(&pool[i], &k, &d); printf("%ld insert-full %d -> %d\n", it, i, nn != NULL); pool[i].nel = save; }
			nn = avtab_insert_nonunique(&pool[i], &k, &d);
			printf("%ld insert %d %u,%u,%u,%x -> %d\n", it, i, k.source_type, k.target_type, k.target_class, k.specified, nn != NULL); if (nn) dump(i);
		} else if (op < 60) {
			struct avtab_key k; struct avtab_node *nn; int steps;
			pickkey(&k);
			if (rnd(2) && pool[i].nel) { u32 s = rnd(pool[i].nslot), t; struct avtab_node *q = NULL; for (t = 0; t < pool[i].nslot && !q; t++) q = pool[i].htable[(s + t) % pool[i].nslot]; if (q) { k = q->key; if (rnd(2)) k.specified = pickspec(); } }
			nn = avtab_search_node(&pool[i], &k); if (prove && pc++ == 3) nn = nn ? NULL : (struct avtab_node *)&pool[i];
			printf("%ld search %d %u,%u,%u,%x ->", it, i, k.source_type, k.target_type, k.target_class, k.specified);
			for (steps = 0; nn && steps < 5; steps++) {
				u16 sp = rnd(2) ? nn->key.specified : pickspec();
				printf(" (%u,%u,%u,%x)", nn->key.source_type, nn->key.target_type, nn->key.target_class, nn->key.specified);
				nn = avtab_search_node_next(nn, sp); printf(" next(%x)", sp);
			}
			if (!nn) printf(" none"); else printf(" (%u,%u,%u,%x)", nn->key.source_type, nn->key.target_type, nn->key.target_class, nn->key.specified);
			printf("\n"); printf("%ld snull %d\n", it, avtab_search_node_next(NULL, 1) == NULL);
		} else if (op < 64) { avtab_destroy(&pool[i]); printf("%ld destroy %d\n", it, i); dump(i); }
		else if (op < 68) {
			if (i != j) { avtab_destroy(&pool[j]); scrubinit(j); rc = avtab_alloc_dup(&pool[j], &pool[i]); printf("%ld alloc_dup %d %d -> %d\n", it, j, i, rc); dump(j); }
		} else if (op < 80) {
			static unsigned char buf[1 << 16]; struct policy_file fp; size_t L = rnd(3) == 0 ? rnd(80) : sizeof buf;
			memset(buf, 0xaa, sizeof buf); fp.data = (char *)buf; fp.len = L;
			rc = avtab_write(&pol, &pool[i], &fp);
			printf("%ld write %d len=%zu -> %d used=%zu\n", it, i, L, rc, L - fp.len);
			if (rc == 0 && L - fp.len < sizeof lastbuf) { lastlen = L - fp.len; memcpy(lastbuf, buf, lastlen); }
			{ size_t u = L - fp.len, q; printf("   "); for (q = 0; q < u && q < 120; q++) printf("%02x", buf[q]); printf("\n"); }
		} else if (op < 88) {
			static unsigned char buf[1 << 16]; struct policy_file fp; size_t L = lastlen;
			memcpy(buf, lastbuf, L);
			switch (rnd(5)) { case 0: break; case 1: L = rnd(L + 1); break; case 2: if (L) buf[rnd(L)] ^= 1 << rnd(8); break; case 3: if (L >= 4) put32(buf, rnd(4) ? rnd(40) : (u32)rnd64()); break; default: if (L >= 12) buf[4 + rnd(8)] = rnd(256); }
			scrubinit(i); pol.policyvers = 34; fp.data = (char *)buf; fp.len = L;
			rc = avtab_read(&pool[i], &fp, &pol);
			printf("%ld read %d len=%zu -> %d left=%zu\n", it, i, L, rc, fp.len); dump(i);
		} else {
			/* crafted stream, exact-size heap buffer */
			unsigned char *buf = malloc(4 + 40 * 40 + 8); struct policy_file fp; size_t L = 0; int cnt = 1 + rnd(8), e, whole = rnd(2); u32 v = pol.policyvers;
			if (whole) { put32(buf, cnt); L = 4; }
			for (e = 0; e < cnt; e++) {
				u16 s = 1 + rnd(3), t = 1 + rnd(3), cl = 1 + rnd(2);
				if (rnd(12) == 0) s = rnd(70000); if (rnd(12) == 0) t = rnd(70000); if (rnd(12) == 0) cl = rnd(70000);
				if (v < 20) {
					u32 items = rnd(8) == 0 ? rnd(12) : 5 + rnd(4), spec = rnd(4) ? (rnd(2) ? (rnd(3) == 0 ? 7 : 1 << rnd(3)) : (rnd(3) == 0 ? 0x70 : 0x10 << rnd(3))) | (rnd(3) == 0 ? 0x80000000u : 0) : (u32)rnd64() & 0x80007777, q;
					put32(buf + L, items); L += 4;
					put32(buf + L, rnd(15) == 0 ? 0x10000 + s : s); L += 4; put32(buf + L, rnd(15) == 0 ? 0x10000 + t : t); L += 4; put32(buf + L, rnd(15) == 0 ? 0x10000 + cl : cl); L += 4; put32(buf + L, spec); L += 4;
					for (q = 4; q < items && q < 40; q++) { put32(buf + L, (u32)rnd64() >> rnd(32)); L += 4; }
				} else {
					u16 spec = rnd(6) ? pickspec() : (rnd(2) ? (u16)(0x8 << rnd(9)) : (u16)rnd64());
					put16(buf + L, s); put16(buf + L + 2, t); put16(buf + L + 4, cl); put16(buf + L + 6, spec); L += 8;
					if (spec & AVTAB_XPERMS) { int q; buf[L++] = rnd(2) ? 1 + rnd(3) : rnd(6); buf[L++] = rnd(256); for (q = 0; q < 8; q++) { put32(buf + L, (u32)rnd64()); L += 4; } }
					else { put32(buf + L, rnd(3) ? 1 + rnd(8) : (u32)rnd64()); L += 4; }
				}
			}
			if (rnd(6) == 0) L = rnd(L + 1);
			{
				unsigned char *ex = malloc(L ? L : 1); memcpy(ex, buf, L); free(buf);
				fp.data = (char *)ex; fp.len = L; scrubinit(i);
				if (whole) { rc = avtab_read(&pool[i], &fp, &pol); printf("%ld readc %d v=%u len=%zu -> %d left=%zu\n", it, i, v, L, rc, fp.len); dump(i); }
				else { cbcount = rnd(3) == 0 ? rnd(3) : 1000; rc = avtab_read_item(&pool[i], &fp, &pol, cb, NULL, rnd(2)); printf("%ld item %d v=%u len=%zu -> %d left=%zu\n", it, i, v, L, rc, fp.len); }
				free(ex);
			}
		}
		fail_in = 0;
	}
	for (i = 0; i < K; i++) avtab_destroy(&pool[i]);
	printf("live at the end: %ld\n", live_nodes);
	return 0;
}
