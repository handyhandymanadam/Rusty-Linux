/* resource tree differential: the pristine tree algorithms (ARM_REF: ref.c) against resource_rs.rs plus the wrappers of resource_glue.c (ARM_RS). A pool of 40 nodes under iomem_resource,
 * ranges drawn mostly from 0..300 (collisions) and sometimes from the ends of the 64-bit space; ops: request, insert (incl. an already linked node), release (with and without
 * children), release_children, adjust, find_next, region_intersects, find_space, reallocate, alignment. Prints every result and the whole tree after every op.
 * usage: t SHARD (env RS_N, RS_PROVE) */
#include "refshim.h"
struct resource iomem_resource = { .name = "mem", .start = 0, .end = ~0ULL, .flags = 0x200 };
int warns, bugs, dbg_released, remove_calls;
static unsigned long long rs_;
static unsigned rnd(unsigned n) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return n ? (unsigned)(rs_ >> 40) % n : 0; }
static unsigned long long rv(void)
{
	switch (rnd(10)) { case 0: return ~0ULL - rnd(3); case 1: return rnd(3); case 2: return 1ULL << (20 + rnd(40)); default: return rnd(300); }
}
static unsigned arch_floor, arch_ceil = ~0u;
void arch_remove_reservations(struct resource *avail) { remove_calls++; if (arch_floor && avail->start < arch_floor) avail->start = arch_floor; if (avail->end > arch_ceil) avail->end = arch_ceil; }
static resource_size_t al_round(void *data, const struct resource *res, resource_size_t size, resource_size_t align)
{ unsigned long d = (unsigned long)data; return d == 1 ? ((res->start + 15) & ~15ULL) : d == 2 ? res->start + 1 : res->end - size + 1; }
#ifdef ARM_REF
#include "ref.c"
#define T_REQ ref_request
#define T_REL ref_release
#define T_RELC ref_release_children
#define T_FIND ref_find_next
#define T_REGION ref_region
#define T_SPACE ref_find_space
#define T_REALLOC ref_reallocate
#define T_INS ref_insert
#define T_ADJ ref_adjust
#define T_ALIGN ref_alignment
#else
struct resource *rust_res_request(struct resource *, struct resource *); int rust_res_release(struct resource *, bool); void rust_res_release_children(struct resource *);
int rust_res_find_next(struct resource *, resource_size_t, resource_size_t, unsigned long, unsigned long, struct resource *);
int rust_res_region_intersects(struct resource *, resource_size_t, size_t, unsigned long, unsigned long);
int rust_res_find_space(struct resource *, struct resource *, struct resource *, resource_size_t, struct resource_constraint *);
int rust_res_reallocate(struct resource *, struct resource *, resource_size_t, struct resource_constraint *);
struct resource *rust_res_insert(struct resource *, struct resource *); int rust_res_adjust(struct resource *, resource_size_t, resource_size_t); resource_size_t rust_res_alignment(struct resource *);
/* the wrappers of resource_glue.c */
void rust_res_warn_dup(void) { warns++; }
void rust_res_bug(void) { bugs++; }
void rust_res_dbg_release(struct resource *r) { dbg_released++; }
resource_size_t rust_res_alignf(resource_alignf f, void *data, const struct resource *avail, resource_size_t size, resource_size_t align) { return f(data, avail, size, align); }
void rust_res_arch_remove_reservations(struct resource *r) { arch_remove_reservations(r); }
#define T_REQ rust_res_request
#define T_REL rust_res_release
#define T_RELC rust_res_release_children
#define T_FIND(io, s, e, f, d, r) rust_res_find_next(io, s, e, f, d, r)
#define T_REGION rust_res_region_intersects
#define T_SPACE rust_res_find_space
#define T_REALLOC rust_res_reallocate
#define T_INS rust_res_insert
#define T_ADJ rust_res_adjust
#define T_ALIGN rust_res_alignment
#endif
#define NN 40
static struct resource pool[NN];
static int idx(struct resource *r) { return !r ? -2 : r == &iomem_resource ? -1 : (int)(r - pool); }
static void dump(void)
{
	printf(" tree:");
	struct resource *p = iomem_resource.child; int depth = 1, guard = 0;
	while (p && guard++ < 200) {
		printf(" %d[%llx-%llx f%lx d%lu D%d]", idx(p), (unsigned long long)p->start, (unsigned long long)p->end, p->flags, p->desc, depth);
		if (p->child) { p = p->child; depth++; }
		else { while (!p->sibling && p->parent && p->parent != &iomem_resource) { p = p->parent; depth--; } p = p->sibling; }
	}
	if (guard >= 200) { printf(" CYCLE\n"); fflush(stdout); exit(3); }
}
static struct resource *pick(int want_in) /* want_in: 1 linked, 0 free, -1 any */
{
	for (int t = 0; t < 12; t++) { struct resource *r = &pool[rnd(NN)]; if (want_in < 0 || (want_in == 1) == (r->parent != NULL)) return r; }
	return want_in < 0 ? &pool[rnd(NN)] : NULL;
}
static void zap(struct resource *r) { while (r) { struct resource *n = r->sibling; zap(r->child); memset(r, 0, sizeof *r); r = n; } }
static struct resource *lpick(void) { struct resource *r = pick(1); return r ? r : &iomem_resource; }
static void fresh(struct resource *r)
{
	unsigned long long a = rv(), b = rnd(4) ? a + rnd(40) : rv();
	if (rnd(30) == 0) { b = a - 1; } /* end < start */
	memset(r, 0, sizeof *r); r->start = a; r->end = b; r->flags = 0x200 | (rnd(3) ? 0x80000000UL : 0) | (rnd(5) == 0 ? 0x100 : 0) | (rnd(8) == 0 ? IORESOURCE_UNSET : 0) | (rnd(6) == 0 ? IORESOURCE_SIZEALIGN : rnd(6) == 0 ? IORESOURCE_STARTALIGN : 0); r->desc = rnd(3);
}
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0; long n = getenv("RS_N") ? atol(getenv("RS_N")) : 24000; int prove = getenv("RS_PROVE") != NULL;
	setvbuf(stdout, NULL, _IOFBF, 1 << 20);
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (long round = 0; round < n / 150; round++) {
		memset(pool, 0, sizeof pool); iomem_resource.child = NULL; arch_floor = rnd(3) ? 0 : rnd(100); arch_ceil = rnd(4) ? ~0u : 150 + rnd(150);
		for (int op = 0; op < 150; op++) {
			unsigned o = rnd(27); struct resource *x, *par; int r; unsigned long long a, b; printf("%ld.%d ", round, op);
			if (o < 5) { x = pick(0); if (!x) continue; fresh(x); par = rnd(3) ? &iomem_resource : lpick();
				struct resource *c = T_REQ(par, x); printf("request %d under %d -> %d", idx(x), idx(par), idx(c)); }
			else if (o < 9) { x = pick(0); if (!x) continue; fresh(x); par = rnd(3) ? &iomem_resource : lpick();
				if (rnd(12) == 0) { x = pick(1); if (!x) continue; par = x->parent; }
				struct resource *c = T_INS(par, x); printf("insert %d under %d -> %d w=%d", idx(x), idx(par), idx(c), warns); }
			else if (o < 11) { x = pick(1); if (!x) continue; int rc = rnd(2); r = T_REL(x, rc); printf("release %d rc=%d -> %d", idx(x), rc, r); if (r == 0 && rc) zap(x->child), x->child = NULL; }
			else if (o < 12) { x = pick(1); if (!x) x = &iomem_resource; if (rnd(4)) { T_RELC(x); printf("relchildren %d d=%d", idx(x), dbg_released); } else continue; }
			else if (o < 14) { x = pick(-1); a = rv(); b = rnd(3) ? rnd(60) : rv() % 1000;
				if (rnd(2)) { /* aim at the neighbours' edges, +-1 */
					unsigned long long c[10]; int k = 0; struct resource *q[5] = { x, x->sibling, x->parent, x->child, x->parent ? x->parent->child : NULL };
					for (int i = 0; i < 5; i++) if (q[i]) { c[k++] = q[i]->start; c[k++] = q[i]->end; }
					if (k) { a = c[rnd(k)] + rnd(3) - 1; unsigned long long e = c[rnd(k)] + rnd(3) - 1; b = e - a + 1; } }
				if (x->child && rnd(3) == 0) { struct resource *lc = x->child; while (lc->sibling) lc = lc->sibling; a = x->child->start - rnd(2); b = lc->end + rnd(2) - a + 1; } /* hug the children */
				if (b == 0 || a + b - 1 < a) { printf("adjust skipped\n"); continue; } r = T_ADJ(x, a, b); printf("adjust %d to %llx +%llx -> %d", idx(x), a, b, r); }
			else if (o < 16) { struct resource out; memset(&out, 0xAB, sizeof out); a = rv(); b = rnd(3) ? a + rnd(100) : rv(); unsigned long fl = rnd(3) ? 0x200 | 0x80000000UL : 0x200; unsigned long d = rnd(3) ? 0 : rnd(3);
				r = T_FIND(&iomem_resource, a, b, fl, d, rnd(30) ? &out : NULL); printf("find %llx-%llx f%lx d%lu -> %d", a, b, fl, d, r); if (r == 0) printf(" [%llx-%llx f%lx d%lu p%d n%p s%p c%p]", out.start, out.end, out.flags, out.desc, idx(out.parent), (void *)out.name, (void *)out.sibling, (void *)out.child); }
			else if (o < 18) { a = rv(); b = rnd(3) ? 1 + rnd(120) : 1 + rv() % 100000; unsigned long fl = rnd(3) ? 0x200 | 0x80000000UL : 0x200; unsigned long d = rnd(3) ? 0 : rnd(3);
				r = T_REGION(rnd(4) ? &iomem_resource : lpick(), a, b, fl, d); printf("region %llx +%llx f%lx d%lu -> %d", a, b, fl, d, r); }
			else if (o < 21) { x = pick(0); if (!x) continue; fresh(x); x->flags |= rnd(2) ? 0 : 0; struct resource_constraint c = { .min = rnd(3) ? 0 : rnd(100), .max = rnd(3) ? ~0ULL : 100 + rnd(300), .align = rnd(5) == 0 ? 0 : 1ULL << rnd(6), .alignf = rnd(3) ? NULL : al_round, .alignf_data = (void *)(unsigned long)rnd(3) };
				a = 1 + rnd(40); struct resource save = *x; par = rnd(3) ? &iomem_resource : lpick();
				r = T_SPACE(par, NULL, x, a, &c); printf("space under %d size %llx min %llx max %llx al %llx -> %d", idx(par), a, c.min, c.max, c.align, r); if (r == 0) printf(" got %llx-%llx", x->start, x->end); else if (memcmp(&save, x, sizeof save)) printf(" CHANGED"); printf(" rm=%d", remove_calls); }
			else if (o < 23) { x = pick(1); if (!x) continue; struct resource_constraint c = { .min = rnd(3) ? 0 : rnd(100), .max = rnd(3) ? ~0ULL : 100 + rnd(300), .align = 1ULL << rnd(5), .alignf = rnd(3) ? NULL : al_round, .alignf_data = (void *)(unsigned long)rnd(3) };
				a = 1 + rnd(40); r = T_REALLOC(x->parent, x, a, &c); printf("realloc %d size %llx -> %d now %llx-%llx b=%d", idx(x), a, r, x->start, x->end, bugs); }
			else if (o >= 24) { /* a non-busy parent with busy children, some adjacent, some starting where the parent starts */
				struct resource *A = pick(0), *C1 = pick(0), *C2 = pick(0); if (!A || !C1 || !C2 || A == C1 || A == C2 || C1 == C2) continue;
				a = rnd(250); b = 10 + rnd(40); memset(A, 0, sizeof *A); A->start = a; A->end = a + b; A->flags = 0x200; r = idx(T_REQ(&iomem_resource, A)); printf("nest A %d %llx-%llx -> %d", idx(A), a, a + b, r);
				if (r == -2) { memset(C1, 0, sizeof *C1); C1->start = a + (rnd(3) ? 0 : rnd(4)); C1->end = a + rnd(b + 1); if (C1->end < C1->start) C1->end = C1->start; C1->flags = 0x200 | 0x80000000UL | (rnd(4) == 0 ? 0x100 : 0);
					r = idx(T_REQ(A, C1)); printf(" C1 %llx-%llx -> %d", C1->start, C1->end, r);
					if (r == -2 && C1->end < A->end && rnd(3)) { memset(C2, 0, sizeof *C2); C2->start = C1->end + 1 + (rnd(3) == 0 ? rnd(3) : 0); C2->end = A->end - (rnd(2) ? 0 : rnd(3)); if (C2->end < C2->start) C2->end = C2->start; C2->flags = 0x200 | 0x80000000UL;
						r = idx(T_REQ(A, C2)); printf(" C2 %llx-%llx -> %d", C2->start, C2->end, r); } } }
			else { x = pick(-1); printf("align %d -> %llx size %llx", idx(x), (unsigned long long)T_ALIGN(x), (unsigned long long)resource_size(x)); }
			dump(); printf("\n");
		}
		if (prove && round == 0) printf("  POISON\n");
	}
	printf("final w=%d b=%d\n", warns, bugs);
	return 0;
}
