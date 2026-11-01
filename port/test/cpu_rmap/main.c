/* cpu_rmap differential: pristine lib/cpu_rmap.c (ARM_REF) against cpu_rmap_glue.c over cpu_rmap_rs.rs (ARM_RS). A fake topology (4..64 CPUs, sparse "possible" mask in some shards, SMT pairs, core groups of 4,
 * NUMA nodes of 8, a random online mask that changes), a handful of rmaps, direct objects and IRQs through the glue (add / remove / affinity notification / free), kref get/put, and allocation
 * failures (the rmap, the update mask). After every op every rmap's size, objects and per-CPU {index,dist} are printed.   usage: t SHARD (env CR_N, CR_PROVE=1) */
#include <linux/cpu_rmap.h>
int warn_count; unsigned int nr_cpu_ids; struct cpumask cpu_possible_mask_v, cpu_online_mask_v;
static long allocs_out, fail_in = -1; static int fail_mask;
void klog(const char *fmt, ...) { char b[300]; va_list ap; va_start(ap, fmt); vsnprintf(b, sizeof b, fmt, ap); va_end(ap); printf("  LOG %s", b); }
static int fails(void) { if (fail_in == 0) { fail_in = -1; return 1; } if (fail_in > 0) fail_in--; return 0; }
void *kzalloc(size_t n, gfp_t g) { (void)g; if (fails()) return NULL; allocs_out++; return calloc(1, n); }
static struct cpu_rmap *M[4]; static int mref[4];
void kfree(const void *p) { if (p) allocs_out--; for (int i = 0; i < 4; i++) if (M[i] == p) M[i] = NULL; free((void *)p); }
bool zalloc_cpumask_var(cpumask_var_t *m, gfp_t f) { (void)f; if (fail_mask) { fail_mask = 0; *m = NULL; return false; } *m = calloc(1, sizeof **m); return true; }
void free_cpumask_var(cpumask_var_t m) { free(m); }
static struct cpumask sib[64], core[64], node[8];
const struct cpumask *topology_sibling_cpumask(int c) { return &sib[c]; }
const struct cpumask *topology_core_cpumask(int c) { return &core[c]; }
int cpu_to_node(int c) { return c / 8; }
const struct cpumask *cpumask_of_node(int n) { return &node[n]; }
#define NIRQ 12
static struct irq_affinity_notify *notifiers[NIRQ];
int irq_set_affinity_notifier(unsigned int irq, struct irq_affinity_notify *n)
{
	struct irq_affinity_notify *old = notifiers[irq];
	if (n) { n->irq = irq; kref_init(&n->kref); }
	notifiers[irq] = n;
	if (old) kref_put(&old->kref, old->release);
	return 0;
}
#include SRC

static unsigned long long rs_;
static unsigned rnd(unsigned n) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return n ? (unsigned)(rs_ >> 40) % n : 0; }
#define NM 4 /* mref[]: the references the test holds on each map */
static int obj_id[64]; static void *objs[64];
static int objidx(struct cpu_rmap *m, void *o)
{
	if (!o) return -1;
	for (int i = 0; i < 64; i++) if (o == &objs[i]) return i;
	for (int q = 0; q < NIRQ; q++) if (notifiers[q] && o == (void *)container_of(notifiers[q], struct irq_glue, notify)) return 100 + q;
	return 999;
}
static void state(void)
{
	printf("  S allocs=%ld warn=%d online=%llx |", allocs_out, warn_count, (unsigned long long)cpu_online_mask_v.bits);
	for (int i = 0; i < NM; i++) {
		if (!M[i]) { printf(" [%d:-]", i); continue; }
		printf(" [%d: r%d sz%u objs", i, M[i]->refcount.refcount.refs, M[i]->size);
		for (unsigned k = 0; k < M[i]->size && k < 24; k++) printf(" %d", objidx(M[i], M[i]->obj[k]));
		printf(" near");
		for (unsigned c = 0; c < nr_cpu_ids; c++) printf(" %u:%u/%u", c, M[i]->near[c].index, M[i]->near[c].dist);
		printf("]");
	}
	printf("\n");
}
static struct cpumask rmask(void)
{
	struct cpumask m = { 0 };
	switch (rnd(5)) { case 0: break; case 1: m.bits = ~0ULL; break; default: m.bits = (rnd(1 << 20) * 0x9e3779b97f4a7c15ULL) >> rnd(40); }
	if (nr_cpu_ids < 64) m.bits &= (1ULL << nr_cpu_ids) - 1;
	return m;
}
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0; long n = getenv("CR_N") ? atol(getenv("CR_N")) : 30000; int prove = getenv("CR_PROVE") != NULL;
	setvbuf(stdout, NULL, _IOFBF, 1 << 20);
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	static const unsigned NR[] = { 4, 8, 16, 64, 5, 7, 13, 33 }; nr_cpu_ids = NR[shard & 7];
	u64 all = nr_cpu_ids < 64 ? (1ULL << nr_cpu_ids) - 1 : ~0ULL;
	cpu_possible_mask_v.bits = shard & 4 ? (0x5555555555555555ULL & all) | 1 : all; /* odd shards: every other CPU */
	if (shard >= 4) cpu_possible_mask_v.bits = (0x6db6db6db6db6db6ULL & all) | 2;
	cpu_online_mask_v.bits = cpu_possible_mask_v.bits;
	for (unsigned c = 0; c < nr_cpu_ids; c++) { sib[c].bits = 3ULL << (c & ~1u); core[c].bits = 0xfULL << (c & ~3u); node[c / 8].bits |= 1ULL << c; }
	for (int i = 0; i < 64; i++) obj_id[i] = i;
	for (long s = 0; s < n; s++) {
		unsigned op = rnd(100); int a = rnd(NM);
		printf("%ld ", s);
		if (rnd(12) == 0) fail_in = rnd(3);
		if (rnd(40) == 0) fail_mask = 1;
		if (op < 6) {
			if (!M[a]) { static const unsigned SZ[] = { 1, 2, 3, 5, 8, 16, 20, 0xffff, 0x10000, 0x20000 }; unsigned sz = SZ[rnd(rnd(8) ? 7 : 10)]; M[a] = alloc_cpu_rmap(sz, GFP_KERNEL); mref[a] = M[a] != NULL; printf("alloc %d size %u -> %d\n", a, sz, M[a] != NULL); }
			else printf("skip\n");
		} else if (op < 20) {
			if (M[a]) { void *o = rnd(15) ? &objs[rnd(64)] : NULL; printf("add %d obj %d -> %d\n", a, objidx(M[a], o), cpu_rmap_add(M[a], o)); } else printf("skip\n");
		} else if (op < 50) {
			if (M[a] && M[a]->size) {
				struct cpumask m = rmask(); unsigned idx = rnd(M[a]->size > 30 ? 30 : M[a]->size); int rc = cpu_rmap_update(M[a], idx, &m);
				printf("update %d idx %u mask %llx -> %d\n", a, idx, (unsigned long long)m.bits, rc);
			} else printf("skip\n");
		} else if (op < 58) {
			cpu_online_mask_v.bits = cpu_possible_mask_v.bits & ~(rnd(3) ? 0 : rmask().bits); printf("online %llx\n", (unsigned long long)cpu_online_mask_v.bits);
		} else if (op < 70) {
			if (M[a] && M[a]->size) { int irq = rnd(NIRQ); printf("irq_add %d irq %d -> %d\n", a, irq, notifiers[irq] ? -999 : irq_cpu_rmap_add(M[a], irq)); } else printf("skip\n");
		} else if (op < 76) {
			int irq = rnd(NIRQ); if (notifiers[irq]) { printf("irq_remove irq %d -> %d\n", irq, irq_cpu_rmap_remove(NULL, irq)); } else printf("skip\n");
		} else if (op < 90) {
			int irq = rnd(NIRQ); if (notifiers[irq]) { struct cpumask m = rmask(); notifiers[irq]->notify(notifiers[irq], &m); printf("notify irq %d mask %llx\n", irq, (unsigned long long)m.bits); } else printf("skip\n");
		} else if (op < 94) {
			if (M[a]) { cpu_rmap_get(M[a]); mref[a]++; printf("get %d\n", a); } else printf("skip\n");
		} else if (op < 97) {
			if (M[a] && mref[a] > 0) { mref[a]--; int freed = cpu_rmap_put(M[a]); printf("put %d -> %d\n", a, freed); } else printf("skip\n");
		} else {
			if (M[a] && mref[a] > 0) { /* free_irq_cpu_rmap() drops the creator's reference after removing the notifiers */
				mref[a]--; int last = M[a]->refcount.refcount.refs == 1; free_irq_cpu_rmap(M[a]); printf("free_irq_cpu_rmap %d (last %d)\n", a, last);
			} else { free_irq_cpu_rmap(NULL); printf("free_irq_cpu_rmap NULL\n"); }
		}
		fail_in = -1; fail_mask = 0;
		if (prove && s == 20) printf("  POISON\n");
		state();
	}
	return 0;
}
