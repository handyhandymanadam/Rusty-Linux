/* port/test/group_cpus/main.c -- lib/group_cpus.c: pristine C vs group_cpus_glue.c over group_cpus_rs.rs, on random machines (CPU count, holes,
 * sibling groups, NUMA nodes, present CPUs), random group counts and single allocation failures. After every call the return, nummasks, every
 * group's CPU set, the allocation count and the number of live allocations must match. usage: main SHARD ; GC_N ; GC_PROVE_CAN_FAIL=1 */
#include "kshim.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int warn_count;
unsigned int nr_cpu_ids, nr_node_ids;
struct cpumask g_possible, g_present, g_sibling[NR_CPUS];
int g_cpu_node[NR_CPUS];
nodemask_t g_node_possible;

static int alloc_n, fail_at = -1, live;
static void *tracked[4096]; static int ntracked;
static void *tr_alloc(size_t n)
{
	if (alloc_n++ == fail_at) return NULL;
	void *p = calloc(1, n ? n : 1);
	tracked[ntracked++] = p; live++;
	return p;
}
void *kcalloc(size_t n, size_t s, gfp_t g) { return tr_alloc(n * s); }
#ifdef OFFSTACK
void *kzalloc(size_t n, gfp_t g) { return tr_alloc(n); }
#endif
void kfree(const void *p)
{
	if (!p) return;
	for (int i = 0; i < ntracked; i++) if (tracked[i] == p) { tracked[i] = tracked[--ntracked]; live--; free((void *)p); return; }
	fprintf(stderr, "BAD FREE %p\n", p); abort();
}
/* the same deterministic (stable) sort for both arms: the kernel's heap sort is not stable, so ties are an unspecified order we must not depend on */
void sort(void *base, size_t num, size_t size, int (*cmp)(const void *, const void *), void (*swap)(void *, void *, int))
{
	char *b = base, tmp[64];
	for (size_t i = 1; i < num; i++) {
		memcpy(tmp, b + i * size, size);
		size_t j = i;
		while (j > 0 && cmp(b + (j - 1) * size, tmp) > 0) { memcpy(b + j * size, b + (j - 1) * size, size); j--; }
		memcpy(b + j * size, tmp, size);
	}
}

struct cpumask *c_group_cpus_evenly(unsigned int, unsigned int *);
struct cpumask *rs_group_cpus_evenly(unsigned int, unsigned int *);

static uint64_t rs_;
static uint64_t R(void) { rs_ ^= rs_ << 13; rs_ ^= rs_ >> 7; rs_ ^= rs_ << 17; return rs_; }

static void topology(void)
{
	memset(&g_possible, 0, sizeof g_possible); memset(&g_present, 0, sizeof g_present); memset(g_sibling, 0, sizeof g_sibling);
	memset(&g_node_possible, 0, sizeof g_node_possible);
	unsigned ncpu = 1 + R() % (R() % 4 == 0 ? NR_CPUS : 24);
	nr_cpu_ids = ncpu;
	unsigned nn = 1 + R() % (R() % 3 == 0 ? MAXNODES : 6);
	nr_node_ids = nn;
	for (unsigned n = 0; n < nn; n++) if (n == 0 || R() % 6) node_set(n, g_node_possible);
	int nodes[MAXNODES], nn_ok = 0;
	for (unsigned n = 0; n < nn; n++) if (g_node_possible.bits[n / 64] >> (n % 64) & 1) nodes[nn_ok++] = n;
	for (unsigned c = 0; c < ncpu; c++) {
		if (R() % 12 == 0 && c) continue;           /* a hole in the possible map */
		cpumask_set_cpu(c, &g_possible);
		if (R() % 4) cpumask_set_cpu(c, &g_present);
	}
	unsigned mode = R() % 3;
	for (unsigned c = 0; c < ncpu; c++) g_cpu_node[c] = mode == 0 ? nodes[R() % nn_ok] : mode == 1 ? nodes[(c * nn_ok / ncpu) % nn_ok] : nodes[c % nn_ok];
	unsigned sib = 1u << (R() % 3);                 /* threads per core 1, 2 or 4 */
	for (unsigned c = 0; c < ncpu; c++) {
		cpumask_set_cpu(c, &g_sibling[c]);
		for (unsigned d = c / sib * sib; d < c / sib * sib + sib && d < ncpu; d++) if (g_possible.bits[d / 64] >> (d % 64) & 1) cpumask_set_cpu(d, &g_sibling[c]);
	}
}

struct res { struct cpumask *masks; unsigned nummasks; int allocs, live, warns; unsigned ng; };
static void call(int arm, unsigned ng, int fail, struct res *r)
{
	alloc_n = 0; fail_at = fail; int l0 = live, w0 = warn_count;
	r->nummasks = 0xdeadbeef; r->ng = ng;
	r->masks = arm ? rs_group_cpus_evenly(ng, &r->nummasks) : c_group_cpus_evenly(ng, &r->nummasks);
	r->allocs = alloc_n; r->live = live - l0; r->warns = warn_count - w0; fail_at = -1;
}
static int same(const struct res *a, const struct res *b)
{
	if (!!a->masks != !!b->masks || a->allocs != b->allocs || a->live != b->live || a->warns != b->warns) return 0;
	if (!a->masks) return 1;
	return a->nummasks == b->nummasks && !memcmp(a->masks, b->masks, a->ng * sizeof(struct cpumask));
}

int main(int argc, char **argv)
{
	unsigned shard = argc > 1 ? atoi(argv[1]) : 0;
	long n = getenv("GC_N") ? atol(getenv("GC_N")) : 20000, bad = 0, nonnull = 0, errs = 0, wraps = 0;
	int prove = getenv("GC_PROVE_CAN_FAIL") != 0;
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (long i = 0; i < n; i++) {
		topology();
		unsigned nodes_in = 0;
		for (unsigned k = 0; k < 4; k++) {
			unsigned ng = R() % 5 == 0 ? R() % 4 : 1 + R() % (R() % 2 ? 200 : 20);
			if (ng > 4000) ng = 4000;
			int fail = R() % 4 == 0 ? (int)(R() % 8) : -1;
			struct res a, b;
			call(0, ng, fail, &a); call(1, ng, fail, &b);
			if (prove && b.masks && i == 3) b.masks[0].bits[0] ^= 1;
			if (!same(&a, &b)) {
				bad++;
				fprintf(stderr, "MISMATCH shard %u case %ld ng=%u fail=%d: C ret=%d nm=%u allocs=%d live=%d warns=%d | Rust ret=%d nm=%u allocs=%d live=%d warns=%d\n",
					shard, i, ng, fail, !!a.masks, a.nummasks, a.allocs, a.live, a.warns, !!b.masks, b.nummasks, b.allocs, b.live, b.warns);
			}
			if (a.masks) { nonnull++; if (a.nummasks < ng) wraps++; } else if (ng) errs++;
			kfree(a.masks); kfree(b.masks);
			(void)nodes_in;
			if (live) { fprintf(stderr, "LEAK %d after case %ld\n", live, i); bad++; live = 0; ntracked = 0; }
			if (bad > 10) goto done;
		}
	}
done:
	printf("shard %u: %ld cases, %ld failures (%ld ok results, %ld failed allocs, %ld with fewer masks than groups, warns %d)\n", shard, n, bad, nonnull, errs, wraps, warn_count);
	return bad != 0;
}
