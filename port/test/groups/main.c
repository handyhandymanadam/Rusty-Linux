/* SPDX-License-Identifier: GPL-2.0 */
/* Differential for kernel/groups.c (gid_cmp, groups_sort, groups_search): pristine C (c_*) vs groups_rs.rs.
 * Both share one sort() (insertion sort that uses both comparison polarities). Random group lists
 * (0..24 entries; values 0..9 and full-range), sorted by each arm, searched for present/absent gids incl. 0 and ~0.
 * usage: main SHARD ; GROUPS_PROVE_CAN_FAIL=1 breaks the Rust arm. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
typedef struct { uint32_t val; } kgid_t;
struct group_info { int usage; int ngroups; kgid_t gid[]; };
void c_groups_sort(struct group_info *);
int c_groups_search(const struct group_info *, kgid_t);
void groups_sort(struct group_info *);
int groups_search(const struct group_info *, kgid_t);
static int poison; static unsigned long long fails, checks;
#define FAIL(...) do { if (fails++ < 10) fprintf(stderr, __VA_ARGS__); } while (0)
void sort(void *base, size_t num, size_t size, int (*cmp)(const void *, const void *), void (*swap)(void *, void *, int))
{
	char *p = base, tmp[16]; (void)swap;
	for (size_t i = 1; i < num; i++) {
		memcpy(tmp, p + i * size, size);
		size_t j = i;
		while (j > 0 && (cmp(p + (j - 1) * size, tmp) > 0 || cmp(tmp, p + (j - 1) * size) < 0)) { memcpy(p + j * size, p + (j - 1) * size, size); j--; }
		memcpy(p + j * size, tmp, size);
	}
}
static uint64_t rs;
static uint64_t rnd(void) { uint64_t z = (rs += 0x9e3779b97f4a7c15ULL); z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL; z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL; return z ^ (z >> 31); }
int main(int argc, char **argv)
{
	unsigned shard = argc > 1 ? atoi(argv[1]) : 0;
	long long n = getenv("GROUPS_N") ? atoll(getenv("GROUPS_N")) : 20000000LL;
	poison = getenv("GROUPS_PROVE_CAN_FAIL") != 0;
	rs = 0x1234567ULL * (shard + 1);
	for (long long it = 0; it < n; it++) {
		int ng = rnd() % 25, wide = rnd() % 3 == 0;
		struct group_info *a = malloc(sizeof *a + 25 * 4), *b = malloc(sizeof *b + 25 * 4);
		a->usage = b->usage = 1; a->ngroups = b->ngroups = ng;
		for (int i = 0; i < ng; i++) {
			uint32_t v = wide ? (rnd() % 4 ? (uint32_t)rnd() : (rnd() & 1 ? ~0u - rnd() % 3 : rnd() % 3)) : rnd() % 10;
			a->gid[i].val = b->gid[i].val = v;
		}
		c_groups_sort(a); groups_sort(b);
		checks++;
		if (memcmp(a->gid, b->gid, ng * 4)) FAIL("sort MISMATCH ng=%d\n", ng);
		for (int q = 0; q < 6; q++) {
			kgid_t g = { q < 2 && ng ? a->gid[rnd() % ng].val : (wide ? (uint32_t)rnd() : (uint32_t)(rnd() % 12)) };
			if (q == 4) g.val = 0; if (q == 5) g.val = ~0u;
			int ra = c_groups_search(a, g), rb = groups_search(b, g);
			if (poison && ng == 3 && q == 0) rb ^= 1;
			checks++; if (ra != rb) FAIL("search MISMATCH ng=%d gid=%u c=%d rs=%d\n", ng, g.val, ra, rb);
		}
		/* unsorted list searched as-is: same (arbitrary) answer */
		a->gid[0].val = ng ? a->gid[ng - 1].val + 1 : 0; b->gid[0].val = a->gid[0].val;
		kgid_t g = { (uint32_t)(rnd() % 12) };
		checks++; if (ng && c_groups_search(a, g) != groups_search(b, g)) FAIL("unsorted search MISMATCH\n");
		checks++; if (c_groups_search(0, g) != groups_search(0, g)) FAIL("NULL search MISMATCH\n");
		free(a); free(b);
	}
	printf("shard %u: %llu checks, %llu failures\n", shard, checks, fails);
	return fails != 0;
}
