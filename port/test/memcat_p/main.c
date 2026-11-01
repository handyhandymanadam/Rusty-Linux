/* memcat_p differential: pristine lib/memcat_p.c (ARM_REF) against memcat_p_glue.c over memcat_p_rs.rs (ARM_RS). Random pairs of NULL-terminated pointer arrays (0..9 elements each, so empty a, empty b,
 * both empty, any mix), allocation failure; prints the merged array (element identity, length) and checks the NULL terminator.   usage: t SHARD (env MC_N, MC_PROVE=1) */
#include <linux/slab.h>
long allocs_out, fail_in = -1;
#include SRC

static unsigned long long rs_;
static unsigned rnd(unsigned n) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return n ? (unsigned)(rs_ >> 40) % n : 0; }
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0; long n = getenv("MC_N") ? atol(getenv("MC_N")) : 50000; int prove = getenv("MC_PROVE") != NULL;
	static void *pool[64];
	setvbuf(stdout, NULL, _IOFBF, 1 << 20);
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (long s = 0; s < n; s++) {
		/* exact-size arrays so any over-read shows under valgrind */
		int na = rnd(10), nb = rnd(10);
		void **a = malloc((na + 1) * sizeof(void *)), **b = malloc((nb + 1) * sizeof(void *));
		for (int i = 0; i < na; i++) a[i] = &pool[rnd(64)];
		a[na] = NULL;
		for (int i = 0; i < nb; i++) b[i] = &pool[rnd(64)];
		b[nb] = NULL;
		fail_in = rnd(20) == 0 ? rnd(2) : -1;
		void **r = __memcat_p(a, b);
		fail_in = -1;
		printf("%ld na=%d nb=%d ->", s, na, nb);
		if (!r) printf(" NULL");
		else { int k = 0; for (; r[k]; k++) printf(" %ld", (long)((void **)r[k] - pool)); printf(" |%d term=%d", k, r[k] == NULL); free(r); allocs_out--; }
		printf("\n");
		if (prove && s == 20) printf("  POISON\n");
		free(a); free(b);
	}
	printf("final live=%ld\n", allocs_out);
	return 0;
}
