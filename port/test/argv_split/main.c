/* argv_split differential: pristine lib/argv_split.c (ARM_REF) against argv_split_glue.c over argv_split_rs.rs (ARM_RS). Random strings over a small alphabet that has every kind of whitespace
 * (the kernel's: \t \n \v \f \r space and 0xa0), words of letters and high bytes, leading / trailing / repeated separators, empty strings, strings longer than KMALLOC_MAX_SIZE - 1, with and
 * without argcp, and allocation failures. Prints argc, every word, the NULL terminator position, and the live allocation count.   usage: t SHARD (env AS_N, AS_PROVE=1) */
#include <linux/slab.h>
long allocs_out, alloc_fail_in = -1;
#include SRC

static unsigned long long rs_;
static unsigned rnd(unsigned n) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return n ? (unsigned)(rs_ >> 40) % n : 0; }
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0; long n = getenv("AS_N") ? atol(getenv("AS_N")) : 40000; int prove = getenv("AS_PROVE") != NULL;
	static const unsigned char ALPHA[] = { 'a', 'b', 'Z', '0', '=', '-', ' ', ' ', '\t', '\n', '\v', '\f', '\r', 0xa0, 0xe9, 0x85, 0x1f };
	setvbuf(stdout, NULL, _IOFBF, 1 << 20);
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	static unsigned char *b; b = malloc(9000);
	for (long s = 0; s < n; s++) {
		size_t len = rnd(8) ? rnd(30) : (rnd(6) ? rnd(300) : 4090 + rnd(12));
		for (size_t i = 0; i < len; i++) b[i] = ALPHA[rnd(sizeof ALPHA)];
		b[len] = 0;
		int ac = -777, *acp = rnd(5) ? &ac : NULL;
		alloc_fail_in = rnd(30) == 0 ? rnd(3) : -1;
		char **v = argv_split(0, (char *)b, acp);
		alloc_fail_in = -1;
		printf("%ld len=%zu argc=%d -> %s", s, len, ac, v ? "ok" : "NULL");
		if (v) {
			int k = 0;
			for (; v[k]; k++) { printf(" ["); for (const unsigned char *p = (unsigned char *)v[k]; *p; p++) printf(*p >= 33 && *p < 127 ? "%c" : "\\x%02x", *p); printf("]"); }
			printf(" words=%d slot=%ld first=%d", k, (long)(v + k - v), acp ? (ac == k) : -1);
			/* the copy sits at argv[-1]: its first word starts inside it */
			printf(" copyok=%d", v[-1] != NULL);
			argv_free(v);
		}
		printf(" live=%ld\n", allocs_out);
		if (prove && s == 20) printf("  POISON\n");
	}
	printf("final live=%ld\n", allocs_out);
	return 0;
}
