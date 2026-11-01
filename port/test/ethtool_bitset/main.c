/* ethtool bitset differential: the pristine bitmap32 helpers and ethnl_bitset32_size() (ARM_REF) against bitset_rs.rs (ARM_RS). Random u32 bitmaps in exact-size heap buffers (so an access past the end
 * shows under valgrind), sparse / dense / all-ones / empty, intervals with every alignment, value / mask pairs with and without a mask, name tables with names of every length including
 * unterminated 32-byte ones, compact and verbose sizes.   usage: t SHARD (env EB_N, EB_PROVE) */
#include "refshim.h"
#include SRCFILE
static unsigned long long rs_;
static unsigned long long rnd64(void) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return (rs_ >> 11) ^ (rs_ << 53); }
static unsigned rnd(unsigned n) { return n ? (unsigned)(rnd64() % n) : 0; }
static u32 *mk(unsigned words, int kind)
{
	u32 *p = malloc(words ? words * 4 : 1); unsigned i;
	for (i = 0; i < words; i++) {
		switch (kind) { case 0: p[i] = 0; break; case 1: p[i] = ~0u; break; case 2: p[i] = (u32)1 << rnd(32); break; default: p[i] = (u32)rnd64(); }
	}
	return p;
}
static unsigned long sum(const u32 *p, unsigned words) { unsigned long h = 1469598103934665603UL; unsigned i; for (i = 0; i < words; i++) h = (h ^ p[i]) * 1099511628211UL; return h; }
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0, prove = getenv("EB_PROVE") != NULL; long n = getenv("EB_N") ? atol(getenv("EB_N")) : 200000, it, pc = 0;
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (it = 0; it < n; it++) {
		unsigned total = 1 + rnd(5), nb = total * 32, k = rnd(4), op = rnd(10);
		u32 *a = mk(total, rnd(4)), *b = mk(total, rnd(4)), *m = mk(total, rnd(4)); bool mod = rnd(2);
		if (op < 2) {
			unsigned start = rnd(3) ? rnd(nb + 1) : rnd(2) * 32 * rnd(total + 1), end = rnd(3) ? rnd(nb + 1) : 32 * rnd(total + 1) + (rnd(2) ? 0 : rnd(32));
			if (end > nb) end = nb;
			ethnl_bitmap32_clear(a, start, end, &mod);
			printf("%ld clear %u %u -> mod=%d %lx\n", it, start, end, mod, sum(a, total));
		} else if (op < 4) {
			unsigned start = rnd(nb + 1), end = rnd(nb + 1); bool r;
			if (rnd(2)) start = 32 * rnd(total + 1); if (rnd(2)) end = 32 * rnd(total + 1);
			r = ethnl_bitmap32_not_zero(a, start, end); if (prove && pc++ == 3) r = !r;
			printf("%ld notzero %u %u -> %d\n", it, start, end, r);
		} else if (op < 6) {
			unsigned bits = 1 + rnd(nb); const u32 *mp = rnd(3) ? m : NULL;
			ethnl_bitmap32_update(a, bits, b, mp, &mod);
			printf("%ld update %u mask=%d -> mod=%d %lx\n", it, bits, mp != NULL, mod, sum(a, total));
		} else if (op < 7) {
			unsigned i = rnd(nb); printf("%ld test %u -> %d\n", it, i, ethnl_bitmap32_test_bit(a, i));
		} else if (op < 8) {
			unsigned bits = rnd(nb + 1); if (rnd(2)) memcpy(b, a, total * 4); if (rnd(3) == 0 && total > 0) b[rnd(total)] ^= (u32)1 << rnd(32);
			printf("%ld equal %u -> %d\n", it, bits, ethnl_bitmap32_equal(a, b, bits));
		} else {
			unsigned bits = rnd(nb + 1), i, w = (bits + 31) / 32; char *names = NULL; bool comp = rnd(2); u32 *vv, *mm;
			if (rnd(2)) {
				names = malloc(bits ? bits * ETH_GSTRING_LEN : 1);
				for (i = 0; i < bits * ETH_GSTRING_LEN; i++) names[i] = 'a' + rnd(26);
				for (i = 0; i < bits; i++) { unsigned len = rnd(5) == 0 ? ETH_GSTRING_LEN : rnd(ETH_GSTRING_LEN); if (len < ETH_GSTRING_LEN) names[i * ETH_GSTRING_LEN + len] = 0; }
			}
			vv = mk(w, rnd(4)); mm = mk(w, rnd(4));
			printf("%ld size %u names=%d compact=%d mask=%d -> %d\n", it, bits, names != NULL, comp, k != 0, ethnl_bitset32_size(vv, k ? mm : NULL, bits, (ethnl_string_array_t)names, comp));
			free(names); free(vv); free(mm);
		}
		free(a); free(b); free(m);
	}
	return 0;
}
