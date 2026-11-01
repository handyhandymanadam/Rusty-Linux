/* SPDX-License-Identifier: GPL-2.0 */
/* lib/genalloc.c: pristine C (c_*) vs the CONFIG_RUST=y code (rs_*: genalloc_glue.c's own wrappers calling genalloc_rs.rs).
 *  1. differential, single thread: bitmap_set_ll / bitmap_clear_ll on random maps (1..6 words, empty / sparse / dense / full) with
 *     random start and length (word-aligned or not, crossing 0..5 word boundaries, zero length), return value and every word
 *     compared; the five allocation algorithms on random maps and parameters (orders 0..12, alignments 1..4096, offsets), compared.
 *  2. stress, N threads on ONE shared bitmap, per arm:
 *     a. contention: every thread repeatedly claims a random range with bitmap_set_ll (a partial claim -- some words set, then one
 *        busy -- is undone with bitmap_clear_ll(start, nr - remain) exactly as gen_pool_alloc_algo_owner does, and that undo must
 *        return 0), checks through a per-bit ownership table that no bit is ever owned twice, then releases with bitmap_clear_ll
 *        (must return 0). At the end the bitmap must be all zero.
 *     b. disjoint: each thread owns bits [t*B, (t+1)*B) with B not a multiple of 64 (neighbours share words) and toggles bits in it with
 *        random-length set/clear; the final map must be the union of what each thread left.
 * usage: main SHARD ; GA_SECONDS, GA_N ; GA_PROVE_CAN_FAIL=1 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>
#include <sched.h>
#define D(r, n, a) r c_##n a; r rs_##n a;
D(unsigned long, bitmap_set_ll, (unsigned long *, unsigned long, unsigned long))
D(unsigned long, bitmap_clear_ll, (unsigned long *, unsigned long, unsigned long))
struct pool { int min_alloc_order; };
struct align { int align; };
struct fixed { unsigned long offset; };
#define ALGO(n) unsigned long c_##n(unsigned long *, unsigned long, unsigned long, unsigned int, void *, struct pool *, unsigned long); \
		unsigned long rs_##n(unsigned long *, unsigned long, unsigned long, unsigned int, void *, struct pool *, unsigned long);
ALGO(gen_pool_first_fit) ALGO(gen_pool_first_fit_align) ALGO(gen_pool_fixed_alloc) ALGO(gen_pool_first_fit_order_align) ALGO(gen_pool_best_fit)
static int poison; static unsigned long long fails, checks;
#define FAIL(...) do { if (__atomic_fetch_add(&fails, 1, __ATOMIC_RELAXED) < 10) fprintf(stderr, __VA_ARGS__); } while (0)
static uint64_t mix(uint64_t z) { z += 0x9e3779b97f4a7c15ULL; z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL; z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL; return z ^ (z >> 31); }

static void fillmap(unsigned long *m, unsigned words, uint64_t *rs)
{
	int kind = mix(*rs += 1) % 5;
	for (unsigned i = 0; i < words; i++) {
		uint64_t r = mix(*rs += 1);
		m[i] = kind == 0 ? 0 : kind == 1 ? ~0UL : kind == 2 ? (r & mix(*rs += 1) & mix(*rs += 1)) : kind == 3 ? (r | mix(*rs += 1) | mix(*rs += 1)) : r;
	}
}

static void diff(unsigned shard, long long n)
{
	uint64_t rs = 0x1234567ULL * (shard + 1);
#define R (mix(rs += 1))
	for (long long it = 0; it < n; it++) {
		unsigned words = 1 + R % 6;
		unsigned long a[6], b[6], nbits = words * 64;
		fillmap(a, words, &rs); memcpy(b, a, sizeof a);
		unsigned long start = R % nbits, nr = R % (nbits - start + 1);
		if (R % 4 == 0) { start &= ~63UL; nr &= ~63UL; if (start + nr > nbits) nr = 0; }
		int op = R % 2;
		unsigned long x = op ? c_bitmap_clear_ll(a, start, nr) : c_bitmap_set_ll(a, start, nr);
		unsigned long y = op ? rs_bitmap_clear_ll(b, start, nr) : rs_bitmap_set_ll(b, start, nr);
		if (poison && it == 9) y++;
		checks++;
		if (x != y || memcmp(a, b, sizeof a)) { FAIL("ll MISMATCH op=%d start=%lu nr=%lu: c=%lu rs=%lu\n", op, start, nr, x, y); continue; }
		/* the five algorithms */
		fillmap(a, words, &rs);
		struct pool pool = { .min_alloc_order = R % 13 };
		struct align al = { .align = 1 << (R % 13) };
		struct fixed fx = { .offset = (unsigned long)(R % 40) << pool.min_alloc_order };
		unsigned long size = R % (nbits + 1), st = R % (size + 1), start_addr = R % 4096;
		start_addr <<= R % 3;
		unsigned int nrb = R % 4 == 0 ? 1 + R % 3 : 1 + R % 70;
		unsigned long (*cf[5])(unsigned long *, unsigned long, unsigned long, unsigned int, void *, struct pool *, unsigned long) =
			{ c_gen_pool_first_fit, c_gen_pool_first_fit_align, c_gen_pool_fixed_alloc, c_gen_pool_first_fit_order_align, c_gen_pool_best_fit };
		unsigned long (*rf[5])(unsigned long *, unsigned long, unsigned long, unsigned int, void *, struct pool *, unsigned long) =
			{ rs_gen_pool_first_fit, rs_gen_pool_first_fit_align, rs_gen_pool_fixed_alloc, rs_gen_pool_first_fit_order_align, rs_gen_pool_best_fit };
		void *data[5] = { 0, &al, &fx, 0, 0 };
		for (int k = 0; k < 5; k++) {
			unsigned long p = cf[k](a, size, st, nrb, data[k], &pool, start_addr), q = rf[k](a, size, st, nrb, data[k], &pool, start_addr);
			checks++;
			if (p != q) FAIL("algo %d MISMATCH size=%lu start=%lu nr=%u order=%d: c=%lu rs=%lu\n", k, size, st, nrb, pool.min_alloc_order, p, q);
		}
	}
}

/* ---- stress ---- */
#define NT 4
#define NBITS 512
struct arm {
	const char *name; int rust; unsigned long map[NBITS / 64]; unsigned char owner[NBITS];
	volatile int stop, bad; uint64_t ops;
};
static unsigned long SET(struct arm *A, unsigned long s, unsigned long n) { return A->rust ? rs_bitmap_set_ll(A->map, s, n) : c_bitmap_set_ll(A->map, s, n); }
static unsigned long CLR(struct arm *A, unsigned long s, unsigned long n) { return A->rust ? rs_bitmap_clear_ll(A->map, s, n) : c_bitmap_clear_ll(A->map, s, n); }
struct targ { struct arm *A; int id; };
static void *contend(void *p)
{
	struct targ *T = p; struct arm *A = T->A; uint64_t rs = 77 + T->id * 1000;
	while (!A->stop) {
		unsigned long s = mix(rs += 1) % (NBITS - 1), n = 1 + mix(rs += 1) % (NBITS - s < 150 ? NBITS - s : 150);
		unsigned long rem = SET(A, s, n);
		if (rem) {
			if (CLR(A, s, n - rem)) A->bad++;   /* the undo must always succeed: those bits are ours */
			sched_yield();
			continue;
		}
		for (unsigned long b = s; b < s + n; b++)
			if (__atomic_exchange_n(&A->owner[b], T->id + 1, __ATOMIC_SEQ_CST)) A->bad++;   /* bit owned twice */
		for (unsigned long b = s; b < s + n; b++)
			if (__atomic_exchange_n(&A->owner[b], 0, __ATOMIC_SEQ_CST) != T->id + 1) A->bad++;
		if (CLR(A, s, n)) A->bad++;
		A->ops++;
	}
	return 0;
}
static void *disjoint(void *p)
{
	struct targ *T = p; struct arm *A = T->A; uint64_t rs = 5 + T->id * 77;
	unsigned long lo = T->id * 100, hi = lo + 100;     /* 100 bits: neighbours share words */
	unsigned char mine[100] = { 0 };
	while (!A->stop) {
		unsigned long s = lo + mix(rs += 1) % 100, n = 1 + mix(rs += 1) % (hi - s);
		int set = mix(rs += 1) & 1;
		/* only touch ranges that are entirely clear (to set) or entirely set (to clear) so every call must succeed */
		int ok = 1; for (unsigned long b = s; b < s + n; b++) if (mine[b - lo] != !set) { ok = 0; break; }
		if (!ok) continue;
		if (set ? SET(A, s, n) : CLR(A, s, n)) A->bad++;
		for (unsigned long b = s; b < s + n; b++) mine[b - lo] = set;
		A->ops++;
	}
	/* publish what this thread left */
	for (int i = 0; i < 100; i++) A->owner[lo + i] = mine[i];
	return 0;
}
static void stress(struct arm *A, int secs, int mode)
{
	pthread_t th[NT]; struct targ ta[NT];
	memset(A->map, 0, sizeof A->map); memset(A->owner, 0, sizeof A->owner); A->stop = 0; A->bad = 0; A->ops = 0;
	for (int i = 0; i < NT; i++) { ta[i].A = A; ta[i].id = i; pthread_create(&th[i], 0, mode ? disjoint : contend, &ta[i]); }
	struct timespec ts = { secs, 0 }; nanosleep(&ts, 0);
	A->stop = 1; for (int i = 0; i < NT; i++) pthread_join(th[i], 0);
	checks++;
	if (mode) {
		for (int b = 0; b < NT * 100; b++) if (((A->map[b / 64] >> (b % 64)) & 1) != A->owner[b]) { A->bad++; break; }
	} else {
		for (unsigned i = 0; i < NBITS / 64; i++) if (A->map[i]) { A->bad++; break; }
	}
	if (A->bad) FAIL("STRESS %s %s: bad=%d\n", A->name, mode ? "disjoint" : "contend", A->bad);
	printf("  stress %s %s: %llu ops, bad %d\n", A->name, mode ? "disjoint" : "contend", (unsigned long long)A->ops, A->bad);
}
int main(int argc, char **argv)
{
	unsigned shard = argc > 1 ? atoi(argv[1]) : 0;
	poison = getenv("GA_PROVE_CAN_FAIL") != 0;
	diff(shard, getenv("GA_N") ? atoll(getenv("GA_N")) : 300000LL);
	int secs = getenv("GA_SECONDS") ? atoi(getenv("GA_SECONDS")) : 2;
	if (secs > 0) {
		static struct arm ac = { .name = "C" }, ar = { .name = "Rust", .rust = 1 };
		stress(&ac, secs, 0); stress(&ar, secs, 0); stress(&ac, secs, 1); stress(&ar, secs, 1);
	}
	printf("shard %u: %llu checks, %llu failures\n", shard, checks, fails);
	return fails != 0;
}
