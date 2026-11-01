/* SPDX-License-Identifier: GPL-2.0 */
/* lib/lockref.c: pristine C (c_lockref_*) vs the port (thunk-shaped lockref.c + lockref_rs.rs), in userspace with a test-and-set lock.
 *  1. differential, single thread: random op sequences over random (lock, count) states incl. 0, negative, -128, locked; every result
 *     and the final word compared.
 *  2. stress, N threads on ONE lockref per arm: get / get_not_zero / get_not_dead / put_return / put_or_lock mixes with exact
 *     accounting (each successful op is +1 or -1); at the end count == start + net, the lock is free, no op saw a torn state.
 *     LR_SABOTAGE=1 makes the Rust arm's get non-atomic (see run.sh --sabotage): the accounting MUST fail.
 * usage: main SHARD ; LR_THREADS, LR_SECONDS ; LR_PROVE_CAN_FAIL=1 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <time.h>
#include <sched.h>
struct lockref { union { uint64_t lock_count __attribute__((aligned(8))); struct { volatile uint32_t lock; int count; }; }; };
#define OPS(p) \
	void p##lockref_get(struct lockref *); int p##lockref_put_return(struct lockref *); bool p##lockref_get_not_zero(struct lockref *); \
	bool p##lockref_put_or_lock(struct lockref *); void p##lockref_mark_dead(struct lockref *); bool p##lockref_get_not_dead(struct lockref *);
OPS(c_) OPS()
void kshim_lock(volatile uint32_t *l) { while (__atomic_exchange_n(l, 1, __ATOMIC_ACQUIRE)) while (*l) sched_yield(); }
void kshim_unlock(volatile uint32_t *l) { __atomic_store_n(l, 0, __ATOMIC_RELEASE); }
static int poison; static unsigned long long fails, checks;
#define FAIL(...) do { if (__atomic_fetch_add(&fails, 1, __ATOMIC_RELAXED) < 10) fprintf(stderr, __VA_ARGS__); } while (0)
static uint64_t mix(uint64_t z) { z += 0x9e3779b97f4a7c15ULL; z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL; z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL; return z ^ (z >> 31); }

/* ---- 1. differential ---- */
static void diff(unsigned shard, long long n)
{
	uint64_t rs = 0x1234567ULL * (shard + 1);
	for (long long it = 0; it < n; it++) {
		struct lockref a, b;
		static const int counts[] = { 0, 1, 2, 3, -1, -128, 100, 2147483647, -2147483647 - 1 };
		int cnt = (mix(rs += 1) % 3) ? counts[mix(rs += 1) % (sizeof counts / sizeof *counts)] : (int)mix(rs += 1);
		a.lock = 0; a.count = cnt;
		if (mix(rs += 1) % 6 == 0) a.lock = 1;           /* held: only the fallback paths apply */
		b = a;
		for (int k = 0; k < 6; k++) {
			int op = mix(rs += 1) % 5; int ra, rb;
			volatile uint32_t *la = &a.lock, *lb = &b.lock;
			switch (op) {
			case 0: if (*la) break; c_lockref_get(&a); lockref_get(&b); ra = rb = 0; break;
			case 1: if (*la) break; ra = c_lockref_get_not_zero(&a); rb = lockref_get_not_zero(&b); break;
			case 2: ra = c_lockref_put_return(&a); rb = lockref_put_return(&b); break;
			case 3: if (*la) break; ra = c_lockref_put_or_lock(&a); rb = lockref_put_or_lock(&b); if (!ra) { *la = 0; *lb = 0; } break;
			default: if (*la) break; ra = c_lockref_get_not_dead(&a); rb = lockref_get_not_dead(&b); break;
			}
			if (poison && it == 11 && k == 0) rb++;
			checks++;
			if (ra != rb || a.lock_count != b.lock_count) { FAIL("diff MISMATCH op=%d cnt=%d: c=%d/%016llx rs=%d/%016llx\n", op, cnt, ra, (unsigned long long)a.lock_count, rb, (unsigned long long)b.lock_count); break; }
		}
	}
}

/* ---- 2. stress ---- */
struct arm { struct lockref lr; const char *name; bool rust; long long net[64]; };
static volatile int stop;
struct targ { struct arm *arm; int id; unsigned long long seed; };
static void *worker(void *p)
{
	struct targ *t = p; struct arm *A = t->arm; uint64_t rs = t->seed; long long net = 0;
	while (!stop) {
		for (int k = 0; k < 256; k++) {
			unsigned op = mix(rs += 1) % 6;
			if (A->rust) {
				switch (op) {
				case 0: lockref_get(&A->lr); net++; break;
				case 1: if (lockref_get_not_zero(&A->lr)) net++; break;
				case 2: if (lockref_get_not_dead(&A->lr)) net++; break;
				case 3: { int r = lockref_put_return(&A->lr); if (r >= 0) net--; break; }
				default: if (lockref_put_or_lock(&A->lr)) net--; else { net--; A->lr.count--; kshim_unlock(&A->lr.lock); } break;
				}
			} else {
				switch (op) {
				case 0: c_lockref_get(&A->lr); net++; break;
				case 1: if (c_lockref_get_not_zero(&A->lr)) net++; break;
				case 2: if (c_lockref_get_not_dead(&A->lr)) net++; break;
				case 3: { int r = c_lockref_put_return(&A->lr); if (r >= 0) net--; break; }
				default: if (c_lockref_put_or_lock(&A->lr)) net--; else { net--; A->lr.count--; kshim_unlock(&A->lr.lock); } break;
				}
			}
		}
	}
	A->net[t->id] = net;
	return 0;
}
static void stress(struct arm *A, int nthreads, int seconds)
{
	pthread_t th[64]; struct targ ta[64];
	A->lr.lock = 0; A->lr.count = 1000000;
	stop = 0;
	for (int i = 0; i < nthreads; i++) { ta[i].arm = A; ta[i].id = i; ta[i].seed = 77 + i * 1000003ULL; pthread_create(&th[i], 0, worker, &ta[i]); }
	struct timespec ts = { seconds, 0 }; nanosleep(&ts, 0);
	stop = 1;
	long long total = 0;
	for (int i = 0; i < nthreads; i++) { pthread_join(th[i], 0); total += A->net[i]; }
	checks++;
	if (A->lr.count != 1000000 + total || A->lr.lock != 0) FAIL("STRESS %s: count %d != %lld, lock=%u\n", A->name, A->lr.count, 1000000 + total, A->lr.lock);
	printf("  stress %s: %d threads, net %lld, count %d, lock %u\n", A->name, nthreads, total, A->lr.count, A->lr.lock);
}
int main(int argc, char **argv)
{
	unsigned shard = argc > 1 ? atoi(argv[1]) : 0;
	poison = getenv("LR_PROVE_CAN_FAIL") != 0;
	diff(shard, getenv("LR_N") ? atoll(getenv("LR_N")) : 5000000LL);
	int th = getenv("LR_THREADS") ? atoi(getenv("LR_THREADS")) : 4, secs = getenv("LR_SECONDS") ? atoi(getenv("LR_SECONDS")) : 2;
	if (secs > 0) {
		static struct arm ac = { .name = "C", .rust = false }, ar = { .name = "Rust", .rust = true };
		stress(&ac, th, secs); stress(&ar, th, secs);
	}
	printf("shard %u: %llu checks, %llu failures\n", shard, checks, fails);
	return fails != 0;
}
