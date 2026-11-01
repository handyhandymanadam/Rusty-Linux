/* dec_and_lock: pristine lib/dec_and_lock.c (ARM_REF) against dec_and_lock_glue.c over dec_and_lock_rs.rs (ARM_RS). Part 1, sequential: all four functions on counters around 0 / 1 / 2 and the int
 * limits; prints the result, the counter, whether the lock is held and that the irqsave flags round-trip. Part 2, the concurrency bar: 8 threads hold a random share of the references to one
 * object and drop them through random variants; across the whole round EXACTLY ONE call returns 1 (and holds the lock), every other returns 0 with the lock free, and the counter ends at 0.
 * usage: t (env DL_ROUNDS, DL_PROVE=1)   -- shards do not apply; the output is deterministic */
#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/export.h>
#include SRC

int *hook_counter; long n_spin_lock, n_spin_unlock, n_raw_lock, n_raw_unlock;
static spinlock_t L = { PTHREAD_MUTEX_INITIALIZER, 0 };
static atomic_t obj; static int nthreads = 8;
static int share[8]; static volatile int winners, wrong_lock, wrong_unlock; static pthread_barrier_t bar;

static int call(int variant, unsigned long *fl)
{
	switch (variant) {
	case 0: return _atomic_dec_and_lock(&obj, &L);
	case 1: return _atomic_dec_and_lock_irqsave(&obj, &L, fl);
	case 2: return _atomic_dec_and_raw_lock(&obj, &L);
	default: return _atomic_dec_and_raw_lock_irqsave(&obj, &L, fl);
	}
}
static void unlock_variant(int v, unsigned long fl) { if (v & 2) { if (v & 1) raw_spin_unlock_irqrestore(&L, fl); else raw_spin_unlock(&L); } else if (v & 1) spin_unlock_irqrestore(&L, fl); else spin_unlock(&L); }
static void *worker(void *arg)
{
	int id = (int)(intptr_t)arg; unsigned seed = id * 2654435761u + 7;
	pthread_barrier_wait(&bar);
	for (int i = 0, todo = share[id]; i < todo; i++) {
		unsigned long fl = 0; seed = seed * 1103515245u + 12345u;
		/* a borrower: take a new reference under the lock, as real users do, so that the slow path can find the counter back above 1 */
		if (!((seed >> 8) & 3)) { spin_lock(&L); if (atomic_read(&obj) > 0) { __atomic_fetch_add(&obj.counter, 1, __ATOMIC_SEQ_CST); todo++; } spin_unlock(&L); }
		int v = (seed >> 16) & 3, r = call(v, &fl);
		if (r == 1) {
			__atomic_fetch_add(&winners, 1, __ATOMIC_SEQ_CST);
			if (!L.held) wrong_lock = 1;
			if (v & 1) { if (fl != FLAGS_MAGIC) wrong_lock = 1; }
			unlock_variant(v, fl);
		} else if (r == 0) {
			/* the lock must have been released (we cannot look at `held`: another thread may hold it) */
		} else wrong_unlock = 1;
		if (i + 1 == share[id] && 0) break;
	}
	return NULL;
}
int main(int argc, char **argv)
{
	long rounds = getenv("DL_ROUNDS") ? atol(getenv("DL_ROUNDS")) : 2000; int prove = getenv("DL_PROVE") != NULL; (void)argc; (void)argv;
	setvbuf(stdout, NULL, _IOFBF, 1 << 16);
	static const int vals[] = { -5, -1, 0, 1, 2, 3, 100, INT_MAX, INT_MIN, INT_MIN + 1 };
	for (int v = 0; v < 4; v++)
		for (unsigned k = 0; k < sizeof vals / sizeof *vals; k++) {
			unsigned long fl = 0; obj.counter = vals[k]; L.held = 0;
			hook_counter = (k & 1) ? &obj.counter : NULL; /* odd entries: a borrower bumps the counter after the fast path gave up */
			int r = call(v, &fl); hook_counter = NULL;
			printf("seq variant %d start %d -> ret %d counter %d held %d flags %s locks spin %ld/%ld raw %ld/%ld\n", v, vals[k], r, obj.counter, L.held, (v & 1) && r == 1 ? (fl == FLAGS_MAGIC ? "saved" : "BAD") : "-", n_spin_lock, n_spin_unlock, n_raw_lock, n_raw_unlock);
			if (r == 1) unlock_variant(v, fl);
		}
	if (prove) printf("POISON\n");
	for (long round = 0; round < rounds; round++) {
		int total = 0; unsigned s = round * 40503u + 1;
		for (int t = 0; t < nthreads; t++) { s = s * 1103515245u + 12345u; share[t] = (s >> 16) % 6; total += share[t]; }
		if (total == 0) { share[0] = 1; total = 1; }
		obj.counter = total; winners = 0; wrong_lock = 0; wrong_unlock = 0; L.held = 0;
		pthread_barrier_init(&bar, NULL, nthreads);
		pthread_t th[8];
		for (int t = 0; t < nthreads; t++) pthread_create(&th[t], NULL, worker, (void *)(intptr_t)t);
		for (int t = 0; t < nthreads; t++) pthread_join(th[t], NULL);
		pthread_barrier_destroy(&bar);
		if (round % 200 == 0 || winners != 1 || obj.counter != 0 || wrong_lock || wrong_unlock || L.held)
			printf("round %ld refs %d: winners %d final %d lock_free %d bad_lock %d bad_ret %d\n", round, total, winners, obj.counter, !L.held, wrong_lock, wrong_unlock);
	}
	return 0;
}
