/* refcount differential: the same cases drive pristine lib/refcount.c (ARM_REF) or refcount_glue.c over refcount_rs.rs (ARM_RS); every operation prints its
 * result, the counter afterwards, how many distinct WARN_ONCE sites have fired and the lock calls made. Then a threaded phase: four threads hammer
 * refcount_dec_not_one() on one counter (no update may be lost: exactly start-1 successes, final value 1).  usage: t SHARD   (env RC_N, RC_PROVE=1) */
#include "kshim.h"
#include <pthread.h>
#include SRC

void (*race_hook)(atomic_t *); int warn_count, warn_log[64], nwarn, lock_log[256], nlock;

static unsigned long long rs_;
static unsigned rnd(unsigned n) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return n ? (unsigned)(rs_ >> 33) % n : 0; }

static const int vals[] = { 0, 1, 2, 3, 4, 100, 0x7ffffffe, 0x7fffffff, (int)0x80000000, REFCOUNT_SATURATED, REFCOUNT_SATURATED + 1, REFCOUNT_SATURATED - 1,
			    -1, -2, (int)0xc0000002 };
#define NV (sizeof(vals) / sizeof(vals[0]))

static unsigned long long lockhash(void) { unsigned long long h = 1469598103934665603ULL; for (int i = 0; i < nlock && i < 256; i++) { h ^= lock_log[i]; h *= 1099511628211ULL; } return h; }

static void one(refcount_t *r, struct mutex *m, spinlock_t *sp, int op, int arg)
{
	unsigned long fl = 0; int ret = -1;
	nlock = 0;
	switch (op) {
	case 0: refcount_warn_saturate(r, (enum refcount_saturation_type)arg); break;
	case 1: ret = refcount_dec_if_one(r); break;
	case 2: ret = refcount_dec_not_one(r); break;
	case 3: ret = refcount_dec_and_mutex_lock(r, m); break;
	case 4: ret = refcount_dec_and_lock(r, sp); break;
	case 5: ret = refcount_dec_and_lock_irqsave(r, sp, &fl); break;
	}
	printf("op%d a=%d -> %d refs=%08x warns=%d locks=%d/%016llx m=%d s=%d fl=%lu\n", op, arg, ret, (unsigned)atomic_read(&r->refs), warn_count, nlock,
	       lockhash(), m->locked, sp->locked, fl);
	m->locked = 0; sp->locked = 0;
}

static refcount_t shared; static long succ[4];
static void *worker(void *p)
{
	long id = (long)p, n = 0;
	while (refcount_dec_not_one(&shared)) n++;
	succ[id] = n;
	return NULL;
}

int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0;
	long n = getenv("RC_N") ? atol(getenv("RC_N")) : 20000;
	refcount_t r; struct mutex m = { 0 }; spinlock_t sp = { 0 };
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (unsigned v = 0; v < NV; v++)
		for (int op = 0; op < 6; op++)
			for (int arg = 0; arg < (op ? 1 : 7); arg++) { refcount_set(&r, vals[v]); printf("v=%08x ", (unsigned)vals[v]); one(&r, &m, &sp, op, arg); }
	for (long i = 0; i < n; i++) {
		refcount_set(&r, rnd(4) ? vals[rnd(NV)] : (int)rnd(8));
		for (int k = 0; k < 6; k++) { int op = rnd(6); printf("c%ld.%d ", i, k); one(&r, &m, &sp, op, rnd(8)); }
	}
	/* threaded phase: no lost update */
	for (int round = 0; round < 20; round++) {
		pthread_t t[4]; long total = 0, start = 50000 + rnd(50000);
		refcount_set(&shared, start);
		for (long i = 0; i < 4; i++) pthread_create(&t[i], NULL, worker, (void *)i);
		for (int i = 0; i < 4; i++) pthread_join(t[i], NULL);
		for (int i = 0; i < 4; i++) total += succ[i];
		printf("threads start=%ld successes=%ld final=%d\n", start, total, atomic_read(&shared.refs));
	}
#ifdef ARM_RS
	if (getenv("RC_PROVE")) printf("poison\n");
#endif
	return 0;
}
