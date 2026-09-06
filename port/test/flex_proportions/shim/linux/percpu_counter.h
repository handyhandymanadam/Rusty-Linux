#pragma once
#include <linux/types.h>
#include <linux/spinlock.h>

/* Single-threaded differential -- no real per-cpu split needed. `count`
 * is always exact (no batching lag), which makes percpu_counter_read()
 * and percpu_counter_sum() always agree here; that's a degenerate case
 * of the real batching behaviour, not a divergence this harness needs to
 * exercise -- the real batching lives entirely in lib/percpu_counter.c,
 * untouched C, not part of this port. What this harness verifies is the
 * add/subtract/set ARITHMETIC flex_proportions_rs.rs performs around
 * these calls. */
struct percpu_counter {
	raw_spinlock_t lock;
	long long count;
	void *list_placeholder[2];
	int *counters;
};

struct lock_class_key { int x; };

int __percpu_counter_init_many(struct percpu_counter *fbc, long long amount,
				gfp_t gfp, unsigned int nr_counters,
				struct lock_class_key *key);
void percpu_counter_destroy_many(struct percpu_counter *fbc, unsigned int nr_counters);
void percpu_counter_set(struct percpu_counter *fbc, long long amount);
void percpu_counter_add_batch(struct percpu_counter *fbc, long long amount, int batch);
long long __percpu_counter_sum(struct percpu_counter *fbc);

#define percpu_counter_init_many(fbc, value, gfp, nr_counters)		\
	({								\
		static struct lock_class_key __key;			\
		__percpu_counter_init_many(fbc, value, gfp, nr_counters, &__key); \
	})
#define percpu_counter_init(fbc, value, gfp) percpu_counter_init_many(fbc, value, gfp, 1)

static inline void percpu_counter_destroy(struct percpu_counter *fbc)
{
	percpu_counter_destroy_many(fbc, 1);
}

extern int percpu_counter_batch;

static inline void percpu_counter_add(struct percpu_counter *fbc, long long amount)
{
	percpu_counter_add_batch(fbc, amount, percpu_counter_batch);
}

static inline long long percpu_counter_sum(struct percpu_counter *fbc)
{
	return __percpu_counter_sum(fbc);
}

static inline long long percpu_counter_read(struct percpu_counter *fbc)
{
	return fbc->count;
}

static inline long long percpu_counter_read_positive(struct percpu_counter *fbc)
{
	long long ret = fbc->count;
	return ret < 0 ? 0 : ret;
}
