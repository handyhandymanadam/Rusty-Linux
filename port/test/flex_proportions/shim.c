/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/percpu_counter.h>
#include <string.h>

int percpu_counter_batch = 32;

int __percpu_counter_init_many(struct percpu_counter *fbc, long long amount,
				gfp_t gfp, unsigned int nr_counters,
				struct lock_class_key *key)
{
	(void)gfp;
	(void)key;
	memset(fbc, 0, nr_counters * sizeof(*fbc));
	fbc->count = amount;
	return 0;
}

void percpu_counter_destroy_many(struct percpu_counter *fbc, unsigned int nr_counters)
{
	(void)fbc;
	(void)nr_counters;
}

void percpu_counter_set(struct percpu_counter *fbc, long long amount)
{
	fbc->count = amount;
}

void percpu_counter_add_batch(struct percpu_counter *fbc, long long amount, int batch)
{
	(void)batch;
	fbc->count += amount;
}

long long __percpu_counter_sum(struct percpu_counter *fbc)
{
	return fbc->count;
}
