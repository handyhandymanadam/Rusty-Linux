#pragma once
#include <linux/compiler.h>
#include <linux/math64.h>
#include <linux/percpu_counter.h>
#include <linux/seqlock_types.h>
#include <linux/seqlock.h>
#include <linux/irqflags.h>

extern unsigned int nr_cpu_ids;

#define ilog2(n) (31 - __builtin_clz(n))
#define BITS_PER_LONG 64
#define FPROP_FRAC_SHIFT 10
#define FPROP_FRAC_BASE (1UL << FPROP_FRAC_SHIFT)

struct fprop_global {
	struct percpu_counter events;
	unsigned int period;
	seqcount_t sequence;
};

int fprop_global_init(struct fprop_global *p, gfp_t gfp);
void fprop_global_destroy(struct fprop_global *p);
bool fprop_new_period(struct fprop_global *p, int periods);

struct fprop_local_percpu {
	struct percpu_counter events;
	unsigned int period;
	raw_spinlock_t lock;
};

int fprop_local_init_percpu(struct fprop_local_percpu *pl, gfp_t gfp);
void fprop_local_destroy_percpu(struct fprop_local_percpu *pl);
void __fprop_add_percpu(struct fprop_global *p, struct fprop_local_percpu *pl, long nr);
void __fprop_add_percpu_max(struct fprop_global *p, struct fprop_local_percpu *pl,
			     int max_frac, long nr);
void fprop_fraction_percpu(struct fprop_global *p, struct fprop_local_percpu *pl,
			    unsigned long *numerator, unsigned long *denominator);
