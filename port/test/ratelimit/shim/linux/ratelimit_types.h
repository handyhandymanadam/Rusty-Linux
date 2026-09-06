#pragma once
#include <linux/spinlock.h>
#include <linux/atomic.h>

#define RATELIMIT_MSG_ON_RELEASE (1 << 0)
#define RATELIMIT_INITIALIZED    (1 << 1)

struct ratelimit_state {
	raw_spinlock_t lock;
	int interval;
	int burst;
	atomic_t rs_n_left;
	atomic_t missed;
	unsigned int flags;
	unsigned long begin;
};

extern int ___ratelimit(struct ratelimit_state *rs, const char *func);
