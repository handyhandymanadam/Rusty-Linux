#pragma once
#include <linux/compiler.h>
#include <linux/bug.h>
#include <linux/printk.h>
#include <linux/ratelimit_types.h>
#include <linux/atomic.h>

static inline void ratelimit_state_inc_miss(struct ratelimit_state *rs)
{
	atomic_inc(&rs->missed);
}

static inline int ratelimit_state_reset_miss(struct ratelimit_state *rs)
{
	return atomic_xchg_relaxed(&rs->missed, 0);
}
