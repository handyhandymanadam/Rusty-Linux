#!/usr/bin/env python3
"""mkglue.py PRISTINE.c OUT.c -- kernel/sched/pelt.c as the glue: upstream with decay_load, __accumulate_pelt_segments, accumulate_sum, ___update_load_sum and ___update_load_avg replaced by wrappers over
pelt_rs.rs. Without CONFIG_RUST the file includes upstream's body, installed byte-identical as pelt_norust.c."""
import sys
s = open(sys.argv[1]).read()
wr = r'''/* RUST-WRAPPERS BEGIN: the sum and average arithmetic is in pelt_rs.rs. */
int rust_pelt_update_load_sum(u64 now, struct sched_avg *sa, unsigned long load, unsigned long runnable, int running, const u32 *inv);
void rust_pelt_update_load_avg(struct sched_avg *sa, unsigned long load);

/* pelt_rs.rs hard-codes these. */
static_assert(offsetof(struct sched_avg, last_update_time) == 0 && offsetof(struct sched_avg, load_sum) == 8 && offsetof(struct sched_avg, runnable_sum) == 16 &&
	      offsetof(struct sched_avg, util_sum) == 24 && offsetof(struct sched_avg, period_contrib) == 28 && offsetof(struct sched_avg, load_avg) == 32 &&
	      offsetof(struct sched_avg, runnable_avg) == 40 && offsetof(struct sched_avg, util_avg) == 48);
static_assert(LOAD_AVG_PERIOD == 32 && LOAD_AVG_MAX == 47742 && PELT_MIN_DIVIDER == 47742 - 1024 && SCHED_CAPACITY_SHIFT == 10 && ARRAY_SIZE(runnable_avg_yN_inv) == 32);

static __always_inline int
___update_load_sum(u64 now, struct sched_avg *sa,
		  unsigned long load, unsigned long runnable, int running)
{
	return rust_pelt_update_load_sum(now, sa, load, runnable, running, runnable_avg_yN_inv);
}

static __always_inline void
___update_load_avg(struct sched_avg *sa, unsigned long load)
{
	rust_pelt_update_load_avg(sa, load);
}
/* RUST-WRAPPERS END */

'''
a = s.index("static u64 decay_load(u64 val, u64 n)"); b = s.index("int __update_load_avg_blocked_se(")
s = s[:a] + wr + s[b:]
note = "// SPDX-License-Identifier: GPL-2.0\n/*\n * RUST PORT (kernel/sched/pelt.c, 6.18.49): the sum and average arithmetic is in pelt_rs.rs, called through the wrappers below; this file (included by build_policy.c) keeps\n * everything that knows sched_entity, cfs_rq and rq. Without CONFIG_RUST upstream's whole file, installed byte-identical as pelt_norust.c, is used instead.\n */\n#ifndef CONFIG_RUST\n#include \"pelt_norust.c\"\n#else\n"
s = s.replace("// SPDX-License-Identifier: GPL-2.0\n", note, 1) + "\n#endif /* CONFIG_RUST */\n"
open(sys.argv[2], "w").write(s)
