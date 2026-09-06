// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2019, Mellanox Technologies inc.  All rights reserved.
 */

// One retained C helper for rdma_dim_rs.rs, same shape as
// logs/porting-hazards.md's "raw uaccess" resolution: schedule_work() is
// `static inline` (inlines down to queue_work_on(WORK_CPU_UNBOUND,
// system_percpu_wq, work), and WORK_CPU_UNBOUND == NR_CPUS -- a
// config-dependent value not worth hardcoding into Rust when a one-line C
// call already gets it right for free). No kabi contract needed: this
// symbol is never called from outside this crate's own Rust, so it is not
// EXPORT_SYMBOL'd and carries no ABI surface of its own.
#include <linux/workqueue.h>

// Called from Rust (rdma_dim_rs.rs) only, via extern "C" -- no C caller, so
// no header declares it. The prototype below is just to satisfy
// -Wmissing-prototypes; it is not part of any exported ABI.
void rust_rdma_dim_schedule_work(struct work_struct *work);

void rust_rdma_dim_schedule_work(struct work_struct *work)
{
	schedule_work(work);
}
