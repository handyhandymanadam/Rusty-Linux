/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_LINUX_SCHED_H
#define _SHIM_LINUX_SCHED_H
/* The oracle does not schedule; the point is the ordering it produces. */
static inline void cond_resched(void) { }
#endif
