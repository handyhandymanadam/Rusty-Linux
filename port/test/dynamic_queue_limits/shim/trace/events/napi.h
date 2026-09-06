/* SPDX-License-Identifier: GPL-2.0 */
/* trace_dql_stall_detected() here RECORDS its arguments instead of doing
 * real tracepoint dispatch -- drv.c compares whether both arms fired it,
 * and with what arguments, for the same inputs. */
#ifndef _SHIM_TRACE_EVENTS_NAPI_H
#define _SHIM_TRACE_EVENTS_NAPI_H

void dql_test_record_trace(unsigned short thrs, unsigned int len,
			    unsigned long last_reap, unsigned long hist_head,
			    unsigned long now, unsigned long *hist);

static inline void trace_dql_stall_detected(unsigned short thrs, unsigned int len,
					     unsigned long last_reap,
					     unsigned long hist_head,
					     unsigned long now,
					     unsigned long *hist)
{
	dql_test_record_trace(thrs, len, last_reap, hist_head, now, hist);
}

#endif
