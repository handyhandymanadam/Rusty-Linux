/* SPDX-License-Identifier: GPL-2.0 */
/* Trimmed reproduction of include/linux/dynamic_queue_limits.h: the
 * struct layout (pahole-verified against the real build, see
 * dynamic_queue_limits_rs.rs's own doc comment for the exact offsets)
 * and only the macros lib/dynamic_queue_limits.c itself references.
 * dql_queued()/dql_avail()/dql_queue_stall() (the header's own
 * static inlines, unrelated to what this file ports) are NOT
 * reproduced -- nothing under test calls them. */
#ifndef _SHIM_LINUX_DQL_H
#define _SHIM_LINUX_DQL_H

#include <string.h>
#include <asm/bug.h>
#include <linux/bitops.h>

#define DQL_HIST_LEN 4
#define DQL_HIST_ENT(dql, idx) ((dql)->history[(idx) % DQL_HIST_LEN])
#define DQL_MAX_OBJECT (UINT_MAX / 16)
#define DQL_MAX_LIMIT ((UINT_MAX / 2) - DQL_MAX_OBJECT)

struct dql {
	unsigned int num_queued;
	unsigned int adj_limit;
	unsigned int last_obj_cnt;
	unsigned short stall_thrs;
	unsigned short __pad0;
	unsigned long history_head;
	unsigned long history[DQL_HIST_LEN];
	unsigned char __cacheline_pad[8];
	unsigned int limit;
	unsigned int num_completed;
	unsigned int prev_ovlimit;
	unsigned int prev_num_queued;
	unsigned int prev_last_obj_cnt;
	unsigned int lowest_slack;
	unsigned long slack_start_time;
	unsigned int max_limit;
	unsigned int min_limit;
	unsigned int slack_hold_time;
	unsigned short stall_max;
	unsigned short __pad1;
	unsigned long last_reap;
	unsigned long stall_cnt;
};

void dql_completed(struct dql *dql, unsigned int count);
void dql_reset(struct dql *dql);
void dql_init(struct dql *dql, unsigned int hold_time);

#endif
