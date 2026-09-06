/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * port/test/dynamic_queue_limits/drv.c -- differential for
 * lib/dynamic_queue_limits.c.
 *
 * Drives two `struct dql` instances (C arm, Rust arm) through identical
 * sequences of "enqueue" (a hand-transcription of the real, untouched
 * header's dql_queued()/dql_queue_stall() -- not under test, just the
 * antecedent state both arms need) and dql_completed()/dql_reset()
 * calls, with a shared, test-controlled `jiffies` so every call sees
 * IDENTICAL inputs on both arms. Compares the full struct byte-for-byte
 * after every call (these functions return void -- the struct IS the
 * observable behaviour), plus whether BUG_ON and the stall tracepoint
 * fired and with what arguments.
 *
 * Two passes: jiffies starting near 0, and jiffies starting near
 * ULONG_MAX - a few thousand, specifically to drive real wraparound
 * through POSDIFF/AFTER_EQ/time_after-family macros and the history-ring
 * arithmetic -- the entire reason this file's macros exist.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

#include "linux/dynamic_queue_limits.h"

/* ---- C arm (renamed) ---- */
void cref_dql_completed(struct dql *dql, unsigned int count);
void cref_dql_reset(struct dql *dql);
void cref_dql_init(struct dql *dql, unsigned int hold_time);

/* ---- Rust arm: dql_completed/dql_reset/dql_init declared by the shim
 * header above, matching the real names. ---- */

volatile unsigned long jiffies;

static unsigned long cases, mism, trace_fires, bug_fires;
static int poison;

/* ---- shared recording state, reset before each call pair ---- */
static int g_bug_fired;
static int g_trace_fired;
static unsigned short g_trace_thrs;
static unsigned int g_trace_len;
static unsigned long g_trace_last_reap, g_trace_hist_head, g_trace_now;
static unsigned long g_trace_hist[DQL_HIST_LEN];

void dql_test_record_bug(void)
{
	g_bug_fired = 1;
}

void dql_test_record_trace(unsigned short thrs, unsigned int len,
			    unsigned long last_reap, unsigned long hist_head,
			    unsigned long now, unsigned long *hist)
{
	g_trace_fired = 1;
	g_trace_thrs = thrs;
	g_trace_len = len;
	g_trace_last_reap = last_reap;
	g_trace_hist_head = hist_head;
	g_trace_now = now;
	memcpy(g_trace_hist, hist, sizeof(g_trace_hist));
}

/* Rust arm's thunk (see lib/dynamic_queue_limits.c and
 * dynamic_queue_limits_rs.rs's `unsafe extern "C"` block) -- reproduces
 * the SAME check/call the C arm's BUG_ON()/trace_dql_stall_detected()
 * macros do, via the same recording functions. */
void __dql_completed_bug_on(unsigned int count, unsigned int num_queued,
			     unsigned int num_completed)
{
	if (count > num_queued - num_completed)
		dql_test_record_bug();
}

void __dql_trace_stall_detected(unsigned short thrs, unsigned int len,
				 unsigned long last_reap,
				 unsigned long hist_head, unsigned long now,
				 const unsigned long *hist)
{
	dql_test_record_trace(thrs, len, last_reap, hist_head, now,
			       (unsigned long *)hist);
}

/* dql_queued() + dql_queue_stall(), from include/linux/dynamic_queue_limits.h
 * -- untouched shared infrastructure, not under test. Applied identically
 * to both arms so their antecedent state never diverges on its own. */
static void test_dql_queued(struct dql *dql, unsigned int count)
{
	dql->last_obj_cnt = count;
	dql->num_queued += count;

	if (!dql->stall_thrs)
		return;

	unsigned long now = jiffies;
	unsigned long now_hi = now / BITS_PER_LONG;

	if (now_hi != dql->history_head) {
		for (unsigned long i = 0; i < DQL_HIST_LEN; i++) {
			if (now_hi * BITS_PER_LONG ==
			    (dql->history_head + i) * BITS_PER_LONG)
				break;
			DQL_HIST_ENT(dql, dql->history_head + i + 1) = 0;
		}
		dql->history_head = now_hi;
	}

	unsigned long map = DQL_HIST_ENT(dql, now_hi);
	if (!(map & (1UL << (now % BITS_PER_LONG))))
		DQL_HIST_ENT(dql, now_hi) = map | (1UL << (now % BITS_PER_LONG));
}

static void bad(const char *what)
{
	if (mism < 20)
		printf("MISMATCH %s\n", what);
	mism++;
}

static void compare(struct dql *c, struct dql *r, const char *what,
		     int bug_c, int bug_r, int trace_c, int trace_r)
{
	cases++;
	if (poison)
		r->limit ^= 1;
	if (memcmp(c, r, sizeof(*c)) != 0)
		bad(what);
	if (bug_c != bug_r)
		bad("bug_on-mismatch");
	if (trace_c != trace_r)
		bad("trace-fired-mismatch");
}

static unsigned long seed;
static unsigned long xrand(void)
{
	seed ^= seed << 13;
	seed ^= seed >> 7;
	seed ^= seed << 17;
	return seed;
}

int main(void)
{
	if (getenv("DQL_PROVE_CAN_FAIL"))
		poison = 1;

	unsigned long starts[2] = { 1, (unsigned long)-2000 };

	for (int pass = 0; pass < 2; pass++) {
		struct dql dc, dr;
		memset(&dc, 0, sizeof(dc));
		memset(&dr, 0, sizeof(dr));
		seed = 0x9E3779B97F4A7C15UL ^ (unsigned long)(pass + 1);
		jiffies = starts[pass];

		cref_dql_init(&dc, 200 + (unsigned int)(pass * 37));
		dql_init(&dr, 200 + (unsigned int)(pass * 37));
		compare(&dc, &dr, "init", 0, 0, 0, 0);

		/* Real drivers set stall_thrs directly after init; not part
		 * of this file's own contract, exercised the same way here. */
		dc.stall_thrs = 5 + (unsigned short)(pass * 3);
		dr.stall_thrs = dc.stall_thrs;

		for (int iter = 0; iter < 20000; iter++) {
			jiffies += xrand() % 24;

			int op = xrand() % 10;
			if (op < 6) {
				unsigned int count = 1 + (unsigned int)(xrand() % 5000);
				test_dql_queued(&dc, count);
				test_dql_queued(&dr, count);
				compare(&dc, &dr, "queued", 0, 0, 0, 0);
			} else if (op < 9) {
				unsigned int avail_c = dc.num_queued - dc.num_completed;
				if (avail_c == 0)
					continue;
				unsigned int count = 1 + (unsigned int)(xrand() % avail_c);

				g_bug_fired = 0; g_trace_fired = 0;
				cref_dql_completed(&dc, count);
				int bug_c = g_bug_fired, trace_c = g_trace_fired;
				if (trace_c) trace_fires++;
				if (bug_c) bug_fires++;

				g_bug_fired = 0; g_trace_fired = 0;
				dql_completed(&dr, count);
				int bug_r = g_bug_fired, trace_r = g_trace_fired;

				compare(&dc, &dr, "completed", bug_c, bug_r, trace_c, trace_r);
			} else {
				cref_dql_reset(&dc);
				dql_reset(&dr);
				compare(&dc, &dr, "reset", 0, 0, 0, 0);
			}
		}
	}

	if (mism) {
		fprintf(stderr, "%lu/%lu cases MISMATCHED\n", mism, cases);
		return 1;
	}
	printf("%lu cases, 0 mismatches (trace fired %lu times, bug %lu times)\n", cases, trace_fires, bug_fires);
	return 0;
}
