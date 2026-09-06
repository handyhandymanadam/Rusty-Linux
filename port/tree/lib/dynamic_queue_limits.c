// SPDX-License-Identifier: GPL-2.0
/*
 * Dynamic byte queue limits.  See include/linux/dynamic_queue_limits.h
 *
 * WHAT IS LEFT OF THIS FILE, AND WHY IT CANNOT BE DELETED
 *
 * Every exported function (dql_completed/dql_reset/dql_init) is in
 * lib/dynamic_queue_limits_rs.rs. What stays here is the two things a
 * faithful Rust body cannot express on its own -- same shape and same
 * reason as lib/crypto/sha1.c's static_call thunk (logs/c-entry-rule.md):
 *
 *   - BUG_ON()'s bug-table entry names its own file and line. Rust's
 *     BUG_ON()-shaped precondition failures elsewhere in this project
 *     (lib/plist_rs.rs, lib/memweight_rs.rs) both keep the real BUG_ON
 *     in C for the same reason: a `panic!()` in the .rs file would trap
 *     correctly, but the splat should say "dql_completed", the function
 *     whose contract was actually violated, not an internal Rust helper.
 *   - trace_dql_stall_detected() is a TRACE_EVENT()-generated static
 *     inline -- jump-label-gated tracepoint machinery with no linkable
 *     symbol, the same shape as an allocation reached through a
 *     `static inline` (logs/porting-hazards.md's pre-triage list).
 *     This gives it one.
 */

/* Same full include list as the original file, even though this thunk's
 * own bodies don't need most of them: the header's OWN static-inline
 * bodies (dql_queued()/dql_queue_stall(), unrelated to what this file
 * ports) reference jiffies/READ_ONCE/WRITE_ONCE, and C requires an
 * included static inline to typecheck whether or not it's called here.
 * Dropping linux/types.h and linux/jiffies.h broke this exact way: a
 * bare `#include <linux/dynamic_queue_limits.h>` failed to compile with
 * "use of undeclared identifier 'jiffies'" inside the header itself. */
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/dynamic_queue_limits.h>
#include <linux/compiler.h>
#include <trace/events/napi.h>

/* Forward-declared for the same reason as sha1_blocks_dispatch():
 * config-full's -Wmissing-prototypes is fatal (-Werror) and both
 * symbols' only caller is Rust, via FFI. */
void __dql_completed_bug_on(unsigned int count, unsigned int num_queued,
			     unsigned int num_completed);
void __dql_trace_stall_detected(unsigned short thrs, unsigned int len,
				 unsigned long last_reap,
				 unsigned long hist_head, unsigned long now,
				 unsigned long *hist);

/* lib/dynamic_queue_limits_rs.rs's dql_completed(): the real C body's
 * `BUG_ON(count > num_queued - dql->num_completed)`, kept here so the
 * bug-table entry names this function, not a Rust one.
 *
 * Not EXPORT_SYMBOL: same as sha1.c's sha1_blocks_dispatch(), nothing
 * outside this file has ever been able to call it -- it exists only for
 * dynamic_queue_limits_rs.rs to link against within the same vmlinux. */
void __dql_completed_bug_on(unsigned int count, unsigned int num_queued,
			     unsigned int num_completed)
{
	BUG_ON(count > num_queued - num_completed);
}

/* lib/dynamic_queue_limits_rs.rs's dql_check_stall(): the real C body's
 * trace_dql_stall_detected() call, given a linkable name. Not
 * EXPORT_SYMBOL, for the same reason. */
void __dql_trace_stall_detected(unsigned short thrs, unsigned int len,
				 unsigned long last_reap,
				 unsigned long hist_head, unsigned long now,
				 unsigned long *hist)
{
	trace_dql_stall_detected(thrs, len, last_reap, hist_head, now, hist);
}
