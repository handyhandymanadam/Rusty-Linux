/* SPDX-License-Identifier: GPL-2.0 */
/* Trimmed reproduction of include/linux/jiffies.h's wraparound-safe time
 * macros, plus a `jiffies` global BOTH arms (and Rust, via its own
 * `#[link_name = "jiffies"]`) read -- drv.c sets it directly so a test
 * case is fully deterministic. */
#ifndef _SHIM_LINUX_JIFFIES_H
#define _SHIM_LINUX_JIFFIES_H

extern volatile unsigned long jiffies;

#define time_after(a, b) ((long)((b) - (a)) < 0)
#define time_before(a, b) time_after(b, a)
#define time_after_eq(a, b) ((long)((a) - (b)) >= 0)
#define time_before_eq(a, b) time_after_eq(b, a)

#endif
