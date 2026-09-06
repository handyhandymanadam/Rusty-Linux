#pragma once
/* The real symbol name, literally "jiffies" -- both the pristine C's own
 * jiffies references AND the Rust side's #[link_name = "jiffies"] resolve
 * to this SAME global, which drv.c drives directly. One knob, both arms,
 * same shape as the uaccess harness's g_fault_at. */
extern volatile unsigned long jiffies;

#define time_after(a, b) \
	((long)((b) - (a)) < 0)
#define time_is_before_jiffies(a) time_after(jiffies, a)
