#!/usr/bin/env python3
"""mkglue.py PRISTINE.c OUT.c -- timer_glue.c = upstream timer.c with the wheel-index and jiffies-rounding arithmetic replaced by calls into timer_rs.rs (see kernel/time/timer_rs.rs)."""
import sys
s = open(sys.argv[1]).read()
def replace_fn(sig, new):
    global s
    i = s.index(sig); j = s.index("\n}\n", i) + 3
    s = s[:i] + new + s[j:]
decl = '''/* The wheel-index and rounding arithmetic is in timer_rs.rs. */
unsigned int rust_timer_calc_wheel_index(unsigned long expires, unsigned long clk, unsigned long *bucket_expiry, unsigned int lvl_depth);
unsigned long rust_timer_round_jiffies(unsigned long j, int cpu, bool force_up, int hz);

static_assert(LVL_CLK_SHIFT == 3 && LVL_BITS == 6 && (HZ > 100 ? LVL_DEPTH == 9 : LVL_DEPTH == 8));

'''
replace_fn("static unsigned long round_jiffies_common(", decl + '''static unsigned long round_jiffies_common(unsigned long j, int cpu,
		bool force_up)
{
	unsigned long original = j;

	j = rust_timer_round_jiffies(j, cpu, force_up, HZ);

	/*
	 * Make sure j is still in the future. Otherwise return the
	 * unmodified value.
	 */
	return time_is_after_jiffies(j) ? j : original;
}
''')
replace_fn("static inline unsigned calc_index(", "")
replace_fn("static int calc_wheel_index(", '''static int calc_wheel_index(unsigned long expires, unsigned long clk,
			    unsigned long *bucket_expiry)
{
	return rust_timer_calc_wheel_index(expires, clk, bucket_expiry, LVL_DEPTH);
}
''')
hdr = "// SPDX-License-Identifier: GPL-2.0\n/*\n * RUST PORT (kernel/time/timer.c, 6.18.49): calc_index, calc_wheel_index and the rounding of round_jiffies_common are in timer_rs.rs. This file keeps the timer\n * bases, lists, softirq, NO_HZ and the exports as upstream has them, passes HZ and LVL_DEPTH, and keeps the final time_is_after_jiffies() test. Upstream's whole file is installed as\n * timer_norust.c for CONFIG_RUST=n.\n */\n"
s = s.replace("// SPDX-License-Identifier: GPL-2.0\n", hdr, 1)
open(sys.argv[2], "w").write(s)
