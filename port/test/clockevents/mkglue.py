#!/usr/bin/env python3
"""mkglue.py PRISTINE.c OUT.c -- clockevents_glue.c = upstream clockevents.c with the conversion arithmetic replaced by calls into clockevents_rs.rs (see kernel/time/clockevents_rs.rs)."""
import sys
s = open(sys.argv[1]).read()
def sub(old, new, count):
    global s
    assert s.count(old) == count, (old, s.count(old))
    s = s.replace(old, new)
def replace_fn(sig, new):
    global s
    i = s.index(sig); j = s.index("\n}\n", i) + 3
    s = s[:i] + new + s[j:]
replace_fn("static u64 cev_delta2ns(", '''static u64 cev_delta2ns(unsigned long latch, struct clock_event_device *evt,
			bool ismax)
{
	if (WARN_ON(!evt->mult))
		evt->mult = 1;

	return rust_ce_delta2ns(latch, evt->mult, evt->shift, ismax);
}
''')
sub("clc = ((unsigned long long) delta * dev->mult) >> dev->shift;", "clc = rust_ce_ns2ticks(delta, dev->mult, dev->shift);", 3)
sub("\tdelta = min(delta, (int64_t) dev->max_delta_ns);\n\tdelta = max(delta, (int64_t) dev->min_delta_ns);\n", "\tdelta = rust_ce_clamp_delta(delta, dev->min_delta_ns, dev->max_delta_ns);\n", 1)
sub("\tif (dev->min_delta_ns < 5000)\n\t\tdev->min_delta_ns = 5000;\n\telse\n\t\tdev->min_delta_ns += dev->min_delta_ns >> 1;\n\n\tif (dev->min_delta_ns > MIN_DELTA_LIMIT)\n\t\tdev->min_delta_ns = MIN_DELTA_LIMIT;\n",
    "\tdev->min_delta_ns = rust_ce_bump_min_delta(dev->min_delta_ns, MIN_DELTA_LIMIT);\n", 1)
sub("\tsec = dev->max_delta_ticks;\n\tdo_div(sec, freq);\n\tif (!sec)\n\t\tsec = 1;\n\telse if (sec > 600 && dev->max_delta_ticks > UINT_MAX)\n\t\tsec = 600;\n",
    "\tsec = rust_ce_config_sec(dev->max_delta_ticks, freq);\n", 1)
decl = '''/* The conversion arithmetic is in clockevents_rs.rs. */
u64 rust_ce_delta2ns(unsigned long latch, u32 mult, u32 shift, bool ismax);
u64 rust_ce_ns2ticks(s64 delta, u32 mult, u32 shift);
s64 rust_ce_clamp_delta(s64 delta, u64 min_delta_ns, u64 max_delta_ns);
u64 rust_ce_bump_min_delta(u64 min_delta_ns, u64 limit);
u64 rust_ce_config_sec(unsigned long max_delta_ticks, u32 freq);

'''
k = s.index("static LIST_HEAD(clockevent_devices);")
s = s[:k] + decl + s[k:]
hdr = "// SPDX-License-Identifier: GPL-2.0\n/*\n * RUST PORT (kernel/time/clockevents.c, 6.18.49): cev_delta2ns, the ticks conversion, the delta clamp, the min-delta growth and the seconds limit of clockevents_config are\n * in clockevents_rs.rs. This file keeps the device list, state handling, programming, binding and sysfs as upstream has them, and passes the fields the arithmetic needs.\n * Upstream's whole file is installed as clockevents_norust.c for CONFIG_RUST=n.\n */\n"
s = s.replace("// SPDX-License-Identifier: GPL-2.0\n", hdr, 1)
open(sys.argv[2], "w").write(s)
