#!/usr/bin/env python3
"""mkglue.py PRISTINE.c OUT.c -- clocksource_glue.c = upstream clocksource.c with the conversion arithmetic replaced by calls into clocksource_rs.rs (see kernel/time/clocksource_rs.rs)."""
import sys
s = open(sys.argv[1]).read()
def replace(sig, new):
    global s
    i = s.index(sig); j = s.index("\n}\n", i) + 3
    s = s[:i] + new + s[j:]
replace("void\nclocks_calc_mult_shift(", '''void
clocks_calc_mult_shift(u32 *mult, u32 *shift, u32 from, u32 to, u32 maxsec)
{
	rust_clocks_calc_mult_shift(mult, shift, from, to, maxsec);
}
''')
replace("static u32 clocksource_max_adjustment(", "")
replace("u64 clocks_calc_max_nsecs(", '''u64 clocks_calc_max_nsecs(u32 mult, u32 shift, u32 maxadj, u64 mask, u64 *max_cyc)
{
	return rust_clocks_calc_max_nsecs(mult, shift, maxadj, mask, max_cyc);
}
''')
replace("static inline void clocksource_update_max_deferment(", "")
replace("void __clocksource_update_freq_scale(", '''void __clocksource_update_freq_scale(struct clocksource *cs, u32 scale, u32 freq)
{
	struct rust_cs_math m = {
		.mask = cs->mask, .max_idle_ns = cs->max_idle_ns, .max_cycles = cs->max_cycles, .max_raw_delta = cs->max_raw_delta,
		.mult = cs->mult, .shift = cs->shift, .maxadj = cs->maxadj, .uncertainty_margin = cs->uncertainty_margin,
	};

	rust_cs_update_freq_scale(&m, scale, freq, WATCHDOG_MAX_SKEW, WATCHDOG_THRESHOLD);
	cs->mult = m.mult;
	cs->shift = m.shift;
	cs->maxadj = m.maxadj;
	cs->uncertainty_margin = m.uncertainty_margin;
	cs->max_idle_ns = m.max_idle_ns;
	cs->max_cycles = m.max_cycles;
	cs->max_raw_delta = m.max_raw_delta;

	WARN_ON_ONCE(cs->uncertainty_margin < 2 * WATCHDOG_MAX_SKEW);

	/*
	 * Only warn for *special* clocksources that self-define
	 * their mult/shift values and don't specify a freq.
	 */
	WARN_ONCE(cs->mult + cs->maxadj < cs->mult,
		"timekeeping: Clocksource %s might overflow on 11%% adjustment\\n",
		cs->name);

	pr_info("%s: mask: 0x%llx max_cycles: 0x%llx, max_idle_ns: %lld ns\\n",
		cs->name, cs->mask, cs->max_cycles, cs->max_idle_ns);
}
''')
decl1 = '''/* The conversion arithmetic is in clocksource_rs.rs. The update works on a copy of the fields it touches. */
struct rust_cs_math {
	u64 mask, max_idle_ns, max_cycles, max_raw_delta;
	u32 mult, shift, maxadj, uncertainty_margin;
};
void rust_clocks_calc_mult_shift(u32 *mult, u32 *shift, u32 from, u32 to, u32 maxsec);
u64 rust_clocks_calc_max_nsecs(u32 mult, u32 shift, u32 maxadj, u64 mask, u64 *max_cyc);
void rust_cs_update_freq_scale(struct rust_cs_math *m, u32 scale, u32 freq, long max_skew, long threshold);

'''
decl2 = '''
/* The constant the Rust uses is checked against the header; the type of the two thresholds is long. */
static_assert(NSEC_PER_SEC == 1000000000L);
static_assert(sizeof(struct rust_cs_math) == 48);
static_assert(sizeof(WATCHDOG_MAX_SKEW) == sizeof(long) && sizeof(WATCHDOG_THRESHOLD) == sizeof(long));
'''
i = s.index("#define WATCHDOG_MAX_SKEW")
j = s.index("\n", i) + 1
s = s[:j] + decl2 + s[j:]
k = s.index("static void clocksource_enqueue(struct clocksource *cs);")
s = s[:k] + decl1 + s[k:]
hdr = "// SPDX-License-Identifier: GPL-2.0+\n/*\n * RUST PORT (kernel/time/clocksource.c, 6.18.49): clocks_calc_mult_shift, clocks_calc_max_nsecs, clocksource_max_adjustment, clocksource_update_max_deferment and the\n * arithmetic of __clocksource_update_freq_scale are in clocksource_rs.rs. This file keeps the registration list, the watchdog, selection and sysfs as upstream has them, the entry\n * points as thunks, and the two WARNs and the pr_info of __clocksource_update_freq_scale. Upstream's whole file is installed as clocksource_norust.c for CONFIG_RUST=n.\n */\n"
s = s.replace("// SPDX-License-Identifier: GPL-2.0+\n", hdr, 1)
open(sys.argv[2], "w").write(s)
