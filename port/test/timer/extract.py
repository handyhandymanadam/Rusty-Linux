#!/usr/bin/env python3
"""extract.py SOURCE.c OUT.c -- the wheel constants and the arithmetic-bearing functions of the PRISTINE kernel/time/timer.c, or of timer_glue.c (same functions as wrappers, plus the Rust
prototypes), as a standalone C file for the differential test. HZ is a compile-time define of the test, as in the kernel."""
import sys
s = open(sys.argv[1]).read()
def fn(sig):
    i = s.index(sig); j = s.index("\n}\n", i) + 3
    return s[i:j]
a = s.index("/* Clock divisor for the next level */"); b = s.index("/*\n * The resulting wheel size.")
out = ['#include "refshim.h"\n', s[a:b]]
if "rust_timer_calc_wheel_index" in s:
    i = s.index("/* The wheel-index and rounding arithmetic is in timer_rs.rs. */"); j = s.index("static_assert(", i)
    out.append(s[i:j])
for sig in ("static inline unsigned calc_index(", "static unsigned long round_jiffies_common(", "static int calc_wheel_index("):
    if sig in s:
        out.append(fn(sig))
open(sys.argv[2], "w").write("\n".join(out))
