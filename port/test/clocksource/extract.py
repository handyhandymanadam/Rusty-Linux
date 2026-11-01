#!/usr/bin/env python3
"""extract.py SOURCE.c OUT.c -- the conversion functions of the PRISTINE kernel/time/clocksource.c, or of clocksource_glue.c (the same functions as thunks, plus the Rust
declarations and struct), as a standalone C file for the differential test."""
import sys
s = open(sys.argv[1]).read()
parts = []
if "struct rust_cs_math {" in s:
    a = s.index("struct rust_cs_math {"); b = s.index("static void clocksource_enqueue(struct clocksource *cs);")
    parts.append(s[a:b])
for sig in ("void\nclocks_calc_mult_shift(", "static u32 clocksource_max_adjustment(", "u64 clocks_calc_max_nsecs(", "static inline void clocksource_update_max_deferment(", "void __clocksource_update_freq_scale("):
    if sig not in s:
        continue
    i = s.index(sig); j = s.index("\n}\n", i) + 3
    parts.append(s[i:j])
open(sys.argv[2], "w").write('#include "refshim.h"\n' + "\n".join(parts))
