#!/usr/bin/env python3
"""extract.py SOURCE.c OUT.c -- fixed_power_int() and calc_load_n() of the PRISTINE loadavg.c (C side); the Rust side needs only the prototype."""
import sys
s = open(sys.argv[1]).read()
if "loadavg_rs.rs" in s and "RUST PORT" in s:
    body = "unsigned long calc_load_n(unsigned long load, unsigned long exp, unsigned long active, unsigned int n);\n"
else:
    a = s.index("static unsigned long\nfixed_power_int("); b = s.index("#ifdef CONFIG_NO_HZ_COMMON", a)
    body = s[a:b]
open(sys.argv[2], "w").write('#include "refshim.h"\n' + body)
