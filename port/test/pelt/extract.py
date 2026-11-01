#!/usr/bin/env python3
"""extract.py SOURCE.c OUT.c -- the PELT arithmetic helpers of the PRISTINE kernel/sched/pelt.c (C side), or the wrappers of the glue (Rust side), as a standalone C file."""
import sys
s = open(sys.argv[1]).read()
if "RUST-WRAPPERS BEGIN" in s:
    body = s[s.index("/* RUST-WRAPPERS BEGIN"):s.index("/* RUST-WRAPPERS END */")]
else:
    body = s[s.index("static u64 decay_load(u64 val, u64 n)"):s.index("int __update_load_avg_blocked_se(")]
open(sys.argv[2], "w").write('#include "refshim.h"\n' + body)
