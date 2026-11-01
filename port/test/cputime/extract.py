#!/usr/bin/env python3
"""extract.py SOURCE.c OUT.c -- the tick-based cputime_adjust() of the PRISTINE kernel/sched/cputime.c (C side), or of the glue with its wrappers (Rust side), as a standalone C file."""
import sys
s = open(sys.argv[1]).read()
head = s.index(" * Adjust tick based cputime random precision")
a = s.index("void cputime_adjust(struct task_cputime *curr, struct prev_cputime *prev,", head)
b = s.index("\n}\n", a) + 3
body = s[a:b]
if "RUST-WRAPPERS BEGIN" in s:
    body = s[s.index("/* RUST-WRAPPERS BEGIN"):s.index("/* RUST-WRAPPERS END */")] + body
open(sys.argv[2], "w").write('#include "refshim.h"\n' + body)
