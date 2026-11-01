#!/usr/bin/env python3
"""extract.py SOURCE.c OUT.c -- the arithmetic-bearing functions of the PRISTINE kernel/time/clockevents.c, or of clockevents_glue.c (same functions with the Rust calls, plus the
Rust prototypes), as a standalone C file for the differential test. Both CONFIG_GENERIC_CLOCKEVENTS_MIN_ADJUST arms of clockevents_program_min_delta are emitted."""
import sys
s = open(sys.argv[1]).read()
def fn(sig, start=0):
    i = s.index(sig, start); j = s.index("\n}\n", i) + 3
    return s[i:j]
out = ['#include "refshim.h"\n']
if "u64 rust_ce_delta2ns" in s:
    a = s.index("/* The conversion arithmetic is in clockevents_rs.rs. */"); b = s.index("static LIST_HEAD(clockevent_devices);")
    out.append(s[a:b])
out.append(fn("static u64 cev_delta2ns("))
else_pos = s.index("#else  /* CONFIG_GENERIC_CLOCKEVENTS_MIN_ADJUST */")
out.append("#ifdef MIN_ADJUST\n" + fn("static int clockevents_increase_min_delta(") + "\n" + fn("static int clockevents_program_min_delta(") + "#else\n" + fn("static int clockevents_program_min_delta(", else_pos) + "#endif\n")
out.append(fn("static void clockevents_config("))
out.append(fn("int clockevents_program_event("))
open(sys.argv[2], "w").write("\n".join(out))
