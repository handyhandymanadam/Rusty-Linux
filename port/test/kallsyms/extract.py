#!/usr/bin/env python3
"""extract.py SOURCE.c OUT.c -- the table walkers of the PRISTINE kernel/kallsyms.c, or of kallsyms_glue.c (same functions as wrappers, plus the Rust structure, prototypes and ksyms()),
as a standalone C file for the differential test."""
import sys
s = open(sys.argv[1]).read()
def fn(sig):
    i = s.index(sig); j = s.index("\n}\n", i) + 3
    return s[i:j]
out = ['#include "refshim.h"\n']
if "struct rust_ksyms {" in s:
    a = s.index("/* The table walkers are in kallsyms_rs.rs;"); b = s.index("static_assert(KSYM_NAME_LEN")
    out.append(s[a:b])
for sig in ("static unsigned int kallsyms_expand_symbol(", "static char kallsyms_get_symbol_type(", "static unsigned int get_symbol_offset(", "unsigned long kallsyms_sym_address(",
            "static unsigned int get_symbol_seq(", "static int kallsyms_lookup_names(", "static unsigned long get_symbol_pos("):
    out.append(fn(sig))
open(sys.argv[2], "w").write("\n".join(out))
