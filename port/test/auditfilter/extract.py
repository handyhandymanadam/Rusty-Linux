#!/usr/bin/env python3
"""extract.py SOURCE.c OUT.c -- the pure checks of the PRISTINE kernel/auditfilter.c, or of auditfilter_glue.c (same functions as thunks, plus the Rust prototypes), as a standalone C file."""
import sys
s = open(sys.argv[1]).read()
def fn(sig):
    i = s.index(sig); j = s.index("\n}\n", i) + 3
    return s[i:j]
out = ['#include "refshim.h"\n']
a = s.index("static u32 audit_ops[] ="); b = s.index("\n};\n", a) + 4
out.append(s[a:b])
if "rust_audit_comparator" in s:
    a = s.index("/* The pure checks are in auditfilter_rs.rs. */"); b = s.index("/* The constants the Rust uses")
    out.append(s[a:b])
for sig in ("static u32 audit_to_op(", "static int audit_field_valid(", "int audit_comparator(", "int audit_uid_comparator(", "int audit_gid_comparator(", "int parent_len(", "int audit_compare_dname_path("):
    out.append(fn(sig))
open(sys.argv[2], "w").write("\n".join(out))
