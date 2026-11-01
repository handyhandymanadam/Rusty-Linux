#!/usr/bin/env python3
"""extract.py SOURCE.c OUT.c -- the text engine of the integer handlers of the PRISTINE kernel/sysctl.c, or of sysctl_glue.c (same functions as wrappers, plus the Rust
prototypes), as a standalone C file for the differential test."""
import sys
s = open(sys.argv[1]).read()
def fn(sig):
    i = s.index(sig); j = s.index("\n}\n", i) + 3
    return s[i:j]
out = ['#include "refshim.h"\n']
out.append(fn("static void warn_sysctl_write(")); out.append(fn("static bool proc_first_pos_non_zero_ignore("))
if "rust_sysctl_get_long" in s:
    a = s.index("/* The text engine of the integer handlers is in sysctl_rs.rs. */"); b = s.index("/* The layout the Rust uses")
    out.append(s[a:b])
out.append("#define TMPBUFLEN 22\n")
for sig in ("static void proc_skip_spaces(", "static void proc_skip_char(", "static int strtoul_lenient(", "static int proc_get_long(", "static void proc_put_long(", "static void proc_put_char(",
            "static int do_proc_dointvec_conv(", "static int do_proc_douintvec_conv("):
    if sig in s:
        out.append(fn(sig))
out.append("#undef TMPBUFLEN\nstatic const char proc_wspace_sep[] = { ' ', '\\t', '\\n' };\n")
out.append("struct do_proc_dointvec_minmax_conv_param { int *min; int *max; };\nstruct do_proc_douintvec_minmax_conv_param { unsigned int *min; unsigned int *max; };\n")
for sig in ("static int __do_proc_dointvec(", "static int do_proc_douintvec_w(", "static int do_proc_douintvec_r(", "static int __do_proc_douintvec(", "static int do_proc_dointvec_minmax_conv(",
            "static int do_proc_douintvec_minmax_conv(", "static int __do_proc_doulongvec_minmax(", "static int do_proc_dointvec_jiffies_conv("):
    out.append(fn(sig))
open(sys.argv[2], "w").write("\n".join(out))
