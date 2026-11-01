#!/usr/bin/env python3
"""extract.py SOURCE.c OUT.c -- the table functions of the PRISTINE avtab.c (C side), or the rust_av_* wrappers of avtab_glue.c (Rust side), as a standalone C file."""
import sys
s = open(sys.argv[1]).read()
if "RUST-WRAPPERS BEGIN" in s:
    body = s[s.index("/* RUST-WRAPPERS BEGIN"):s.index("/* RUST-WRAPPERS END */")]
else:
    a = s.index("/* Based on MurmurHash3"); b = s.index("#ifdef CONFIG_SECURITY_SELINUX_DEBUG")
    c = s.index("/* clang-format off */"); d = s.index("void __init avtab_cache_init(void)")
    body = s[a:b] + s[c:d]
open(sys.argv[2], "w").write('#include "refshim.h"\n#include "avtab.h"\n#include "policydb.h"\n' + body)
