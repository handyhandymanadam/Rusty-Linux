#!/usr/bin/env python3
"""extract.py KIND SOURCE.c OUT.c -- KIND hashtab|symtab: the pristine functions (C side) or the rust_* wrappers of the glue (Rust side), as a standalone C file."""
import sys
kind, src, out = sys.argv[1:4]
s = open(src).read()
if "RUST-WRAPPERS BEGIN" in s:
    body = s[s.index("/* RUST-WRAPPERS BEGIN"):s.index("/* RUST-WRAPPERS END */")]
elif kind == "hashtab":
    body = s[s.index("static u32 hashtab_compute_size("):s.index("#ifdef CONFIG_SECURITY_SELINUX_DEBUG")] + s[s.index("int hashtab_duplicate("):s.index("void __init hashtab_cache_init(void)")]
else:
    body = s[s.index("static unsigned int symhash("):]
open(out, "w").write('#include "refshim.h"\n#include "hashtab.h"\n#include "symtab.h"\n' + body)
