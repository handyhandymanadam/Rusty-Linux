#!/usr/bin/env python3
"""extract.py SOURCE.c OUT.c -- cubic_root() and bictcp_update() of the PRISTINE tcp_cubic.c (C side), or the wrappers of tcp_cubic_glue.c (Rust side), plus struct bictcp, as a standalone C file."""
import sys
s = open(sys.argv[1]).read()
st = s[s.index("struct bictcp {"):s.index("};", s.index("struct bictcp {")) + 3]
if "RUST-WRAPPERS BEGIN" in s:
    body = s[s.index("/* RUST-WRAPPERS BEGIN"):s.index("/* RUST-WRAPPERS END */")]
else:
    a = s.index("static u32 cubic_root(u64 a)"); b = s.index("__bpf_kfunc static void cubictcp_cong_avoid(")
    body = s[a:b]
open(sys.argv[2], "w").write('#include "refshim.h"\n' + st + body)
