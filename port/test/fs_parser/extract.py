#!/usr/bin/env python3
"""extract.py KIND SOURCE.c OUT.c -- the parsing code of the PRISTINE fs_parser.c (C side) or the rust_fp_* shims plus the thunks of the glue (Rust side) as a standalone C file."""
import sys
s = open(sys.argv[1]).read()
if "RUST-WRAPPERS BEGIN" in s:
    # the wrappers and the thunks lookup_constant .. fs_param_is_gid
    wr = s[s.index("/* RUST-WRAPPERS BEGIN"):s.index("/* RUST-WRAPPERS END */")]
    a = s.index("int lookup_constant("); b = s.index("int fs_lookup_param(")
    c = s.index("int fs_param_is_bool(", b); d = s.index("int fs_param_is_blockdev(")
    body = wr + s[a:b] + s[c:d]
else:
    a = s.index("static const struct constant_table *\n__lookup_constant("); b = s.index("/**\n * fs_lookup_param")
    c = s.index("static int fs_param_bad_value("); d = s.index("int fs_param_is_blockdev(")
    body = s[a:b] + s[c:d]
open(sys.argv[2], "w").write('#include "refshim.h"\n' + body)
