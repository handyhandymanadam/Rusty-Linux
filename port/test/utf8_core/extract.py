#!/usr/bin/env python3
"""extract.py SOURCE.c OUT.c -- the comparison / folding / hashing functions of the PRISTINE utf8-core.c (C side), or of the glue with its wrappers (Rust side), as a standalone C file."""
import sys
s = open(sys.argv[1]).read()
a = s.index("int utf8_validate("); b = s.index("static const struct utf8data *find_table_version(")
body = s[a:b]
if "RUST-WRAPPERS BEGIN" in s:
    body = s[s.index("/* RUST-WRAPPERS BEGIN"):s.index("/* RUST-WRAPPERS END */")] + body
open(sys.argv[2], "w").write('#include "refshim.h"\n#include "utf8n.h"\n' + body)
