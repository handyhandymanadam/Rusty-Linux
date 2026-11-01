#!/usr/bin/env python3
"""extract.py SOURCE.c OUT.c -- the functions of the PRISTINE conditional.c (C side), or the rust_cd_* wrappers of conditional_glue.c (Rust side), as a standalone C file."""
import sys
s = open(sys.argv[1]).read()
if "RUST-WRAPPERS BEGIN" in s:
    body = s[s.index("/* RUST-WRAPPERS BEGIN"):s.index("/* RUST-WRAPPERS END */")]
else:
    body = s[s.index("/*\n * cond_evaluate_expr evaluates"):]
open(sys.argv[2], "w").write('#include "refshim.h"\n#include "avtab.h"\n#include "policydb.h"\n#include "conditional.h"\n#include "services.h"\n#define COND_EXPR_MAXDEPTH_CHECK 0\n' + body)
