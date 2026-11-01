#!/usr/bin/env python3
"""extract.py SOURCE.c OUT.c -- the bitmap functions of the PRISTINE ebitmap.c (mode ref), or the rust_eb_* wrappers of ebitmap_glue.c (mode rs), as a standalone C file."""
import sys
s = open(sys.argv[1]).read()
if "RUST-WRAPPERS BEGIN" in s:
    a = s.index("/* RUST-WRAPPERS BEGIN"); b = s.index("/* RUST-WRAPPERS END */")
    body = s[a:b]
else:
    a = s.index("bool ebitmap_equal("); b = s.index("#ifdef CONFIG_NETLABEL")
    c = s.index("/*\n * Check to see if all the bits set in e2"); d = s.index("void __init ebitmap_cache_init(void)")
    body = s[a:b] + s[c:d]
open(sys.argv[2], "w").write('#include "refshim.h"\n#include "ebitmap.h"\n#define BITS_PER_U64 ((u32)(sizeof(u64) * 8))\n#include <linux/jhash.h>\n' + body)
