#!/usr/bin/env python3
"""extract.py SOURCE.c OUT.c -- the hash algorithms and __ext4fs_dirhash() of the PRISTINE fs/ext4/hash.c, or of hash_glue.c (the Rust prototype and the dispatch), as a standalone C file."""
import sys
s = open(sys.argv[1]).read()
if "rust_ext4_dirhash" in s:
    a = s.index("/* The hash algorithms (TEA")
else:
    a = s.index("#define DELTA")
k = s.index("static int __ext4fs_dirhash("); b = s.index("\n}\n", k) + 3
open(sys.argv[2], "w").write('#include "refshim.h"\n' + s[a:b])
