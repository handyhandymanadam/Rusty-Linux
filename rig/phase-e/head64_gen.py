#!/usr/bin/env python3
"""head64_gen.py <pristine head64.c> <out.inc>: the REAL C of head64.c from reset_early_page_tables() to the end of
do_early_exception() (the early page-fault group), unedited except that `static void __init reset_early_page_tables`
keeps its `static` (the harness wraps it)."""
import sys
s = open(sys.argv[1]).read()
a = s.index("/* Wipe all early page tables except for the kernel symbol map */")
b = s.index("/* Don't add a printk in there.")
body = s[a:b]
assert body.count("__early_make_pgtable(") == 2 and "do_early_exception" in body
open(sys.argv[2], "w").write(body)
print("head64 C kept: %d bytes, no edits" % len(body))
