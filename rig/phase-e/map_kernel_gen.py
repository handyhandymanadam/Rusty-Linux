#!/usr/bin/env python3
"""map_kernel_gen.py <pristine map_kernel.c> <out.inc>: the REAL C of map_kernel.c from its first function
to the end, with exactly two edits: the two `for (;;);` become `return 0xdead0001/2;` so a userspace test
can observe the hang, and __startup_64 is renamed c_startup_64. Prints the edits it made."""
import re, sys
s = open(sys.argv[1]).read()
i = s.index("static inline bool check_la57_support")
body = s[i:]
a = "\tif (physaddr >> MAX_PHYSMEM_BITS)\n\t\tfor (;;);"
b = "\tif (load_delta & ~PMD_MASK)\n\t\tfor (;;);"
assert body.count(a) == 1 and body.count(b) == 1 and body.count("for (;;);") == 2
body = body.replace(a, a.replace("for (;;);", "return 0xdead0001UL;")).replace(b, b.replace("for (;;);", "return 0xdead0002UL;"))
assert body.count("__startup_64(") == 1
body = body.replace("__startup_64(", "c_startup_64(")
open(sys.argv[2], "w").write(body)
print("edits: 2 hangs -> return 0xdead0001/2; __startup_64 -> c_startup_64; %d bytes of C kept" % len(body))
