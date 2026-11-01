#!/usr/bin/env python3
"""Slice the two static helpers (__lzo[rle]_compress, __lzo[rle]_decompress) out
of the PRISTINE crypto/lzo.c or crypto/lzo-rle.c (every run, never copied)."""
import re, sys
s = open(sys.argv[1]).read()
a = s.index("static int __lzo")
b = re.search(r"static int lzo(rle)?_scompress", s).start()
c = s.index("static int __lzo", b)
d = re.search(r"static int lzo(rle)?_sdecompress", s).start()
open(sys.argv[2], "w").write(s[a:b] + s[c:d])
