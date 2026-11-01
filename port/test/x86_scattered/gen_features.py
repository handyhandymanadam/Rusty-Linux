#!/usr/bin/env python3
"""gen_features.py <asm/cpufeatures.h> <out.h>: numeric #defines for every X86_FEATURE_* of the REAL header (word*32+bit forms)."""
import re, sys
t = open(sys.argv[1]).read()
out = []
for m in re.finditer(r"^#define\s+(X86_FEATURE_\w+)\s+\(\s*(\d+)\s*\*\s*32\s*\+\s*(\d+)\s*\)", t, re.M):
    out.append("#define %s %d" % (m.group(1), int(m.group(2)) * 32 + int(m.group(3))))
open(sys.argv[2], "w").write("\n".join(out) + "\n")
print(len(out), "features", file=sys.stderr)
