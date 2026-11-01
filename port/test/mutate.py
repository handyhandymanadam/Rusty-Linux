#!/usr/bin/env python3
"""mutate.py <rust-source>: print the source with the first occurrence of $FROM replaced by $TO.
<NL> in either string stands for a newline (a literal backslash-n in the Rust, e.g. b'\\n', is left alone).
Exits 1 if $FROM is not in the source (a mutant that cannot be applied is a harness bug, not a catch)."""
import os, sys
s = open(sys.argv[1]).read()
f = os.environ["FROM"].replace("<NL>", "\n")
t = os.environ["TO"].replace("<NL>", "\n")
if f not in s:
    sys.exit("pattern missing: " + f)
sys.stdout.write(s.replace(f, t, 1))
