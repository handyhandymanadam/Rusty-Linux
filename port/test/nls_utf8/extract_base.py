#!/usr/bin/env python3
"""Slice utf8_to_utf32/utf32_to_utf8 (and their table) out of the PRISTINE
fs/nls/nls_base.c into a standalone C file. Extracted every run, never copied."""
import sys
s = open(sys.argv[1]).read()
a = s.index("struct utf8_table {")
b = s.index("static inline void put_utf16")
open(sys.argv[2], "w").write(
    '#include <linux/init.h>\n#include <linux/nls.h>\n#include <linux/errno.h>\n'
    '#define EXPORT_SYMBOL(x)\n' + s[a:b])
