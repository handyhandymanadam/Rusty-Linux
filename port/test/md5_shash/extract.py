#!/usr/bin/env python3
"""Slice the four static export/import helpers and md5_zero_message_hash out of
the PRISTINE crypto/md5.c (every run, never copied)."""
import sys
s = open(sys.argv[1]).read()
a = s.index("static int __crypto_md5_export(")
b = s.index("EXPORT_SYMBOL_GPL(md5_zero_message_hash);")
open(sys.argv[2], "w").write(s[a:b])
