#!/usr/bin/env python3
"""Slice the four static export/import helpers out of the PRISTINE
crypto/sha256.c (every run, never copied)."""
import sys
s = open(sys.argv[1]).read()
a = s.index("static int __crypto_sha256_export(")
b = s.index("/* SHA-224 */")
open(sys.argv[2], "w").write(s[a:b])
