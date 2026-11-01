#!/usr/bin/env python3
"""Slice the five callbacks (ghash_init .. ghash_exit_tfm) out of the PRISTINE
crypto/ghash-generic.c (every run, never copied)."""
import sys
s = open(sys.argv[1]).read()
a = s.index("static int ghash_init(")
b = s.index("static struct shash_alg ghash_alg")
open(sys.argv[2], "w").write(s[a:b])
