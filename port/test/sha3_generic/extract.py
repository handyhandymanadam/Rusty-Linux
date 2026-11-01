#!/usr/bin/env python3
"""Slice keccak core + crypto_sha3_{init,update,finup} out of the PRISTINE
crypto/sha3_generic.c (every run, never copied): from '#define KECCAK_ROUNDS'
to just before 'static struct shash_alg algs[]'."""
import sys
s = open(sys.argv[1]).read()
a = s.index("#define KECCAK_ROUNDS")
b = s.index("static struct shash_alg algs[]")
open(sys.argv[2], "w").write(s[a:b])
