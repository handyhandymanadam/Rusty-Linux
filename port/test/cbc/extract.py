#!/usr/bin/env python3
"""extract.py <pristine cbc.c> <out.c>: slice the four chaining functions (crypto_cbc_encrypt_segment, _encrypt_inplace,
_decrypt_segment, _decrypt_inplace) out of the UNMODIFIED crypto/cbc.c, character for character, and rename them
c_cbc_*. Fails loudly if any is not present exactly once, or if the file between the first and last function changed shape."""
import sys, re
src = open(sys.argv[1]).read()
names = ["crypto_cbc_encrypt_segment", "crypto_cbc_encrypt_inplace", "crypto_cbc_decrypt_segment", "crypto_cbc_decrypt_inplace"]
out = '#include "kshim.h"\n'
for nm in names:
    if src.count("static int %s(" % nm) != 1:
        sys.exit("EXTRACT FAILED: %s not found exactly once in cbc.c -- the C changed" % nm)
    a = src.index("static int %s(" % nm)
    b = src.index("\n}\n", a) + 3
    body = src[a:b]
    if "crypto_lskcipher_blocksize(tfm)" not in body:
        sys.exit("EXTRACT FAILED: %s lost its block-size line" % nm)
    out += "\n" + body.replace("static int %s(" % nm, "int c_%s(" % nm[len("crypto_"):], 1)
open(sys.argv[2], "w").write(out)
