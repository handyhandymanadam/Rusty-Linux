#!/usr/bin/env python3
"""extract.py <pristine rsa_helper.c> <out.c>: slice the eight rsa_get_* functions (everything from `int rsa_get_n(` to the
doc comment of rsa_parse_pub_key) out of the UNMODIFIED crypto/rsa_helper.c, character for character, and rename them c_*.
Fails loudly if the span does not hold exactly the eight definitions."""
import sys, re
src = open(sys.argv[1]).read()
a = src.index("int rsa_get_n(")
b = src.index("/**\n * rsa_parse_pub_key()")
span = src[a:b]
names = ["n", "e", "d", "p", "q", "dp", "dq", "qinv"]
for nm in names:
    if span.count("int rsa_get_%s(void *context" % nm) != 1:
        sys.exit("EXTRACT FAILED: rsa_get_%s not found exactly once -- the C changed" % nm)
if len(re.findall(r"^int rsa_get_", span, re.M)) != 8:
    sys.exit("EXTRACT FAILED: the span does not hold exactly eight rsa_get_* functions")
for nm in names:
    span = span.replace("int rsa_get_%s(" % nm, "int c_rsa_get_%s(" % nm, 1)
open(sys.argv[2], "w").write('#include "kshim.h"\n' + span)
