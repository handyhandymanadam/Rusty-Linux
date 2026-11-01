#!/usr/bin/env python3
"""extract.py SOURCE.c OUT.c -- the pristine bitmap32 helpers, ethnl_bitset32_size() and ethnl_bitmap32_equal() as a standalone C file (the C side), or the prototype block of bitset_glue.c (the Rust side)."""
import sys
s = open(sys.argv[1]).read()
if "RUST-PROTOS BEGIN" in s:
    body = s[s.index("/* RUST-PROTOS BEGIN"):s.index("/* RUST-PROTOS END */")]
    body += "int ethnl_bitset32_size(const u32 *val, const u32 *mask, unsigned int nbits, ethnl_string_array_t names, bool compact);\n"
    # the glue keeps ethnl_lower_bits() for its own use; the harness does not need it
else:
    def fn(sig):
        k = s.index(sig); return s[k:s.index("\n}\n", k) + 3]
    body = s[s.index("static u32 ethnl_lower_bits("):s.index("static bool ethnl_bitmap32_test_bit(")] + fn("static bool ethnl_bitmap32_test_bit(")
    body = body.replace("static void ethnl_bitmap32_clear", "void ethnl_bitmap32_clear").replace("static bool ethnl_bitmap32_not_zero", "bool ethnl_bitmap32_not_zero").replace("static void ethnl_bitmap32_update", "void ethnl_bitmap32_update")
    body += "\n" + fn("int ethnl_bitset32_size(") + "\n" + fn("static bool ethnl_bitmap32_equal(")
    body = body.replace("static bool ethnl_bitmap32_test_bit", "bool ethnl_bitmap32_test_bit").replace("static bool ethnl_bitmap32_equal", "bool ethnl_bitmap32_equal")
open(sys.argv[2], "w").write('#include "refshim.h"\n' + body)
