#!/usr/bin/env python3
"""extract_ref.py PRISTINE ucount.c OUT.c -- the counter walks of the PRISTINE kernel/ucount.c as a standalone reference."""
import sys
s = open(sys.argv[1]).read()
def fn(sig):
    i = s.index(sig); j = s.index("\n}\n", i) + 3
    return s[i:j]
parts = [fn("static inline bool atomic_long_inc_below("), fn("struct ucounts *inc_ucount("), fn("void dec_ucount("), fn("long inc_rlimit_ucounts("),
         fn("bool dec_rlimit_ucounts("), fn("static void do_dec_rlimit_put_ucounts("), fn("void dec_rlimit_put_ucounts("), fn("long inc_rlimit_get_ucounts("),
         fn("bool is_rlimit_overlimit(")]
open(sys.argv[2], "w").write('#include "refshim.h"\n' + "\n".join(parts))
