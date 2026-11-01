#!/usr/bin/env python3
"""extract.py PRISTINE GLUE OUTDIR -- slice the code under test out of the two C files
every run (never copied):
  ref_slice.c  : pristine crypto/aes_generic.c from byte() through crypto_aes_decrypt()
                 (all four tables, crypto_aes_set_key, both block functions)
  subj_slice.c : the real glue port/tree/crypto/aes_generic_glue.c from crypto_ft_tab
                 through crypto_aes_decrypt() (ft/it data, set_key, the two thunks)"""
import sys, os
pr, gl, out = sys.argv[1:4]
s = open(pr).read()
a = s.index("static inline u8 byte("); b = s.index("static struct crypto_alg aes_alg")
open(os.path.join(out, "ref_slice.c"), "w").write(s[a:b])
g = open(gl).read()
a = g.index("__visible const u32 crypto_ft_tab"); b = g.index("static struct crypto_alg aes_alg")
open(os.path.join(out, "subj_slice.c"), "w").write(g[a:b])
