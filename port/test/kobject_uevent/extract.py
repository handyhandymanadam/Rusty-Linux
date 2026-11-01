#!/usr/bin/env python3
"""extract.py <pristine kobject_uevent.c> <glue kobject_uevent_glue.c> <out ref.c> <out rs.c>: the pieces of the two files the differential compiles."""
import re, sys
P = open(sys.argv[1]).read().split('\n'); G = open(sys.argv[2]).read(); GL = G.split('\n')
def fn(L, pat, end='}'):
    i = next(k for k, l in enumerate(L) if re.match(pat, l)); e = i
    while L[e] != end: e += 1
    return '\n'.join(L[i:e + 1])
ref = '\n\n'.join([fn(P, r'static int kobject_action_type'), fn(P, r'static const char \*action_arg_word_end'), fn(P, r'static int kobject_action_args'),
                   fn(P, r'int kobject_synth_uevent'), fn(P, r'static void zap_modalias_env'), fn(P, r'int add_uevent_var')])
open(sys.argv[3], 'w').write(ref)
b = G[G.index('/* ---- BEGIN RUST WRAPPERS'):G.index('/* ---- END RUST WRAPPERS')]
rs = b + '\n' + fn(GL, r'int kobject_synth_uevent') + '\n' + fn(GL, r'static void zap_modalias_env') + '\n' + fn(P, r'int add_uevent_var')
open(sys.argv[4], 'w').write(rs)
