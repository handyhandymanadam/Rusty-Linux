#!/usr/bin/env python3
"""extract_ref.py PRISTINE notifier.c OUT.c -- the chain core of the PRISTINE kernel/notifier.c as a standalone reference."""
import sys
s = open(sys.argv[1]).read()
a = s.index("static int notifier_chain_register(")
b = s.index("int atomic_notifier_chain_register(")
c = s.rindex("/**", a, b)
open(sys.argv[2], "w").write('#include "refshim.h"\n' + s[a:c] + '''
int ref_register(struct notifier_block **nl, struct notifier_block *n, bool u) { return notifier_chain_register(nl, n, u); }
int ref_unregister(struct notifier_block **nl, struct notifier_block *n) { return notifier_chain_unregister(nl, n); }
int ref_call(struct notifier_block **nl, unsigned long v, void *p, int k, int *nc) { return notifier_call_chain(nl, v, p, k, nc); }
int ref_robust(struct notifier_block **nl, unsigned long u, unsigned long d, void *p) { return notifier_call_chain_robust(nl, u, d, p); }
''')
