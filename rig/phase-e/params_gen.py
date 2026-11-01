#!/usr/bin/env python3
"""params_gen.py <pristine params.c> <pristine lib/cmdline.c> <out.inc>: the REAL C of dash2underscore, parameqn, parameq,
param_check_unsafe, parse_one, parse_args (params.c) and next_arg (lib/cmdline.c), cut by markers, nothing edited."""
import sys
def cut(path, start, endmark_after=None):
    src = open(path).read().split('\n')
    a = next(i for i, l in enumerate(src) if l.startswith(start))
    return src, a
p, a = cut(sys.argv[1], 'static char dash2underscore')
d = next(i for i, l in enumerate(p) if l.startswith('char *parse_args'))
e = next(i for i in range(d, len(p)) if p[i] == '}')
out = p[a:e + 1]
c, k = cut(sys.argv[2], 'char *next_arg')
e = next(i for i in range(k, len(c)) if c[i] == '}')
out += c[k:e + 1]
open(sys.argv[3], 'w').write('\n'.join(out) + '\n')
