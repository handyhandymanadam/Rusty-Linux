#!/usr/bin/env python3
"""early_gen.py <pristine main.c> <out.inc>: the REAL C of do_early_param, parse_early_options, parse_early_param (one contiguous block), unedited."""
import sys
src = open(sys.argv[1]).read().split('\n')
a = next(i for i, l in enumerate(src) if l.startswith('/* Check for early params. */'))
d = next(i for i, l in enumerate(src) if l.startswith('void __init parse_early_param'))
b = next(i for i in range(d, len(src)) if src[i] == '}')
open(sys.argv[2], 'w').write('\n'.join(src[a:b + 1]) + '\n')
