#!/usr/bin/env python3
"""extract.py <pristine iov_iter.c>: print the ported functions (and their static helpers) of lib/iov_iter.c, verbatim, for the oracle build."""
import re, sys
src = open(sys.argv[1]).read()
names = ['iov_iter_bvec_advance','iov_iter_iovec_advance','iov_iter_folioq_advance','iov_iter_advance','iov_iter_folioq_revert','iov_iter_revert',
         'iov_iter_single_seg_count','iov_iter_alignment_iovec','iov_iter_alignment_bvec','iov_iter_alignment','iov_iter_gap_alignment',
         'iov_npages','bvec_npages','iov_iter_npages','iov_iter_restore']
out = []
for n in names:
    m = re.search(r'^(?:static\s+)?[A-Za-z_][^\n;{}]*?\b' + re.escape(n) + r'\(', src, re.M)
    i = src.index('{', m.end()); d = 0; k = i
    while True:
        d += (src[k] == '{') - (src[k] == '}')
        if d == 0: break
        k += 1
    out.append(src[m.start():k + 1] + '\n')
print('\n'.join(out))
