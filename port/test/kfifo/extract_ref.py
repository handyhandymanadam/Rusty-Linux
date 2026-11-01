#!/usr/bin/env python3
"""Slice the kfifo core (the functions kfifo_rs.rs has) out of the PRISTINE lib/kfifo.c: static helpers first, then the 12 exports."""
import re, sys
s = open(sys.argv[1]).read()
names = ['kfifo_unused','__kfifo_init','kfifo_copy_in','__kfifo_in','kfifo_copy_out','__kfifo_out_peek','__kfifo_out_linear','__kfifo_out',
         '__kfifo_max_r','__KFIFO_PEEK','__kfifo_peek_n','__KFIFO_POKE','__kfifo_poke_n','__kfifo_len_r','__kfifo_in_r','kfifo_out_copy_r',
         '__kfifo_out_peek_r','__kfifo_out_linear_r','__kfifo_out_r','__kfifo_skip_r']
parts = []
for n in names:
    if n.startswith('__KFIFO'):
        m = re.search(r'^#define\s+' + n + r'\b.*?(?:\n(?!\n)(?:\s+\\|.*\\\n)*)', s, re.M | re.S)
        # macro: from #define through the last line that does not end in a backslash
        i = s.index('#define\t' + n) if ('#define\t' + n) in s else s.index('#define ' + n)
        j = i
        while True:
            e = s.index('\n', j)
            if not s[j:e].rstrip().endswith('\\'): break
            j = e + 1
        parts.append((i, s[i:e + 1])); continue
    m = re.search(r'^(?:static (?:inline )?)?(?:unsigned (?:int|long)|int|void)\s+\**' + re.escape(n) + r'\(', s, re.M)
    assert m, n
    st = s.rfind('\n', 0, m.start()) + 1
    e = s.index('\n}\n', m.start()) + 3
    parts.append((st, s[st:e]))
parts.sort()
pre = '''#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#define EXPORT_SYMBOL(x)
#define min(a, b) ((a) < (b) ? (a) : (b))
#define min3(a, b, c) min(min(a, b), c)
#define smp_wmb() __atomic_thread_fence(__ATOMIC_RELEASE)
static inline int is_power_of_2(unsigned long n) { return n != 0 && (n & (n - 1)) == 0; }
/* n == 0: the C shifts by -1, which x86 reduces to 63; the result is cut to 32 bits by the caller, i.e. 0 */
static inline unsigned long rounddown_pow_of_two(unsigned long n) { return n ? 1UL << (63 - __builtin_clzl(n)) : 0; }
struct __kfifo { unsigned int in; unsigned int out; unsigned int mask; unsigned int esize; void *data; };
'''
open(sys.argv[2], "w").write(pre + "\n".join(p for _, p in parts))
