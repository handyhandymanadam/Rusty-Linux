#!/usr/bin/env python3
"""extract_ref.py <genalloc c file> <out.c> <helpers|glue>: slice the pieces genalloc_rs.rs replaces out of a genalloc.c.
helpers: from the PRISTINE file -- set_bits_ll, clear_bits_ll, bitmap_set_ll, bitmap_clear_ll and the five allocation algorithms.
glue:    from genalloc_glue.c -- the two static bitmap_*_ll wrappers and the five thunk-shaped algorithms (what the Rust arm really calls)."""
import re, sys
s = open(sys.argv[1]).read()
mode = sys.argv[3]
names = ['bitmap_set_ll', 'bitmap_clear_ll', 'gen_pool_first_fit', 'gen_pool_first_fit_align', 'gen_pool_fixed_alloc',
         'gen_pool_first_fit_order_align', 'gen_pool_best_fit']
if mode == 'helpers':
    names = ['set_bits_ll', 'clear_bits_ll'] + names
parts = []
for n in names:
    m = re.search(r'^(?:static (?:inline )?)?(?:unsigned long|int)\s*\n?\s*' + re.escape(n) + r'\(', s, re.M)
    assert m, n
    st = s.rfind('\n', 0, m.start()) + 1
    # include a preceding "static inline int" / "static unsigned long" line when the name starts the next line
    e = s.index('\n}\n', m.start()) + 3
    parts.append((st, s[st:e]))
parts.sort()
pre = '''#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#define EXPORT_SYMBOL(x)
#define BITS_PER_LONG 64
#define BIT_WORD(nr) ((nr) / BITS_PER_LONG)
#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))
#define BITMAP_LAST_WORD_MASK(nbits) (~0UL >> (-(nbits) & (BITS_PER_LONG - 1)))
#define READ_ONCE(x) (*(volatile __typeof__(x) *)&(x))
#define try_cmpxchg(p, oldp, new) __atomic_compare_exchange_n((p), (oldp), (new), 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
#define cpu_relax() __asm__ volatile("pause" ::: "memory")
#define WARN_ON(x) (x)
struct gen_pool { int min_alloc_order; };
struct genpool_data_align { int align; };
struct genpool_data_fixed { unsigned long offset; };
unsigned long bitmap_find_next_zero_area_off(unsigned long *map, unsigned long size, unsigned long start, unsigned int nr,
					     unsigned long align_mask, unsigned long align_offset);
unsigned long _find_next_bit(const unsigned long *addr, unsigned long nbits, unsigned long start);
#define find_next_bit(a, n, s) _find_next_bit((a), (n), (s))
#define bitmap_find_next_zero_area(m, s, st, nr, am) bitmap_find_next_zero_area_off((m), (s), (st), (nr), (am), 0)
static inline unsigned long roundup_pow_of_two(unsigned long n) { return n == 1 ? 1 : 1UL << (64 - __builtin_clzl(n - 1)); }
unsigned long rust_genalloc_bitmap_set_ll(unsigned long *map, unsigned long start, unsigned long nr);
unsigned long rust_genalloc_bitmap_clear_ll(unsigned long *map, unsigned long start, unsigned long nr);
unsigned long rust_gen_pool_first_fit(unsigned long *map, unsigned long size, unsigned long start, unsigned int nr);
unsigned long rust_gen_pool_first_fit_align(unsigned long *map, unsigned long size, unsigned long start, unsigned int nr,
					    unsigned long align, int order, unsigned long start_addr);
unsigned long rust_gen_pool_fixed_alloc(unsigned long *map, unsigned long size, unsigned long start, unsigned int nr,
					unsigned long offset, int order);
unsigned long rust_gen_pool_first_fit_order_align(unsigned long *map, unsigned long size, unsigned long start, unsigned int nr);
unsigned long rust_gen_pool_best_fit(unsigned long *map, unsigned long size, unsigned long start, unsigned int nr);
'''
body = "\n".join(p for _, p in parts).replace('static unsigned long\nbitmap_', 'unsigned long\nbitmap_')   # the harness links to them
open(sys.argv[2], "w").write(pre + body)
