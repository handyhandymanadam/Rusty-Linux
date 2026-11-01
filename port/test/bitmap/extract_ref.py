#!/usr/bin/env python3
"""Slice the bitmap operations out of the PRISTINE lib/bitmap.c (everything but the allocators) into a standalone C file."""
import sys
s = open(sys.argv[1]).read()
a = s.index("bool __bitmap_equal(")
b = s.index("unsigned long *bitmap_alloc(")
c = s.index("#if BITS_PER_LONG == 64\n/**\n * bitmap_from_arr32")
d = s.index("#if BITS_PER_LONG == 32")
pre = '''#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <stdbool.h>
typedef uint64_t u64; typedef uint32_t u32; typedef uint16_t u16; typedef uint8_t u8;
#define BITS_PER_LONG 64
#define CONFIG_NUMA 1
#define EXPORT_SYMBOL(x)
#define EXPORT_SYMBOL_GPL(x)
#define BITS_PER_TYPE(t) (sizeof(t) * 8)
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define BITS_TO_LONGS(nr) DIV_ROUND_UP(nr, BITS_PER_LONG)
#define BIT_WORD(nr) ((nr) / BITS_PER_LONG)
#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))
#define BITMAP_LAST_WORD_MASK(nbits) (~0UL >> (-(nbits) & (BITS_PER_LONG - 1)))
#define __ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))
#define hweight_long(w) ((unsigned int)__builtin_popcountl(w))
unsigned long _find_next_bit(const unsigned long *addr, unsigned long nbits, unsigned long start);
unsigned long _find_next_zero_bit(const unsigned long *addr, unsigned long nbits, unsigned long start);
unsigned long __find_nth_bit(const unsigned long *addr, unsigned long size, unsigned long n);
#define find_next_bit(a, s, o) _find_next_bit(a, s, o)
#define find_next_zero_bit(a, s, o) _find_next_zero_bit(a, s, o)
static inline unsigned long find_nth_bit(const unsigned long *addr, unsigned long size, unsigned long n) { if (n >= size) return size; return __find_nth_bit(addr, size, n); }
#define for_each_set_bit(bit, addr, size) for ((bit) = find_next_bit((addr), (size), 0); (bit) < (size); (bit) = find_next_bit((addr), (size), (bit) + 1))
static inline int test_bit(unsigned long nr, const unsigned long *addr) { return 1UL & (addr[nr / 64] >> (nr & 63)); }
static inline void set_bit(unsigned long nr, volatile unsigned long *addr) { __atomic_fetch_or(&addr[nr / 64], 1UL << (nr & 63), __ATOMIC_RELAXED); }
static inline void bitmap_zero(unsigned long *dst, unsigned int nbits) { memset(dst, 0, BITS_TO_LONGS(nbits) * sizeof(unsigned long)); }
unsigned int __bitmap_weight(const unsigned long *bitmap, unsigned int bits);
static inline unsigned int bitmap_weight(const unsigned long *src, unsigned int nbits) { return __bitmap_weight(src, nbits); }
'''
open(sys.argv[2], "w").write(pre + s[a:b] + s[c:d])
