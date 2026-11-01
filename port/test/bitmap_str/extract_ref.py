#!/usr/bin/env python3
"""Slice struct region .. bitmap_parse (the parsers) out of the PRISTINE lib/bitmap-str.c, skipping the _user variant."""
import sys
s = open(sys.argv[1]).read()
a = s.index("struct region {")
u0 = s.index("int bitmap_parselist_user(")
u0 = s.rfind("/**", 0, u0)
u1 = s.index("EXPORT_SYMBOL(bitmap_parselist_user);") + len("EXPORT_SYMBOL(bitmap_parselist_user);")
b = s.index("EXPORT_SYMBOL(bitmap_parse);") + len("EXPORT_SYMBOL(bitmap_parse);")
pre = '''#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <stdbool.h>
#include <errno.h>
typedef uint64_t u64; typedef uint32_t u32; typedef uint8_t u8;
#define EXPORT_SYMBOL(x)
#define ERR_PTR(e) ((void *)(long)(e))
#define PTR_ERR(p) ((long)(p))
#define IS_ERR(p) ((unsigned long)(p) >= (unsigned long)-4095)
#define KSTRTOX_OVERFLOW (1U << 31)
#define BITS_TO_U32(n) (((n) + 31) / 32)
#define min(a, b) ((a) < (b) ? (a) : (b))
#define _S 0x20
extern const unsigned char _ctype[];
#define isspace(c) ((_ctype[(int)(unsigned char)(c)] & _S) != 0)
unsigned int _parse_integer(const char *s, unsigned int base, unsigned long long *p);
int hex_to_bin(unsigned char ch);
char *strnchrnul(const char *s, size_t count, int c);
void __bitmap_set(unsigned long *map, unsigned int start, int len);
void __bitmap_clear(unsigned long *map, unsigned int start, int len);
unsigned long _find_next_bit(const unsigned long *addr, unsigned long nbits, unsigned long start);
#define bitmap_set(m, s, n) __bitmap_set(m, s, n)
#define bitmap_clear(m, s, n) __bitmap_clear(m, s, n)
#define find_next_bit(a, sz, o) _find_next_bit(a, sz, o)
static inline void bitmap_zero(unsigned long *dst, unsigned int nbits) { memset(dst, 0, ((nbits + 63) / 64) * 8); }
'''
open(sys.argv[2], "w").write(pre + s[a:u0] + s[u1:b])
