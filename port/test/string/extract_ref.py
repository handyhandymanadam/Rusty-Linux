#!/usr/bin/env python3
"""Slice lib/string.c for x86-64: everything from the first function to the end, minus sized_strscpy and strlcat (they stay C in the port),
with the architecture-provided functions (__HAVE_ARCH_*) predefined away exactly as asm/string_64.h does."""
import sys, re
s = open(sys.argv[1]).read()
a = s.index("#ifndef __HAVE_ARCH_STRNCASECMP")
t = s[a:]
# drop sized_strscpy (+ ALLBUTLAST) and strlcat blocks
x0 = t.index("#ifdef __BIG_ENDIAN\n# define ALLBUTLAST_BYTE_MASK")
x1 = t.index("EXPORT_SYMBOL(sized_strscpy);") + len("EXPORT_SYMBOL(sized_strscpy);")
t = t[:x0] + t[x1:]
l0 = t.index("#ifndef __HAVE_ARCH_STRLCAT"); l1 = t.index("#endif", l0) + len("#endif")
t = t[:l0] + t[l1:]
t = t.replace("#undef memcmp\n", "")
pre = '''#include <stddef.h>
#include <stdint.h>
typedef uint64_t u64; typedef uint32_t u32; typedef uint16_t u16; typedef uint8_t u8;
#define EXPORT_SYMBOL(x)
#define __visible
#define BITS_PER_LONG 64
#define CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS 1
#define CONFIG_ARCH_HAS_FAST_MULTIPLIER 1
#define __HAVE_ARCH_MEMSET
#define __HAVE_ARCH_MEMSET16
#define __HAVE_ARCH_MEMSET32
#define __HAVE_ARCH_MEMSET64
#define __HAVE_ARCH_MEMCPY
#define __HAVE_ARCH_MEMMOVE
#define _U 0x01
extern const unsigned char _ctype[];
#define __ismask(x) (_ctype[(int)(unsigned char)(x)])
#define isupper(c) ((__ismask(c)&(_U)) != 0)
static inline unsigned char __tolower(unsigned char c) { if (isupper(c)) c -= 'A'-'a'; return c; }
#define tolower(c) __tolower(c)
#define get_unaligned(p) ({ __typeof__(*(p)) __v; __builtin_memcpy(&__v, (p), sizeof(__v)); __v; })
'''
open(sys.argv[2], "w").write(pre + t)
