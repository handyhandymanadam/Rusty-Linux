#!/usr/bin/env python3
"""Slice in_aton .. in6_pton (and xdigit2bin, IN6PTON_*) out of the PRISTINE net/core/utils.c."""
import sys
s = open(sys.argv[1]).read()
a = s.index("__be32 in_aton(")
b = s.index("static int inet4_pton(")
pre = '''#include <stddef.h>
#include <stdint.h>
#include <string.h>
typedef uint8_t u8; typedef uint32_t __be32;
int hex_to_bin(unsigned char ch);
#define EXPORT_SYMBOL(x)
static inline uint32_t htonl(uint32_t x) { return __builtin_bswap32(x); }
'''
open(sys.argv[2], "w").write(pre + s[a:b])
