#!/usr/bin/env python3
"""Slice the four conversion functions (and their table/helpers) out of the
PRISTINE fs/nls/nls_base.c into a standalone C file. Extracted every run."""
import sys
s = open(sys.argv[1]).read()
a = s.index("struct utf8_table {")
b = s.index("int __register_nls(")
pre = '''#include <errno.h>
typedef unsigned char u8; typedef unsigned short u16; typedef unsigned int u32;
typedef u32 unicode_t; typedef u16 knls_wchar;
#define wchar_t knls_wchar
enum utf16_endian { UTF16_HOST_ENDIAN, UTF16_LITTLE_ENDIAN, UTF16_BIG_ENDIAN };
#define EXPORT_SYMBOL(x)
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error host must be little endian
#endif
#define __cpu_to_le16(x) ((u16)(x))
#define __cpu_to_be16(x) ((u16)__builtin_bswap16((u16)(x)))
#define __le16_to_cpu(x) ((u16)(x))
#define __be16_to_cpu(x) ((u16)__builtin_bswap16((u16)(x)))
'''
open(sys.argv[2], "w").write(pre + s[a:b])
