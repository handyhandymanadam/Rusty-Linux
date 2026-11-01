#!/usr/bin/env python3
"""Slice prandom_u32_state and prandom_bytes_state out of the PRISTINE lib/random32.c."""
import sys
s = open(sys.argv[1]).read()
a = s.rfind("/**", 0, s.index("u32 prandom_u32_state("))
b = s.index("EXPORT_SYMBOL(prandom_bytes_state);")
pre = '''#include <stddef.h>
#include <stdint.h>
#include <string.h>
typedef uint32_t u32; typedef uint32_t __u32; typedef uint8_t u8;
struct rnd_state { __u32 s1, s2, s3, s4; };
#define EXPORT_SYMBOL(x)
#define BITS_PER_BYTE 8
#define put_unaligned(v, p) do { __typeof__(v) __v = (v); memcpy((p), &__v, sizeof(__v)); } while (0)
'''
open(sys.argv[2], "w").write(pre + s[a:b])
