#!/usr/bin/env python3
"""Slice everything but match_strdup out of the PRISTINE lib/parser.c; the REAL include/linux/parser.h is included."""
import sys
s = open(sys.argv[1]).read()
a = s.index("#define NUMBER_BUF_LEN")
b = s.rfind("/**", 0, s.index("char *match_strdup("))
pre = '''#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <stdbool.h>
typedef uint64_t u64;
#define EXPORT_SYMBOL(x)
#define _D 0x04
extern const unsigned char _ctype[];
#define isdigit(c) ((_ctype[(int)(unsigned char)(c)] & _D) != 0)
long simple_strtol(const char *, char **, unsigned int);
unsigned long simple_strtoul(const char *, char **, unsigned int);
int kstrtoull(const char *, unsigned int, u64 *);
int kstrtouint(const char *, unsigned int, unsigned int *);
#include "linux/parser.h"
'''
open(sys.argv[2], "w").write(pre + s[a:b])
