#!/usr/bin/env python3
"""Slice gid_cmp/groups_sort/groups_search out of the PRISTINE kernel/groups.c into a standalone C file."""
import sys
s = open(sys.argv[1]).read()
a = s.index("static int gid_cmp(")
b = s.index("/**\n * set_groups - Change a group")
pre = '''#include <stddef.h>
#include <stdint.h>
typedef uint32_t gid_t_; typedef struct { gid_t_ val; } kgid_t;
struct group_info { int usage; int ngroups; kgid_t gid[]; };
void sort(void *base, size_t num, size_t size, int (*cmp)(const void *, const void *), void (*swap)(void *, void *, int));
#define EXPORT_SYMBOL(x)
static inline int gid_gt(kgid_t a, kgid_t b) { return a.val > b.val; }
static inline int gid_lt(kgid_t a, kgid_t b) { return a.val < b.val; }
'''
open(sys.argv[2], "w").write(pre + s[a:b])
