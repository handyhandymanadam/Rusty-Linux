#!/usr/bin/env python3
"""extract_ref.py <kernel-src-root> <pristine time.c> <out.c>
Build the C reference for the time conversions: the macro blocks of the REAL include/linux/jiffies.h and
include/vdso/jiffies.h (line ranges verified by their first line), plus the pristine functions of kernel/time/time.c
(everything the Rust replaces; jiffies_64_to_clock_t and nsec_to_clock_t stay C in the port and are skipped)."""
import re, sys
root, tc, out = sys.argv[1:4]
J = open(root + "/include/linux/jiffies.h").read().split("\n")
def block(a, b, first):                      # 1-based inclusive line numbers, checked
    assert J[a - 1].startswith(first), (a, J[a - 1], first)
    return "\n".join(J[a - 1:b])
def find(prefix, start=0):
    for i in range(start, len(J)):
        if J[i].startswith(prefix): return i + 1
    raise SystemExit("not found: " + prefix)
blocks = []
a = find("#if HZ >= 12 && HZ < 24"); e = find("# error Invalid value of HZ."); blocks.append(block(a, e + 1, "#if HZ >= 12"))
a = find("#define SH_DIV"); blocks.append(block(a, a + 1, "#define SH_DIV"))
a = find("#define MAX_JIFFY_OFFSET"); blocks.append(block(a, a, "#define MAX_JIFFY_OFFSET"))
a = find("#define SEC_JIFFIE_SC (31 - SHIFT_HZ)"); e = find("#endif", find("# define MAX_SEC_IN_JIFFIES", find("#if BITS_PER_LONG < 64")))
blocks.append(block(a, e, "#define SEC_JIFFIE_SC"))
a = find("#if HZ <= MSEC_PER_SEC && !(MSEC_PER_SEC % HZ)"); e = find("#endif", a + 25)
blocks.append(block(a, e, "#if HZ <= MSEC_PER_SEC"))
a = find("#if !(USEC_PER_SEC % HZ)"); e = find("#endif", a)
blocks.append(block(a, e, "#if !(USEC_PER_SEC % HZ)"))
V = open(root + "/include/vdso/jiffies.h").read()
tick = re.search(r"^#define TICK_NSEC .*$", V, re.M).group(0)
src = open(tc).read()
names = ["jiffies_to_msecs", "jiffies_to_usecs", "mktime64", "ns_to_kernel_old_timeval", "set_normalized_timespec64", "ns_to_timespec64",
         "__msecs_to_jiffies", "__usecs_to_jiffies", "timespec64_to_jiffies", "jiffies_to_timespec64", "jiffies_to_clock_t",
         "clock_t_to_jiffies", "jiffies64_to_nsecs", "jiffies64_to_msecs", "nsecs_to_jiffies64", "nsecs_to_jiffies", "timespec64_add_safe"]
funcs = []
for n in names:
    m = re.search(r"^(?:[A-Za-z_][\w \*]*?\s|\w+\n)\**" + re.escape(n) + r"\(", src, re.M)
    assert m, n
    start = src.rfind("\n", 0, m.start()) + 1
    prev_end = start - 1; prev_start = src.rfind("\n", 0, prev_end) + 1; prev = src[prev_start:prev_end]
    if prev and not prev.rstrip().endswith((";", "}", "*/", "{", "#endif")) and not prev.startswith(("#", "/*", " *")) and "(" not in prev:
        start = prev_start
    e = src.index("\n}\n", m.start()) + 3
    funcs.append(src[start:e])
pre = '''#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include "linux/types.h"
typedef int64_t time64_t; typedef uint64_t timeu64_t; typedef long clock_t; typedef long suseconds_t;
#define BITS_PER_LONG 64
#define LONG_MAX_ __LONG_MAX__
#undef LONG_MAX
#define LONG_MAX __LONG_MAX__
#define MSEC_PER_SEC 1000L
#define USEC_PER_SEC 1000000L
#define NSEC_PER_SEC 1000000000L
#define USER_HZ 100
#define TIME64_MAX ((time64_t)LONG_MAX)
#define likely(x) (x)
#define unlikely(x) (x)
#define EXPORT_SYMBOL(x)
#define EXPORT_SYMBOL_GPL(x)
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
struct timespec64 { time64_t tv_sec; long tv_nsec; };
struct __kernel_old_timeval { long tv_sec; suseconds_t tv_usec; };
static inline u64 div_u64(u64 d, u32 v) { return d / v; }
static inline u64 div_u64_rem(u64 d, u32 v, u32 *rem) { *rem = d % v; return d / v; }
#define BUILD_BUG_ON(x) ((void)sizeof(char[1 - 2 * !!(x)]))
struct timespec64 ns_to_timespec64(s64 nsec);
'''
post_decl = "unsigned int jiffies_to_msecs(const unsigned long j);\nunsigned int jiffies_to_usecs(const unsigned long j);\n"
with open(out, "w") as f:
    f.write(pre + tick + "\n#include \"timeconst.h\"\n" + post_decl + "\n".join(blocks) + "\n" + "\n".join(funcs))
