/* Userspace stand-ins for what the IDA code needs beyond the xarray shim (../xarray/shim). Failure injection: fail_alloc counts kzalloc()s down and
 * fails the one that hits zero (negative: every one fails); fail_node does the same for xarray node allocations (radix_tree_stub.c). */
#ifndef KSHIM_H
#define KSHIM_H
#include <linux/xarray.h>
#include <linux/bitmap.h>
#include <linux/export.h>
#include <linux/idr.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
extern long fail_alloc, fail_node, live_bitmaps; extern int warn_count;
static inline void *kzalloc(size_t n, gfp_t gfp) { (void)gfp; if (fail_alloc < 0 || (fail_alloc > 0 && --fail_alloc == 0)) return NULL; live_bitmaps++; return calloc(1, n); }
static inline void kfree(const void *p) { if (p) live_bitmaps--; free((void *)p); }
#undef WARN
#define WARN(cond, ...) ({ int __r = !!(cond); if (__r) warn_count++; __r; })
static inline int bitmap_full(const unsigned long *a, unsigned n) { for (unsigned i = 0; i < n; i++) if (!((a[i / 64] >> (i % 64)) & 1)) return 0; return 1; }
static inline unsigned long find_next_zero_bit(const unsigned long *a, unsigned long size, unsigned long off) { for (unsigned long i = off; i < size; i++) if (!((a[i / 64] >> (i % 64)) & 1)) return i; return size; }
#endif
