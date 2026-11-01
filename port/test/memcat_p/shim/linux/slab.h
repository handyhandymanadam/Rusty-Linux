#ifndef SH_SLAB_H
#define SH_SLAB_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#define GFP_KERNEL 0
#define EXPORT_SYMBOL_GPL(x)
extern long allocs_out, fail_in;
static inline void *kmalloc_array(size_t n, size_t sz, int g) { (void)g; if (n > SIZE_MAX / sz) return NULL; if (fail_in == 0) { fail_in = -1; return NULL; } if (fail_in > 0) fail_in--; allocs_out++; return malloc(n * sz); }
#endif
