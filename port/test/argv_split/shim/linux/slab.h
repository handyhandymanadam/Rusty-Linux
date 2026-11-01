#ifndef SH_SLAB_H
#define SH_SLAB_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef unsigned int gfp_t;
#define KMALLOC_MAX_SIZE 4096UL /* small so the cap on the copied string is exercised */
extern long allocs_out, alloc_fail_in;
static inline int fails(void) { if (alloc_fail_in == 0) { alloc_fail_in = -1; return 1; } if (alloc_fail_in > 0) alloc_fail_in--; return 0; }
static inline void *kmalloc_array(size_t n, size_t sz, gfp_t g) { (void)g; if (n > SIZE_MAX / sz || fails()) return NULL; allocs_out++; return malloc(n * sz); }
static inline char *kstrndup(const char *s, size_t max, gfp_t g) { (void)g; if (!s || fails()) return NULL; size_t n = strnlen(s, max); char *p = malloc(n + 1); allocs_out++; memcpy(p, s, n); p[n] = 0; return p; }
static inline void kfree(const void *p) { if (p) allocs_out--; free((void *)p); }
#endif
