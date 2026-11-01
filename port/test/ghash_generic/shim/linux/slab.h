#pragma once
#include <stdlib.h>
#include <linux/types.h>
#define GFP_KERNEL 0
extern int shim_fail_alloc;      /* when set, kzalloc() fails */
static inline void *kzalloc(size_t n, gfp_t f) { (void)f; return shim_fail_alloc ? NULL : calloc(1, n); }
void kfree_sensitive(const void *p);
