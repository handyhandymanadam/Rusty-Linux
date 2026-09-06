#pragma once
#include <stdlib.h>
#include <string.h>

typedef int gfp_t;
#define GFP_KERNEL 0

static inline void *kmalloc(size_t size, gfp_t flags)
{
	(void)flags;
	return malloc(size);
}

static inline void *kcalloc(size_t n, size_t size, gfp_t flags)
{
	(void)flags;
	return calloc(n, size);
}

static inline void kfree(const void *p)
{
	free((void *)p);
}

/* kfree_sensitive() wipes before freeing; this differential compares
 * digest output, not memory contents after free, so a plain free() gives
 * an identical observable result -- same reasoning as md5's userspace
 * memzero_explicit() shim. size is unknown here, which is fine: nothing
 * reads freed memory in this harness. */
static inline void kfree_sensitive(const void *p)
{
	free((void *)p);
}
