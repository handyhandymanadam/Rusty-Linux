/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_LINUX_SLAB_H
#define _SHIM_LINUX_SLAB_H
#include <stddef.h>

#define GFP_KERNEL 0

extern void *kmalloc(size_t size, gfp_t gfp);
extern void *kcalloc(size_t n, size_t size, gfp_t gfp);
extern void kfree(const void *objp);
extern char *kstrdup(const char *s, gfp_t gfp);

#endif
