#pragma once
#include <stdlib.h>
#include <linux/types.h>
#define GFP_KERNEL 0
/* allocation accounting + failure injection (gf128mul test): see main.c */
void *shim_kzalloc(size_t n);
#define kzalloc(n, f) ((void)(f), shim_kzalloc(n))
void kfree_sensitive(const void *p);
