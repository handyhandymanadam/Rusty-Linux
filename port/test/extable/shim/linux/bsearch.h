#pragma once
#include <stddef.h>
typedef int (*cmp_func_t)(const void *key, const void *elt);
void *bsearch(const void *key, const void *base, size_t num, size_t size,
	      cmp_func_t cmp);
