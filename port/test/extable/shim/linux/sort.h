#pragma once
#include <stddef.h>
typedef int (*cmp_func_t)(const void *a, const void *b);
typedef void (*swap_func_t)(void *a, void *b, int size);
void sort(void *base, size_t num, size_t size, cmp_func_t cmp, swap_func_t swap);
