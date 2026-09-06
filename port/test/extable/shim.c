/* SPDX-License-Identifier: GPL-2.0-only */
/* sort()/bsearch() for port/test/extable/ -- both arms call the SAME shim,
 * so what's compared is sort_extable()/search_extable()'s own comparator
 * and swap logic, not a reimplementation of the primitives. sort() MUST
 * call swap() for every relocation (not memmove) -- that is exactly what
 * swap_ex() depends on to keep each entry's relative offsets correct. */
#include <stddef.h>

typedef int (*cmp_func_t)(const void *a, const void *b);
typedef void (*swap_func_t)(void *a, void *b, int size);

void sort(void *base, size_t num, size_t size, cmp_func_t cmp, swap_func_t swap)
{
	char *b = base;
	for (size_t i = 1; i < num; i++) {
		size_t j = i;
		while (j > 0 && cmp(b + j * size, b + (j - 1) * size) < 0) {
			swap(b + j * size, b + (j - 1) * size, (int)size);
			j--;
		}
	}
}

void *bsearch(const void *key, const void *base, size_t num, size_t size,
	      cmp_func_t cmp)
{
	const char *b = base;
	size_t start = 0, end = num;
	while (start < end) {
		size_t mid = start + (end - start) / 2;
		int result = cmp(key, b + mid * size);
		if (result < 0)
			end = mid;
		else if (result > 0)
			start = mid + 1;
		else
			return (void *)(b + mid * size);
	}
	return NULL;
}
