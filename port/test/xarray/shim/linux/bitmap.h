/* SPDX-License-Identifier: GPL-2.0 */
/* Trimmed reproduction of include/linux/bitmap.h: only the primitives
 * lib/xarray.c itself calls. Real implementations (correct for any
 * word count), not mocks -- XA_MARK_LONGS is 1 for every XA_CHUNK_SHIFT
 * this project uses, but these do not assume that. */
#ifndef _SHIM_XARRAY_LINUX_BITMAP_H
#define _SHIM_XARRAY_LINUX_BITMAP_H
#include <linux/bitops.h>

static inline int test_bit(unsigned long nr, const unsigned long *addr)
{
	return (addr[nr / BITS_PER_LONG] >> (nr % BITS_PER_LONG)) & 1UL;
}

static inline void __set_bit(unsigned long nr, unsigned long *addr)
{
	addr[nr / BITS_PER_LONG] |= (1UL << (nr % BITS_PER_LONG));
}

static inline void __clear_bit(unsigned long nr, unsigned long *addr)
{
	addr[nr / BITS_PER_LONG] &= ~(1UL << (nr % BITS_PER_LONG));
}

static inline int __test_and_set_bit(unsigned long nr, unsigned long *addr)
{
	int old = test_bit(nr, addr);
	__set_bit(nr, addr);
	return old;
}

static inline int __test_and_clear_bit(unsigned long nr, unsigned long *addr)
{
	int old = test_bit(nr, addr);
	__clear_bit(nr, addr);
	return old;
}

static inline unsigned long find_next_bit(const unsigned long *addr,
		unsigned long size, unsigned long offset)
{
	unsigned long i;

	for (i = offset; i < size; i++)
		if (test_bit(i, addr))
			return i;
	return size;
}

static inline void bitmap_clear(unsigned long *map, unsigned int start,
		unsigned int nbits)
{
	unsigned int i;

	for (i = start; i < start + nbits; i++)
		__clear_bit(i, map);
}

static inline void bitmap_fill(unsigned long *dst, unsigned int nbits)
{
	unsigned int i;

	for (i = 0; i < nbits; i++)
		__set_bit(i, dst);
}

static inline int bitmap_empty(const unsigned long *src, unsigned int nbits)
{
	unsigned int i;

	for (i = 0; i < nbits; i++)
		if (test_bit(i, src))
			return 0;
	return 1;
}

#endif
