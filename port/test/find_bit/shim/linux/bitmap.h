/* SPDX-License-Identifier: GPL-2.0 */
/* Trimmed reproduction of include/linux/bitmap.h: only what
 * lib/find_bit.c itself references. __bitmap_weight() is a REAL
 * reimplementation (BITMAP_WEIGHT macro copied verbatim from
 * lib/bitmap.c, since find_bit.c's find_random_bit() genuinely depends
 * on it, not a mock of it). */
#ifndef _SHIM_LINUX_BITMAP_H
#define _SHIM_LINUX_BITMAP_H
#include <linux/bitops.h>

#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))
#define BITMAP_LAST_WORD_MASK(nbits) (~0UL >> (-(nbits) & (BITS_PER_LONG - 1)))

unsigned int __bitmap_weight(const unsigned long *bitmap, unsigned int bits);

static inline unsigned int bitmap_weight(const unsigned long *src, unsigned int nbits)
{
	return __bitmap_weight(src, nbits);
}

/* `size`/`n` are always runtime values at find_bit.c's own call sites
 * (find_next_clump8, find_random_bit), so these skip the real header's
 * small_const_nbits() compile-time fast path and go straight to the
 * underlying exported symbols -- which is the only path those call
 * sites can ever take anyway. */
unsigned long _find_next_bit(const unsigned long *addr, unsigned long nbits, unsigned long start);
unsigned long _find_first_bit(const unsigned long *addr, unsigned long size);
unsigned long __find_nth_bit(const unsigned long *addr, unsigned long size, unsigned long n);

static inline unsigned long find_next_bit(const unsigned long *addr, unsigned long size,
					   unsigned long offset)
{
	return _find_next_bit(addr, size, offset);
}

static inline unsigned long find_first_bit(const unsigned long *addr, unsigned long size)
{
	return _find_first_bit(addr, size);
}

static inline unsigned long find_nth_bit(const unsigned long *addr, unsigned long size,
					  unsigned long n)
{
	return __find_nth_bit(addr, size, n);
}

/* Byte-aligned only (this shim's one caller always rounds `start` down to
 * a multiple of 8 first) and little-endian only -- matches this
 * project's only target, x86-64. */
#define bitmap_get_value8(map, start) \
	((unsigned long)((const unsigned char *)(map))[(start) / 8])

#endif
