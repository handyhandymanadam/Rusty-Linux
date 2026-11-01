/* SPDX-License-Identifier: GPL-2.0 */
/* Trimmed reproduction of include/linux/bitops.h: only what
 * lib/xarray.c itself references. Real semantics, not mocks -- see
 * port/test/find_bit/shim/linux/bitops.h for the precedent. */
#ifndef _SHIM_XARRAY_LINUX_BITOPS_H
#define _SHIM_XARRAY_LINUX_BITOPS_H

#define BITS_PER_LONG 64
#define BITS_TO_LONGS(nr) (((nr) + BITS_PER_LONG - 1) / BITS_PER_LONG)

static inline unsigned long __ffs(unsigned long word)
{
	return __builtin_ctzl(word);
}

#endif
