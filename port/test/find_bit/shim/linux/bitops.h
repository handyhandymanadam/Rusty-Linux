/* SPDX-License-Identifier: GPL-2.0 */
/* Trimmed reproduction of include/linux/bitops.h: only what
 * lib/find_bit.c itself references. fns() copied verbatim from
 * include/linux/bitops.h (lines 286-291 of the real header). */
#ifndef _SHIM_LINUX_BITOPS_H
#define _SHIM_LINUX_BITOPS_H

#define BITS_PER_LONG 64
#define likely(x) (x)
#define unlikely(x) (x)

static inline unsigned long hweight_long(unsigned long w)
{
	return __builtin_popcountl(w);
}

static inline unsigned long __ffs(unsigned long word)
{
	return __builtin_ctzl(word);
}

static inline unsigned long __fls(unsigned long word)
{
	return 63 - __builtin_clzl(word);
}

static inline unsigned int fns(unsigned long word, unsigned int n)
{
	while (word && n--)
		word &= word - 1;
	return word ? __ffs(word) : BITS_PER_LONG;
}

#endif
