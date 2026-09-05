/* Userspace shim: lz4defs.h's LZ4_NbCommonBytes uses __ffs/__fls only. */
#ifndef _SHIM_LINUX_BITOPS_H
#define _SHIM_LINUX_BITOPS_H
#include <stddef.h>
#define BITS_PER_LONG (8 * (int)sizeof(long))
static inline unsigned long __ffs(unsigned long word)
{
	return (unsigned long)__builtin_ctzl(word);
}
static inline unsigned long __fls(unsigned long word)
{
	return (unsigned long)(BITS_PER_LONG - 1 - __builtin_clzl(word));
}
#endif
