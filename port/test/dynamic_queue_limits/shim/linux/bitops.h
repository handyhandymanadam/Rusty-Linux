/* SPDX-License-Identifier: GPL-2.0 */
/* Trimmed: only what lib/dynamic_queue_limits.c itself references. */
#ifndef _SHIM_LINUX_BITOPS_H
#define _SHIM_LINUX_BITOPS_H

#define BITS_PER_LONG (__CHAR_BIT__ * (int)sizeof(long))

static inline int test_bit(unsigned long nr, const unsigned long *addr)
{
	return (addr[nr / BITS_PER_LONG] >> (nr % BITS_PER_LONG)) & 1UL;
}

#define smp_rmb() __asm__ __volatile__("" ::: "memory")
#define smp_wmb() __asm__ __volatile__("" ::: "memory")

#endif
