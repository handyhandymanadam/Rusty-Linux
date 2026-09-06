/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_LINUX_COMPILER_H
#define _SHIM_LINUX_COMPILER_H

#define READ_ONCE(x) (*(const volatile __typeof__(x) *)&(x))
#define WRITE_ONCE(x, val) (*(volatile __typeof__(x) *)&(x) = (val))
#define barrier() __asm__ __volatile__("" ::: "memory")
#define BITS_PER_LONG (__CHAR_BIT__ * (int)sizeof(long))

#endif
