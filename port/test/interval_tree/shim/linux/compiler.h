/* SPDX-License-Identifier: GPL-2.0-only */
/* <linux/compiler.h>, reduced to the four things lib/rbtree.c and
 * <linux/rbtree_augmented.h> actually use: WRITE_ONCE, READ_ONCE,
 * __always_inline and barrier(). Measured, not guessed --
 *     grep -o 'WRITE_ONCE|READ_ONCE|__always_inline|barrier|unlikely' rbtree.c
 * returns exactly those plus unlikely(), which the shared base defines.
 *
 * WRITE_ONCE/READ_ONCE ARE REPRODUCED AS VOLATILE ACCESSES, not as plain
 * ones. They are not decoration here: __rb_change_child() publishes a child
 * pointer that a lockless reader may be walking, and the kernel's whole
 * rbtree-under-RCU arrangement rests on those stores being single and
 * un-reordered. A shim that quietly downgraded them would compile an oracle
 * the kernel does not build -- the lib/lz4 lesson (logs/floor.md RULE T4). */
#ifndef _SHIM_INTERVAL_TREE_LINUX_COMPILER_H
#define _SHIM_INTERVAL_TREE_LINUX_COMPILER_H

#include <linux/kernel.h>	/* the shared base */

#ifndef barrier
#define barrier() __asm__ __volatile__("" : : : "memory")
#endif

#define READ_ONCE(x)      (*(const volatile __typeof__(x) *)&(x))
#define WRITE_ONCE(x, val) \
	do { *(volatile __typeof__(x) *)&(x) = (val); } while (0)

#endif
