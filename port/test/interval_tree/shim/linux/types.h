/* SPDX-License-Identifier: GPL-2.0-only */
/* Just enough <linux/types.h> to build lib/rbtree.c and lib/interval_tree.c
 * in userspace. Nothing here selects a code path: neither file forks on a
 * type width. The endianness and CONFIG_64BIT derivation that DOES select
 * paths lives in the shared base (port/test/common/shim/linux/kernel.h) and
 * is pulled in below so this harness cannot be the one that forgot. */
#ifndef _SHIM_INTERVAL_TREE_LINUX_TYPES_H
#define _SHIM_INTERVAL_TREE_LINUX_TYPES_H

#include <linux/kernel.h>	/* the shared base: likely/unlikely, CONFIG_64BIT */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

#endif
