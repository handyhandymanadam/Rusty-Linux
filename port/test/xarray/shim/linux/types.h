/* SPDX-License-Identifier: GPL-2.0-only */
/* Just enough <linux/types.h> to build lib/xarray.c in userspace, same
 * shape as port/test/interval_tree/shim/linux/types.h. gfp_t and
 * atomic_t are here (not a separate shim header) because xarray.h
 * itself expects them from <linux/types.h>. */
#ifndef _SHIM_XARRAY_LINUX_TYPES_H
#define _SHIM_XARRAY_LINUX_TYPES_H

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

#ifndef __bitwise
#define __bitwise
#endif
typedef unsigned int __bitwise gfp_t;
typedef struct { int counter; } atomic_t;

struct list_head {
	struct list_head *next, *prev;
};

struct rcu_head {
	struct rcu_head *next;
	void (*func)(struct rcu_head *head);
};

struct list_lru;

#endif
