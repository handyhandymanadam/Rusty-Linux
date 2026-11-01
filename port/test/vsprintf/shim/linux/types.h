/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_VSPRINTF_LINUX_TYPES_H
#define _SHIM_VSPRINTF_LINUX_TYPES_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifndef __user
#define __user
#endif

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

typedef u16 __be16;
typedef u32 __be32;
typedef u64 __be64;
typedef unsigned short sa_family_t;
typedef unsigned int gfp_t;
typedef long long time64_t;
typedef long long dma_addr_t;
typedef unsigned long resource_size_t;
typedef u64 netdev_features_t;
typedef u64 phys_addr_t;

/* include/uapi/linux/in6.h, unchanged. */
struct in6_addr {
	union {
		u8 u6_addr8[16];
		__be16 u6_addr16[8];
		__be32 u6_addr32[4];
	} in6_u;
#define s6_addr		in6_u.u6_addr8
#define s6_addr16	in6_u.u6_addr16
#define s6_addr32	in6_u.u6_addr32
};

#endif
