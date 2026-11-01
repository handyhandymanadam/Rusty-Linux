/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SHIM_XARRAY_LINUX_GFP_H
#define _SHIM_XARRAY_LINUX_GFP_H
#include <linux/types.h>

#define __GFP_BITS_SHIFT 8
#define GFP_NOWAIT	((gfp_t)0x1)
#define GFP_KERNEL	((gfp_t)0x2)
#define __GFP_ACCOUNT	((gfp_t)0x4)
#define __GFP_DIRECT_RECLAIM ((gfp_t)0x8)

static inline int gfpflags_allow_blocking(gfp_t gfp)
{
	return (gfp & __GFP_DIRECT_RECLAIM) != 0;
}

#endif
