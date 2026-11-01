#ifndef SHR_GFP_H
#define SHR_GFP_H
#include <linux/types.h>
/* __GFP_BITS_SHIFT is 24 like config-full (the tag bits of xa_flags sit above it). Zone bits as upstream's low nibble. */
#define __GFP_DMA	((gfp_t)0x01u)
#define __GFP_HIGHMEM	((gfp_t)0x02u)
#define __GFP_DMA32	((gfp_t)0x04u)
#define __GFP_MOVABLE	((gfp_t)0x08u)
#define GFP_ZONEMASK	(__GFP_DMA|__GFP_HIGHMEM|__GFP_DMA32|__GFP_MOVABLE)
#define __GFP_DIRECT_RECLAIM ((gfp_t)0x400u)
#define __GFP_ACCOUNT	((gfp_t)0x200000u)
#define __GFP_NOWARN	((gfp_t)0x200u)
#define __GFP_BITS_SHIFT 24
#define __GFP_BITS_MASK ((gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
#define GFP_NOWAIT	((gfp_t)0x800u)
#define GFP_KERNEL	((gfp_t)(0x400u | 0x1000u))
static inline int gfpflags_allow_blocking(gfp_t gfp) { return (gfp & __GFP_DIRECT_RECLAIM) != 0; }
#endif
