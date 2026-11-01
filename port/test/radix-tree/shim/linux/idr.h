#ifndef SHR_IDR_H
#define SHR_IDR_H
#include <linux/radix-tree.h>
struct idr { struct radix_tree_root idr_rt; unsigned int idr_base; unsigned int idr_next; };
#define IDR_FREE 0
#define IDR_RT_MARKER (ROOT_IS_IDR | (__force gfp_t)(1 << (ROOT_TAG_SHIFT + IDR_FREE)))
#endif
