/* Just the IDA declarations of include/linux/idr.h (the real header pulls in radix-tree.h). Layout and constants as upstream. */
#ifndef _SHIM_IDR_H
#define _SHIM_IDR_H
#include <linux/xarray.h>
#define IDA_CHUNK_SIZE		128
#define IDA_BITMAP_LONGS	(IDA_CHUNK_SIZE / sizeof(long))
#define IDA_BITMAP_BITS 	(IDA_BITMAP_LONGS * sizeof(long) * 8)
struct ida_bitmap { unsigned long bitmap[IDA_BITMAP_LONGS]; };
struct ida { struct xarray xa; };
#define IDA_INIT_FLAGS	(XA_FLAGS_LOCK_IRQ | XA_FLAGS_ALLOC)
#endif
