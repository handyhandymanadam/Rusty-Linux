/* decompress_unxz.c's non-XZ_PREBOOT arm includes this but never uses
 * kmalloc/GFP_KERNEL directly (only via malloc/free, which mm.h's shim
 * here leaves as real libc) -- empty is enough. */
#ifndef _SHIM_UNXZ_LINUX_SLAB_H
#define _SHIM_UNXZ_LINUX_SLAB_H
#endif
