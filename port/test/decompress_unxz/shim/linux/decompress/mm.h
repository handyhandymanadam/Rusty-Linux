/* Test-only replacement for include/linux/decompress/mm.h's non-STATIC arm.
 * decompress_unxz.c includes this only when __KERNEL__ is defined (which
 * the test compile sets, to reach the same non-XZ_PREBOOT arm the kernel
 * build takes) -- the real header's non-STATIC arm needs full kernel
 * headers for its kmalloc/vmalloc-backed malloc/free; here they stay
 * real libc malloc/free (this file's own malloc calls are tiny bookkeeping
 * buffers, not the actual XZ state -- that's owned by xz_dec_init(), which
 * this test also gives real libc-backed allocation via shim/xz_config.h).
 * Only STATIC/INIT are needed, matching this port's other test shims:
 * defined here, AFTER decompress_unxz.c's own top-of-file `#ifdef STATIC`
 * has already resolved (undefined there -> the non-XZ_PREBOOT arm this
 * port replaces). */
#ifndef DECOMPR_MM_H
#define DECOMPR_MM_H
#include <stdlib.h>
#define STATIC
#define INIT
#endif
