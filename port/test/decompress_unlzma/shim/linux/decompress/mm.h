/* Test-only replacement for include/linux/decompress/mm.h's non-STATIC arm.
 * decompress_unlzma.c includes this unconditionally (not gated on STATIC
 * itself) -- the real header's non-STATIC arm needs full kernel headers
 * for its kmalloc/vmalloc-backed malloc/large_malloc; here they stay real
 * libc malloc/free (matching this port's other test shims). STATIC/INIT
 * empty, defined here AFTER decompress_unlzma.c's own top-of-file `#ifdef
 * STATIC` has already resolved (undefined there -> the non-PREBOOT arm
 * this port replaces). */
#ifndef DECOMPR_MM_H
#define DECOMPR_MM_H
#include <stdlib.h>
#define STATIC
#define INIT
#define large_malloc(a) malloc(a)
#define large_free(a) free(a)
#endif
