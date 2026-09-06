/* Test-only replacement for include/linux/decompress/mm.h's non-STATIC arm.
 * decompress_unzstd.c includes this unconditionally (not gated on STATIC
 * itself) -- the real header's non-STATIC arm needs full kernel headers
 * for its vmalloc-backed large_malloc/large_free; here they stay real
 * libc malloc/free (the C oracle's own allocations are workspace buffers
 * sized the same way the kernel sizes them, not anything ABI-sensitive).
 * STATIC/INIT empty, matching this port's other test shims (see
 * decompress_unxz's identical file): defined here, AFTER
 * decompress_unzstd.c's own top-of-file `#ifdef STATIC` has already
 * resolved (undefined there -> the non-UNZSTD_PREBOOT arm this port
 * replaces). */
#ifndef DECOMPR_MM_H
#define DECOMPR_MM_H
#include <stdlib.h>
#define STATIC
#define INIT
#define large_malloc(a) malloc(a)
#define large_free(a) free(a)
#endif
