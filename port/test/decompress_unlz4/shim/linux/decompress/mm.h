/* Test-only replacement for include/linux/decompress/mm.h's non-STATIC arm
 * (real mm.h needs full kernel headers for its kmalloc/vmalloc versions).
 * `#define STATIC` here matches the real header exactly: it happens AFTER
 * decompress_unlz4.c's own top-of-file `#ifdef STATIC` has already resolved
 * (STATIC is undefined at that point, so PREBOOT is not set -- the
 * non-PREBOOT arm this port replaces), and is needed for the file's LATER
 * `STATIC inline int INIT unlz4(...)` to parse at all. */
#ifndef DECOMPR_MM_H
#define DECOMPR_MM_H
#include <stdlib.h>
#define large_malloc(a) malloc(a)
#define large_free(a) free(a)
#define INIT
#define STATIC
#endif
