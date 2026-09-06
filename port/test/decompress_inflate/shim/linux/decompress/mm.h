/* Test-only replacement for include/linux/decompress/mm.h's non-STATIC arm.
 * decompress_inflate.c includes this unconditionally (not gated on STATIC
 * itself) -- the real header's non-STATIC arm needs full kernel headers
 * for its kmalloc-backed malloc/free; here they stay real libc malloc/free
 * (this port's own test harness controls allocation the same way this
 * port's other test shims do -- see decompress_unxz's identical file).
 * STATIC/INIT empty, defined here AFTER decompress_inflate.c's own
 * top-of-file `#ifdef STATIC` has already resolved (undefined there ->
 * the non-PREBOOT arm this port replaces). */
#ifndef DECOMPR_MM_H
#define DECOMPR_MM_H
#include <stdlib.h>
#define STATIC
#define INIT
#endif
