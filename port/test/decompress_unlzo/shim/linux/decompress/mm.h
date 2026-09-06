/* Test-only replacement for include/linux/decompress/mm.h's non-STATIC arm
 * (real mm.h needs full kernel headers). Unlike decompress_unlz4's shim,
 * this file (decompress_unlzo.c) calls plain malloc/free directly -- under
 * the real mm.h those become kmalloc/kfree, but for a userspace oracle
 * leaving them unmapped (real libc malloc/free) is exactly right. Only
 * STATIC/INIT are needed, same timing reasoning as unlz4's shim: this
 * define happens AFTER decompress_unlzo.c's own top-of-file #ifdef STATIC
 * has already resolved (undefined there -> the non-PREBOOT arm this port
 * replaces), and is needed for the file's later `STATIC inline long INIT
 * parse_header(...)` / `STATIC int INIT unlzo(...)` to parse at all. */
#ifndef DECOMPR_MM_H
#define DECOMPR_MM_H
#include <stdlib.h>
#define INIT
#define STATIC
#endif
