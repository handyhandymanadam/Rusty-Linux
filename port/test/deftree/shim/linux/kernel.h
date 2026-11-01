/* Userspace stand-in adding what ../zlib_inflate/shim's kernel.h and
 * ../common/shim's don't: BUG_ON, which deflate.c's
 * zlib_deflate_workspacesize() calls directly. */
#include_next <linux/kernel.h>

#ifndef BUG_ON
#include <assert.h>
#define BUG_ON(cond) assert(!(cond))
#endif
