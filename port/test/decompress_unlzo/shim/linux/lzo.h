/* Userspace shim: only what decompress_unlzo.c's non-PREBOOT arm uses.
 * Both the C oracle and the Rust port (via drv.c's link line) resolve
 * lzo1x_decompress_safe against the SYSTEM liblzo2, not this declaration's
 * body -- this just has to match its real signature. */
#ifndef _SHIM_UNLZO_LINUX_LZO_H
#define _SHIM_UNLZO_LINUX_LZO_H
#include <stddef.h>

#define lzo1x_worst_compress(x) ((x) + ((x) / 16) + 64 + 3 + 2)

#define LZO_E_OK                     0
#define LZO_E_ERROR                  (-1)
#define LZO_E_OUT_OF_MEMORY          (-2)
#define LZO_E_NOT_COMPRESSIBLE       (-3)
#define LZO_E_INPUT_OVERRUN          (-4)
#define LZO_E_OUTPUT_OVERRUN         (-5)
#define LZO_E_LOOKBEHIND_OVERRUN     (-6)
#define LZO_E_EOF_NOT_FOUND          (-7)
#define LZO_E_INPUT_NOT_CONSUMED     (-8)
#define LZO_E_NOT_YET_IMPLEMENTED    (-9)
#define LZO_E_INVALID_ARGUMENT       (-10)

int lzo1x_decompress_safe(const unsigned char *src, size_t src_len,
			  unsigned char *dst, size_t *dst_len);
#endif
