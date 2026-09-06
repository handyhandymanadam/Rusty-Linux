/* Userspace shim: only what decompress_unlz4.c's non-PREBOOT arm uses. Both
 * the C oracle and the Rust port (via drv.c's link line) resolve
 * LZ4_decompress_safe against the SYSTEM liblz4, not this declaration's
 * body -- this just has to match its real signature. */
#ifndef _SHIM_UNLZ4_LINUX_LZ4_H
#define _SHIM_UNLZ4_LINUX_LZ4_H
#include <stddef.h>

#define LZ4_MAX_INPUT_SIZE 0x7E000000
#define LZ4_COMPRESSBOUND(isize) ( \
	(unsigned int)(isize) > (unsigned int)LZ4_MAX_INPUT_SIZE \
	? 0 \
	: (isize) + ((isize)/255) + 16)

static inline int LZ4_compressBound(size_t isize)
{
	return LZ4_COMPRESSBOUND(isize);
}

int LZ4_decompress_safe(const char *source, char *dest, int compressedSize,
	int maxDecompressedSize);
#endif
