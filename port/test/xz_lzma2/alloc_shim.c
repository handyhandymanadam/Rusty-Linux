/* SPDX-License-Identifier: GPL-2.0
 *
 * The two allocator symbols the port calls out to.
 *
 * In the kernel, `vmalloc` is alloc_hooks(vmalloc_noprof(...)) since 6.10's
 * allocation profiling and has NO linkable symbol, so the port cannot call it
 * and lib/xz/xz_dec_lzma2.c gains a three-line xz_dec_lzma2_dict_alloc()
 * wrapper instead (the port's divergence 8). `vfree` is a real out-of-line
 * EXPORT_SYMBOL and is called directly.
 *
 * Here both are malloc/free. The harness only has to make them exist with the
 * right shapes; it is not trying to be a kernel allocator.
 */
#include <stdlib.h>
#include <stdint.h>

unsigned char *xz_dec_lzma2_dict_alloc(uint32_t size)
{
	return malloc(size);
}

void vfree(const void *addr)
{
	free((void *)addr);
}
