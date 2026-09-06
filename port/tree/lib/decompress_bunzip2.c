// SPDX-License-Identifier: GPL-2.0
/*
 * The Rust bzip2 decoder's kmalloc/vmalloc thunks.
 *
 * Both are macros with no linkable symbol -- kmalloc is `alloc_hooks(
 * kmalloc_noprof(...))` and vmalloc is `alloc_hooks(vmalloc_noprof(...))`
 * since 6.10's allocation profiling (include/linux/slab.h,
 * include/linux/vmalloc.h). kfree and vfree are real EXPORT_SYMBOLs and are
 * called directly from decompress_bunzip2_rs.rs; only the allocating halves
 * need a C body. See that file's module doc for the rest of the port.
 */
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

/* Prototypes for decompress_bunzip2_rs.rs's `extern "C"` declarations --
 * -Wmissing-prototypes requires these visible before the definitions below,
 * since nothing else in the C tree calls either function. Both callers
 * (start_bunzip, bunzip2) are __init, so these are too -- upstream's INIT
 * macro (mm.h's non-STATIC arm) marks every function in this file that way,
 * and there is no reason for the two functions replacing part of it to be
 * the exception that keeps a few bytes resident after boot. */
void *decompress_bunzip2_alloc(unsigned int size) __init;
void *decompress_bunzip2_dict_alloc(unsigned int size) __init;

void * __init decompress_bunzip2_alloc(unsigned int size)
{
	return kmalloc(size, GFP_KERNEL);
}

void * __init decompress_bunzip2_dict_alloc(unsigned int size)
{
	return vmalloc(size);
}
