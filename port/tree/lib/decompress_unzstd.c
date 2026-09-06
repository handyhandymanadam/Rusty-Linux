// SPDX-License-Identifier: GPL-2.0
/*
 * The Rust unzstd wrapper's vmalloc thunk.
 *
 * vmalloc is `alloc_hooks(vmalloc_noprof(...))` since 6.10's allocation
 * profiling -- a macro with no linkable symbol. vfree is a real
 * EXPORT_SYMBOL and is called directly from decompress_unzstd_rs.rs; only
 * the allocating half needs a C body. See that file's module doc for the
 * rest of the port.
 *
 * `size` is `unsigned long`, matching vmalloc's real parameter type --
 * found by adversarial review: an earlier version took `unsigned int`,
 * which truncates any request at or above 4GiB to its low 32 bits instead
 * of passing it through to vmalloc unchanged, while every caller on the
 * Rust side still hands zstd_init_dstream() the untruncated size. That
 * turns the C's clean vmalloc failure (a window size a crafted frame
 * header can pick freely, per this file's own module doc, requesting more
 * memory than vmalloc will ever grant) into zstd being told it owns far
 * more workspace than was actually allocated -- an out-of-bounds write on
 * initramfs input, not merely a wrong error path.
 */
#include <linux/init.h>
#include <linux/vmalloc.h>

/* -Wmissing-prototypes requires this visible before the definition below,
 * since nothing else in the C tree calls it. __init: its only caller,
 * unzstd(), is __init too. */
void *decompress_unzstd_alloc(unsigned long size) __init;

void * __init decompress_unzstd_alloc(unsigned long size)
{
	return vmalloc(size);
}
