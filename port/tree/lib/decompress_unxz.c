// SPDX-License-Identifier: 0BSD
/*
 * The Rust unxz wrapper's kmalloc thunk.
 *
 * kmalloc is `alloc_hooks(kmalloc_noprof(...))` since 6.10's allocation
 * profiling -- a macro with no linkable symbol. kfree is a real
 * EXPORT_SYMBOL and is called directly from decompress_unxz_rs.rs; only
 * the allocating half needs a C body. See that file's module doc for the
 * rest of the port.
 */
#include <linux/init.h>
#include <linux/slab.h>

/* -Wmissing-prototypes requires this visible before the definition below,
 * since nothing else in the C tree calls it. __init: its only caller,
 * unxz(), is __init too. */
void *decompress_unxz_alloc(unsigned int size) __init;

void * __init decompress_unxz_alloc(unsigned int size)
{
	return kmalloc(size, GFP_KERNEL);
}
