// SPDX-License-Identifier: GPL-2.0-only
/*
 * The Rust unlz4 wrapper's vmalloc thunk.
 *
 * vmalloc is `alloc_hooks(vmalloc_noprof(...))` since 6.10's allocation
 * profiling -- a macro with no linkable symbol. vfree is a real
 * EXPORT_SYMBOL and is called directly from decompress_unlz4_rs.rs; only
 * the allocating half needs a C body. See that file's module doc for the
 * rest of the port.
 */
#include <linux/init.h>
#include <linux/vmalloc.h>

/* -Wmissing-prototypes requires this visible before the definition below,
 * since nothing else in the C tree calls it. __init: its only caller,
 * unlz4(), is __init too. */
void *decompress_unlz4_alloc(unsigned int size) __init;

void * __init decompress_unlz4_alloc(unsigned int size)
{
	return vmalloc(size);
}
