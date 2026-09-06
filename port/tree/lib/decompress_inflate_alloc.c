// SPDX-License-Identifier: GPL-2.0
/*
 * The Rust gunzip wrapper's kmalloc thunk.
 *
 * A SEPARATE file from decompress_inflate.c on purpose, unlike this file
 * family's other alloc shims: decompress_inflate.c's own `#ifdef STATIC`
 * arm is genuinely live in this project, not dead code the way
 * bunzip2/unlz4/unlzo/unxz/unzstd's preboot arms are. `arch/x86/boot/
 * compressed/misc.c` textually `#include`s "../../../../lib/
 * decompress_inflate.c" under `#ifdef CONFIG_KERNEL_GZIP`, and both of
 * this project's configs set CONFIG_KERNEL_GZIP=y (the kernel image itself
 * is gzip-compressed) -- so unlike every other format in this family,
 * decompress_inflate.c's textual-include arm actually gets compiled, into
 * the pre-boot decompression stub. Overwriting that file the way the
 * other five ports overwrite theirs would silently break kernel self-
 * decompression. See decompress_inflate_rs.rs's module doc for the rest
 * of this reasoning and how the Makefile keeps both arms working.
 *
 * kmalloc is `alloc_hooks(kmalloc_noprof(...))` since 6.10's allocation
 * profiling -- a macro with no linkable symbol. kfree is a real
 * EXPORT_SYMBOL and is called directly from decompress_inflate_rs.rs; only
 * the allocating half needs a C body.
 *
 * `size`/return type are `unsigned long`, matching kmalloc's own
 * parameter and sizeof's return type -- found by adversarial review:
 * an earlier version used `unsigned int` here, the same narrowing
 * decompress_unzstd_alloc() had before its own fix. Not live today (every
 * caller here passes a small, fixed-shape value -- 0x8000,
 * GZIP_IOBUF_SIZE, sizeof(struct z_stream_s), or a workspace size derived
 * from those), but it is the same unsound interface, kept narrow only by
 * the values the current callers happen to pass rather than by the
 * function's own signature.
 */
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/zutil.h>
#include "zlib_inflate/inftrees.h"
#include "zlib_inflate/inflate.h"

/* -Wmissing-prototypes requires this visible before the definitions below,
 * since nothing else in the C tree calls either. __init: their only caller,
 * gunzip(), is __init too. */
void *decompress_inflate_alloc(unsigned long size) __init;
unsigned long decompress_inflate_state_size(void) __init;

void * __init decompress_inflate_alloc(unsigned long size)
{
	return kmalloc(size, GFP_KERNEL);
}

/*
 * sizeof(struct inflate_state) -- needed by the Rust side's single-call
 * (flush == NULL) workspace-allocation branch, which upstream sizes to just
 * this struct rather than the full zlib_inflate_workspacesize() (which
 * additionally accounts for the trailing sliding-window buffer that
 * single-call mode disables). struct inflate_state is internal to
 * zlib_inflate/, not something Rust should duplicate a layout for just to
 * compute one number: this is the one fact about it nothing outside this
 * function needs, so a tiny accessor here is safer than hand-copying
 * inftrees.h's ENOUGH-sized trailing arrays into a second, driftable
 * definition.
 */
unsigned long __init decompress_inflate_state_size(void)
{
	return sizeof(struct inflate_state);
}
