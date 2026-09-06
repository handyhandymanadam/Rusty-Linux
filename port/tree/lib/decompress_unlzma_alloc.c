// SPDX-License-Identifier: GPL-2.0
/*
 * The Rust unlzma decoder's kmalloc/vmalloc thunks.
 *
 * A SEPARATE file from decompress_unlzma.c, unlike this file family's
 * single-allocator members: decompress_unlzma.c's own `#ifdef STATIC`
 * body is BOTH the wrapper and the whole LZMA algorithm in one
 * translation unit (unlike e.g. decompress_unlzo.c, whose algorithm body
 * lives separately in lzo/lzo1x_decompress_safe.c and can be replaced
 * independently of that library file). `arch/x86/boot/compressed/misc.c`
 * textually `#include`s "../../../../lib/decompress_unlzma.c" under
 * `#ifdef CONFIG_KERNEL_LZMA` -- neither of this project's configs sets
 * that (both use CONFIG_KERNEL_GZIP, verified against the built
 * .config), so unlike decompress_inflate.c this arm is genuinely dead
 * code here, covered by no test. Kept byte-identical to upstream anyway,
 * the same precedent `logs/build-limits.md` already documents for
 * lzo/lzo1x_decompress_safe.c's own pre-boot body: CONFIG_KERNEL_LZMA is
 * a real, supported kernel configuration even though this project does
 * not build it, and "if it ever drifts from the Rust, nothing in this
 * project will notice" is a documented, accepted limit -- not silently
 * introduced by overwriting the one file that carries both the wrapper
 * and the algorithm.
 *
 * Unlike this file family's single-allocator members, decompress_unlzma.c
 * calls plain malloc() (mm.h's non-STATIC arm: kmalloc(a, GFP_KERNEL)) for
 * the input buffer only, and large_malloc()/large_free() (vmalloc/vfree)
 * for the output buffer and the probability-model array -- so both
 * allocator families are needed here. Both are macros with no linkable
 * symbol since 6.10's allocation profiling; kfree and vfree are real
 * EXPORT_SYMBOLs and are called directly from decompress_unlzma_rs.rs.
 * See that file's module doc for the rest of the port.
 */
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

/* -Wmissing-prototypes requires this visible before the definitions below,
 * since nothing else in the C tree calls either. __init: their only
 * caller, unlzma(), is __init too. */
void *decompress_unlzma_alloc(unsigned long size) __init;
void *decompress_unlzma_large_alloc(unsigned long size) __init;

void * __init decompress_unlzma_alloc(unsigned long size)
{
	return kmalloc(size, GFP_KERNEL);
}

void * __init decompress_unlzma_large_alloc(unsigned long size)
{
	return vmalloc(size);
}
