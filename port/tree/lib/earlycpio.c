// SPDX-License-Identifier: GPL-2.0-only
/* ----------------------------------------------------------------------- *
 *
 *   Copyright 2012 Intel Corporation; author H. Peter Anvin
 *
 * ----------------------------------------------------------------------- */

/*
 * earlycpio.c
 *
 * Find a specific cpio member; must precede any compressed content.
 * This is used to locate data items in the initramfs used by the
 * kernel itself during early boot (before the main initramfs is
 * decompressed.)  It is the responsibility of the initramfs creator
 * to ensure that these items are uncompressed at the head of the
 * blob.  Depending on the boot loader or package tool that may be a
 * separate file or part of the same file.
 *
 * PORTED TO RUST -- entirely. find_cpio_data() is defined in
 * lib/earlycpio_rs.rs with NO C entry symbol, because it is global but not
 * EXPORT_SYMBOL and therefore has no MODVERSIONS CRC. Compare
 * lib/union_find_rs.rs, which is in the same position.
 *
 * What is left here is one thing Rust cannot express: pr_warn() is a macro
 * over printk carrying a per-call format string, and the splat should name
 * this file.
 */

#include <linux/earlycpio.h>
#include <linux/kernel.h>
#include <linux/printk.h>

/* Called from lib/earlycpio_rs.rs. */
void rust_earlycpio_warn_long_name(const char *name);
void rust_earlycpio_warn_long_name(const char *name)
{
	pr_warn("File %s exceeding MAX_CPIO_FILE_NAME [%d]\n",
		name, MAX_CPIO_FILE_NAME);
}
