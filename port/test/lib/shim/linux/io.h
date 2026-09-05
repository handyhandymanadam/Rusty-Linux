/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_LINUX_IO_H
#define _SHIM_LINUX_IO_H
/*
 * Enough of <linux/io.h> to compile the pristine lib/check_signature.c in
 * userspace. readb() in the kernel is __raw_readb() plus the architecture's
 * ordering barriers; on x86 the load itself is a plain movb, and this test
 * compares WHICH BYTES ARE READ AND IN WHAT ORDER, not the barriers. The
 * ordering is settled by construction instead: the Rust calls
 * rust_helper_readb() once per byte, ascending, which is what the C's readb()
 * loop does.
 */
#define __iomem

static inline unsigned char readb(const volatile void *addr)
{
	return *(const volatile unsigned char *)addr;
}
#endif
