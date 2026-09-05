// SPDX-License-Identifier: GPL-2.0
/*
 * PORTED TO RUST. The body is lib/check_signature_rs.rs; what is left here is
 * the C entry symbol and its EXPORT_SYMBOL() line.
 *
 * See logs/c-entry-rule.md for when a C entry symbol stays and when it goes.
 */
#include <linux/io.h>
#include <linux/export.h>

/* lib/check_signature_rs.rs */
int rust_check_signature(const volatile void __iomem *io_addr,
			 const unsigned char *signature, int length);

/**
 *	check_signature		-	find BIOS signatures
 *	@io_addr: mmio address to check
 *	@signature:  signature block
 *	@length: length of signature
 *
 *	Perform a signature comparison with the mmio address io_addr. This
 *	address should have been obtained by ioremap.
 *	Returns 1 on a match.
 */

int check_signature(const volatile void __iomem *io_addr,
			const unsigned char *signature, int length)
{
	return rust_check_signature(io_addr, signature, length);
}
EXPORT_SYMBOL(check_signature);
