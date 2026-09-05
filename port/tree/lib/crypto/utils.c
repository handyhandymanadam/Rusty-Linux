// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Crypto library utility functions
 *
 * Copyright (c) 2006 Herbert Xu <herbert@gondor.apana.org.au>
 *
 * PORTED TO RUST. The body is lib/crypto/utils_rs.rs; what is left here is
 * the C entry symbol, its EXPORT_SYMBOL_GPL(), and the two configuration
 * flags the Rust needs and must not guess at:
 *
 *   CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS  decides whether the relative
 *                                           alignment dance runs at all
 *   CONFIG_64BIT                            decides whether 8-byte chunks
 *                                           are used
 *
 * Same reasoning as lib/sort.c: guessing either would silently change the
 * chunk width on an architecture nobody was testing on, and the resulting
 * bug would be an unaligned access rather than a wrong answer.
 *
 * See logs/c-entry-rule.md for when a C entry symbol stays and when it goes.
 */

#include <crypto/utils.h>
#include <linux/export.h>
#include <linux/module.h>
#include <linux/types.h>

#ifdef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
#define XOR_EFFICIENT_UNALIGNED true
#else
#define XOR_EFFICIENT_UNALIGNED false
#endif

#ifdef CONFIG_64BIT
#define XOR_64BIT true
#else
#define XOR_64BIT false
#endif

/* lib/crypto/utils_rs.rs */
void rust_crypto_xor(u8 *dst, const u8 *src1, const u8 *src2, unsigned int len,
		     bool efficient_unaligned, bool is_64bit);

void __crypto_xor(u8 *dst, const u8 *src1, const u8 *src2, unsigned int len)
{
	rust_crypto_xor(dst, src1, src2, len, XOR_EFFICIENT_UNALIGNED, XOR_64BIT);
}
EXPORT_SYMBOL_GPL(__crypto_xor);

MODULE_DESCRIPTION("Crypto library utility functions");
MODULE_LICENSE("GPL");
