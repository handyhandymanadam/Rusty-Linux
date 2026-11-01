// SPDX-License-Identifier: GPL-2.0-only
/*
 * GHASH: hash function for GCM (Galois/Counter Mode).
 *
 * Copyright (c) 2007 Nokia Siemens Networks - Mikko Herranen <mh1@iki.fi>
 * Copyright (c) 2009 Intel Corp.
 *   Author: Huang Ying <ying.huang@intel.com>
 */

/*
 * GHASH is a keyed hash function used in GCM authentication tag generation.
 *
 * The original GCM paper [1] presents GHASH as a function GHASH(H, A, C) which
 * takes a 16-byte hash key H, additional authenticated data A, and a ciphertext
 * C.  It formats A and C into a single byte string X, interprets X as a
 * polynomial over GF(2^128), and evaluates this polynomial at the point H.
 *
 * However, the NIST standard for GCM [2] presents GHASH as GHASH(H, X) where X
 * is the already-formatted byte string containing both A and C.
 *
 * "ghash" in the Linux crypto API uses the 'X' (pre-formatted) convention,
 * since the API supports only a single data stream per hash.  Thus, the
 * formatting of 'A' and 'C' is done in the "gcm" template, not in "ghash".
 *
 * The reason "ghash" is separate from "gcm" is to allow "gcm" to use an
 * accelerated "ghash" when a standalone accelerated "gcm(aes)" is unavailable.
 * It is generally inappropriate to use "ghash" for other purposes, since it is
 * an "ε-almost-XOR-universal hash function", not a cryptographic hash function.
 * It can only be used securely in crypto modes specially designed to use it.
 *
 * [1] The Galois/Counter Mode of Operation (GCM)
 *     (http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.694.695&rep=rep1&type=pdf)
 * [2] Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC
 *     (https://csrc.nist.gov/publications/detail/sp/800-38d/final)
 */

#include <crypto/gf128mul.h>
#include <crypto/ghash.h>
#include <crypto/internal/hash.h>
#include <crypto/utils.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

/*
 * RUST PORT: the block loop, the zero-padded final block, the setkey protocol
 * (length check, free the old table, build the new one, wipe the key copy) and
 * the cra_exit free are in ghash_rs.rs. The GF(2^128) multiply is NOT in this
 * file: gf128mul_4k_lle() is lib/crypto/gf128mul.c, still C. The callbacks
 * below stay C: they reach their context through shash_desc_ctx()/
 * crypto_shash_ctx()/crypto_tfm_ctx(), static inline accessors over
 * Kconfig-dependent structs (same shape as crypto/md5.c).
 */
void crypto_ghash_rs_init(u8 *buffer);
int crypto_ghash_rs_setkey(struct gf128mul_4k **slot, const u8 *key,
			   unsigned int keylen);
unsigned int crypto_ghash_rs_update(u8 *buffer, const struct gf128mul_4k *gf128,
				    const u8 *src, unsigned int srclen);
void crypto_ghash_rs_finup(u8 *buffer, const struct gf128mul_4k *gf128,
			   const u8 *src, unsigned int len, u8 *dst);
void crypto_ghash_rs_exit(struct gf128mul_4k **slot);

static int ghash_init(struct shash_desc *desc)
{
	struct ghash_desc_ctx *dctx = shash_desc_ctx(desc);

	crypto_ghash_rs_init(dctx->buffer);

	return 0;
}

static int ghash_setkey(struct crypto_shash *tfm,
			const u8 *key, unsigned int keylen)
{
	struct ghash_ctx *ctx = crypto_shash_ctx(tfm);

	return crypto_ghash_rs_setkey(&ctx->gf128, key, keylen);
}

static int ghash_update(struct shash_desc *desc,
			 const u8 *src, unsigned int srclen)
{
	struct ghash_desc_ctx *dctx = shash_desc_ctx(desc);
	struct ghash_ctx *ctx = crypto_shash_ctx(desc->tfm);

	return crypto_ghash_rs_update(dctx->buffer, ctx->gf128, src, srclen);
}

static int ghash_finup(struct shash_desc *desc, const u8 *src,
		       unsigned int len, u8 *dst)
{
	struct ghash_desc_ctx *dctx = shash_desc_ctx(desc);
	struct ghash_ctx *ctx = crypto_shash_ctx(desc->tfm);

	crypto_ghash_rs_finup(dctx->buffer, ctx->gf128, src, len, dst);

	return 0;
}

static void ghash_exit_tfm(struct crypto_tfm *tfm)
{
	struct ghash_ctx *ctx = crypto_tfm_ctx(tfm);

	crypto_ghash_rs_exit(&ctx->gf128);
}

static struct shash_alg ghash_alg = {
	.digestsize	= GHASH_DIGEST_SIZE,
	.init		= ghash_init,
	.update		= ghash_update,
	.finup		= ghash_finup,
	.setkey		= ghash_setkey,
	.descsize	= sizeof(struct ghash_desc_ctx),
	.base		= {
		.cra_name		= "ghash",
		.cra_driver_name	= "ghash-generic",
		.cra_priority		= 100,
		.cra_flags		= CRYPTO_AHASH_ALG_BLOCK_ONLY,
		.cra_blocksize		= GHASH_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct ghash_ctx),
		.cra_module		= THIS_MODULE,
		.cra_exit		= ghash_exit_tfm,
	},
};

static int __init ghash_mod_init(void)
{
	return crypto_register_shash(&ghash_alg);
}

static void __exit ghash_mod_exit(void)
{
	crypto_unregister_shash(&ghash_alg);
}

module_init(ghash_mod_init);
module_exit(ghash_mod_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("GHASH hash function");
MODULE_ALIAS_CRYPTO("ghash");
MODULE_ALIAS_CRYPTO("ghash-generic");
