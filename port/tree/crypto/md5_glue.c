// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Crypto API support for MD5 and HMAC-MD5
 *
 * Copyright 2025 Google LLC
 */
#include <crypto/internal/hash.h>
#include <crypto/md5.h>
#include <linux/kernel.h>
#include <linux/module.h>

/*
 * Export and import functions.  crypto_shash wants a particular format that
 * matches that used by some legacy drivers.  It currently is the same as the
 * library MD5 context, except the value in bytecount must be block-aligned and
 * the remainder must be stored in an extra u8 appended to the struct.
 *
 * RUST PORT: the four __crypto_md5_{export,import}[_core]() bodies and the
 * exported md5_zero_message_hash table are in md5_shash_rs.rs. The shash_alg
 * table, the module glue and the one-line callbacks below stay C: the
 * callbacks reach their context through shash_desc_ctx()/crypto_shash_ctx(),
 * static inline accessors over Kconfig-dependent structs (see the Rust file).
 */

#define MD5_SHASH_STATE_SIZE (sizeof(struct md5_ctx) + 1)
static_assert(sizeof(struct md5_ctx) == sizeof(struct md5_state));
static_assert(offsetof(struct md5_ctx, state) == offsetof(struct md5_state, hash));
static_assert(offsetof(struct md5_ctx, bytecount) == offsetof(struct md5_state, byte_count));
static_assert(offsetof(struct md5_ctx, buf) == offsetof(struct md5_state, block));

int crypto_md5_rs_export(const struct md5_ctx *ctx0, void *out);
int crypto_md5_rs_import(struct md5_ctx *ctx, const void *in);
int crypto_md5_rs_export_core(const struct md5_ctx *ctx, void *out);
int crypto_md5_rs_import_core(struct md5_ctx *ctx, const void *in);

#define __crypto_md5_export crypto_md5_rs_export
#define __crypto_md5_import crypto_md5_rs_import
#define __crypto_md5_export_core crypto_md5_rs_export_core
#define __crypto_md5_import_core crypto_md5_rs_import_core

#define MD5_CTX(desc) ((struct md5_ctx *)shash_desc_ctx(desc))

static int crypto_md5_init(struct shash_desc *desc)
{
	md5_init(MD5_CTX(desc));
	return 0;
}

static int crypto_md5_update(struct shash_desc *desc,
			     const u8 *data, unsigned int len)
{
	md5_update(MD5_CTX(desc), data, len);
	return 0;
}

static int crypto_md5_final(struct shash_desc *desc, u8 *out)
{
	md5_final(MD5_CTX(desc), out);
	return 0;
}

static int crypto_md5_digest(struct shash_desc *desc,
			     const u8 *data, unsigned int len, u8 *out)
{
	md5(data, len, out);
	return 0;
}

static int crypto_md5_export(struct shash_desc *desc, void *out)
{
	return __crypto_md5_export(MD5_CTX(desc), out);
}

static int crypto_md5_import(struct shash_desc *desc, const void *in)
{
	return __crypto_md5_import(MD5_CTX(desc), in);
}

static int crypto_md5_export_core(struct shash_desc *desc, void *out)
{
	return __crypto_md5_export_core(MD5_CTX(desc), out);
}

static int crypto_md5_import_core(struct shash_desc *desc, const void *in)
{
	return __crypto_md5_import_core(MD5_CTX(desc), in);
}

#define HMAC_MD5_KEY(tfm) ((struct hmac_md5_key *)crypto_shash_ctx(tfm))
#define HMAC_MD5_CTX(desc) ((struct hmac_md5_ctx *)shash_desc_ctx(desc))

static int crypto_hmac_md5_setkey(struct crypto_shash *tfm,
				  const u8 *raw_key, unsigned int keylen)
{
	hmac_md5_preparekey(HMAC_MD5_KEY(tfm), raw_key, keylen);
	return 0;
}

static int crypto_hmac_md5_init(struct shash_desc *desc)
{
	hmac_md5_init(HMAC_MD5_CTX(desc), HMAC_MD5_KEY(desc->tfm));
	return 0;
}

static int crypto_hmac_md5_update(struct shash_desc *desc,
				  const u8 *data, unsigned int len)
{
	hmac_md5_update(HMAC_MD5_CTX(desc), data, len);
	return 0;
}

static int crypto_hmac_md5_final(struct shash_desc *desc, u8 *out)
{
	hmac_md5_final(HMAC_MD5_CTX(desc), out);
	return 0;
}

static int crypto_hmac_md5_digest(struct shash_desc *desc,
				  const u8 *data, unsigned int len, u8 *out)
{
	hmac_md5(HMAC_MD5_KEY(desc->tfm), data, len, out);
	return 0;
}

static int crypto_hmac_md5_export(struct shash_desc *desc, void *out)
{
	return __crypto_md5_export(&HMAC_MD5_CTX(desc)->hash_ctx, out);
}

static int crypto_hmac_md5_import(struct shash_desc *desc, const void *in)
{
	struct hmac_md5_ctx *ctx = HMAC_MD5_CTX(desc);

	ctx->ostate = HMAC_MD5_KEY(desc->tfm)->ostate;
	return __crypto_md5_import(&ctx->hash_ctx, in);
}

static int crypto_hmac_md5_export_core(struct shash_desc *desc, void *out)
{
	return __crypto_md5_export_core(&HMAC_MD5_CTX(desc)->hash_ctx, out);
}

static int crypto_hmac_md5_import_core(struct shash_desc *desc, const void *in)
{
	struct hmac_md5_ctx *ctx = HMAC_MD5_CTX(desc);

	ctx->ostate = HMAC_MD5_KEY(desc->tfm)->ostate;
	return __crypto_md5_import_core(&ctx->hash_ctx, in);
}

static struct shash_alg algs[] = {
	{
		.base.cra_name		= "md5",
		.base.cra_driver_name	= "md5-lib",
		.base.cra_priority	= 300,
		.base.cra_blocksize	= MD5_BLOCK_SIZE,
		.base.cra_module	= THIS_MODULE,
		.digestsize		= MD5_DIGEST_SIZE,
		.init			= crypto_md5_init,
		.update			= crypto_md5_update,
		.final			= crypto_md5_final,
		.digest			= crypto_md5_digest,
		.export			= crypto_md5_export,
		.import			= crypto_md5_import,
		.export_core		= crypto_md5_export_core,
		.import_core		= crypto_md5_import_core,
		.descsize		= sizeof(struct md5_ctx),
		.statesize		= MD5_SHASH_STATE_SIZE,
	},
	{
		.base.cra_name		= "hmac(md5)",
		.base.cra_driver_name	= "hmac-md5-lib",
		.base.cra_priority	= 300,
		.base.cra_blocksize	= MD5_BLOCK_SIZE,
		.base.cra_ctxsize	= sizeof(struct hmac_md5_key),
		.base.cra_module	= THIS_MODULE,
		.digestsize		= MD5_DIGEST_SIZE,
		.setkey			= crypto_hmac_md5_setkey,
		.init			= crypto_hmac_md5_init,
		.update			= crypto_hmac_md5_update,
		.final			= crypto_hmac_md5_final,
		.digest			= crypto_hmac_md5_digest,
		.export			= crypto_hmac_md5_export,
		.import			= crypto_hmac_md5_import,
		.export_core		= crypto_hmac_md5_export_core,
		.import_core		= crypto_hmac_md5_import_core,
		.descsize		= sizeof(struct hmac_md5_ctx),
		.statesize		= MD5_SHASH_STATE_SIZE,
	},
};

static int __init crypto_md5_mod_init(void)
{
	return crypto_register_shashes(algs, ARRAY_SIZE(algs));
}
module_init(crypto_md5_mod_init);

static void __exit crypto_md5_mod_exit(void)
{
	crypto_unregister_shashes(algs, ARRAY_SIZE(algs));
}
module_exit(crypto_md5_mod_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Crypto API support for MD5 and HMAC-MD5");

MODULE_ALIAS_CRYPTO("md5");
MODULE_ALIAS_CRYPTO("md5-lib");
MODULE_ALIAS_CRYPTO("hmac(md5)");
MODULE_ALIAS_CRYPTO("hmac-md5-lib");
