// SPDX-License-Identifier: GPL-2.0-only
/*
 * Cryptographic API.
 */

#include <crypto/internal/scompress.h>
#include <linux/init.h>
#include <linux/lzo.h>
#include <linux/module.h>
#include <linux/slab.h>

static void *lzo_alloc_ctx(void)
{
	void *ctx;

	ctx = kvmalloc(LZO1X_MEM_COMPRESS, GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	return ctx;
}

static void lzo_free_ctx(void *ctx)
{
	kvfree(ctx);
}

/*
 * RUST PORT: __lzo_compress() and __lzo_decompress() -- the widening of the
 * output length, the call into the library, the nonzero -> -EINVAL mapping and
 * the write-back on success -- are in lzo_rs.rs. The scomp table, the module
 * glue and the one-line callbacks stay C, and so do lzo_alloc_ctx()/
 * lzo_free_ctx(): kvmalloc()/kvfree() are alloc_hooks() macros with no symbol.
 */
int crypto_lzo_rs_compress(const u8 *src, unsigned int slen,
			   u8 *dst, unsigned int *dlen, void *ctx);
int crypto_lzo_rs_decompress(const u8 *src, unsigned int slen,
			     u8 *dst, unsigned int *dlen);
#define __lzo_compress crypto_lzo_rs_compress
#define __lzo_decompress crypto_lzo_rs_decompress

static int lzo_scompress(struct crypto_scomp *tfm, const u8 *src,
			 unsigned int slen, u8 *dst, unsigned int *dlen,
			 void *ctx)
{
	return __lzo_compress(src, slen, dst, dlen, ctx);
}

static int lzo_sdecompress(struct crypto_scomp *tfm, const u8 *src,
			   unsigned int slen, u8 *dst, unsigned int *dlen,
			   void *ctx)
{
	return __lzo_decompress(src, slen, dst, dlen);
}

static struct scomp_alg scomp = {
	.streams		= {
		.alloc_ctx	= lzo_alloc_ctx,
		.free_ctx	= lzo_free_ctx,
	},
	.compress		= lzo_scompress,
	.decompress		= lzo_sdecompress,
	.base			= {
		.cra_name	= "lzo",
		.cra_driver_name = "lzo-scomp",
		.cra_module	 = THIS_MODULE,
	}
};

static int __init lzo_mod_init(void)
{
	return crypto_register_scomp(&scomp);
}

static void __exit lzo_mod_fini(void)
{
	crypto_unregister_scomp(&scomp);
}

module_init(lzo_mod_init);
module_exit(lzo_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("LZO Compression Algorithm");
MODULE_ALIAS_CRYPTO("lzo");
