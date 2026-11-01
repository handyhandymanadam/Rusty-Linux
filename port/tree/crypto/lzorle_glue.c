// SPDX-License-Identifier: GPL-2.0-only
/*
 * Cryptographic API.
 */

#include <crypto/internal/scompress.h>
#include <linux/init.h>
#include <linux/lzo.h>
#include <linux/module.h>
#include <linux/slab.h>

static void *lzorle_alloc_ctx(void)
{
	void *ctx;

	ctx = kvmalloc(LZO1X_MEM_COMPRESS, GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	return ctx;
}

static void lzorle_free_ctx(void *ctx)
{
	kvfree(ctx);
}

/*
 * RUST PORT: __lzorle_compress() and __lzorle_decompress() -- the widening of the
 * output length, the call into the library, the nonzero -> -EINVAL mapping and
 * the write-back on success -- are in lzorle_rs.rs. The scomp table, the module
 * glue and the one-line callbacks stay C, and so do lzorle_alloc_ctx()/
 * lzorle_free_ctx(): kvmalloc()/kvfree() are alloc_hooks() macros with no symbol.
 */
int crypto_lzorle_rs_compress(const u8 *src, unsigned int slen,
			   u8 *dst, unsigned int *dlen, void *ctx);
int crypto_lzorle_rs_decompress(const u8 *src, unsigned int slen,
			     u8 *dst, unsigned int *dlen);
#define __lzorle_compress crypto_lzorle_rs_compress
#define __lzorle_decompress crypto_lzorle_rs_decompress

static int lzorle_scompress(struct crypto_scomp *tfm, const u8 *src,
			 unsigned int slen, u8 *dst, unsigned int *dlen,
			 void *ctx)
{
	return __lzorle_compress(src, slen, dst, dlen, ctx);
}

static int lzorle_sdecompress(struct crypto_scomp *tfm, const u8 *src,
			   unsigned int slen, u8 *dst, unsigned int *dlen,
			   void *ctx)
{
	return __lzorle_decompress(src, slen, dst, dlen);
}

static struct scomp_alg scomp = {
	.streams		= {
		.alloc_ctx	= lzorle_alloc_ctx,
		.free_ctx	= lzorle_free_ctx,
	},
	.compress		= lzorle_scompress,
	.decompress		= lzorle_sdecompress,
	.base			= {
		.cra_name	= "lzo-rle",
		.cra_driver_name = "lzo-rle-scomp",
		.cra_module	 = THIS_MODULE,
	}
};

static int __init lzorle_mod_init(void)
{
	return crypto_register_scomp(&scomp);
}

static void __exit lzorle_mod_fini(void)
{
	crypto_unregister_scomp(&scomp);
}

module_init(lzorle_mod_init);
module_exit(lzorle_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("LZO-RLE Compression Algorithm");
MODULE_ALIAS_CRYPTO("lzo-rle");
