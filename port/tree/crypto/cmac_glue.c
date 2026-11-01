// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * CMAC: Cipher Block Mode for Authentication
 *
 * Copyright © 2013 Jussi Kivilinna <jussi.kivilinna@iki.fi>
 *
 * Based on work by:
 *  Copyright © 2013 Tom St Denis <tstdenis@elliptictech.com>
 * Based on crypto/xcbc.c:
 *  Copyright © 2006 USAGI/WIDE Project,
 *   Author: Kazunori Miyazawa <miyazawa@linux-ipv6.org>
 */

#include <crypto/internal/cipher.h>
#include <crypto/internal/hash.h>
#include <crypto/utils.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>

/*
 * RUST PORT: the CMAC subkey derivation (K1, K2 by GF(2^128) / GF(2^64) doubling of the
 * encrypted zero block) and the byte-level part of the final block (xor of the message
 * tail, 0x80 padding, xor of K1 or K2) are cmac_rs_derive_subkeys() and
 * cmac_rs_finup_xor() in cmac_rs.rs. Everything else here (the cipher calls, the
 * shash_alg/template/instance glue) is crypto API plumbing over Kconfig-dependent
 * structs and stays C. In-contract callers pass bs 8 or 16 and len <= bs.
 */
void cmac_rs_derive_subkeys(u8 *consts, unsigned int bs);
void cmac_rs_finup_xor(u8 *prev, const u8 *src, unsigned int len, const u8 *consts,
		       unsigned int bs);

/*
 * +------------------------
 * | <parent tfm>
 * +------------------------
 * | cmac_tfm_ctx
 * +------------------------
 * | consts (block size * 2)
 * +------------------------
 */
struct cmac_tfm_ctx {
	struct crypto_cipher *child;
	__be64 consts[];
};

static int crypto_cmac_digest_setkey(struct crypto_shash *parent,
				     const u8 *inkey, unsigned int keylen)
{
	struct cmac_tfm_ctx *ctx = crypto_shash_ctx(parent);
	unsigned int bs = crypto_shash_blocksize(parent);
	__be64 *consts = ctx->consts;
	int err = 0;

	err = crypto_cipher_setkey(ctx->child, inkey, keylen);
	if (err)
		return err;

	/* encrypt the zero block */
	memset(consts, 0, bs);
	crypto_cipher_encrypt_one(ctx->child, (u8 *)consts, (u8 *)consts);

	cmac_rs_derive_subkeys((u8 *)consts, bs);

	return 0;
}

static int crypto_cmac_digest_init(struct shash_desc *pdesc)
{
	int bs = crypto_shash_blocksize(pdesc->tfm);
	u8 *prev = shash_desc_ctx(pdesc);

	memset(prev, 0, bs);
	return 0;
}

static int crypto_cmac_digest_update(struct shash_desc *pdesc, const u8 *p,
				     unsigned int len)
{
	struct crypto_shash *parent = pdesc->tfm;
	struct cmac_tfm_ctx *tctx = crypto_shash_ctx(parent);
	struct crypto_cipher *tfm = tctx->child;
	int bs = crypto_shash_blocksize(parent);
	u8 *prev = shash_desc_ctx(pdesc);

	do {
		crypto_xor(prev, p, bs);
		crypto_cipher_encrypt_one(tfm, prev, prev);
		p += bs;
		len -= bs;
	} while (len >= bs);
	return len;
}

static int crypto_cmac_digest_finup(struct shash_desc *pdesc, const u8 *src,
				    unsigned int len, u8 *out)
{
	struct crypto_shash *parent = pdesc->tfm;
	struct cmac_tfm_ctx *tctx = crypto_shash_ctx(parent);
	struct crypto_cipher *tfm = tctx->child;
	int bs = crypto_shash_blocksize(parent);
	u8 *prev = shash_desc_ctx(pdesc);

	cmac_rs_finup_xor(prev, src, len, (const u8 *)tctx->consts, bs);
	crypto_cipher_encrypt_one(tfm, out, prev);
	return 0;
}

static int cmac_init_tfm(struct crypto_shash *tfm)
{
	struct shash_instance *inst = shash_alg_instance(tfm);
	struct cmac_tfm_ctx *ctx = crypto_shash_ctx(tfm);
	struct crypto_cipher_spawn *spawn;
	struct crypto_cipher *cipher;

	spawn = shash_instance_ctx(inst);
	cipher = crypto_spawn_cipher(spawn);
	if (IS_ERR(cipher))
		return PTR_ERR(cipher);

	ctx->child = cipher;

	return 0;
}

static int cmac_clone_tfm(struct crypto_shash *tfm, struct crypto_shash *otfm)
{
	struct cmac_tfm_ctx *octx = crypto_shash_ctx(otfm);
	struct cmac_tfm_ctx *ctx = crypto_shash_ctx(tfm);
	struct crypto_cipher *cipher;

	cipher = crypto_clone_cipher(octx->child);
	if (IS_ERR(cipher))
		return PTR_ERR(cipher);

	ctx->child = cipher;

	return 0;
}

static void cmac_exit_tfm(struct crypto_shash *tfm)
{
	struct cmac_tfm_ctx *ctx = crypto_shash_ctx(tfm);
	crypto_free_cipher(ctx->child);
}

static int cmac_create(struct crypto_template *tmpl, struct rtattr **tb)
{
	struct shash_instance *inst;
	struct crypto_cipher_spawn *spawn;
	struct crypto_alg *alg;
	u32 mask;
	int err;

	err = crypto_check_attr_type(tb, CRYPTO_ALG_TYPE_SHASH, &mask);
	if (err)
		return err;

	inst = kzalloc(sizeof(*inst) + sizeof(*spawn), GFP_KERNEL);
	if (!inst)
		return -ENOMEM;
	spawn = shash_instance_ctx(inst);

	err = crypto_grab_cipher(spawn, shash_crypto_instance(inst),
				 crypto_attr_alg_name(tb[1]), 0, mask);
	if (err)
		goto err_free_inst;
	alg = crypto_spawn_cipher_alg(spawn);

	switch (alg->cra_blocksize) {
	case 16:
	case 8:
		break;
	default:
		err = -EINVAL;
		goto err_free_inst;
	}

	err = crypto_inst_setname(shash_crypto_instance(inst), tmpl->name, alg);
	if (err)
		goto err_free_inst;

	inst->alg.base.cra_priority = alg->cra_priority;
	inst->alg.base.cra_blocksize = alg->cra_blocksize;
	inst->alg.base.cra_ctxsize = sizeof(struct cmac_tfm_ctx) +
				     alg->cra_blocksize * 2;
	inst->alg.base.cra_flags = CRYPTO_AHASH_ALG_BLOCK_ONLY |
				   CRYPTO_AHASH_ALG_FINAL_NONZERO;

	inst->alg.digestsize = alg->cra_blocksize;
	inst->alg.descsize = alg->cra_blocksize;
	inst->alg.init = crypto_cmac_digest_init;
	inst->alg.update = crypto_cmac_digest_update;
	inst->alg.finup = crypto_cmac_digest_finup;
	inst->alg.setkey = crypto_cmac_digest_setkey;
	inst->alg.init_tfm = cmac_init_tfm;
	inst->alg.clone_tfm = cmac_clone_tfm;
	inst->alg.exit_tfm = cmac_exit_tfm;

	inst->free = shash_free_singlespawn_instance;

	err = shash_register_instance(tmpl, inst);
	if (err) {
err_free_inst:
		shash_free_singlespawn_instance(inst);
	}
	return err;
}

static struct crypto_template crypto_cmac_tmpl = {
	.name = "cmac",
	.create = cmac_create,
	.module = THIS_MODULE,
};

static int __init crypto_cmac_module_init(void)
{
	return crypto_register_template(&crypto_cmac_tmpl);
}

static void __exit crypto_cmac_module_exit(void)
{
	crypto_unregister_template(&crypto_cmac_tmpl);
}

module_init(crypto_cmac_module_init);
module_exit(crypto_cmac_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("CMAC keyed hash algorithm");
MODULE_ALIAS_CRYPTO("cmac");
MODULE_IMPORT_NS("CRYPTO_INTERNAL");
