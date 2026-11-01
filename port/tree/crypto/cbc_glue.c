// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * CBC: Cipher Block Chaining mode
 *
 * Copyright (c) 2006-2016 Herbert Xu <herbert@gondor.apana.org.au>
 */

#include <crypto/internal/skcipher.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/log2.h>
#include <linux/module.h>

/*
 * RUST PORT: the four chaining loops of this file (encrypt/decrypt x out-of-place/in-place: xor with
 * the IV, one block-cipher call per block, IV update, remainder) are cbc_rs_*() in cbc_rs.rs. The
 * cipher is reached from Rust through the two one-line callbacks below (crypto_lskcipher_encrypt /
 * crypto_lskcipher_decrypt on one block with a NULL IV, return value ignored as upstream does), so no
 * struct is mirrored. Everything else (the FINAL-flag / in-place dispatch, the template, instance
 * creation and module_init, all over Kconfig-dependent lskcipher structs) stays C.
 */
typedef void (*cbc_rs_cipher_t)(void *tfm, const u8 *src, u8 *dst, unsigned int len);
unsigned int cbc_rs_encrypt_segment(void *tfm, cbc_rs_cipher_t enc, unsigned int bsize, const u8 *src,
				    u8 *dst, unsigned int nbytes, u8 *iv);
unsigned int cbc_rs_encrypt_inplace(void *tfm, cbc_rs_cipher_t enc, unsigned int bsize, u8 *src,
				    unsigned int nbytes, u8 *oiv);
unsigned int cbc_rs_decrypt_segment(void *tfm, cbc_rs_cipher_t dec, unsigned int bsize, const u8 *src,
				    u8 *dst, unsigned int nbytes, u8 *oiv);
unsigned int cbc_rs_decrypt_inplace(void *tfm, cbc_rs_cipher_t dec, unsigned int bsize, u8 *src,
				    unsigned int nbytes, u8 *iv);

static void cbc_enc_one(void *tfm, const u8 *src, u8 *dst, unsigned int len)
{
	crypto_lskcipher_encrypt(tfm, src, dst, len, NULL);
}

static void cbc_dec_one(void *tfm, const u8 *src, u8 *dst, unsigned int len)
{
	crypto_lskcipher_decrypt(tfm, src, dst, len, NULL);
}

static int crypto_cbc_encrypt_segment(struct crypto_lskcipher *tfm,
				      const u8 *src, u8 *dst, unsigned nbytes,
				      u8 *iv)
{
	return cbc_rs_encrypt_segment(tfm, cbc_enc_one, crypto_lskcipher_blocksize(tfm), src, dst, nbytes, iv);
}

static int crypto_cbc_encrypt_inplace(struct crypto_lskcipher *tfm,
				      u8 *src, unsigned nbytes, u8 *oiv)
{
	return cbc_rs_encrypt_inplace(tfm, cbc_enc_one, crypto_lskcipher_blocksize(tfm), src, nbytes, oiv);
}

static int crypto_cbc_encrypt(struct crypto_lskcipher *tfm, const u8 *src,
			      u8 *dst, unsigned len, u8 *iv, u32 flags)
{
	struct crypto_lskcipher **ctx = crypto_lskcipher_ctx(tfm);
	bool final = flags & CRYPTO_LSKCIPHER_FLAG_FINAL;
	struct crypto_lskcipher *cipher = *ctx;
	int rem;

	if (src == dst)
		rem = crypto_cbc_encrypt_inplace(cipher, dst, len, iv);
	else
		rem = crypto_cbc_encrypt_segment(cipher, src, dst, len, iv);

	return rem && final ? -EINVAL : rem;
}

static int crypto_cbc_decrypt_segment(struct crypto_lskcipher *tfm,
				      const u8 *src, u8 *dst, unsigned nbytes,
				      u8 *oiv)
{
	return cbc_rs_decrypt_segment(tfm, cbc_dec_one, crypto_lskcipher_blocksize(tfm), src, dst, nbytes, oiv);
}

static int crypto_cbc_decrypt_inplace(struct crypto_lskcipher *tfm,
				      u8 *src, unsigned nbytes, u8 *iv)
{
	return cbc_rs_decrypt_inplace(tfm, cbc_dec_one, crypto_lskcipher_blocksize(tfm), src, nbytes, iv);
}

static int crypto_cbc_decrypt(struct crypto_lskcipher *tfm, const u8 *src,
			      u8 *dst, unsigned len, u8 *iv, u32 flags)
{
	struct crypto_lskcipher **ctx = crypto_lskcipher_ctx(tfm);
	bool final = flags & CRYPTO_LSKCIPHER_FLAG_FINAL;
	struct crypto_lskcipher *cipher = *ctx;
	int rem;

	if (src == dst)
		rem = crypto_cbc_decrypt_inplace(cipher, dst, len, iv);
	else
		rem = crypto_cbc_decrypt_segment(cipher, src, dst, len, iv);

	return rem && final ? -EINVAL : rem;
}

static int crypto_cbc_create(struct crypto_template *tmpl, struct rtattr **tb)
{
	struct lskcipher_instance *inst;
	int err;

	inst = lskcipher_alloc_instance_simple(tmpl, tb);
	if (IS_ERR(inst))
		return PTR_ERR(inst);

	err = -EINVAL;
	if (!is_power_of_2(inst->alg.co.base.cra_blocksize))
		goto out_free_inst;

	if (inst->alg.co.statesize)
		goto out_free_inst;

	inst->alg.encrypt = crypto_cbc_encrypt;
	inst->alg.decrypt = crypto_cbc_decrypt;

	err = lskcipher_register_instance(tmpl, inst);
	if (err) {
out_free_inst:
		inst->free(inst);
	}

	return err;
}

static struct crypto_template crypto_cbc_tmpl = {
	.name = "cbc",
	.create = crypto_cbc_create,
	.module = THIS_MODULE,
};

static int __init crypto_cbc_module_init(void)
{
	return crypto_register_template(&crypto_cbc_tmpl);
}

static void __exit crypto_cbc_module_exit(void)
{
	crypto_unregister_template(&crypto_cbc_tmpl);
}

module_init(crypto_cbc_module_init);
module_exit(crypto_cbc_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("CBC block cipher mode of operation");
MODULE_ALIAS_CRYPTO("cbc");
