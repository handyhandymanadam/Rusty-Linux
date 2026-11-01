// SPDX-License-Identifier: GPL-2.0-or-later
/* RSA asymmetric public-key algorithm [RFC3447]
 *
 * Copyright (c) 2015, Intel Corporation
 * Authors: Tadeusz Struk <tadeusz.struk@intel.com>
 */

#include <linux/fips.h>
#include <linux/module.h>
#include <linux/mpi.h>
#include <crypto/internal/rsa.h>
#include <crypto/internal/akcipher.h>
#include <crypto/akcipher.h>
#include <crypto/algapi.h>

struct rsa_mpi_key {
	MPI n;
	MPI e;
	MPI d;
	MPI p;
	MPI q;
	MPI dp;
	MPI dq;
	MPI qinv;
};

/*
 * RUST PORT: the RSA primitive (rsa_check_payload, RSAEP, RSADP with the CRT, the key loading and the
 * key-size / FIPS exponent rules, the free of the eight MPIs) is rsa_rs_*() in rsa_rs.rs. They take the
 * transform's struct rsa_mpi_key and the request's scatterlists, so struct akcipher_request and the
 * transform context accessors stay here as one-line wrappers. What stays C: the akcipher_alg table,
 * rsa_init/rsa_exit (registration of the algorithm and the pkcs1pad / rsassa-pkcs1 templates) and the
 * struct rsa_mpi_key definition (it sizes the context).
 */
int rsa_rs_enc(const struct rsa_mpi_key *pkey, struct scatterlist *src, unsigned int src_len,
	       struct scatterlist *dst, unsigned int dst_len);
int rsa_rs_dec(const struct rsa_mpi_key *pkey, struct scatterlist *src, unsigned int src_len,
	       struct scatterlist *dst, unsigned int dst_len);
void rsa_rs_free_key(struct rsa_mpi_key *key);
int rsa_rs_set_pub_key(struct rsa_mpi_key *mpi_key, const void *key, unsigned int keylen);
int rsa_rs_set_priv_key(struct rsa_mpi_key *mpi_key, const void *key, unsigned int keylen);
unsigned int rsa_rs_max_size(const struct rsa_mpi_key *pkey);

static inline struct rsa_mpi_key *rsa_get_key(struct crypto_akcipher *tfm)
{
	return akcipher_tfm_ctx(tfm);
}

static int rsa_enc(struct akcipher_request *req)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	const struct rsa_mpi_key *pkey = rsa_get_key(tfm);

	return rsa_rs_enc(pkey, req->src, req->src_len, req->dst, req->dst_len);
}

static int rsa_dec(struct akcipher_request *req)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	const struct rsa_mpi_key *pkey = rsa_get_key(tfm);

	return rsa_rs_dec(pkey, req->src, req->src_len, req->dst, req->dst_len);
}

static int rsa_set_pub_key(struct crypto_akcipher *tfm, const void *key,
			   unsigned int keylen)
{
	return rsa_rs_set_pub_key(akcipher_tfm_ctx(tfm), key, keylen);
}

static int rsa_set_priv_key(struct crypto_akcipher *tfm, const void *key,
			    unsigned int keylen)
{
	return rsa_rs_set_priv_key(akcipher_tfm_ctx(tfm), key, keylen);
}

static unsigned int rsa_max_size(struct crypto_akcipher *tfm)
{
	struct rsa_mpi_key *pkey = akcipher_tfm_ctx(tfm);

	return rsa_rs_max_size(pkey);
}

static void rsa_exit_tfm(struct crypto_akcipher *tfm)
{
	struct rsa_mpi_key *pkey = akcipher_tfm_ctx(tfm);

	rsa_rs_free_key(pkey);
}

static struct akcipher_alg rsa = {
	.encrypt = rsa_enc,
	.decrypt = rsa_dec,
	.set_priv_key = rsa_set_priv_key,
	.set_pub_key = rsa_set_pub_key,
	.max_size = rsa_max_size,
	.exit = rsa_exit_tfm,
	.base = {
		.cra_name = "rsa",
		.cra_driver_name = "rsa-generic",
		.cra_priority = 100,
		.cra_module = THIS_MODULE,
		.cra_ctxsize = sizeof(struct rsa_mpi_key),
	},
};

static int __init rsa_init(void)
{
	int err;

	err = crypto_register_akcipher(&rsa);
	if (err)
		return err;

	err = crypto_register_template(&rsa_pkcs1pad_tmpl);
	if (err)
		goto err_unregister_rsa;

	err = crypto_register_template(&rsassa_pkcs1_tmpl);
	if (err)
		goto err_unregister_rsa_pkcs1pad;

	return 0;

err_unregister_rsa_pkcs1pad:
	crypto_unregister_template(&rsa_pkcs1pad_tmpl);
err_unregister_rsa:
	crypto_unregister_akcipher(&rsa);
	return err;
}

static void __exit rsa_exit(void)
{
	crypto_unregister_template(&rsassa_pkcs1_tmpl);
	crypto_unregister_template(&rsa_pkcs1pad_tmpl);
	crypto_unregister_akcipher(&rsa);
}

module_init(rsa_init);
module_exit(rsa_exit);
MODULE_ALIAS_CRYPTO("rsa");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RSA generic algorithm");
