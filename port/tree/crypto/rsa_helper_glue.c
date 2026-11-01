// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * RSA key extract helper
 *
 * Copyright (c) 2015, Intel Corporation
 * Authors: Tadeusz Struk <tadeusz.struk@intel.com>
 */
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/err.h>
#include <linux/fips.h>
#include <crypto/internal/rsa.h>
#include "rsapubkey.asn1.h"
#include "rsaprivkey.asn1.h"

/*
 * RUST PORT: the eight ASN.1 field callbacks rsa_get_n/e/d/p/q/dp/dq/qinv (the checks and the stores
 * into struct rsa_key, including the FIPS modulus-size rule) are in rsa_helper_rs.rs. They are not
 * exported; the generated rsapubkey/rsaprivkey decoder tables reference them by symbol. What stays C
 * here: the two exported parse entry points, each one asn1_ber_decoder() call on a generated table.
 */

/**
 * rsa_parse_pub_key() - decodes the BER encoded buffer and stores in the
 *                       provided struct rsa_key, pointers to the raw key as is,
 *                       so that the caller can copy it or MPI parse it, etc.
 *
 * @rsa_key:	struct rsa_key key representation
 * @key:	key in BER format
 * @key_len:	length of key
 *
 * Return:	0 on success or error code in case of error
 */
int rsa_parse_pub_key(struct rsa_key *rsa_key, const void *key,
		      unsigned int key_len)
{
	return asn1_ber_decoder(&rsapubkey_decoder, rsa_key, key, key_len);
}
EXPORT_SYMBOL_GPL(rsa_parse_pub_key);

/**
 * rsa_parse_priv_key() - decodes the BER encoded buffer and stores in the
 *                        provided struct rsa_key, pointers to the raw key
 *                        as is, so that the caller can copy it or MPI parse it,
 *                        etc.
 *
 * @rsa_key:	struct rsa_key key representation
 * @key:	key in BER format
 * @key_len:	length of key
 *
 * Return:	0 on success or error code in case of error
 */
int rsa_parse_priv_key(struct rsa_key *rsa_key, const void *key,
		       unsigned int key_len)
{
	return asn1_ber_decoder(&rsaprivkey_decoder, rsa_key, key, key_len);
}
EXPORT_SYMBOL_GPL(rsa_parse_priv_key);
