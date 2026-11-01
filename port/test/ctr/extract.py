#!/usr/bin/env python3
"""extract.py <pristine ctr.c> <kernel algapi.c> <out.c>: slice the logic blocks out of the UNMODIFIED crypto/ctr.c into
c_final / c_segment / c_inplace / c_rfc_iv, and crypto_inc (verbatim, with crypto_inc_byte) out of crypto/algapi.c.
Fails loudly if any block is not present exactly once, character for character."""
import sys
src = open(sys.argv[1]).read(); alg = open(sys.argv[2]).read()
blocks = {
 "final": "\tcrypto_cipher_encrypt_one(tfm, keystream, ctrblk);\n\tcrypto_xor_cpy(dst, keystream, src, nbytes);\n\n\tcrypto_inc(ctrblk, bsize);\n",
 "segment": "\tdo {\n\t\t/* create keystream */\n\t\tfn(crypto_cipher_tfm(tfm), dst, ctrblk);\n\t\tcrypto_xor(dst, src, bsize);\n\n\t\t/* increment counter in counterblock */\n\t\tcrypto_inc(ctrblk, bsize);\n\n\t\tsrc += bsize;\n\t\tdst += bsize;\n\t} while ((nbytes -= bsize) >= bsize);\n\n\treturn nbytes;\n",
 "inplace": "\tdo {\n\t\t/* create keystream */\n\t\tfn(crypto_cipher_tfm(tfm), keystream, ctrblk);\n\t\tcrypto_xor(dst, keystream, bsize);\n\n\t\t/* increment counter in counterblock */\n\t\tcrypto_inc(ctrblk, bsize);\n\n\t\tdst += bsize;\n\t} while ((nbytes -= bsize) >= bsize);\n\n\treturn nbytes;\n",
 "rfc": "\tmemcpy(iv, ctx->nonce, CTR_RFC3686_NONCE_SIZE);\n\tmemcpy(iv + CTR_RFC3686_NONCE_SIZE, req->iv, CTR_RFC3686_IV_SIZE);\n\n\t/* initialize counter portion of counter block */\n\t*(__be32 *)(iv + CTR_RFC3686_NONCE_SIZE + CTR_RFC3686_IV_SIZE) =\n\t\tcpu_to_be32(1);\n",
}
for k, b in blocks.items():
    if src.count(b) != 1:
        sys.exit("EXTRACT FAILED: %s block not found exactly once in ctr.c -- the C changed" % k)
a0 = alg.index("static inline void crypto_inc_byte(u8 *a, unsigned int size)")
a1 = alg.index("EXPORT_SYMBOL_GPL(crypto_inc);")
inc = alg[a0:a1]
if inc.count("crypto_inc_byte(a, size);") != 1 or "void crypto_inc(u8 *a, unsigned int size)" not in inc:
    sys.exit("EXTRACT FAILED: crypto_inc slice")
open(sys.argv[3], "w").write('''#include "kshim.h"
typedef void (*ctr_fn_t)(void *, u8 *, const u8 *);
static void fn_cia(void *t, u8 *d, const u8 *s) { (void)t; toy_encrypt_block(d, s); }
void c_final(u8 *ctrblk, unsigned int bsize, void *tfm, u8 *keystream, const u8 *src, u8 *dst, unsigned int nbytes)
{
%s}
unsigned int c_segment(u8 *ctrblk, unsigned int bsize, void *tfm, const u8 *src, u8 *dst, unsigned int nbytes)
{
	ctr_fn_t fn = fn_cia;
%s}
unsigned int c_inplace(u8 *ctrblk, unsigned int bsize, void *tfm, u8 *keystream, u8 *dst, unsigned int nbytes)
{
	ctr_fn_t fn = fn_cia;
%s}
void c_rfc_iv(u8 *iv, const u8 *nonce, const u8 *req_iv)
{
	struct { const u8 *nonce; } c = { nonce }, *ctx = &c;
	struct { const u8 *iv; } r = { req_iv }, *req = &r;
%s}
/* crypto/algapi.c, verbatim */
%s''' % (blocks["final"], blocks["segment"], blocks["inplace"], blocks["rfc"], inc))
