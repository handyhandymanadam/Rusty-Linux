#!/usr/bin/env python3
"""extract.py <pristine ecb.c> <out.c>: slice crypto_ecb_crypt() (signature, block-size line, loop, remainder rule) out of
the UNMODIFIED crypto/ecb.c, character for character, and rename it c_ecb_crypt. Fails loudly if it is not present
exactly once."""
import sys
src = open(sys.argv[1]).read()
func = '''static int crypto_ecb_crypt(struct crypto_cipher *cipher, const u8 *src,
			    u8 *dst, unsigned nbytes, bool final,
			    void (*fn)(struct crypto_tfm *, u8 *, const u8 *))
{
	const unsigned int bsize = crypto_cipher_blocksize(cipher);

	while (nbytes >= bsize) {
		fn(crypto_cipher_tfm(cipher), dst, src);

		src += bsize;
		dst += bsize;

		nbytes -= bsize;
	}

	return nbytes && final ? -EINVAL : nbytes;
}
'''
if src.count(func) != 1:
    sys.exit("EXTRACT FAILED: crypto_ecb_crypt not found exactly once in ecb.c -- the C changed")
open(sys.argv[2], "w").write('#include "kshim.h"\n' + func.replace("static int crypto_ecb_crypt(", "int c_ecb_crypt("))
