#!/usr/bin/env python3
"""extract.py <pristine hmac.c> <out.c>: slice the pad-derivation statements out of the UNMODIFIED crypto/hmac.c
into a function c_derive_pads(). Fails loudly if the block is not present exactly twice (hmac_setkey and
hmac_setkey_ahash) with identical text, or if the HMAC_*_VALUE constants are not in the shim's header."""
import sys
src = open(sys.argv[1]).read()
block = '''	memset(ipad + keylen, 0, bs - keylen);
	memcpy(opad, ipad, bs);

	for (i = 0; i < bs; i++) {
		ipad[i] ^= HMAC_IPAD_VALUE;
		opad[i] ^= HMAC_OPAD_VALUE;
	}
'''
if src.count(block) != 2:
    sys.exit("EXTRACT FAILED: pad derivation block found %d times, expected 2 -- the C changed" % src.count(block))
open(sys.argv[2], 'w').write('''#include <string.h>
#include "kshim.h"
void c_derive_pads(u8 *ipad, u8 *opad, int bs, unsigned int keylen)
{
	int i;
%s}
''' % block)
