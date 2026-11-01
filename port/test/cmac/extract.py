#!/usr/bin/env python3
"""extract.py <pristine cmac.c> <out.c>: slice the two logic blocks out of the UNMODIFIED crypto/cmac.c into
c_derive_subkeys() and c_finup_xor(). Fails loudly if either block is not present exactly once, character for character."""
import sys
src = open(sys.argv[1]).read()
b1 = src[src.index("\tswitch (bs) {\n\tcase 16:"):src.index("\treturn 0;\n}\n\nstatic int crypto_cmac_digest_init")]
b2_start = "\tcrypto_xor(prev, src, len);\n\tif (len != bs) {\n\t\tprev[len] ^= 0x80;\n\t\toffset += bs;\n\t}\n\tcrypto_xor(prev, (const u8 *)tctx->consts + offset, bs);\n"
for name, blk in (("subkey switch", b1), ("finup xor", b2_start)):
    if src.count(blk) != 1 or "gfmask" not in b1:
        sys.exit("EXTRACT FAILED: %s block not found exactly once -- the C changed" % name)
if "case 8:" not in b1 or "0x1B" not in b1 or "0x87" not in b1:
    sys.exit("EXTRACT FAILED: subkey block no longer the expected one")
open(sys.argv[2], 'w').write('''#include <stdint.h>
#include <string.h>
#include "kshim.h"
void c_derive_subkeys(u8 *consts8, unsigned int bs)
{
	__be64 *consts = (__be64 *)consts8;
	u64 _const[2];
	int i;
	u8 msb_mask, gfmask;
%s}
void c_finup_xor(u8 *prev, const u8 *src, unsigned int len_u, const u8 *consts8, unsigned int bs_u)
{
	struct { const void *consts; } t = { consts8 }, *tctx = &t;
	int bs = bs_u;
	unsigned int len = len_u, offset = 0;
%s}
''' % (b1, b2_start))
