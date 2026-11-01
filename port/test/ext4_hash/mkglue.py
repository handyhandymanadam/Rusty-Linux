#!/usr/bin/env python3
"""mkglue.py PRISTINE.c OUT.c -- hash_glue.c = upstream fs/ext4/hash.c with the hash algorithms replaced by a call into hash_rs.rs (see fs/ext4/hash_rs.rs)."""
import sys
s = open(sys.argv[1]).read()
def cut(first_sig, last_sig):
    """remove from the line starting first_sig through the end of the function starting at last_sig"""
    global s
    i = s.index(first_sig); k = s.index(last_sig); j = s.index("\n}\n", k) + 3
    s = s[:i] + s[j:]
# the helpers: from the TEA transform's DELTA through str2hashbuf_unsigned
i = s.index("#define DELTA"); k = s.index("static void str2hashbuf_unsigned("); j = s.index("\n}\n", k) + 3
s = s[:i] + '''/* The hash algorithms (TEA, half-MD4, the legacy hashes and the string packers) are in hash_rs.rs. */
int rust_ext4_dirhash(int version, const char *name, int len, const u32 *seed, u32 *hash, u32 *minor_hash);

static_assert(DX_HASH_LEGACY == 0 && DX_HASH_HALF_MD4 == 1 && DX_HASH_TEA == 2 && DX_HASH_LEGACY_UNSIGNED == 3 && DX_HASH_HALF_MD4_UNSIGNED == 4 && DX_HASH_TEA_UNSIGNED == 5);
''' + s[j:]
old_head = s[s.index("static int __ext4fs_dirhash("):s.index("\tswitch (hinfo->hash_version) {")]
new_head = '''static int __ext4fs_dirhash(const struct inode *dir, const char *name, int len,
			    struct dx_hash_info *hinfo)
{
	__u32	hash;
	__u32	minor_hash = 0;

'''
s = s.replace(old_head, new_head)
a = s.index("\tcase DX_HASH_LEGACY_UNSIGNED:"); b = s.index("\tcase DX_HASH_SIPHASH:")
s = s[:a] + '''	case DX_HASH_LEGACY_UNSIGNED:
	case DX_HASH_LEGACY:
	case DX_HASH_HALF_MD4_UNSIGNED:
	case DX_HASH_HALF_MD4:
	case DX_HASH_TEA_UNSIGNED:
	case DX_HASH_TEA:
		rust_ext4_dirhash(hinfo->hash_version, name, len, hinfo->seed, &hash, &minor_hash);
		break;
''' + s[b:]
hdr = "// SPDX-License-Identifier: GPL-2.0\n/*\n * RUST PORT (fs/ext4/hash.c, 6.18.49): the hash algorithms (TEA, half-MD4, the legacy hashes, the string packers) are in hash_rs.rs. This file keeps ext4fs_dirhash() with the\n * casefold path, the siphash version, the invalid-version warning and the final masking as upstream has them. Upstream's whole file is installed as hash_norust.c for CONFIG_RUST=n.\n */\n"
s = s.replace("// SPDX-License-Identifier: GPL-2.0\n", hdr, 1)
open(sys.argv[2], "w").write(s)
