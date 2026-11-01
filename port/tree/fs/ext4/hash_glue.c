// SPDX-License-Identifier: GPL-2.0
/*
 * RUST PORT (fs/ext4/hash.c, 6.18.49): the hash algorithms (TEA, half-MD4, the legacy hashes, the string packers) are in hash_rs.rs. This file keeps ext4fs_dirhash() with the
 * casefold path, the siphash version, the invalid-version warning and the final masking as upstream has them. Upstream's whole file is installed as hash_norust.c for CONFIG_RUST=n.
 */
/*
 *  linux/fs/ext4/hash.c
 *
 * Copyright (C) 2002 by Theodore Ts'o
 */

#include <linux/fs.h>
#include <linux/unicode.h>
#include <linux/compiler.h>
#include <linux/bitops.h>
#include "ext4.h"

/* The hash algorithms (TEA, half-MD4, the legacy hashes and the string packers) are in hash_rs.rs. */
int rust_ext4_dirhash(int version, const char *name, int len, const u32 *seed, u32 *hash, u32 *minor_hash);

static_assert(DX_HASH_LEGACY == 0 && DX_HASH_HALF_MD4 == 1 && DX_HASH_TEA == 2 && DX_HASH_LEGACY_UNSIGNED == 3 && DX_HASH_HALF_MD4_UNSIGNED == 4 && DX_HASH_TEA_UNSIGNED == 5);

/*
 * Returns the hash of a filename.  If len is 0 and name is NULL, then
 * this function can be used to test whether or not a hash version is
 * supported.
 *
 * The seed is an 4 longword (32 bits) "secret" which can be used to
 * uniquify a hash.  If the seed is all zero's, then some default seed
 * may be used.
 *
 * A particular hash version specifies whether or not the seed is
 * represented, and whether or not the returned hash is 32 bits or 64
 * bits.  32 bit hashes will return 0 for the minor hash.
 */
static int __ext4fs_dirhash(const struct inode *dir, const char *name, int len,
			    struct dx_hash_info *hinfo)
{
	__u32	hash;
	__u32	minor_hash = 0;

	switch (hinfo->hash_version) {
	case DX_HASH_LEGACY_UNSIGNED:
	case DX_HASH_LEGACY:
	case DX_HASH_HALF_MD4_UNSIGNED:
	case DX_HASH_HALF_MD4:
	case DX_HASH_TEA_UNSIGNED:
	case DX_HASH_TEA:
		rust_ext4_dirhash(hinfo->hash_version, name, len, hinfo->seed, &hash, &minor_hash);
		break;
	case DX_HASH_SIPHASH:
	{
		struct qstr qname = QSTR_INIT(name, len);
		__u64	combined_hash;

		if (fscrypt_has_encryption_key(dir)) {
			combined_hash = fscrypt_fname_siphash(dir, &qname);
		} else {
			ext4_warning_inode(dir, "Siphash requires key");
			return -1;
		}

		hash = (__u32)(combined_hash >> 32);
		minor_hash = (__u32)combined_hash;
		break;
	}
	default:
		hinfo->hash = 0;
		hinfo->minor_hash = 0;
		ext4_warning(dir->i_sb,
			     "invalid/unsupported hash tree version %u",
			     hinfo->hash_version);
		return -EINVAL;
	}
	hash = hash & ~1;
	if (hash == (EXT4_HTREE_EOF_32BIT << 1))
		hash = (EXT4_HTREE_EOF_32BIT - 1) << 1;
	hinfo->hash = hash;
	hinfo->minor_hash = minor_hash;
	return 0;
}

int ext4fs_dirhash(const struct inode *dir, const char *name, int len,
		   struct dx_hash_info *hinfo)
{
#if IS_ENABLED(CONFIG_UNICODE)
	const struct unicode_map *um = dir->i_sb->s_encoding;
	int r, dlen;
	unsigned char *buff;
	struct qstr qstr = {.name = name, .len = len };

	if (len && IS_CASEFOLDED(dir) &&
	   (!IS_ENCRYPTED(dir) || fscrypt_has_encryption_key(dir))) {
		buff = kzalloc(PATH_MAX, GFP_KERNEL);
		if (!buff)
			return -ENOMEM;

		dlen = utf8_casefold(um, &qstr, buff, PATH_MAX);
		if (dlen < 0) {
			kfree(buff);
			goto opaque_seq;
		}

		r = __ext4fs_dirhash(dir, buff, dlen, hinfo);

		kfree(buff);
		return r;
	}
opaque_seq:
#endif
	return __ext4fs_dirhash(dir, name, len, hinfo);
}
