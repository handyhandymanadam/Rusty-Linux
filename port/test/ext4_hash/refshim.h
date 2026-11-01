/* Stand-ins for what the pristine slice of fs/ext4/hash.c uses. */
#ifndef REFSHIM_H
#define REFSHIM_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint32_t u32, __u32; typedef uint64_t u64, __u64;
#define EINVAL 22
#define fallthrough __attribute__((fallthrough))
static inline u32 rol32(u32 w, unsigned s) { return (w << (s & 31)) | (w >> ((32 - s) & 31)); }
enum { DX_HASH_LEGACY, DX_HASH_HALF_MD4, DX_HASH_TEA, DX_HASH_LEGACY_UNSIGNED, DX_HASH_HALF_MD4_UNSIGNED, DX_HASH_TEA_UNSIGNED, DX_HASH_SIPHASH };
#define EXT4_HTREE_EOF_32BIT ((1UL << (32 - 1)) - 1)
struct super_block { int x; }; struct inode { struct super_block *i_sb; };
struct qstr { const char *name; unsigned len; };
#define QSTR_INIT(n, l) { .name = n, .len = l }
struct dx_hash_info { u32 hash; u32 minor_hash; int hash_version; u32 *seed; };
extern int has_key_g, warns;
static inline bool fscrypt_has_encryption_key(const struct inode *i) { return has_key_g; }
static inline u64 fscrypt_fname_siphash(const struct inode *i, const struct qstr *q) { u64 h = 0xcbf29ce484222325ULL; unsigned k; for (k = 0; k < q->len; k++) h = (h ^ (unsigned char)q->name[k]) * 0x100000001b3ULL; return h; }
#define ext4_warning_inode(i, ...) (warns++)
#define ext4_warning(sb, ...) (warns++)
#define static_assert(x) _Static_assert(1, "")
#endif
