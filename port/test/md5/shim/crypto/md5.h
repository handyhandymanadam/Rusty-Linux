#pragma once
/* include/crypto/md5.h, trimmed of the CRYPTO_MD5_STATESIZE machinery (needs
 * crypto/hash.h, not used by lib/crypto/md5.c itself) and the
 * md5_zero_message_hash declaration (defined in crypto/md5.c, a different
 * file this project does not port). Struct layouts are copied verbatim --
 * those are exactly what this differential exists to hold constant. */
#include <stddef.h>
#include <linux/types.h>

#define MD5_DIGEST_SIZE		16
#define MD5_HMAC_BLOCK_SIZE	64
#define MD5_BLOCK_SIZE		64
#define MD5_BLOCK_WORDS		16
#define MD5_HASH_WORDS		4

#define MD5_H0	0x67452301UL
#define MD5_H1	0xefcdab89UL
#define MD5_H2	0x98badcfeUL
#define MD5_H3	0x10325476UL

struct md5_block_state {
	u32 h[MD5_HASH_WORDS];
};

struct md5_ctx {
	struct md5_block_state state;
	u64 bytecount;
	u8 buf[MD5_BLOCK_SIZE] __attribute__((aligned(__alignof__(__le64))));
};

void md5_init(struct md5_ctx *ctx);
void md5_update(struct md5_ctx *ctx, const u8 *data, size_t len);
void md5_final(struct md5_ctx *ctx, u8 out[MD5_DIGEST_SIZE]);
void md5(const u8 *data, size_t len, u8 out[MD5_DIGEST_SIZE]);

struct hmac_md5_key {
	struct md5_block_state istate;
	struct md5_block_state ostate;
};

struct hmac_md5_ctx {
	struct md5_ctx hash_ctx;
	struct md5_block_state ostate;
};

void hmac_md5_preparekey(struct hmac_md5_key *key,
			 const u8 *raw_key, size_t raw_key_len);
void hmac_md5_init(struct hmac_md5_ctx *ctx, const struct hmac_md5_key *key);
void hmac_md5_init_usingrawkey(struct hmac_md5_ctx *ctx,
			       const u8 *raw_key, size_t raw_key_len);
static inline void hmac_md5_update(struct hmac_md5_ctx *ctx,
				   const u8 *data, size_t data_len)
{
	md5_update(&ctx->hash_ctx, data, data_len);
}
void hmac_md5_final(struct hmac_md5_ctx *ctx, u8 out[MD5_DIGEST_SIZE]);
void hmac_md5(const struct hmac_md5_key *key,
	      const u8 *data, size_t data_len, u8 out[MD5_DIGEST_SIZE]);
void hmac_md5_usingrawkey(const u8 *raw_key, size_t raw_key_len,
			  const u8 *data, size_t data_len,
			  u8 out[MD5_DIGEST_SIZE]);
