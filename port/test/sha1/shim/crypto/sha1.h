#pragma once
/* Minimal reproduction of include/crypto/sha1.h: only what
 * lib/crypto/sha1.c itself references. Both arms (pristine C and Rust) are
 * checked against the SAME shim, so what's compared is the two ports'
 * logic, not this header. */
#include <stddef.h>
#include "../linux/types.h"

#define SHA1_DIGEST_SIZE 20
#define SHA1_BLOCK_SIZE  64
#define SHA1_WORKSPACE_WORDS 16

#define SHA1_H0 0x67452301UL
#define SHA1_H1 0xefcdab89UL
#define SHA1_H2 0x98badcfeUL
#define SHA1_H3 0x10325476UL
#define SHA1_H4 0xc3d2e1f0UL

void sha1_init_raw(__u32 *buf);
void sha1_transform(__u32 *digest, const char *data, __u32 *array);

struct sha1_block_state {
	u32 h[SHA1_DIGEST_SIZE / 4];
};

struct sha1_ctx {
	struct sha1_block_state state;
	u64 bytecount;
	u8 buf[SHA1_BLOCK_SIZE];
};
void sha1_init(struct sha1_ctx *ctx);
void sha1_update(struct sha1_ctx *ctx, const u8 *data, size_t len);
void sha1_final(struct sha1_ctx *ctx, u8 out[SHA1_DIGEST_SIZE]);
void sha1(const u8 *data, size_t len, u8 out[SHA1_DIGEST_SIZE]);

struct hmac_sha1_key {
	struct sha1_block_state istate;
	struct sha1_block_state ostate;
};
struct hmac_sha1_ctx {
	struct sha1_ctx sha_ctx;
	struct sha1_block_state ostate;
};
void hmac_sha1_preparekey(struct hmac_sha1_key *key,
			  const u8 *raw_key, size_t raw_key_len);
void hmac_sha1_init(struct hmac_sha1_ctx *ctx, const struct hmac_sha1_key *key);
void hmac_sha1_init_usingrawkey(struct hmac_sha1_ctx *ctx,
				const u8 *raw_key, size_t raw_key_len);
static inline void hmac_sha1_update(struct hmac_sha1_ctx *ctx,
				    const u8 *data, size_t data_len)
{
	sha1_update(&ctx->sha_ctx, data, data_len);
}
void hmac_sha1_final(struct hmac_sha1_ctx *ctx, u8 out[SHA1_DIGEST_SIZE]);
void hmac_sha1(const struct hmac_sha1_key *key,
	       const u8 *data, size_t data_len, u8 out[SHA1_DIGEST_SIZE]);
void hmac_sha1_usingrawkey(const u8 *raw_key, size_t raw_key_len,
			   const u8 *data, size_t data_len,
			   u8 out[SHA1_DIGEST_SIZE]);
