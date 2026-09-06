#pragma once
/* Minimal reproduction of include/crypto/sha2.h's SHA-224/SHA-256 section:
 * only what lib/crypto/sha256.c itself references. Both arms (pristine C
 * and Rust) are checked against the SAME shim, so what's compared is the
 * two ports' logic, not this header. */
#include <stddef.h>
#include <stdbool.h>
#include "../linux/types.h"

#define SHA224_DIGEST_SIZE 28
#define SHA224_BLOCK_SIZE  64
#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE  64

#define SHA224_H0 0xc1059ed8UL
#define SHA224_H1 0x367cd507UL
#define SHA224_H2 0x3070dd17UL
#define SHA224_H3 0xf70e5939UL
#define SHA224_H4 0xffc00b31UL
#define SHA224_H5 0x68581511UL
#define SHA224_H6 0x64f98fa7UL
#define SHA224_H7 0xbefa4fa4UL

#define SHA256_H0 0x6a09e667UL
#define SHA256_H1 0xbb67ae85UL
#define SHA256_H2 0x3c6ef372UL
#define SHA256_H3 0xa54ff53aUL
#define SHA256_H4 0x510e527fUL
#define SHA256_H5 0x9b05688cUL
#define SHA256_H6 0x1f83d9abUL
#define SHA256_H7 0x5be0cd19UL

struct sha256_block_state {
	u32 h[8];
};

struct __sha256_ctx {
	struct sha256_block_state state;
	u64 bytecount;
	u8 buf[SHA256_BLOCK_SIZE];
};
void __sha256_update(struct __sha256_ctx *ctx, const u8 *data, size_t len);

struct sha224_ctx {
	struct __sha256_ctx ctx;
};
void sha224_init(struct sha224_ctx *ctx);
static inline void sha224_update(struct sha224_ctx *ctx, const u8 *data, size_t len)
{
	__sha256_update(&ctx->ctx, data, len);
}
void sha224_final(struct sha224_ctx *ctx, u8 out[SHA224_DIGEST_SIZE]);
void sha224(const u8 *data, size_t len, u8 out[SHA224_DIGEST_SIZE]);

struct __hmac_sha256_key {
	struct sha256_block_state istate, ostate;
};
struct __hmac_sha256_ctx {
	struct __sha256_ctx sha_ctx;
	struct sha256_block_state ostate;
};
void __hmac_sha256_init(struct __hmac_sha256_ctx *ctx,
			const struct __hmac_sha256_key *key);

struct hmac_sha224_key {
	struct __hmac_sha256_key key;
};
struct hmac_sha224_ctx {
	struct __hmac_sha256_ctx ctx;
};
void hmac_sha224_preparekey(struct hmac_sha224_key *key,
			    const u8 *raw_key, size_t raw_key_len);
static inline void hmac_sha224_init(struct hmac_sha224_ctx *ctx,
				    const struct hmac_sha224_key *key)
{
	__hmac_sha256_init(&ctx->ctx, &key->key);
}
void hmac_sha224_init_usingrawkey(struct hmac_sha224_ctx *ctx,
				  const u8 *raw_key, size_t raw_key_len);
static inline void hmac_sha224_update(struct hmac_sha224_ctx *ctx,
				      const u8 *data, size_t data_len)
{
	__sha256_update(&ctx->ctx.sha_ctx, data, data_len);
}
void hmac_sha224_final(struct hmac_sha224_ctx *ctx, u8 out[SHA224_DIGEST_SIZE]);
void hmac_sha224(const struct hmac_sha224_key *key,
		 const u8 *data, size_t data_len, u8 out[SHA224_DIGEST_SIZE]);
void hmac_sha224_usingrawkey(const u8 *raw_key, size_t raw_key_len,
			     const u8 *data, size_t data_len,
			     u8 out[SHA224_DIGEST_SIZE]);

struct sha256_ctx {
	struct __sha256_ctx ctx;
};
void sha256_init(struct sha256_ctx *ctx);
static inline void sha256_update(struct sha256_ctx *ctx, const u8 *data, size_t len)
{
	__sha256_update(&ctx->ctx, data, len);
}
void sha256_final(struct sha256_ctx *ctx, u8 out[SHA256_DIGEST_SIZE]);
void sha256(const u8 *data, size_t len, u8 out[SHA256_DIGEST_SIZE]);
void sha256_finup_2x(const struct sha256_ctx *ctx, const u8 *data1,
		     const u8 *data2, size_t len, u8 out1[SHA256_DIGEST_SIZE],
		     u8 out2[SHA256_DIGEST_SIZE]);
bool sha256_finup_2x_is_optimized(void);

struct hmac_sha256_key {
	struct __hmac_sha256_key key;
};
struct hmac_sha256_ctx {
	struct __hmac_sha256_ctx ctx;
};
void hmac_sha256_preparekey(struct hmac_sha256_key *key,
			    const u8 *raw_key, size_t raw_key_len);
static inline void hmac_sha256_init(struct hmac_sha256_ctx *ctx,
				    const struct hmac_sha256_key *key)
{
	__hmac_sha256_init(&ctx->ctx, &key->key);
}
void hmac_sha256_init_usingrawkey(struct hmac_sha256_ctx *ctx,
				  const u8 *raw_key, size_t raw_key_len);
static inline void hmac_sha256_update(struct hmac_sha256_ctx *ctx,
				      const u8 *data, size_t data_len)
{
	__sha256_update(&ctx->ctx.sha_ctx, data, data_len);
}
void hmac_sha256_final(struct hmac_sha256_ctx *ctx, u8 out[SHA256_DIGEST_SIZE]);
void hmac_sha256(const struct hmac_sha256_key *key,
		 const u8 *data, size_t data_len, u8 out[SHA256_DIGEST_SIZE]);
void hmac_sha256_usingrawkey(const u8 *raw_key, size_t raw_key_len,
			     const u8 *data, size_t data_len,
			     u8 out[SHA256_DIGEST_SIZE]);
