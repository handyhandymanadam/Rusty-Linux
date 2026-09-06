#pragma once
/* Minimal reproduction of include/crypto/sha2.h's SHA-384/SHA-512 section:
 * only what lib/crypto/sha512.c itself references. Both arms (pristine C
 * and Rust) are checked against the SAME shim, so what's compared is the
 * two ports' logic, not this header. */
#include <stddef.h>
#include "../linux/types.h"

#define SHA384_DIGEST_SIZE 48
#define SHA384_BLOCK_SIZE  128
#define SHA512_DIGEST_SIZE 64
#define SHA512_BLOCK_SIZE  128

#define SHA384_H0 0xcbbb9d5dc1059ed8ULL
#define SHA384_H1 0x629a292a367cd507ULL
#define SHA384_H2 0x9159015a3070dd17ULL
#define SHA384_H3 0x152fecd8f70e5939ULL
#define SHA384_H4 0x67332667ffc00b31ULL
#define SHA384_H5 0x8eb44a8768581511ULL
#define SHA384_H6 0xdb0c2e0d64f98fa7ULL
#define SHA384_H7 0x47b5481dbefa4fa4ULL

#define SHA512_H0 0x6a09e667f3bcc908ULL
#define SHA512_H1 0xbb67ae8584caa73bULL
#define SHA512_H2 0x3c6ef372fe94f82bULL
#define SHA512_H3 0xa54ff53a5f1d36f1ULL
#define SHA512_H4 0x510e527fade682d1ULL
#define SHA512_H5 0x9b05688c2b3e6c1fULL
#define SHA512_H6 0x1f83d9abfb41bd6bULL
#define SHA512_H7 0x5be0cd19137e2179ULL

struct sha512_block_state {
	u64 h[8];
};

struct __sha512_ctx {
	struct sha512_block_state state;
	u64 bytecount_lo;
	u64 bytecount_hi;
	u8 buf[SHA512_BLOCK_SIZE];
};
void __sha512_update(struct __sha512_ctx *ctx, const u8 *data, size_t len);

struct __hmac_sha512_key {
	struct sha512_block_state istate;
	struct sha512_block_state ostate;
};
struct __hmac_sha512_ctx {
	struct __sha512_ctx sha_ctx;
	struct sha512_block_state ostate;
};
void __hmac_sha512_init(struct __hmac_sha512_ctx *ctx,
			const struct __hmac_sha512_key *key);

struct sha384_ctx {
	struct __sha512_ctx ctx;
};
void sha384_init(struct sha384_ctx *ctx);
static inline void sha384_update(struct sha384_ctx *ctx, const u8 *data, size_t len)
{
	__sha512_update(&ctx->ctx, data, len);
}
void sha384_final(struct sha384_ctx *ctx, u8 out[SHA384_DIGEST_SIZE]);
void sha384(const u8 *data, size_t len, u8 out[SHA384_DIGEST_SIZE]);

struct hmac_sha384_key {
	struct __hmac_sha512_key key;
};
struct hmac_sha384_ctx {
	struct __hmac_sha512_ctx ctx;
};
void hmac_sha384_preparekey(struct hmac_sha384_key *key,
			    const u8 *raw_key, size_t raw_key_len);
static inline void hmac_sha384_init(struct hmac_sha384_ctx *ctx,
				    const struct hmac_sha384_key *key)
{
	__hmac_sha512_init(&ctx->ctx, &key->key);
}
void hmac_sha384_init_usingrawkey(struct hmac_sha384_ctx *ctx,
				  const u8 *raw_key, size_t raw_key_len);
static inline void hmac_sha384_update(struct hmac_sha384_ctx *ctx,
				      const u8 *data, size_t data_len)
{
	__sha512_update(&ctx->ctx.sha_ctx, data, data_len);
}
void hmac_sha384_final(struct hmac_sha384_ctx *ctx, u8 out[SHA384_DIGEST_SIZE]);
void hmac_sha384(const struct hmac_sha384_key *key,
		 const u8 *data, size_t data_len, u8 out[SHA384_DIGEST_SIZE]);
void hmac_sha384_usingrawkey(const u8 *raw_key, size_t raw_key_len,
			     const u8 *data, size_t data_len,
			     u8 out[SHA384_DIGEST_SIZE]);

struct sha512_ctx {
	struct __sha512_ctx ctx;
};
void sha512_init(struct sha512_ctx *ctx);
static inline void sha512_update(struct sha512_ctx *ctx, const u8 *data, size_t len)
{
	__sha512_update(&ctx->ctx, data, len);
}
void sha512_final(struct sha512_ctx *ctx, u8 out[SHA512_DIGEST_SIZE]);
void sha512(const u8 *data, size_t len, u8 out[SHA512_DIGEST_SIZE]);

struct hmac_sha512_key {
	struct __hmac_sha512_key key;
};
struct hmac_sha512_ctx {
	struct __hmac_sha512_ctx ctx;
};
void hmac_sha512_preparekey(struct hmac_sha512_key *key,
			    const u8 *raw_key, size_t raw_key_len);
static inline void hmac_sha512_init(struct hmac_sha512_ctx *ctx,
				    const struct hmac_sha512_key *key)
{
	__hmac_sha512_init(&ctx->ctx, &key->key);
}
void hmac_sha512_init_usingrawkey(struct hmac_sha512_ctx *ctx,
				  const u8 *raw_key, size_t raw_key_len);
static inline void hmac_sha512_update(struct hmac_sha512_ctx *ctx,
				      const u8 *data, size_t data_len)
{
	__sha512_update(&ctx->ctx.sha_ctx, data, data_len);
}
void hmac_sha512_final(struct hmac_sha512_ctx *ctx, u8 out[SHA512_DIGEST_SIZE]);
void hmac_sha512(const struct hmac_sha512_key *key,
		 const u8 *data, size_t data_len, u8 out[SHA512_DIGEST_SIZE]);
void hmac_sha512_usingrawkey(const u8 *raw_key, size_t raw_key_len,
			     const u8 *data, size_t data_len,
			     u8 out[SHA512_DIGEST_SIZE]);
