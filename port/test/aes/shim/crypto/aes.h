#pragma once
/* Minimal reproduction of include/crypto/aes.h: only what lib/crypto/aes.c
 * itself references. Both arms (pristine C and Rust) are checked against
 * the SAME shim, so what's compared is the two ports' logic, not this
 * header. */
#include "../linux/types.h"

#define AES_KEYSIZE_128 16
#define AES_KEYSIZE_192 24
#define AES_KEYSIZE_256 32
#define AES_BLOCK_SIZE  16
#define AES_MAX_KEYLENGTH (15 * 16)
#define AES_MAX_KEYLENGTH_U32 (AES_MAX_KEYLENGTH / sizeof(u32))

struct crypto_aes_ctx {
	u32 key_enc[AES_MAX_KEYLENGTH_U32];
	u32 key_dec[AES_MAX_KEYLENGTH_U32];
	u32 key_length;
};

static inline int aes_check_keylen(unsigned int keylen)
{
	switch (keylen) {
	case AES_KEYSIZE_128:
	case AES_KEYSIZE_192:
	case AES_KEYSIZE_256:
		break;
	default:
		return -22; /* -EINVAL */
	}
	return 0;
}

int aes_expandkey(struct crypto_aes_ctx *ctx, const u8 *in_key,
		  unsigned int key_len);
void aes_encrypt(const struct crypto_aes_ctx *ctx, u8 *out, const u8 *in);
void aes_decrypt(const struct crypto_aes_ctx *ctx, u8 *out, const u8 *in);
