#pragma once
/* Userspace stand-ins for what crypto/aes_generic.c and its glue use. The pristine
 * C slice, the glue slice and the Rust are all checked against THIS one header, so
 * what is compared is the cipher logic, not the header. struct crypto_aes_ctx is
 * pinned to the kernel's layout (kabi: 484 bytes, key_length at 480). */
#include <stdint.h>
#include <string.h>
typedef uint8_t u8;
typedef uint32_t u32;
#define __visible
#define ____cacheline_aligned __attribute__((aligned(64)))
#define EXPORT_SYMBOL_GPL(sym)
#define AES_BLOCK_SIZE 16
struct crypto_aes_ctx {
	u32 key_enc[60];
	u32 key_dec[60];
	u32 key_length;
};
_Static_assert(sizeof(struct crypto_aes_ctx) == 484, "crypto_aes_ctx layout");
struct crypto_tfm { void *ctx; };
static inline void *crypto_tfm_ctx(struct crypto_tfm *t) { return t->ctx; }
int aes_expandkey(struct crypto_aes_ctx *ctx, const u8 *in_key, unsigned int key_len);
static inline u32 get_unaligned_le32(const void *p) { u32 v; memcpy(&v, p, 4); return v; }
static inline void put_unaligned_le32(u32 v, void *p) { memcpy(p, &v, 4); }
