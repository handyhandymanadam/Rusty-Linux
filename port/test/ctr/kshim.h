#include <stdint.h>
#include <string.h>
typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64; typedef uint32_t __be32;
#define be32_to_cpu(x) __builtin_bswap32(x)
#define cpu_to_be32(x) __builtin_bswap32(x)
#define IS_ENABLED(x) 1
#define IS_ALIGNED(x, a) (((x) & ((a) - 1)) == 0)
#define likely(x) __builtin_expect(!!(x), 1)
#define CTR_RFC3686_NONCE_SIZE 4
#define CTR_RFC3686_IV_SIZE 8
#define CTR_RFC3686_BLOCK_SIZE 16
/* the cipher: supplied by main.c (a deterministic toy block cipher) */
void toy_encrypt_block(u8 *dst, const u8 *src);
static inline void crypto_cipher_encrypt_one(void *tfm, u8 *dst, const u8 *src) { (void)tfm; toy_encrypt_block(dst, src); }
static inline void *crypto_cipher_tfm(void *t) { return t; }
/* crypto_xor / crypto_xor_cpy: include/crypto/utils.h (word-wise for constant sizes, else __crypto_xor): same bytes */
static inline void crypto_xor(u8 *dst, const u8 *src, unsigned int n) { while (n--) { *dst = *dst ^ *src; dst++; src++; } }
static inline void crypto_xor_cpy(u8 *dst, const u8 *s1, const u8 *s2, unsigned int n) { while (n--) *dst++ = *s1++ ^ *s2++; }
void crypto_inc(u8 *a, unsigned int size);
