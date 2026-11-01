#include <stdint.h>
#include <string.h>
#include <stdbool.h>
typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;
#define MAX_CIPHER_BLOCKSIZE 16
/* stand-ins for what the four pristine CBC loops use: struct crypto_lskcipher, its block size, the two one-block
 * cipher entry points and crypto_xor() (include/crypto/utils.h: word-wise for constant sizes, else __crypto_xor: same bytes) */
struct crypto_lskcipher { unsigned int bsize; };
static inline unsigned int crypto_lskcipher_blocksize(struct crypto_lskcipher *t) { return t->bsize; }
int toy_cipher_call(int enc, const u8 *src, u8 *dst, unsigned len, u8 *iv);   /* main.c */
static inline int crypto_lskcipher_encrypt(struct crypto_lskcipher *t, const u8 *src, u8 *dst, unsigned len, u8 *iv)
{ (void)t; return toy_cipher_call(1, src, dst, len, iv); }
static inline int crypto_lskcipher_decrypt(struct crypto_lskcipher *t, const u8 *src, u8 *dst, unsigned len, u8 *iv)
{ (void)t; return toy_cipher_call(0, src, dst, len, iv); }
static inline void crypto_xor(u8 *dst, const u8 *src, unsigned int n) { while (n--) { *dst = *dst ^ *src; dst++; src++; } }
