#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;
/* stand-ins for the two crypto structs and the two accessors crypto_ecb_crypt() uses */
struct crypto_tfm { int unused; };
struct crypto_cipher { struct crypto_tfm tfm; unsigned int bsize; };
static inline unsigned int crypto_cipher_blocksize(struct crypto_cipher *c) { return c->bsize; }
static inline struct crypto_tfm *crypto_cipher_tfm(struct crypto_cipher *c) { return &c->tfm; }
