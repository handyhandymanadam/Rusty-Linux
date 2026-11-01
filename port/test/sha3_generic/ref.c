/* The pristine crypto/sha3_generic.c keccak core and entry bodies, compiled
 * as-is (extracted), over the smallest userspace stand-ins for the kernel
 * types they touch. The stand-ins are checked against include/crypto/sha3.h
 * by run.sh. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;
typedef uint32_t __le32; typedef uint64_t __le64;
#define SHA3_INLINE inline
#define EXPORT_SYMBOL(x)
#define le64_to_cpu(x) (x)           /* x86-64 host, as the kernel target */
static inline u64 rol64(u64 w, unsigned s) { return (w << (s & 63)) | (w >> ((64 - s) & 63)); }
static inline u64 get_unaligned_le64(const void *p) { u64 v; memcpy(&v, p, 8); return v; }
static inline void put_unaligned_le64(u64 v, void *p) { memcpy(p, &v, 8); }
static inline void put_unaligned_le32(u32 v, void *p) { memcpy(p, &v, 4); }
static inline void memzero_explicit(void *s, size_t n) { memset(s, 0, n); }

#define SHA3_224_DIGEST_SIZE	(224 / 8)
#define SHA3_224_BLOCK_SIZE	(200 - 2 * SHA3_224_DIGEST_SIZE)
#define SHA3_STATE_SIZE		200
struct sha3_state {
	u64		st[SHA3_STATE_SIZE / 8];
};
struct crypto_shash { unsigned int blocksize, digestsize; };
struct shash_desc { struct crypto_shash *tfm; struct sha3_state ctx; };
static inline void *shash_desc_ctx(struct shash_desc *d) { return &d->ctx; }
static inline unsigned int crypto_shash_blocksize(struct crypto_shash *t) { return t->blocksize; }
static inline unsigned int crypto_shash_digestsize(struct crypto_shash *t) { return t->digestsize; }

#include "EXTRACT"

int c_init(struct shash_desc *d) { return crypto_sha3_init(d); }
int c_update(struct shash_desc *d, const u8 *p, unsigned n) { return crypto_sha3_update(d, p, n); }
int c_finup(struct shash_desc *d, const u8 *p, unsigned n, u8 *o) { return crypto_sha3_finup(d, p, n, o); }

/* plain-signature wrappers, mirroring the Rust entry points (state as u64[25]) */
void c_init_st(u64 *st)
{
	struct crypto_shash t = { 0, 0 };
	struct shash_desc d = { &t, { { 0 } } };
	memset(st, 0xcc, 200);       /* init must overwrite all 200 bytes */
	memcpy(d.ctx.st, st, 200);
	crypto_sha3_init(&d);
	memcpy(st, d.ctx.st, 200);
}
unsigned int c_update_st(u64 *st, const u8 *p, unsigned int n, unsigned int rsiz)
{
	struct crypto_shash t = { rsiz, 0 };
	struct shash_desc d = { &t, { { 0 } } };
	int r;
	memcpy(d.ctx.st, st, 200);
	r = crypto_sha3_update(&d, p, n);
	memcpy(st, d.ctx.st, 200);
	return (unsigned int)r;
}
void c_finup_st(u64 *st, const u8 *p, unsigned int n, u8 *out, unsigned int ds, unsigned int rsiz)
{
	struct crypto_shash t = { rsiz, ds };
	struct shash_desc d = { &t, { { 0 } } };
	memcpy(d.ctx.st, st, 200);
	crypto_sha3_finup(&d, p, n, out);
	memcpy(st, d.ctx.st, 200);
}
