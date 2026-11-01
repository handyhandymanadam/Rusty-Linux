/* The pristine crypto/ghash-generic.c callbacks, compiled as-is (extracted)
 * over userspace stand-ins, against the REAL include/crypto/{ghash,gf128mul,
 * b128ops}.h. gf128mul_*_4k_lle come from the REAL lib/crypto/gf128mul.c
 * (compiled separately, run.sh). */
#include <string.h>
#include <crypto/gf128mul.h>
#include <crypto/ghash.h>
#define EINVAL 22
#define ENOMEM 12
#define BUILD_BUG_ON(x) _Static_assert(!(x), #x)
struct crypto_shash { void *ctx; };
struct crypto_tfm { void *ctx; };
struct shash_desc { struct crypto_shash *tfm; struct ghash_desc_ctx ctx; };
static inline void *shash_desc_ctx(struct shash_desc *d) { return &d->ctx; }
static inline void *crypto_shash_ctx(struct crypto_shash *t) { return t->ctx; }
static inline void *crypto_tfm_ctx(struct crypto_tfm *t) { return t->ctx; }
static inline void memzero_explicit(void *s, size_t n) { memset(s, 0, n); }
static inline void crypto_xor(u8 *dst, const u8 *src, unsigned n) { while (n--) *dst++ ^= *src++; }

#include "EXTRACT"

/* plain-signature wrappers mirroring the Rust entry points */
void c_init(u8 *buf) { struct shash_desc d; memset(&d, 0xcc, sizeof d); ghash_init(&d); memcpy(buf, d.ctx.buffer, 16); }
int c_setkey(struct gf128mul_4k **slot, const u8 *key, unsigned n)
{ struct ghash_ctx c = { *slot }; struct crypto_shash t = { &c }; int r = ghash_setkey(&t, key, n); *slot = c.gf128; return r; }
unsigned c_update(u8 *buf, const struct gf128mul_4k *g, const u8 *src, unsigned n)
{ struct ghash_ctx c = { (struct gf128mul_4k *)g }; struct crypto_shash t = { &c }; struct shash_desc d = { &t, { { 0 } } };
  memcpy(d.ctx.buffer, buf, 16); int r = ghash_update(&d, src, n); memcpy(buf, d.ctx.buffer, 16); return (unsigned)r; }
void c_finup(u8 *buf, const struct gf128mul_4k *g, const u8 *src, unsigned n, u8 *dst)
{ struct ghash_ctx c = { (struct gf128mul_4k *)g }; struct crypto_shash t = { &c }; struct shash_desc d = { &t, { { 0 } } };
  memcpy(d.ctx.buffer, buf, 16); ghash_finup(&d, src, n, dst); memcpy(buf, d.ctx.buffer, 16); }
void c_exit(struct gf128mul_4k **slot)
{ struct ghash_ctx c = { *slot }; struct crypto_tfm t = { &c }; ghash_exit_tfm(&t); }

int shim_fail_alloc;
static int frees;
int shim_frees(void) { return frees; }
void kfree_sensitive(const void *p) { if (p) { memset((void *)p, 0, sizeof(struct gf128mul_4k)); free((void *)p); frees++; } }
